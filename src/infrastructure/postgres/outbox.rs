//! Concurrent-safe DM outbox leasing and completion.

use std::time::Duration;

use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    PostgresStore, StoreError,
    models::ClaimedDeliveryRow,
    types::{ClaimedDelivery, DeliveryAttempt, DeliveryOutcome},
};

impl PostgresStore {
    /// Claims due DM deliveries without waiting on rows held by other workers.
    ///
    /// A batch shares one unguessable lease token. Completion is a
    /// compare-and-swap on `(event_id, lease_token)`, so an expired worker
    /// cannot overwrite a newer worker's result.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty/oversized claim, a zero lease, corrupt
    /// persisted counters, or a PostgreSQL failure.
    pub async fn claim_due_deliveries(
        &self,
        limit: u32,
        lease_duration: Duration,
    ) -> Result<Vec<ClaimedDelivery>, StoreError> {
        if limit == 0 || limit > 1_000 {
            return Err(StoreError::InvalidArgument {
                field: "limit",
                reason: "must be between 1 and 1000",
            });
        }
        if lease_duration.is_zero() {
            return Err(StoreError::InvalidArgument {
                field: "lease_duration",
                reason: "must be greater than zero",
            });
        }

        let limit = i64::from(limit);
        let lease_milliseconds =
            i64::try_from(lease_duration.as_millis()).map_err(|_| StoreError::NumericRange {
                field: "lease_duration",
            })?;
        if lease_milliseconds == 0 {
            return Err(StoreError::InvalidArgument {
                field: "lease_duration",
                reason: "must be at least one millisecond",
            });
        }
        let lease_token = Uuid::new_v4();

        let rows = sqlx::query_as::<_, ClaimedDeliveryRow>(
            r"
            WITH claim_clock AS MATERIALIZED (
                SELECT clock_timestamp() AS now
            ),
            candidates AS MATERIALIZED (
                SELECT event_id
                FROM hook_private.dm_outbox, claim_clock
                WHERE status IN ('pending', 'retrying')
                  AND available_at <= claim_clock.now
                  AND (leased_until IS NULL OR leased_until <= claim_clock.now)
                ORDER BY available_at, event_id
                FOR UPDATE SKIP LOCKED
                LIMIT $1
            )
            UPDATE hook_private.dm_outbox AS delivery
            SET lease_token = $2,
                leased_until = claim_clock.now + ($3 * INTERVAL '1 millisecond'),
                updated_at = claim_clock.now
            FROM candidates, claim_clock
            WHERE delivery.event_id = candidates.event_id
            RETURNING delivery.event_id,
                      delivery.request_body,
                      delivery.attempts,
                      delivery.lease_token,
                      delivery.leased_until
            ",
        )
        .bind(limit)
        .bind(lease_token)
        .bind(lease_milliseconds)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(ClaimedDelivery::try_from).collect()
    }

    /// Extends a still-owned delivery lease.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::LeaseLost`] when another worker owns the row or it
    /// is no longer deliverable.
    pub async fn extend_delivery_lease(
        &self,
        event_id: crate::domain::EventId,
        lease_token: Uuid,
        extension: Duration,
    ) -> Result<OffsetDateTime, StoreError> {
        if extension.is_zero() {
            return Err(StoreError::InvalidArgument {
                field: "extension",
                reason: "must be greater than zero",
            });
        }
        let milliseconds = i64::try_from(extension.as_millis())
            .map_err(|_| StoreError::NumericRange { field: "extension" })?;
        if milliseconds == 0 {
            return Err(StoreError::InvalidArgument {
                field: "extension",
                reason: "must be at least one millisecond",
            });
        }

        let leased_until = sqlx::query_scalar::<_, OffsetDateTime>(
            r"
            UPDATE hook_private.dm_outbox
            SET leased_until = clock_timestamp() + ($3 * INTERVAL '1 millisecond'),
                updated_at = clock_timestamp()
            WHERE event_id = $1
              AND lease_token = $2
              AND status IN ('pending', 'retrying')
            RETURNING leased_until
            ",
        )
        .bind(event_id.as_uuid())
        .bind(lease_token)
        .bind(milliseconds)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::LeaseLost)?;

        Ok(leased_until)
    }

    /// Records one claimed DM attempt and releases the lease atomically.
    ///
    /// Only [`DeliveryOutcome::Delivered`] records HTTP 202, the DM durability
    /// boundary defined by the service contract.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::LeaseLost`] if the lease was reclaimed or the job
    /// became terminal, and returns a database error for invalid diagnostics.
    pub async fn complete_delivery(&self, attempt: &DeliveryAttempt) -> Result<(), StoreError> {
        let rows_affected = match &attempt.outcome {
            DeliveryOutcome::Delivered => mark_delivered(&self.pool, attempt).await?,
            DeliveryOutcome::Retry {
                retry_after,
                reason,
                http_status,
            } => {
                validate_failure_reason(reason)?;
                let http_status = encode_http_status(*http_status)?;
                let retry_milliseconds = duration_milliseconds(*retry_after, "retry_after")?;
                schedule_retry(&self.pool, attempt, retry_milliseconds, reason, http_status).await?
            }
            DeliveryOutcome::Failed {
                reason,
                http_status,
            } => {
                validate_failure_reason(reason)?;
                let http_status = encode_http_status(*http_status)?;
                mark_failed(&self.pool, attempt, reason, http_status).await?
            }
        };

        if rows_affected != 1 {
            return Err(StoreError::LeaseLost);
        }
        Ok(())
    }
}

async fn mark_delivered(pool: &sqlx::PgPool, attempt: &DeliveryAttempt) -> Result<u64, StoreError> {
    let result = sqlx::query(
        r"
        WITH completion_clock AS MATERIALIZED (
            SELECT clock_timestamp() AS now
        )
        UPDATE hook_private.dm_outbox
        SET status = 'delivered',
            attempts = attempts + 1,
            lease_token = NULL,
            leased_until = NULL,
            last_attempt_at = completion_clock.now,
            delivered_at = completion_clock.now,
            failed_at = NULL,
            failure_reason = NULL,
            last_http_status = 202,
            updated_at = completion_clock.now
        FROM completion_clock
        WHERE event_id = $1
          AND lease_token = $2
          AND status IN ('pending', 'retrying')
        ",
    )
    .bind(attempt.event_id.as_uuid())
    .bind(attempt.lease_token)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

async fn schedule_retry(
    pool: &sqlx::PgPool,
    attempt: &DeliveryAttempt,
    retry_milliseconds: i64,
    reason: &str,
    http_status: Option<i16>,
) -> Result<u64, StoreError> {
    let result = sqlx::query(
        r"
        WITH completion_clock AS MATERIALIZED (
            SELECT clock_timestamp() AS now
        )
        UPDATE hook_private.dm_outbox
        SET status = 'retrying',
            attempts = attempts + 1,
            available_at = completion_clock.now + ($3 * INTERVAL '1 millisecond'),
            lease_token = NULL,
            leased_until = NULL,
            last_attempt_at = completion_clock.now,
            delivered_at = NULL,
            failed_at = NULL,
            failure_reason = $4,
            last_http_status = $5,
            updated_at = completion_clock.now
        FROM completion_clock
        WHERE event_id = $1
          AND lease_token = $2
          AND status IN ('pending', 'retrying')
        ",
    )
    .bind(attempt.event_id.as_uuid())
    .bind(attempt.lease_token)
    .bind(retry_milliseconds)
    .bind(reason)
    .bind(http_status)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

async fn mark_failed(
    pool: &sqlx::PgPool,
    attempt: &DeliveryAttempt,
    reason: &str,
    http_status: Option<i16>,
) -> Result<u64, StoreError> {
    let result = sqlx::query(
        r"
        WITH completion_clock AS MATERIALIZED (
            SELECT clock_timestamp() AS now
        )
        UPDATE hook_private.dm_outbox
        SET status = 'failed',
            attempts = attempts + 1,
            lease_token = NULL,
            leased_until = NULL,
            last_attempt_at = completion_clock.now,
            delivered_at = NULL,
            failed_at = completion_clock.now,
            failure_reason = $3,
            last_http_status = $4,
            updated_at = completion_clock.now
        FROM completion_clock
        WHERE event_id = $1
          AND lease_token = $2
          AND status IN ('pending', 'retrying')
        ",
    )
    .bind(attempt.event_id.as_uuid())
    .bind(attempt.lease_token)
    .bind(reason)
    .bind(http_status)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

impl TryFrom<ClaimedDeliveryRow> for ClaimedDelivery {
    type Error = StoreError;

    fn try_from(row: ClaimedDeliveryRow) -> Result<Self, Self::Error> {
        let attempts =
            u32::try_from(row.attempts).map_err(|error| StoreError::corrupt("DM outbox", error))?;
        let attempt_number = attempts
            .checked_add(1)
            .ok_or_else(|| StoreError::corrupt("DM outbox", "attempt counter overflow"))?;
        Ok(Self {
            event_id: row.event_id.into(),
            request_body: row.request_body,
            attempt_number,
            lease_token: row.lease_token,
            leased_until: row.leased_until,
        })
    }
}

fn encode_http_status(status: Option<u16>) -> Result<Option<i16>, StoreError> {
    status
        .map(|status| {
            if !(100..=599).contains(&status) {
                return Err(StoreError::InvalidArgument {
                    field: "http_status",
                    reason: "must be between 100 and 599",
                });
            }
            i16::try_from(status).map_err(|_| StoreError::NumericRange {
                field: "http_status",
            })
        })
        .transpose()
}

fn duration_milliseconds(duration: Duration, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(duration.as_millis()).map_err(|_| StoreError::NumericRange { field })
}

fn validate_failure_reason(reason: &str) -> Result<(), StoreError> {
    if reason.chars().count() > 2_000 || reason.chars().any(char::is_control) {
        return Err(StoreError::InvalidArgument {
            field: "failure_reason",
            reason: "must be at most 2000 characters and contain no control characters",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_http_status_codes() {
        assert!(encode_http_status(Some(99)).is_err());
        assert!(encode_http_status(Some(600)).is_err());
    }

    #[test]
    fn accepts_missing_and_valid_http_status_codes() -> Result<(), StoreError> {
        assert_eq!(encode_http_status(None)?, None);
        assert_eq!(encode_http_status(Some(429))?, Some(429));
        Ok(())
    }

    #[test]
    fn failure_reasons_are_bounded_and_single_line() {
        assert!(validate_failure_reason(&"x".repeat(2_001)).is_err());
        assert!(validate_failure_reason(&"界".repeat(2_000)).is_ok());
        assert!(validate_failure_reason("connection reset\nresponse body").is_err());
        assert!(validate_failure_reason("connection reset").is_ok());
    }
}
