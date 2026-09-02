//! Ordered delivery streams and consumer acknowledgment cursors.

use time::OffsetDateTime;

use crate::domain::{ActorRef, DeliveryCursor, EventRecord, OrganizationId, SiliconId};

use super::{MAX_DELIVERY_BATCH, PostgresStore, StoreError, models::EventRow};

impl PostgresStore {
    /// Returns retained events after a stream position in ascending order.
    ///
    /// Events from disabled or deleted hooks remain deliverable; they were
    /// verified when accepted and disappear only through retention.
    ///
    /// # Errors
    ///
    /// Returns an error for a negative position, an out-of-range limit, a
    /// PostgreSQL failure, or persisted rows that violate domain invariants.
    pub async fn fetch_deliveries(
        &self,
        organization_id: &OrganizationId,
        silicon_id: &SiliconId,
        after_sequence: i64,
        limit: u32,
    ) -> Result<Vec<EventRecord>, StoreError> {
        if after_sequence < 0 {
            return Err(StoreError::InvalidArgument {
                field: "after_sequence",
                reason: "must not be negative",
            });
        }
        if limit == 0 || limit > MAX_DELIVERY_BATCH {
            return Err(StoreError::InvalidArgument {
                field: "limit",
                reason: "must be between 1 and 1000",
            });
        }
        let rows = sqlx::query_as::<_, EventRow>(
            "SELECT event.id, event.hook_id, event.org_id, event.silicon_id, event.provider,
                    event.summary, event.delivery_sequence,
                    event.method, event.url, event.path, event.query_string, event.headers,
                    event.body, event.remote_ip, event.received_at
             FROM hook.events AS event
             WHERE event.org_id = $1
               AND event.silicon_id = $2
               AND event.delivery_sequence > $3
               AND event.expires_at > clock_timestamp()
             ORDER BY event.delivery_sequence
             LIMIT $4",
        )
        .bind(organization_id.as_str())
        .bind(silicon_id.as_str())
        .bind(after_sequence)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(EventRecord::try_from).collect()
    }

    /// Returns the highest sequence ever allocated for a Silicon.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure.
    pub async fn latest_sequence(&self, silicon_id: &SiliconId) -> Result<i64, StoreError> {
        let latest = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT last_sequence FROM hook_private.delivery_sequences WHERE silicon_id = $1",
        )
        .bind(silicon_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        Ok(latest.flatten().unwrap_or(0))
    }

    /// Returns a consumer's acknowledged position for a Silicon stream.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure.
    pub async fn delivery_cursor(
        &self,
        silicon_id: &SiliconId,
        consumer: &ActorRef,
    ) -> Result<DeliveryCursor, StoreError> {
        let row = sqlx::query_as::<_, (i64, OffsetDateTime)>(
            "SELECT acknowledged_through, updated_at
             FROM hook_private.delivery_cursors
             WHERE silicon_id = $1 AND consumer_kind = $2 AND consumer_id = $3",
        )
        .bind(silicon_id.as_str())
        .bind(super::actor_kind_as_str(consumer.kind()))
        .bind(consumer.id().as_str())
        .fetch_optional(&self.pool)
        .await?;
        Ok(DeliveryCursor {
            silicon_id: silicon_id.clone(),
            acknowledged_through: row.map_or(0, |(through, _)| through),
            updated_at: row.map(|(_, updated_at)| updated_at),
        })
    }

    /// Advances a consumer's acknowledged position; positions never move back.
    ///
    /// # Errors
    ///
    /// Returns an error for a negative position or a PostgreSQL failure.
    pub async fn acknowledge_deliveries(
        &self,
        silicon_id: &SiliconId,
        consumer: &ActorRef,
        through_sequence: i64,
        acknowledged_at: OffsetDateTime,
    ) -> Result<DeliveryCursor, StoreError> {
        if through_sequence < 0 {
            return Err(StoreError::InvalidArgument {
                field: "through_sequence",
                reason: "must not be negative",
            });
        }
        let (through, updated_at) = sqlx::query_as::<_, (i64, OffsetDateTime)>(
            "INSERT INTO hook_private.delivery_cursors (
                 silicon_id, consumer_kind, consumer_id, acknowledged_through, updated_at
             )
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (silicon_id, consumer_kind, consumer_id) DO UPDATE
             SET acknowledged_through = GREATEST(
                     hook_private.delivery_cursors.acknowledged_through, EXCLUDED.acknowledged_through
                 ),
                 updated_at = GREATEST(hook_private.delivery_cursors.updated_at, EXCLUDED.updated_at)
             RETURNING acknowledged_through, updated_at",
        )
        .bind(silicon_id.as_str())
        .bind(super::actor_kind_as_str(consumer.kind()))
        .bind(consumer.id().as_str())
        .bind(through_sequence)
        .bind(acknowledged_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(DeliveryCursor {
            silicon_id: silicon_id.clone(),
            acknowledged_through: through,
            updated_at: Some(updated_at),
        })
    }
}
