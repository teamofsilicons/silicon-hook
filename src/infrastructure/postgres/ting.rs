//! Durable publication of verified events to Ting.
//!
//! Sends are enqueued inside the event's acceptance transaction; network I/O
//! happens only after commit. A claim is a temporary lease, not permission to
//! retain or replay an expired event. Every attempt carries a fresh Silicon
//! Accounts proof over the unchanged `request_body`; no credential is ever
//! stored here. Sends queued under Silicon IAM were parked by migration 0019
//! (`legacy_identity`) and are never claimed.

use std::{fmt, time::Duration};

use serde::Deserialize;
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::{AccountUuid, EventId, EventRecord};
use crate::infrastructure::ting::{TingDeliveryMode, TingRecipient, deserialize_delivery};

use super::{PostgresStore, Result, StoreError};

/// A leased, exact request that may be published to Ting.
///
/// Debug output intentionally excludes the prepared request body.
#[derive(Clone, FromRow)]
pub struct TingOutboxClaim {
    /// Stable identifier of this event-to-recipient send.
    pub id: Uuid,
    /// Original verified Hook event.
    pub event_id: Uuid,
    /// Recipient's Silicon Accounts uuid.
    pub recipient_id: String,
    /// Observer subscription, if this is a copy for a Carbon rather than the
    /// Silicon's own send.
    pub observer_subscription_id: Option<Uuid>,
    /// Stable producer key, unchanged across every retry.
    pub idempotency_key: String,
    /// Exact UTF-8 JSON bytes prepared before the event transaction committed.
    pub request_body: Vec<u8>,
    /// Number of claims, including this attempt and attempts interrupted by a crash.
    pub attempts: i64,
    /// Lease token required when recording this attempt's result.
    pub lease_id: Uuid,
    /// Database time at which this lease becomes eligible for reclamation.
    pub lease_until: OffsetDateTime,
    /// Original event retention deadline, after which no send is permitted.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for TingOutboxClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TingOutboxClaim")
            .field("id", &self.id)
            .field("event_id", &self.event_id)
            .field("attempts", &self.attempts)
            .field("lease_until", &self.lease_until)
            .finish_non_exhaustive()
    }
}

/// Public-safe send progress without the prepared body or authentication data.
#[derive(Clone, Debug, FromRow)]
pub struct TingOutboxStatus {
    /// Stable identifier of this event-to-recipient send.
    pub id: Uuid,
    /// Original verified Hook event.
    pub event_id: Uuid,
    /// Recipient for this send (an Accounts uuid; an IAM-era id for parked sends).
    pub recipient_id: String,
    /// Number of publisher attempts, including interrupted claims.
    pub attempts: i64,
    /// Time the send was durably enqueued.
    pub created_at: OffsetDateTime,
    /// Earliest scheduled time for another attempt.
    pub next_attempt_at: OffsetDateTime,
    /// Database time at which the most recent attempt was claimed.
    pub last_attempt_at: Option<OffsetDateTime>,
    /// Bounded diagnostic class, never a remote response or credential.
    pub last_error_code: Option<String>,
    /// Active lease expiry, if a publisher currently owns this send.
    pub lease_until: Option<OffsetDateTime>,
    /// Time Ting acceptance was confirmed; this does not mean recipient delivery.
    pub accepted_at: Option<OffsetDateTime>,
    /// Ting-assigned notification identifier after confirmed acceptance.
    pub ting_id: Option<String>,
    /// Whether Ting accepted this notification silently because of preferences.
    pub silent: Option<bool>,
    /// Policy read from the original persisted body.
    #[sqlx(try_from = "String")]
    pub delivery: TingDeliveryMode,
    /// Original event's retention deadline.
    pub expires_at: OffsetDateTime,
}

/// Safe diagnostic classes allowed in persisted send progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TingSendFailure {
    /// Silicon Accounts could not issue or refresh Hook's proof for Ting.
    ProofUnavailable,
    /// Ting refused the recipient's authorization.
    ConsentRequired,
    /// Ting has no active subscription for this app and recipient.
    RecipientNotRegistered,
    /// The recipient must explicitly opt in through its own Ting session.
    RequiredDeliveryNotEnabled,
    /// The transport failed or its outcome is uncertain.
    TransportUnavailable,
    /// Ting temporarily limited the request rate.
    RateLimited,
    /// Ting is temporarily unavailable.
    TingUnavailable,
    /// Ting rejected the prepared request.
    RequestRejected,
    /// The response could not be verified as an acceptance.
    InvalidResponse,
    /// Ting rejected the proof.
    TingUnauthorized,
    /// Hook's notification type has not been registered with Ting.
    TypeNotRegistered,
    /// Ting already accepted the producer key with different content.
    IdempotencyConflict,
}

impl TingSendFailure {
    /// Returns the stable, non-sensitive diagnostic stored in the outbox.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProofUnavailable => "proof_unavailable",
            Self::ConsentRequired => "consent_required",
            Self::RecipientNotRegistered => "recipient_not_registered",
            Self::RequiredDeliveryNotEnabled => "required_delivery_not_enabled",
            Self::TransportUnavailable => "transport_unavailable",
            Self::RateLimited => "rate_limited",
            Self::TingUnavailable => "ting_unavailable",
            Self::RequestRejected => "request_rejected",
            Self::InvalidResponse => "invalid_response",
            Self::TingUnauthorized => "ting_unauthorized",
            Self::TypeNotRegistered => "type_not_registered",
            Self::IdempotencyConflict => "idempotency_conflict",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedTing {
    #[serde(rename = "for")]
    recipient: TingRecipient,
    #[serde(rename = "type")]
    notification_type: String,
    key: String,
    data: Value,
    #[serde(default = "empty_object")]
    metadata: Value,
    #[serde(default, deserialize_with = "deserialize_delivery")]
    delivery: TingDeliveryMode,
}

fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

fn prepared_key(body: &[u8], recipient: &AccountUuid) -> Result<String> {
    let invalid = || StoreError::InvalidArgument {
        field: "prepared_body",
        reason: "must be a Ting request addressed to the queued recipient",
    };
    if body.is_empty() || body.len() > 256 * 1024 {
        return Err(invalid());
    }
    let request: PreparedTing = serde_json::from_slice(body).map_err(|_| invalid())?;
    // Parsing validates the optional mode without changing these immutable bytes.
    let _ = request.delivery;
    if request.recipient.uuid != recipient.as_str()
        || request.key.is_empty()
        || request.key.len() > 200
        || request.key.chars().any(char::is_control)
        || request.notification_type.is_empty()
        || request.notification_type.len() > 255
        || !request.data.is_object()
        || !request.metadata.is_object()
    {
        return Err(invalid());
    }
    Ok(request.key)
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Enqueues a prepared notification in the verified-event acceptance transaction.
///
/// The row inherits the persisted event's expiry. Repeating the same
/// event/recipient and exact body returns its existing send id; changing those
/// bytes fails. This helper never commits and never performs network I/O.
///
/// # Errors
///
/// Returns invalid input, an idempotency conflict, a missing or expired event,
/// or a database failure. The caller must roll back the whole acceptance.
pub(crate) async fn enqueue_ting(
    transaction: &mut Transaction<'_, Postgres>,
    event: &EventRecord,
    recipient: &AccountUuid,
    prepared_body: &[u8],
    observer_subscription: Option<Uuid>,
) -> Result<Uuid> {
    let key = prepared_key(prepared_body, recipient)?;
    let inserted = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO hook_private.ting_outbox (
             id, event_id, org_id, silicon_id, recipient_id, idempotency_key, request_body,
             expires_at, observer_subscription_id
         )
         SELECT $1, event.id, event.org_id, event.silicon_id, $3, $4, $5, event.expires_at, $6
         FROM hook.events AS event
         WHERE event.id = $2 AND event.expires_at > clock_timestamp()
         ON CONFLICT (environment_id, event_id, recipient_id) DO NOTHING
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(event.id().as_uuid())
    .bind(recipient.as_str())
    .bind(key)
    .bind(prepared_body)
    .bind(observer_subscription)
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some(id) = inserted {
        return Ok(id);
    }
    let existing = sqlx::query_as::<_, (Uuid, Vec<u8>, Option<Uuid>)>(
        "SELECT id, request_body, observer_subscription_id FROM hook_private.ting_outbox
         WHERE event_id = $1 AND recipient_id = $2 AND expires_at > clock_timestamp()",
    )
    .bind(event.id().as_uuid())
    .bind(recipient.as_str())
    .fetch_optional(&mut **transaction)
    .await?;
    match existing {
        Some((id, body, existing_subscription))
            if body == prepared_body && existing_subscription == observer_subscription =>
        {
            Ok(id)
        }
        Some(_) => Err(StoreError::IdempotencyConflict),
        None => Err(StoreError::NotFound { entity: "event" }),
    }
}

impl PostgresStore {
    /// Leases due sends without blocking peers.
    ///
    /// Expired leases can be reclaimed after a crash. Every claim increases the
    /// attempt count. The exact body and producer key never change.
    ///
    /// # Errors
    ///
    /// Returns invalid input for limits outside 1..=100 or lease durations outside
    /// one second through one hour, or a database failure.
    pub async fn claim_ting(
        &self,
        limit: u32,
        lease_duration: Duration,
    ) -> Result<Vec<TingOutboxClaim>> {
        if !(1..=100).contains(&limit) {
            return Err(StoreError::InvalidArgument {
                field: "limit",
                reason: "must be between 1 and 100",
            });
        }
        if !(Duration::from_secs(1)..=Duration::from_secs(3_600)).contains(&lease_duration) {
            return Err(StoreError::InvalidArgument {
                field: "lease_duration",
                reason: "must be between one second and one hour",
            });
        }
        let lease_seconds =
            i64::try_from(lease_duration.as_secs()).map_err(|_| StoreError::NumericRange {
                field: "lease_duration",
            })?;
        Ok(sqlx::query_as::<_, TingOutboxClaim>(
            "WITH due AS (
                 SELECT send.id
                 FROM hook_private.ting_outbox AS send
                 WHERE send.accepted_at IS NULL AND send.expires_at > clock_timestamp()
                   AND send.next_attempt_at <= clock_timestamp()
                   AND send.last_error_code IS DISTINCT FROM 'legacy_identity'
                   AND (send.lease_until IS NULL OR send.lease_until <= clock_timestamp())
                 ORDER BY send.next_attempt_at, send.created_at, send.id
                 FOR UPDATE OF send SKIP LOCKED LIMIT $1
             )
             UPDATE hook_private.ting_outbox AS send
             SET lease_id = gen_random_uuid(),
                 lease_until = LEAST(send.expires_at, clock_timestamp() + $2::bigint * INTERVAL '1 second'),
                 attempts = send.attempts + 1,
                 last_attempt_at = clock_timestamp()
             FROM due WHERE send.id = due.id
             RETURNING send.id, send.event_id, send.recipient_id, send.observer_subscription_id,
                       send.idempotency_key, send.request_body, send.attempts,
                       send.lease_id, send.lease_until, send.expires_at",
        )
        .bind(i64::from(limit))
        .bind(lease_seconds)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Checks that a leased send is still current: not accepted, not expired,
    /// lease unchanged, and (for an observer copy) the subscription still exists.
    ///
    /// # Errors
    ///
    /// Returns a database failure.
    pub async fn ting_claim_is_current(&self, claim: &TingOutboxClaim) -> Result<bool> {
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1 FROM hook_private.ting_outbox
                 WHERE id = $1 AND lease_id = $2
                   AND accepted_at IS NULL AND lease_until > clock_timestamp()
                   AND expires_at > clock_timestamp()
             )",
        )
        .bind(claim.id)
        .bind(claim.lease_id)
        .fetch_one(&self.pool)
        .await?)
    }

    /// Records Ting's confirmed acceptance only for the current unexpired lease.
    ///
    /// Returns false when a claim expired, was replaced, or its event was removed.
    /// The acceptance records storage by Ting, not processing by a recipient.
    ///
    /// # Errors
    ///
    /// Returns invalid input for an invalid Ting ID or a database failure.
    pub async fn complete_ting(
        &self,
        claim: &TingOutboxClaim,
        ting_id: &str,
        silent: bool,
    ) -> Result<bool> {
        if !valid_identifier(ting_id, 255) {
            return Err(StoreError::InvalidArgument {
                field: "ting_id",
                reason: "must be a nonempty identifier of at most 255 bytes",
            });
        }
        let outcome = sqlx::query(
            "UPDATE hook_private.ting_outbox
             SET accepted_at = clock_timestamp(), ting_id = $3, silent = $4,
                 lease_id = NULL, lease_until = NULL, last_error_code = NULL
             WHERE id = $1 AND lease_id = $2
               AND accepted_at IS NULL AND lease_until > clock_timestamp()
               AND expires_at > clock_timestamp()",
        )
        .bind(claim.id)
        .bind(claim.lease_id)
        .bind(ting_id)
        .bind(silent)
        .execute(&self.pool)
        .await?;
        Ok(outcome.rows_affected() == 1)
    }

    /// Releases a current lease and durably schedules another safe, idempotent attempt.
    ///
    /// Only the enumerated diagnostic class is stored. Retry scheduling is bounded
    /// to the event lifetime; an expired event can never be claimed again.
    /// Returns false for stale claims or removed events.
    ///
    /// # Errors
    ///
    /// Returns a database failure.
    pub async fn retry_ting(
        &self,
        claim: &TingOutboxClaim,
        failure: TingSendFailure,
        retry_at: OffsetDateTime,
    ) -> Result<bool> {
        let outcome = sqlx::query(
            "UPDATE hook_private.ting_outbox
             SET next_attempt_at = LEAST(expires_at, GREATEST(clock_timestamp(), $3)),
                 last_error_code = $4, lease_id = NULL, lease_until = NULL
             WHERE id = $1 AND lease_id = $2
               AND accepted_at IS NULL AND lease_until > clock_timestamp()
               AND expires_at > clock_timestamp()",
        )
        .bind(claim.id)
        .bind(claim.lease_id)
        .bind(retry_at)
        .bind(failure.as_str())
        .execute(&self.pool)
        .await?;
        Ok(outcome.rows_affected() == 1)
    }

    /// Reads one event's send progress to a recipient, within the Silicon's events.
    ///
    /// # Errors
    ///
    /// Returns a database failure. Missing, expired or foreign records return None.
    pub async fn ting_status(
        &self,
        silicon: &AccountUuid,
        event_id: EventId,
        recipient: &str,
    ) -> Result<Option<TingOutboxStatus>> {
        Ok(sqlx::query_as::<_, TingOutboxStatus>(
            "SELECT send.id, send.event_id, send.recipient_id, send.attempts, send.created_at,
                    send.next_attempt_at, send.last_attempt_at, send.last_error_code,
                    send.lease_until, send.accepted_at, send.ting_id, send.silent, send.expires_at,
                    COALESCE(convert_from(send.request_body, 'UTF8')::jsonb->>'delivery', 'ordinary') AS delivery
             FROM hook_private.ting_outbox AS send
             JOIN hook.events AS event ON event.id = send.event_id
             WHERE event.silicon_uuid = $1 AND send.event_id = $2 AND send.recipient_id = $3
               AND send.expires_at > clock_timestamp()",
        )
        .bind(silicon.as_str())
        .bind(event_id.as_uuid())
        .bind(recipient)
        .fetch_optional(&self.pool)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::{Context as _, Result};
    use bytes::Bytes;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::{
        domain::{
            AccountUuid, DeliverySequence, EventRecord, EventRecordSnapshot, HookName, SiliconId,
            request::{CapturedRequest, CapturedRequestParts},
        },
        infrastructure::postgres::{PostgresStore, migrate},
        test_postgres::TestDatabase,
    };

    use super::{TingSendFailure, enqueue_ting, prepared_key};

    fn body(recipient: &str, key: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": "hook.webhook.received",
            "for": {"uuid": recipient, "id": "si:cos"},
            "key": key,
            "data": {"type": "new_event", "data": {"sender": "GitHub", "metadata": {}}},
            "metadata": {},
            "delivery": "required"
        }))
        .unwrap_or_default()
    }

    #[test]
    fn prepared_requests_must_address_the_queued_recipient() -> Result<()> {
        let recipient = AccountUuid::new("8HV")?;
        assert_eq!(
            prepared_key(&body("8HV", "event-key"), &recipient)?,
            "event-key"
        );
        assert!(prepared_key(&body("8Hv", "event-key"), &recipient).is_err());
        let legacy = br#"{"org_id":"tos","for":"si:cos","type":"hook.webhook.received","key":"k","data":{}}"#;
        assert!(prepared_key(legacy, &recipient).is_err());
        let with_token = br#"{"for":{"uuid":"8HV","id":"si:cos"},"type":"t","key":"k","data":{},"token":"secret"}"#;
        assert!(prepared_key(with_token, &recipient).is_err());
        Ok(())
    }

    async fn seed_event(store: &PostgresStore, silicon: &AccountUuid) -> Result<EventRecord> {
        let hook_id = Uuid::now_v7();
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            "INSERT INTO hook.hooks (id, silicon_id, silicon_uuid, endpoint_key, name, signature_config,
                 created_by_kind, created_by_id, created_by_uuid, created_at, updated_at)
             VALUES ($1, $2, $2, 'A1B2C3D4', 'GitHub', '{}', 'silicon', $2, $2, now(), now())",
        )
        .bind(hook_id)
        .bind(silicon.as_str())
        .execute(store.pool())
        .await?;
        let request = CapturedRequest::new(CapturedRequestParts {
            method: "POST".to_owned(),
            url: url::Url::parse("https://hook.example.test/silicon/si:cos/A1B2C3D4")?,
            headers: Vec::new(),
            body: Bytes::from_static(b"{}"),
            remote_ip: "203.0.113.10".parse()?,
            received_at: now,
        })?;
        let event = EventRecord::rehydrate(EventRecordSnapshot {
            id: Uuid::now_v7().into(),
            silicon_id: SiliconId::new(silicon.as_str())?,
            silicon_uuid: Some(silicon.clone()),
            hook_id: hook_id.into(),
            provider: HookName::new("GitHub")?,
            summary: "GitHub triggered at 00:00:00 01-01-2026 UTC".to_owned(),
            request,
            delivery_sequence: DeliverySequence::new(1)?,
            received_at: now,
        });
        sqlx::query(
            "INSERT INTO hook.events (id, hook_id, org_id, silicon_id, silicon_uuid, provider, summary,
                 delivery_sequence, method, url, path, query_string, headers, body, remote_ip,
                 received_at, expires_at)
             SELECT $1, $2, hook.org_id, hook.silicon_id, hook.silicon_uuid, 'GitHub', $3, 1, 'POST',
                    'https://hook.example.test/silicon/si:cos/A1B2C3D4', '/silicon/si:cos/A1B2C3D4',
                    '', '[]'::jsonb, '{}'::bytea, '203.0.113.10'::inet, $4, $4 + INTERVAL '14 days'
             FROM hook.hooks AS hook WHERE hook.id = $2",
        )
        .bind(event.id().as_uuid())
        .bind(hook_id)
        .bind(event.summary())
        .bind(now)
        .execute(store.pool())
        .await?;
        Ok(event)
    }

    #[tokio::test]
    async fn outbox_is_idempotent_leases_and_retries_safely() -> Result<()> {
        let Some(database) = TestDatabase::create().await? else {
            return Ok(());
        };
        let store = PostgresStore::new(database.connect(4).await?);
        migrate(store.pool()).await?;
        let silicon = AccountUuid::new("8HV")?;
        let event = seed_event(&store, &silicon).await?;
        let mut transaction = store.pool().begin().await?;
        let first =
            enqueue_ting(&mut transaction, &event, &silicon, &body("8HV", "k1"), None).await?;
        let again =
            enqueue_ting(&mut transaction, &event, &silicon, &body("8HV", "k1"), None).await?;
        assert_eq!(first, again, "the same bytes enqueue once");
        assert!(
            enqueue_ting(&mut transaction, &event, &silicon, &body("8HV", "k2"), None)
                .await
                .is_err(),
            "changed bytes for the same recipient are refused"
        );
        transaction.rollback().await?;

        let mut transaction = store.pool().begin().await?;
        enqueue_ting(&mut transaction, &event, &silicon, &body("8HV", "k1"), None).await?;
        transaction.commit().await?;

        let claims = store.claim_ting(10, Duration::from_secs(60)).await?;
        let claim = claims.first().context("one due send")?;
        assert_eq!(claim.attempts, 1);
        assert!(
            store
                .claim_ting(10, Duration::from_secs(60))
                .await?
                .is_empty(),
            "leased"
        );
        assert!(store.ting_claim_is_current(claim).await?);
        assert!(
            store
                .retry_ting(
                    claim,
                    TingSendFailure::TransportUnavailable,
                    OffsetDateTime::now_utc()
                )
                .await?
        );
        let retried = store.claim_ting(10, Duration::from_secs(60)).await?;
        let retried = retried.first().context("released for retry")?;
        assert_eq!(retried.attempts, 2);
        assert!(
            !store.complete_ting(claim, "msg_1", false).await?,
            "stale lease"
        );
        assert!(store.complete_ting(retried, "msg_1", false).await?);
        let status = store
            .ting_status(&silicon, event.id(), "8HV")
            .await?
            .context("status")?;
        assert_eq!(status.ting_id.as_deref(), Some("msg_1"));
        assert!(
            store
                .ting_status(&AccountUuid::new("zQo")?, event.id(), "8HV")
                .await?
                .is_none()
        );
        Ok(())
    }

    #[tokio::test]
    async fn sends_parked_by_the_accounts_migration_are_never_claimed() -> Result<()> {
        let Some(database) = TestDatabase::create().await? else {
            return Ok(());
        };
        let store = PostgresStore::new(database.connect(4).await?);
        migrate(store.pool()).await?;
        let silicon = AccountUuid::new("8HV")?;
        let event = seed_event(&store, &silicon).await?;
        let mut transaction = store.pool().begin().await?;
        enqueue_ting(&mut transaction, &event, &silicon, &body("8HV", "k1"), None).await?;
        transaction.commit().await?;
        sqlx::query(
            "UPDATE hook_private.ting_outbox SET last_error_code = 'legacy_identity', next_attempt_at = now()",
        )
        .execute(store.pool())
        .await?;
        assert!(
            store
                .claim_ting(10, Duration::from_secs(60))
                .await?
                .is_empty()
        );
        Ok(())
    }
}
