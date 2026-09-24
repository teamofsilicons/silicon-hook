//! Durable, tenant-scoped publication of verified events to Ting.
//!
//! Enqueue inside the event transaction; perform network I/O only after commit.
//! A claim is a temporary lease, not permission to retain or replay an expired
//! event. Each attempt needs a new IAM proof over `request_body` without
//! reserialization. No authentication material belongs in this table.

use std::{fmt, time::Duration};

use serde::Deserialize;
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::{EventId, EventRecord, OrganizationId, SiliconId};
use crate::infrastructure::ting::{TingDeliveryMode, deserialize_delivery};

use super::{PostgresStore, Result, StoreError};

/// A leased, exact request that may be published to Ting.
///
/// Debug output intentionally excludes the prepared request body.
#[derive(Clone, FromRow)]
pub struct TingOutboxClaim {
    /// Stable identifier of this event-to-recipient send.
    pub id: Uuid,
    /// Owning test environment, or the zero UUID for production.
    pub environment_id: Uuid,
    /// Current authority generation for this publication attempt; zero for production.
    pub environment_generation: i64,
    /// Original verified Hook event.
    pub event_id: Uuid,
    /// Owning organization.
    pub org_id: String,
    /// Silicon whose Hook accepted the event.
    pub silicon_id: String,
    /// Ting recipient, scoped to this environment and organization.
    pub recipient_id: String,
    /// Carbon receiving interest, if this is an observer rather than primary copy.
    pub recipient_binding_id: Option<Uuid>,
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
            .field("environment_id", &self.environment_id)
            .field("environment_generation", &self.environment_generation)
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
    /// Recipient for this send.
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
    /// Policy read from the original persisted body, including legacy ordinary sends.
    #[sqlx(try_from = "String")]
    pub delivery: TingDeliveryMode,
    /// Original event's retention deadline.
    pub expires_at: OffsetDateTime,
}

/// Safe diagnostic classes allowed in persisted send progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TingSendFailure {
    /// IAM could not confirm authority or produce a fresh proof.
    AuthorizationUnavailable,
    /// A represented actor has not granted the required scope.
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
    /// Required integration configuration is unavailable.
    PublisherNotConfigured,
    /// The configured publisher identity is temporarily unavailable.
    PublisherUnavailable,
    /// The configured publisher identity is no longer authorized.
    PublisherUnauthorized,
    /// Ting rejected the request-bound proof or its authorization.
    TingUnauthorized,
    /// Hook's notification type has not been registered with Ting.
    TypeNotRegistered,
    /// Ting already accepted the producer key with different content.
    IdempotencyConflict,
    /// The test environment changed while preparing publication.
    EnvironmentChanged,
    /// The enclosing runtime must renew the Carbon's current access authority.
    ObserverAuthorityRefreshRequired,
    /// Current Carbon authority could not be checked with IAM.
    ObserverAuthorizationUnavailable,
}

impl TingSendFailure {
    /// Returns the stable, non-sensitive diagnostic stored in the outbox.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationUnavailable => "authorization_unavailable",
            Self::ConsentRequired => "consent_required",
            Self::RecipientNotRegistered => "recipient_not_registered",
            Self::RequiredDeliveryNotEnabled => "required_delivery_not_enabled",
            Self::TransportUnavailable => "transport_unavailable",
            Self::RateLimited => "rate_limited",
            Self::TingUnavailable => "ting_unavailable",
            Self::RequestRejected => "request_rejected",
            Self::InvalidResponse => "invalid_response",
            Self::PublisherNotConfigured => "publisher_not_configured",
            Self::PublisherUnavailable => "publisher_unavailable",
            Self::PublisherUnauthorized => "publisher_unauthorized",
            Self::TingUnauthorized => "ting_unauthorized",
            Self::TypeNotRegistered => "type_not_registered",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::EnvironmentChanged => "environment_changed",
            Self::ObserverAuthorityRefreshRequired => "observer_authority_refresh_required",
            Self::ObserverAuthorizationUnavailable => "observer_authorization_unavailable",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedTing {
    org_id: String,
    #[serde(rename = "for")]
    recipient: String,
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

fn prepared_key(body: &[u8], org: &str, recipient: &str) -> Result<String> {
    let invalid = || StoreError::InvalidArgument {
        field: "prepared_body",
        reason: "must be a Ting request matching the event organization and recipient",
    };
    if body.is_empty() || body.len() > 256 * 1024 {
        return Err(invalid());
    }
    let request: PreparedTing = serde_json::from_slice(body).map_err(|_| invalid())?;
    // Parsing validates the optional mode without changing these immutable bytes.
    let _ = request.delivery;
    if request.org_id != org
        || request.recipient != recipient
        || !valid_identifier(recipient, 255)
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
/// The row inherits the persisted event's tenant and original expiry. Repeating
/// the same event/recipient and exact body returns its existing send ID; changing
/// those bytes fails. This helper never commits and never performs network I/O.
///
/// # Errors
///
/// Returns invalid input, an idempotency conflict, a missing/expired event, or a
/// database failure. The caller must roll back the whole acceptance on failure.
pub(crate) async fn enqueue_ting(
    transaction: &mut Transaction<'_, Postgres>,
    event: &EventRecord,
    recipient: &str,
    prepared_body: &[u8],
) -> Result<Uuid> {
    enqueue_ting_bound(transaction, event, recipient, prepared_body, None).await
}

/// Atomically links an observer send to the receiving interest that authorizes it.
pub(crate) async fn enqueue_ting_for_subscription(
    transaction: &mut Transaction<'_, Postgres>,
    event: &EventRecord,
    recipient: &str,
    prepared_body: &[u8],
    binding_id: Uuid,
) -> Result<Uuid> {
    enqueue_ting_bound(
        transaction,
        event,
        recipient,
        prepared_body,
        Some(binding_id),
    )
    .await
}

async fn enqueue_ting_bound(
    transaction: &mut Transaction<'_, Postgres>,
    event: &EventRecord,
    recipient: &str,
    prepared_body: &[u8],
    binding_id: Option<Uuid>,
) -> Result<Uuid> {
    let key = prepared_key(prepared_body, event.organization_id().as_str(), recipient)?;
    let inserted = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO hook_private.ting_outbox (
             id, event_id, org_id, silicon_id, recipient_id, idempotency_key, request_body, expires_at,
             recipient_binding_id
         )
         SELECT $1, event.id, event.org_id, event.silicon_id, $5, $6, $7, event.expires_at, $8
         FROM hook.events event
         WHERE event.id = $2 AND event.org_id = $3 AND event.silicon_id = $4
           AND event.environment_id = hook_private.environment_id()
           AND hook_private.environment_is_available()
           AND event.expires_at > clock_timestamp()
         ON CONFLICT (environment_id, event_id, recipient_id) DO NOTHING
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(event.id().as_uuid())
    .bind(event.organization_id().as_str())
    .bind(event.silicon_id().as_str())
    .bind(recipient)
    .bind(key)
    .bind(prepared_body)
    .bind(binding_id)
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some(id) = inserted {
        return Ok(id);
    }
    let existing = sqlx::query_as::<_, (Uuid, Vec<u8>, Option<Uuid>)>(
        "SELECT id, request_body, recipient_binding_id FROM hook_private.ting_outbox
         WHERE event_id = $1 AND org_id = $2 AND silicon_id = $3 AND recipient_id = $4
           AND environment_id = hook_private.environment_id()
           AND hook_private.environment_is_available()
           AND expires_at > clock_timestamp()",
    )
    .bind(event.id().as_uuid())
    .bind(event.organization_id().as_str())
    .bind(event.silicon_id().as_str())
    .bind(recipient)
    .fetch_optional(&mut **transaction)
    .await?;
    match existing {
        Some((id, body, existing_binding))
            if body == prepared_body && existing_binding == binding_id =>
        {
            Ok(id)
        }
        Some(_) => Err(StoreError::IdempotencyConflict),
        None => Err(StoreError::NotFound { entity: "event" }),
    }
}

impl PostgresStore {
    /// Leases due sends in this store's pinned environment without blocking peers.
    ///
    /// Expired leases can be reclaimed after a crash. Every claim increases the
    /// attempt count. The original exact body and producer key remain unchanged.
    /// Pending retained events adopt this pool's current authority generation,
    /// including leases invalidated by a rotation. Their reference identity stays fixed.
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
            "WITH authority AS (
                 SELECT CASE
                     WHEN hook_private.environment_id() = '00000000-0000-0000-0000-000000000000'::uuid
                     THEN 0 ELSE current_setting('hook.environment_generation')::bigint END AS generation
             ), due AS (
                 SELECT send.id, authority.generation
                 FROM hook_private.ting_outbox AS send CROSS JOIN authority
                 WHERE send.environment_id = hook_private.environment_id()
                   AND hook_private.environment_is_available()
                   AND send.environment_generation <= authority.generation
                   AND accepted_at IS NULL AND expires_at > clock_timestamp()
                   AND next_attempt_at <= clock_timestamp()
                   AND (lease_until IS NULL OR lease_until <= clock_timestamp()
                        OR send.environment_generation < authority.generation)
                 ORDER BY next_attempt_at, created_at, id
                 FOR UPDATE OF send SKIP LOCKED LIMIT $1
             )
             UPDATE hook_private.ting_outbox AS send
             SET environment_generation = due.generation,
                 lease_id = gen_random_uuid(),
                 lease_until = LEAST(send.expires_at, clock_timestamp() + $2::bigint * INTERVAL '1 second'),
                 attempts = send.attempts + 1,
                 last_attempt_at = clock_timestamp()
             FROM due WHERE send.id = due.id
             RETURNING send.id, send.environment_id, send.environment_generation,
                       send.event_id, send.org_id, send.silicon_id, send.recipient_id, send.recipient_binding_id,
                       send.idempotency_key, send.request_body, send.attempts,
                       send.lease_id, send.lease_until, send.expires_at",
        )
        .bind(i64::from(limit))
        .bind(lease_seconds)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Checks that a leased send is still retained and authorized by this pool's generation.
    ///
    /// Call immediately before external publication after acquiring credentials.
    /// A lifecycle change after this check still cannot retract a dispatched HTTP
    /// request, but stale results cannot recreate or acknowledge cleaned rows.
    ///
    /// # Errors
    ///
    /// Returns a database failure.
    pub async fn ting_claim_is_current(&self, claim: &TingOutboxClaim) -> Result<bool> {
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1 FROM hook_private.ting_outbox
                 WHERE id = $1 AND lease_id = $2 AND environment_id = $3
                   AND environment_generation = $4
                   AND environment_generation = CASE
                       WHEN hook_private.environment_id() = '00000000-0000-0000-0000-000000000000'::uuid
                       THEN 0 ELSE current_setting('hook.environment_generation')::bigint END
                   AND environment_id = hook_private.environment_id()
                   AND hook_private.environment_is_available()
                   AND accepted_at IS NULL AND lease_until > clock_timestamp()
                   AND expires_at > clock_timestamp()
             )",
        )
        .bind(claim.id)
        .bind(claim.lease_id)
        .bind(claim.environment_id)
        .bind(claim.environment_generation)
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
             SET accepted_at = clock_timestamp(), ting_id = $5, silent = $6,
                 lease_id = NULL, lease_until = NULL, last_error_code = NULL
             WHERE id = $1 AND lease_id = $2 AND environment_id = $3
               AND environment_generation = $4
               AND environment_generation = CASE
                   WHEN hook_private.environment_id() = '00000000-0000-0000-0000-000000000000'::uuid
                   THEN 0 ELSE current_setting('hook.environment_generation')::bigint END
               AND environment_id = hook_private.environment_id()
               AND hook_private.environment_is_available()
               AND accepted_at IS NULL AND lease_until > clock_timestamp()
               AND expires_at > clock_timestamp()",
        )
        .bind(claim.id)
        .bind(claim.lease_id)
        .bind(claim.environment_id)
        .bind(claim.environment_generation)
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
             SET next_attempt_at = LEAST(expires_at, GREATEST(clock_timestamp(), $5)),
                 last_error_code = $6, lease_id = NULL, lease_until = NULL
             WHERE id = $1 AND lease_id = $2 AND environment_id = $3
               AND environment_generation = $4
               AND environment_generation = CASE
                   WHEN hook_private.environment_id() = '00000000-0000-0000-0000-000000000000'::uuid
                   THEN 0 ELSE current_setting('hook.environment_generation')::bigint END
               AND environment_id = hook_private.environment_id()
               AND hook_private.environment_is_available()
               AND accepted_at IS NULL AND lease_until > clock_timestamp()
               AND expires_at > clock_timestamp()",
        )
        .bind(claim.id)
        .bind(claim.lease_id)
        .bind(claim.environment_id)
        .bind(claim.environment_generation)
        .bind(retry_at)
        .bind(failure.as_str())
        .execute(&self.pool)
        .await?;
        Ok(outcome.rows_affected() == 1)
    }

    /// Reads one event/recipient's send progress within its explicit tenant scope.
    ///
    /// # Errors
    ///
    /// Returns a database failure. Missing, expired or foreign records return None.
    pub async fn ting_status(
        &self,
        organization_id: &OrganizationId,
        silicon_id: &SiliconId,
        event_id: EventId,
        recipient: &str,
    ) -> Result<Option<TingOutboxStatus>> {
        Ok(sqlx::query_as::<_, TingOutboxStatus>(
            "SELECT id, event_id, recipient_id, attempts, created_at, next_attempt_at,
                    last_attempt_at, last_error_code, lease_until, accepted_at, ting_id,
                    silent, expires_at,
                    COALESCE(convert_from(request_body, 'UTF8')::jsonb->>'delivery', 'ordinary') AS delivery
             FROM hook_private.ting_outbox
             WHERE org_id = $1 AND silicon_id = $2 AND event_id = $3 AND recipient_id = $4
               AND environment_id = hook_private.environment_id()
               AND hook_private.environment_is_available()
               AND expires_at > clock_timestamp()",
        )
        .bind(organization_id.as_str())
        .bind(silicon_id.as_str())
        .bind(event_id.as_uuid())
        .bind(recipient)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Lists recent retained send progress for an authenticated Silicon and organization.
    ///
    /// # Errors
    ///
    /// Returns invalid input for a limit outside 1..=100 or a database failure.
    pub async fn list_ting_status(
        &self,
        organization_id: &OrganizationId,
        silicon_id: &SiliconId,
        limit: u32,
    ) -> Result<Vec<TingOutboxStatus>> {
        if !(1..=100).contains(&limit) {
            return Err(StoreError::InvalidArgument {
                field: "limit",
                reason: "must be between 1 and 100",
            });
        }
        Ok(sqlx::query_as::<_, TingOutboxStatus>(
            "SELECT id, event_id, recipient_id, attempts, created_at, next_attempt_at,
                    last_attempt_at, last_error_code, lease_until, accepted_at, ting_id,
                    silent, expires_at,
                    COALESCE(convert_from(request_body, 'UTF8')::jsonb->>'delivery', 'ordinary') AS delivery
             FROM hook_private.ting_outbox
             WHERE org_id = $1 AND silicon_id = $2
               AND environment_id = hook_private.environment_id()
               AND hook_private.environment_is_available()
               AND expires_at > clock_timestamp()
             ORDER BY created_at DESC, id DESC LIMIT $3",
        )
        .bind(organization_id.as_str())
        .bind(silicon_id.as_str())
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::{Context as _, Result};
    use bytes::Bytes;
    use sqlx::postgres::PgPoolOptions;
    use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
    use testcontainers_modules::postgres::Postgres;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::{
        domain::{
            DeliverySequence, EventRecord, EventRecordSnapshot, HookName, OrganizationId,
            SiliconId,
            request::{CapturedRequest, CapturedRequestParts},
        },
        infrastructure::postgres::{PostgresStore, migrate},
    };

    use super::{TingSendFailure, enqueue_ting, prepared_key};

    #[test]
    fn prepared_requests_cannot_cross_tenants_or_contain_auth_fields() {
        let valid = br#" { "org_id":"tos", "for":"si_test", "type":"hook.event.received", "key":"event-key", "data":{} } "#;
        assert_eq!(
            prepared_key(valid, "tos", "si_test").ok().as_deref(),
            Some("event-key")
        );
        assert!(prepared_key(valid, "another-org", "si_test").is_err());
        assert!(prepared_key(valid, "tos", "another-recipient").is_err());
        let secret = br#"{"org_id":"tos","for":"si_test","type":"hook.event.received","key":"k","data":{},"proof_token":"secret"}"#;
        let result = prepared_key(secret, "tos", "si_test");
        assert!(result.is_err());
        assert!(!format!("{result:?}").contains("secret"));
        let duplicate = br#"{"org_id":"foreign","org_id":"tos","for":"si_test","type":"hook.event.received","key":"k","data":{}}"#;
        assert!(prepared_key(duplicate, "tos", "si_test").is_err());
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one database scenario exercises crash recovery end to end"
    )]
    async fn outbox_commits_atomically_recovers_leases_and_cascades_with_event() -> Result<()> {
        let container = Postgres::default().with_tag("16-alpine").start().await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&format!(
                "postgres://postgres:postgres@{host}:{port}/postgres"
            ))
            .await?;
        migrate(&pool).await?;
        let store = PostgresStore::new(pool);
        let now = OffsetDateTime::now_utc().replace_nanosecond(0)?;
        let event = EventRecord::rehydrate(EventRecordSnapshot {
            id: Uuid::now_v7().into(),
            organization_id: OrganizationId::new("tos")?,
            silicon_id: SiliconId::new("si_test")?,
            hook_id: Uuid::now_v7().into(),
            provider: HookName::new("example")?,
            summary: "example triggered".to_owned(),
            request: CapturedRequest::new(CapturedRequestParts {
                method: "POST".to_owned(),
                url: "https://hook.example.test/provider".parse()?,
                headers: vec![],
                body: Bytes::new(),
                remote_ip: "127.0.0.1".parse()?,
                received_at: now,
            })?,
            delivery_sequence: DeliverySequence::new(1)?,
            received_at: now,
        });
        sqlx::query(
            "INSERT INTO hook.hooks (id, org_id, silicon_id, endpoint_key, name,
                 signature_config, created_by_kind, created_by_id, created_at, updated_at)
             VALUES ($1, 'tos', 'si_test', 'ABCD1234', 'example', '{}'::jsonb,
                 'silicon', 'si_test', $2, $2)",
        )
        .bind(event.hook_id().as_uuid())
        .bind(now)
        .execute(store.pool())
        .await?;
        let mut transaction = store.pool().begin().await?;
        sqlx::query(
            "INSERT INTO hook.events (id, hook_id, org_id, silicon_id, provider, summary,
                 delivery_sequence, method, url, path, query_string, headers, body,
                 remote_ip, received_at, expires_at)
             VALUES ($1, $2, 'tos', 'si_test', 'example', 'example triggered', 1, 'POST',
                 'https://hook.example.test/provider', '/provider', '', '[]'::jsonb,
                 ''::bytea, '127.0.0.1'::inet, $3, $4)",
        )
        .bind(event.id().as_uuid())
        .bind(event.hook_id().as_uuid())
        .bind(now)
        .bind(event.expires_at())
        .execute(&mut *transaction)
        .await?;
        let body = br#" { "org_id":"tos", "for":"si_test", "type":"hook.event.received", "key":"event-key", "data":{} } "#;
        enqueue_ting(&mut transaction, &event, "si_test", body).await?;
        transaction.rollback().await?;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook_private.ting_outbox")
                .fetch_one(store.pool())
                .await?,
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook.events")
                .fetch_one(store.pool())
                .await?,
            0
        );

        let mut transaction = store.pool().begin().await?;
        sqlx::query(
            "INSERT INTO hook.events (id, hook_id, org_id, silicon_id, provider, summary,
                 delivery_sequence, method, url, path, query_string, headers, body,
                 remote_ip, received_at, expires_at)
             VALUES ($1, $2, 'tos', 'si_test', 'example', 'example triggered', 1, 'POST',
                 'https://hook.example.test/provider', '/provider', '', '[]'::jsonb,
                 ''::bytea, '127.0.0.1'::inet, $3, $4)",
        )
        .bind(event.id().as_uuid())
        .bind(event.hook_id().as_uuid())
        .bind(now)
        .bind(event.expires_at())
        .execute(&mut *transaction)
        .await?;
        let id = enqueue_ting(&mut transaction, &event, "si_test", body).await?;
        assert_eq!(
            enqueue_ting(&mut transaction, &event, "si_test", body).await?,
            id
        );
        transaction.commit().await?;

        let (first, competing) = tokio::join!(
            store.claim_ting(1, Duration::from_secs(60)),
            store.claim_ting(1, Duration::from_secs(60)),
        );
        let mut all_claims = first?;
        all_claims.extend(competing?);
        assert_eq!(all_claims.len(), 1);
        let first = all_claims.pop().context("one winning publisher")?;
        assert_eq!(first.request_body.as_slice(), body.as_slice());
        assert_eq!(first.environment_generation, 0);
        assert_eq!(first.expires_at, event.expires_at());
        assert!(store.ting_claim_is_current(&first).await?);
        assert!(!format!("{first:?}").contains("event-key"));

        // Model a crashed publisher whose lease expired, without waiting for time.
        sqlx::query("UPDATE hook_private.ting_outbox SET lease_until = clock_timestamp() - INTERVAL '1 second' WHERE id = $1")
            .bind(id).execute(store.pool()).await?;
        let second = store
            .claim_ting(1, Duration::from_secs(60))
            .await?
            .pop()
            .context("expired lease is reclaimable")?;
        assert_ne!(first.lease_id, second.lease_id);
        assert_eq!(second.attempts, 2);
        assert_eq!(second.request_body.as_slice(), body.as_slice());
        assert!(!store.complete_ting(&first, "msg_stale", false).await?);
        assert!(
            !store
                .retry_ting(&first, TingSendFailure::TransportUnavailable, now)
                .await?
        );
        assert!(
            store
                .retry_ting(
                    &second,
                    TingSendFailure::TransportUnavailable,
                    OffsetDateTime::now_utc() + time::Duration::minutes(1)
                )
                .await?
        );
        assert!(
            store
                .claim_ting(1, Duration::from_secs(60))
                .await?
                .is_empty()
        );
        sqlx::query(
            "UPDATE hook_private.ting_outbox SET next_attempt_at = clock_timestamp() WHERE id = $1",
        )
        .bind(id)
        .execute(store.pool())
        .await?;
        let third = store
            .claim_ting(1, Duration::from_secs(60))
            .await?
            .pop()
            .context("scheduled retry becomes claimable")?;
        assert!(store.complete_ting(&third, "msg_accepted", true).await?);
        assert!(
            !store
                .retry_ting(&third, TingSendFailure::TransportUnavailable, now)
                .await?
        );
        assert!(
            store
                .claim_ting(1, Duration::from_secs(60))
                .await?
                .is_empty()
        );
        let status = store
            .ting_status(
                event.organization_id(),
                event.silicon_id(),
                event.id(),
                "si_test",
            )
            .await?
            .context("accepted send status")?;
        assert_eq!(status.ting_id.as_deref(), Some("msg_accepted"));
        assert_eq!(status.silent, Some(true));
        assert_eq!(status.last_error_code, None);
        assert!(
            store
                .ting_status(
                    &OrganizationId::new("foreign")?,
                    event.silicon_id(),
                    event.id(),
                    "si_test"
                )
                .await?
                .is_none()
        );

        sqlx::query("DELETE FROM hook.events WHERE id = $1")
            .bind(event.id().as_uuid())
            .execute(store.pool())
            .await?;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook_private.ting_outbox")
                .fetch_one(store.pool())
                .await?,
            0
        );
        Ok(())
    }
}
