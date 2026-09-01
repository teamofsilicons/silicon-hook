//! Public persistence commands and results.

use std::time::Duration;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::dm_contract::{DmRequestBody, DmRequestBodyError};
use crate::domain::{
    ActorRef, ApplicationId, EncryptedSecret, EventCursor, EventFilter, EventId, EventRecord, Hook,
    HookId, OrganizationId, RequestDigest, SiliconId,
};

/// Stable scope and content binding for a management idempotency key.
#[derive(Clone, Debug)]
pub struct IdempotencyScope {
    /// Stable operation name, such as `hook.create`.
    pub operation: String,
    /// Effective IAM actor, excluding an OBO calling application.
    pub actor: ActorRef,
    /// OBO calling application; part of the replay-authority boundary.
    pub calling_application_id: Option<ApplicationId>,
    /// Organization in which the operation is performed.
    pub organization_id: OrganizationId,
    /// Stable operation-specific target identity.
    pub target_id: String,
    /// Caller-supplied visible-ASCII idempotency key.
    pub key: String,
    /// SHA-256 digest of the canonical request.
    pub request_digest: [u8; 32],
}

/// Durable result metadata for a content-identical management replay.
///
/// Plaintext signing secrets are intentionally not representable here. Secret
/// material remains encrypted with the runtime keyring while at rest.
#[derive(Clone, Debug, PartialEq)]
pub struct PersistedResponse {
    /// Original HTTP status code.
    pub status: u16,
    /// Resource created or mutated by the operation, when applicable.
    pub resource_id: Option<HookId>,
    /// Encrypted one-time secret needed to reconstruct a bounded replay.
    pub encrypted_secret: Option<EncryptedSecret>,
    /// Last instant at which a secret-bearing response may be replayed.
    pub secret_replay_until: Option<OffsetDateTime>,
}

/// Actor and request facts written to the append-only audit trail.
#[derive(Clone, Debug)]
pub struct AuditContext {
    /// Effective IAM actor.
    pub actor: ActorRef,
    /// OBO application, separate from the effective actor.
    pub calling_application_id: Option<ApplicationId>,
    /// Correlation identifier assigned by the API.
    pub request_id: Option<String>,
}

/// Active ingress hook resolved together with PostgreSQL's authoritative time.
#[derive(Clone, Debug)]
pub struct IngressHookResolution {
    /// Active hook and encrypted signing secret.
    pub hook: Hook,
    /// Database timestamp sampled by the same statement that resolved the hook.
    pub database_time: OffsetDateTime,
}

/// Audited hook mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditAction {
    /// A non-default hook was created.
    Created,
    /// A hook stopped accepting new ingress without entering deletion recovery.
    Disabled,
    /// A disabled hook resumed accepting new ingress.
    Enabled,
    /// A hook was soft-deleted.
    Deleted,
    /// A soft-deleted hook was restored.
    Restored,
    /// A hook signing secret was replaced.
    SecretRotated,
    /// IAM provisioned the default hook for a Silicon.
    IamProvisioned,
}

impl AuditAction {
    pub(crate) const fn as_db_str(self) -> &'static str {
        match self {
            Self::Created => "hook.created",
            Self::Disabled => "hook.disabled",
            Self::Enabled => "hook.enabled",
            Self::Deleted => "hook.deleted",
            Self::Restored => "hook.restored",
            Self::SecretRotated => "hook.secret_rotated",
            Self::IamProvisioned => "hook.iam_provisioned",
        }
    }
}

/// Atomic hook creation request.
#[derive(Clone, Debug)]
pub struct CreateHook {
    /// Fully validated active hook aggregate to insert.
    pub hook: Hook,
    /// Whether this is IAM's unique default hook.
    pub is_iam_default: bool,
    /// Management idempotency scope.
    pub idempotency: IdempotencyScope,
    /// Response stored for content-identical replay.
    pub response: PersistedResponse,
    /// Audit attribution written in the same transaction.
    pub audit: AuditContext,
    /// Database time used for idempotency and audit records.
    pub recorded_at: OffsetDateTime,
}

/// Result of an atomic create or IAM-provision operation.
#[derive(Clone, Debug)]
pub enum CreateHookOutcome {
    /// This call created the hook.
    Created(Hook),
    /// A content-identical earlier call supplied the original response.
    Replayed {
        /// Rehydrated hook metadata associated with the original result.
        hook: Hook,
        /// Original status and encrypted one-time secret.
        response: PersistedResponse,
    },
}

/// IAM provisioning uses the same idempotent result semantics as creation.
pub type ProvisionHookOutcome = CreateHookOutcome;

/// Scope and attribution for a soft-delete transition.
#[derive(Clone, Debug)]
pub struct HookMutation {
    /// Organization owning the hook.
    pub organization_id: OrganizationId,
    /// Silicon owning the hook.
    pub silicon_id: SiliconId,
    /// Hook to mutate.
    pub hook_id: HookId,
    /// Audit attribution.
    pub audit: AuditContext,
    /// Authoritative mutation time.
    pub occurred_at: OffsetDateTime,
}

/// Atomic desired-state activation mutation for one or more hooks.
#[derive(Clone, Debug)]
pub struct BatchHookActivation {
    /// Organization owning every target hook.
    pub organization_id: OrganizationId,
    /// Silicon owning every target hook.
    pub silicon_id: SiliconId,
    /// Unique hooks to lock and mutate as one transaction.
    pub hook_ids: Vec<HookId>,
    /// Desired ingress state: `true` enables and `false` disables.
    pub enabled: bool,
    /// Audit attribution shared by every actual transition.
    pub audit: AuditContext,
    /// Authoritative mutation time.
    pub occurred_at: OffsetDateTime,
}

/// Atomic signing-secret replacement.
#[derive(Clone, Debug)]
pub struct RotateSecret {
    /// Organization owning the hook.
    pub organization_id: OrganizationId,
    /// Silicon owning the hook.
    pub silicon_id: SiliconId,
    /// Hook whose secret is replaced.
    pub hook_id: HookId,
    /// Newly encrypted secret material.
    pub encrypted_secret: EncryptedSecret,
    /// Management idempotency scope.
    pub idempotency: IdempotencyScope,
    /// Secret-bearing result metadata persisted only in encrypted form.
    pub response: PersistedResponse,
    /// Audit attribution.
    pub audit: AuditContext,
    /// Authoritative mutation time.
    pub occurred_at: OffsetDateTime,
}

/// Result of an idempotent signing-secret rotation.
#[derive(Clone, Debug)]
pub enum RotateSecretOutcome {
    /// This call rotated the signing secret.
    Rotated(Hook),
    /// A content-identical earlier call supplied the encrypted result.
    Replayed {
        /// Current hook metadata, verified to still use the replayed secret.
        hook: Hook,
        /// Original status and encrypted one-time secret.
        response: PersistedResponse,
    },
}

/// Idempotent restore command.
#[derive(Clone, Debug)]
pub struct RestoreHook {
    /// Organization owning the hook.
    pub organization_id: OrganizationId,
    /// Silicon owning the hook.
    pub silicon_id: SiliconId,
    /// Hook to restore.
    pub hook_id: HookId,
    /// Management idempotency scope.
    pub idempotency: IdempotencyScope,
    /// Non-secret result metadata.
    pub response: PersistedResponse,
    /// Audit attribution.
    pub audit: AuditContext,
    /// Authoritative restore time.
    pub occurred_at: OffsetDateTime,
}

/// Result of an idempotent hook restore.
#[derive(Clone, Debug)]
pub enum RestoreHookOutcome {
    /// This call restored the hook.
    Restored(Hook),
    /// A content-identical earlier call returned the current non-deleted hook.
    Replayed {
        /// Current active or disabled hook metadata.
        hook: Hook,
        /// Original non-secret result status.
        response: PersistedResponse,
    },
}

/// One DM outbox row claimed under an expiring ownership token.
#[derive(Clone, Debug, PartialEq)]
pub struct ClaimedDelivery {
    /// Stable event identifier used by DM for deduplication.
    pub event_id: EventId,
    /// Exact immutable JSON body to send to DM.
    pub request_body: Vec<u8>,
    /// Attempt number that will be recorded if this lease is completed.
    pub attempt_number: u32,
    /// Compare-and-swap token proving ownership of this claim.
    pub lease_token: Uuid,
    /// Time at which another worker may reclaim the row.
    pub leased_until: OffsetDateTime,
}

/// Outcome of one DM HTTP attempt.
#[derive(Clone, Debug, PartialEq)]
pub enum DeliveryOutcome {
    /// DM durably accepted the event with HTTP 202.
    Delivered,
    /// The failure is retryable after a database-clock-relative delay.
    Retry {
        /// Delay from PostgreSQL's completion timestamp before another claim.
        retry_after: Duration,
        /// Redacted bounded diagnostic detail.
        reason: String,
        /// HTTP status when a response was received.
        http_status: Option<u16>,
    },
    /// The failure is terminal or the attempt budget was exhausted.
    Failed {
        /// Redacted bounded diagnostic detail.
        reason: String,
        /// HTTP status when a response was received.
        http_status: Option<u16>,
    },
}

/// Compare-and-swap update for a claimed delivery.
#[derive(Clone, Debug, PartialEq)]
pub struct DeliveryAttempt {
    /// Claimed event.
    pub event_id: EventId,
    /// Ownership token returned by the claim.
    pub lease_token: Uuid,
    /// Result to persist.
    pub outcome: DeliveryOutcome,
}

/// Counts returned by one bounded maintenance pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaintenanceResult {
    /// Event history rows removed beyond each hook's newest 10,000.
    pub events_purged: u64,
    /// Terminal outbox receipts removed after their history was evicted.
    pub outbox_rows_purged: u64,
    /// Expired management idempotency rows removed.
    pub idempotency_rows_purged: u64,
    /// Hooks permanently removed after the 45-day recovery window.
    pub hooks_purged: u64,
}

/// One independently scheduled retention-maintenance class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MaintenanceTask {
    /// Evict history outside each hook's visible window.
    EventHistory,
    /// Permanently remove hooks beyond their recovery period.
    ExpiredHooks,
    /// Remove terminal delivery receipts after history eviction.
    TerminalOutbox,
    /// Remove expired management-idempotency records.
    ExpiredIdempotency,
}

impl MaintenanceTask {
    /// Fair scheduling order used for every maintenance cycle.
    pub(crate) const ALL: [Self; 4] = [
        Self::EventHistory,
        Self::ExpiredHooks,
        Self::TerminalOutbox,
        Self::ExpiredIdempotency,
    ];

    /// Stable, non-sensitive diagnostic name.
    pub(crate) const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::EventHistory => "event_history",
            Self::ExpiredHooks => "expired_hooks",
            Self::TerminalOutbox => "terminal_outbox",
            Self::ExpiredIdempotency => "expired_idempotency",
        }
    }
}

/// Result of one bounded, independently committed maintenance task.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MaintenanceBatch {
    /// Rows removed by this task.
    pub(crate) rows_affected: u64,
    /// Whether immediately eligible work remains for this task.
    pub(crate) more_work: bool,
}

/// An accepted event and its ingress idempotency key.
#[derive(Clone, Debug)]
pub struct NewEvent {
    /// Validated immutable event with pending delivery state.
    pub event: EventRecord,
    /// Exact bounded JSON representation committed to the DM outbox.
    pub(crate) dm_request_body: DmRequestBody,
    /// Ciphertext that authenticated this request before the transaction.
    /// The store compares it under the hook row lock to linearize rotation.
    pub expected_encrypted_secret: EncryptedSecret,
    /// Digest of the exact authenticated timestamp-and-body representation.
    /// This closes replay attempts that substitute a new idempotency key.
    pub authenticated_request_digest: RequestDigest,
    /// Caller-supplied visible-ASCII idempotency key.
    pub idempotency_key: String,
}

impl NewEvent {
    /// Constructs an event acceptance command and freezes its exact bounded DM
    /// representation before any persistence work starts.
    ///
    /// # Errors
    ///
    /// Returns an error when the normalized DM body cannot be serialized or
    /// exceeds the common API/worker acceptance bound.
    pub fn new(
        event: EventRecord,
        expected_encrypted_secret: EncryptedSecret,
        authenticated_request_digest: RequestDigest,
        idempotency_key: String,
    ) -> Result<Self, DmRequestBodyError> {
        let dm_request_body = DmRequestBody::from_event(&event)?;
        Ok(Self {
            event,
            dm_request_body,
            expected_encrypted_secret,
            authenticated_request_digest,
            idempotency_key,
        })
    }
}

/// Result of atomically accepting an event and its DM outbox job.
#[derive(Clone, Debug)]
pub enum IngressAcceptance {
    /// This request committed a new immutable event and outbox row.
    Accepted {
        /// Newly committed stable event identifier.
        event_id: EventId,
    },
    /// A content-identical request was accepted earlier.
    Replayed {
        /// Stable identifier from the original acceptance.
        event_id: EventId,
    },
}

/// Authorized keyset request for retained event history.
#[derive(Clone, Debug)]
pub struct EventPageRequest {
    /// Organization boundary.
    pub organization_id: OrganizationId,
    /// Silicon boundary.
    pub silicon_id: SiliconId,
    /// Optional hook and event-type restrictions.
    pub filter: EventFilter,
    /// Exclusive descending keyset boundary.
    pub cursor: Option<EventCursor>,
    /// Number of records requested, from 1 through 10,000.
    pub limit: u32,
}

/// One retained event-history page and its next database boundary.
#[derive(Clone, Debug)]
pub struct EventPage {
    /// Rehydrated event history records.
    pub items: Vec<EventRecord>,
    /// Exclusive boundary for the next page, before cursor authentication.
    pub next_cursor: Option<EventCursor>,
}
