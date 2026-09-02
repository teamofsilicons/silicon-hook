//! Public persistence commands and results.

use time::OffsetDateTime;

use crate::domain::{
    ActorRef, ApplicationId, BlockReason, BlockedRequestId, EncryptedSecret, EndpointKey, EventId,
    HistoryCursor, HistoryFilter, Hook, HookId, HookUpdate, OrganizationId, SiliconId,
    request::CapturedRequest,
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

/// Outcome of routing a public endpoint key.
#[derive(Clone, Debug)]
pub enum EndpointResolution {
    /// The key belongs to an active hook.
    Active {
        /// Hook and its signing policy.
        hook: Box<Hook>,
        /// Database timestamp sampled by the same statement.
        database_time: OffsetDateTime,
    },
    /// The key belongs to a disabled or deleted hook.
    Inactive,
    /// The key was rotated away and is permanently retired for this Silicon.
    Retired,
    /// No hook has ever used the key for this Silicon.
    Unknown,
}

/// Audited hook mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditAction {
    /// A non-default hook was created.
    Created,
    /// Hook metadata or signing policy changed.
    Updated,
    /// A hook stopped accepting requests without entering deletion recovery.
    Disabled,
    /// A disabled hook resumed accepting requests.
    Enabled,
    /// A hook was soft-deleted.
    Deleted,
    /// A soft-deleted hook was restored.
    Restored,
    /// A hook signing secret was replaced.
    SecretRotated,
    /// A hook endpoint key was replaced and the old key retired.
    EndpointRotated,
    /// IAM provisioned the default hook for a Silicon.
    IamProvisioned,
}

impl AuditAction {
    pub(crate) const fn as_db_str(self) -> &'static str {
        match self {
            Self::Created => "hook.created",
            Self::Updated => "hook.updated",
            Self::Disabled => "hook.disabled",
            Self::Enabled => "hook.enabled",
            Self::Deleted => "hook.deleted",
            Self::Restored => "hook.restored",
            Self::SecretRotated => "hook.secret_rotated",
            Self::EndpointRotated => "hook.endpoint_rotated",
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

/// Non-idempotency-keyed metadata and signing-policy replacement.
#[derive(Clone, Debug)]
pub struct UpdateHook {
    /// Organization owning the hook.
    pub organization_id: OrganizationId,
    /// Silicon owning the hook.
    pub silicon_id: SiliconId,
    /// Hook to update.
    pub hook_id: HookId,
    /// Fields to replace.
    pub update: HookUpdate,
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

/// Atomic endpoint-key replacement.
#[derive(Clone, Debug)]
pub struct RotateEndpoint {
    /// Organization owning the hook.
    pub organization_id: OrganizationId,
    /// Silicon owning the hook.
    pub silicon_id: SiliconId,
    /// Hook whose endpoint is replaced.
    pub hook_id: HookId,
    /// Freshly generated replacement key.
    pub replacement: EndpointKey,
    /// Management idempotency scope.
    pub idempotency: IdempotencyScope,
    /// Non-secret result metadata.
    pub response: PersistedResponse,
    /// Audit attribution.
    pub audit: AuditContext,
    /// Authoritative rotation time.
    pub occurred_at: OffsetDateTime,
}

/// Result of an idempotent endpoint rotation.
#[derive(Clone, Debug)]
pub enum RotateEndpointOutcome {
    /// This call rotated the endpoint and retired the previous key.
    Rotated(Hook),
    /// A content-identical earlier call already rotated the endpoint.
    Replayed {
        /// Current hook metadata with the rotated key.
        hook: Hook,
        /// Original non-secret result status.
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

/// A verified request to append to a hook's log and its Silicon's stream.
#[derive(Clone, Debug)]
pub struct AcceptEvent {
    /// Preallocated stable event identifier.
    pub event_id: EventId,
    /// Receiving hook as resolved for this request.
    pub hook: Hook,
    /// Exact captured request.
    pub request: CapturedRequest,
}

/// An unverified request to append to a hook's blocked log.
#[derive(Clone, Debug)]
pub struct RecordBlockedRequest {
    /// Preallocated stable identifier.
    pub id: BlockedRequestId,
    /// Receiving hook as resolved for this request.
    pub hook: Hook,
    /// Exact captured request.
    pub request: CapturedRequest,
    /// Why delivery was withheld.
    pub reason: BlockReason,
}

/// Authorized keyset request for retained history.
#[derive(Clone, Debug)]
pub struct HistoryPageRequest {
    /// Organization boundary.
    pub organization_id: OrganizationId,
    /// Silicon boundary.
    pub silicon_id: SiliconId,
    /// Optional hook restriction.
    pub filter: HistoryFilter,
    /// Exclusive descending keyset boundary.
    pub cursor: Option<HistoryCursor>,
    /// Number of records requested, from 1 through 10,000.
    pub limit: u32,
}

/// One retained history page and its next database boundary.
#[derive(Clone, Debug)]
pub struct HistoryPage<T> {
    /// Rehydrated records, newest first.
    pub items: Vec<T>,
    /// Exclusive boundary for the next page, before cursor authentication.
    pub next_cursor: Option<HistoryCursor>,
}

/// Counts returned by one bounded maintenance pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaintenanceResult {
    /// Verified request rows removed after their 14-day retention.
    pub events_purged: u64,
    /// Blocked request rows removed after their 14-day retention.
    pub blocked_requests_purged: u64,
    /// Hooks permanently removed after the 45-day recovery window.
    pub hooks_purged: u64,
    /// Expired management idempotency rows removed.
    pub idempotency_rows_purged: u64,
    /// Inactive, non-permanent address blocks removed.
    pub ip_blocks_purged: u64,
}

/// One independently scheduled retention-maintenance class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MaintenanceTask {
    /// Remove verified requests past retention.
    ExpiredEvents,
    /// Remove blocked requests past retention.
    ExpiredBlockedRequests,
    /// Permanently remove hooks beyond their recovery period.
    ExpiredHooks,
    /// Remove expired management-idempotency records.
    ExpiredIdempotency,
    /// Remove stale temporary address blocks.
    StaleIpBlocks,
}

impl MaintenanceTask {
    /// Fair scheduling order used for every maintenance cycle.
    pub(crate) const ALL: [Self; 5] = [
        Self::ExpiredEvents,
        Self::ExpiredBlockedRequests,
        Self::ExpiredHooks,
        Self::ExpiredIdempotency,
        Self::StaleIpBlocks,
    ];

    /// Stable, non-sensitive diagnostic name.
    pub(crate) const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::ExpiredEvents => "expired_events",
            Self::ExpiredBlockedRequests => "expired_blocked_requests",
            Self::ExpiredHooks => "expired_hooks",
            Self::ExpiredIdempotency => "expired_idempotency",
            Self::StaleIpBlocks => "stale_ip_blocks",
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
