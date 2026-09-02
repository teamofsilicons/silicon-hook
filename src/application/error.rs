//! Transport-independent failures produced by Hook use cases.

use thiserror::Error;
use time::OffsetDateTime;

/// Stable semantic failures returned by application workflows.
#[derive(Debug, Error)]
pub enum ApplicationError {
    /// A caller-controlled value violated a public invariant.
    #[error("invalid {field}")]
    Validation {
        /// Stable field or input category.
        field: &'static str,
    },
    /// A caller-controlled value violated an invariant, with a safe explanation.
    #[error("invalid {field}: {detail}")]
    ValidationDetailed {
        /// Stable field or input category.
        field: &'static str,
        /// Human-readable, non-sensitive detail.
        detail: String,
    },
    /// The authenticated principal may not perform the operation.
    #[error("operation is forbidden")]
    Forbidden,
    /// A resource does not exist within the authorized tenant scope.
    #[error("resource was not found")]
    NotFound,
    /// A deleted resource is outside its recovery window.
    #[error("hook recovery period has expired")]
    RecoveryExpired,
    /// The endpoint key was rotated away and is permanently retired.
    #[error("endpoint key has been retired")]
    EndpointRetired,
    /// The client address is blocked for this endpoint.
    #[error("client address is blocked for this endpoint")]
    IpBlocked {
        /// End of the block.
        until: OffsetDateTime,
    },
    /// An idempotency key was reused for different content.
    #[error("idempotency key conflicts with an earlier request")]
    IdempotencyConflict,
    /// The aggregate cannot perform the requested state transition.
    #[error("resource state conflicts with this operation")]
    StateConflict,
    /// A one-time credential can no longer be replayed safely.
    #[error("one-time secret is no longer available")]
    SecretUnavailable,
    /// The target Silicon owns the maximum number of retained hooks.
    #[error("the retained hook limit has been reached")]
    HookLimitReached,
    /// The request body or headers exceed a capture bound.
    #[error("request exceeds a capture bound")]
    PayloadTooLarge,
    /// A required infrastructure dependency cannot currently serve requests.
    #[error("a required dependency is unavailable")]
    Unavailable(#[source] anyhow::Error),
    /// A dependency or internal invariant failed unexpectedly.
    #[error("internal application failure")]
    Internal(#[source] anyhow::Error),
}

impl ApplicationError {
    pub(super) fn internal(error: impl Into<anyhow::Error>) -> Self {
        Self::Internal(error.into())
    }

    pub(super) fn unavailable(error: impl Into<anyhow::Error>) -> Self {
        Self::Unavailable(error.into())
    }
}
