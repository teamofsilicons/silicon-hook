//! Transport-independent failures produced by Hook use cases.

use thiserror::Error;

/// Stable semantic failures returned by application workflows.
#[derive(Debug, Error)]
pub enum ApplicationError {
    /// A caller-controlled value violated a public invariant.
    #[error("invalid {field}")]
    Validation {
        /// Stable field or input category.
        field: &'static str,
    },
    /// The request body is not syntactically valid JSON.
    #[error("request body contains malformed JSON")]
    MalformedJson,
    /// The authenticated principal may not perform the operation.
    #[error("operation is forbidden")]
    Forbidden,
    /// A resource does not exist within the authorized tenant scope.
    #[error("resource was not found")]
    NotFound,
    /// A deleted resource is outside its recovery window.
    #[error("hook recovery period has expired")]
    RecoveryExpired,
    /// An idempotency key was reused for different content.
    #[error("idempotency key conflicts with an earlier request")]
    IdempotencyConflict,
    /// The aggregate cannot perform the requested state transition.
    #[error("resource state conflicts with this operation")]
    StateConflict,
    /// A one-time credential can no longer be replayed safely.
    #[error("one-time secret is no longer available")]
    SecretUnavailable,
    /// IAM has already provisioned the unique default hook.
    #[error("the Silicon IAM hook already exists")]
    IamHookAlreadyExists,
    /// The target Silicon owns the maximum number of retained hooks.
    #[error("the retained hook limit has been reached")]
    HookLimitReached,
    /// The public webhook signature is absent, stale, malformed, or invalid.
    #[error("webhook signature is invalid")]
    InvalidSignature,
    /// The normalized representation cannot fit the durable DM contract.
    #[error("normalized event representation is too large")]
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
