//! Persistence-specific failures with stable semantic classifications.

use thiserror::Error;

/// Result returned by PostgreSQL persistence operations.
pub type Result<T> = std::result::Result<T, StoreError>;

/// Failures produced by the PostgreSQL adapter.
#[derive(Debug, Error)]
pub enum StoreError {
    /// SQL execution, connection, or transaction failure.
    #[error("PostgreSQL operation failed")]
    Database(#[source] sqlx::Error),
    /// A migration could not be applied.
    #[error("PostgreSQL migration failed")]
    Migration(#[source] sqlx::migrate::MigrateError),
    /// The reachable database does not have the exact schema this build expects.
    #[error("PostgreSQL schema is not ready: {reason}")]
    SchemaNotReady {
        /// Actionable, non-sensitive mismatch detail for operators.
        reason: String,
    },
    /// A persisted row could not be rehydrated into a valid domain value.
    #[error("persisted {entity} data is invalid: {reason}")]
    CorruptData {
        /// Kind of persisted entity that failed validation.
        entity: &'static str,
        /// Non-sensitive validation detail.
        reason: String,
    },
    /// The requested aggregate does not exist in the supplied tenant scope.
    #[error("{entity} was not found")]
    NotFound {
        /// Kind of missing aggregate.
        entity: &'static str,
    },
    /// An optimistic state transition lost a race or targeted the wrong state.
    #[error("{entity} changed concurrently or is in the wrong state")]
    StateConflict {
        /// Kind of aggregate that rejected the transition.
        entity: &'static str,
    },
    /// An idempotency key was reused with different request content.
    #[error("idempotency key is already bound to different request content")]
    IdempotencyConflict,
    /// A completed idempotent operation no longer permits replaying its secret.
    #[error("the one-time secret replay window has expired")]
    SecretReplayExpired,
    /// The secret from an older idempotent result has since been rotated.
    #[error("the one-time secret was superseded by a later rotation")]
    SecretSuperseded,
    /// A generated endpoint key collided with a live or retired key.
    #[error("endpoint key already exists or was retired for this Silicon")]
    EndpointKeyConflict,
    /// A concurrent request already created the Silicon's IAM hook.
    #[error("the Silicon IAM hook already exists")]
    IamDefaultExists,
    /// The Silicon already owns the maximum number of recoverable hooks.
    #[error("the retained hook limit has been reached for this Silicon")]
    HookLimitReached,
    /// A numeric input cannot be represented safely by PostgreSQL.
    #[error("{field} is outside PostgreSQL's supported range")]
    NumericRange {
        /// Name of the out-of-range input.
        field: &'static str,
    },
    /// A repository command violated a method-level precondition.
    #[error("invalid {field}: {reason}")]
    InvalidArgument {
        /// Invalid input field.
        field: &'static str,
        /// Stable non-sensitive explanation.
        reason: &'static str,
    },
}

impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl From<sqlx::migrate::MigrateError> for StoreError {
    fn from(error: sqlx::migrate::MigrateError) -> Self {
        Self::Migration(error)
    }
}

impl StoreError {
    /// Returns a bounded diagnostic class that never includes SQL text, row
    /// values, credentials, or provider details.
    #[must_use]
    pub const fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::Database(_) => "database",
            Self::Migration(_) => "migration",
            Self::SchemaNotReady { .. } => "schema_not_ready",
            Self::CorruptData { .. } => "corrupt_data",
            Self::NotFound { .. } => "not_found",
            Self::StateConflict { .. } => "state_conflict",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::SecretReplayExpired => "secret_replay_expired",
            Self::SecretSuperseded => "secret_superseded",
            Self::EndpointKeyConflict => "endpoint_key_conflict",
            Self::IamDefaultExists => "iam_default_exists",
            Self::HookLimitReached => "hook_limit_reached",
            Self::NumericRange { .. } => "numeric_range",
            Self::InvalidArgument { .. } => "invalid_argument",
        }
    }

    pub(crate) fn corrupt(entity: &'static str, error: impl std::fmt::Display) -> Self {
        Self::CorruptData {
            entity,
            reason: error.to_string(),
        }
    }
}
