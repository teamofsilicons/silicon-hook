//! Errors raised while constructing or transitioning domain values.

use thiserror::Error;

/// Secure operating-system randomness was unavailable.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("secure operating-system randomness is unavailable")]
pub struct EntropyError;

/// A value failed a domain boundary validation.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DomainError {
    /// A required value was empty.
    #[error("{field} must not be empty")]
    Empty {
        /// Name of the invalid field.
        field: &'static str,
    },
    /// A string exceeded its contract length limit.
    #[error("{field} must be at most {max} characters")]
    TooLong {
        /// Name of the invalid field.
        field: &'static str,
        /// Maximum permitted length in the unit defined by that field.
        max: usize,
    },
    /// A value did not match its required syntax.
    #[error("{field} has an invalid format: {reason}")]
    InvalidFormat {
        /// Name of the invalid field.
        field: &'static str,
        /// Stable, non-sensitive reason suitable for client validation errors.
        reason: &'static str,
    },
    /// A value fell outside an inclusive numeric range.
    #[error("{field} must be between {min} and {max}")]
    OutOfRange {
        /// Name of the invalid field.
        field: &'static str,
        /// Inclusive minimum.
        min: u64,
        /// Inclusive maximum.
        max: u64,
    },
}

/// A requested aggregate state transition is not permitted.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransitionError {
    /// The operation requires an active hook.
    #[error("hook is already deleted")]
    HookAlreadyDeleted,
    /// The operation requires a deleted hook.
    #[error("hook is already active")]
    HookAlreadyActive,
    /// The hook has passed its recovery deadline.
    #[error("hook recovery period has expired")]
    HookRecoveryExpired,
    /// A transition timestamp predates the aggregate state it follows.
    #[error("{field} timestamp precedes {predecessor}")]
    TimestampOutOfOrder {
        /// Invalid timestamp field.
        field: &'static str,
        /// Earlier state whose timestamp is authoritative.
        predecessor: &'static str,
    },
    /// A completed or permanently failed delivery cannot be changed.
    #[error("delivery in state {status} is terminal")]
    DeliveryTerminal {
        /// Serialized delivery-state name.
        status: &'static str,
    },
    /// A persisted delivery counter cannot be incremented safely.
    #[error("delivery attempt counter overflowed")]
    DeliveryAttemptOverflow,
}
