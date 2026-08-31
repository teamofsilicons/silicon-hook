//! Injectable time source for deterministic lifecycle and replay tests.

use time::OffsetDateTime;

/// Supplies UTC time to application workflows.
pub trait Clock: Send + Sync {
    /// Returns the current UTC instant.
    fn now(&self) -> OffsetDateTime;
}

/// Production clock backed by the operating system.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}
