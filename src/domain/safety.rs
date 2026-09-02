//! Per-endpoint abuse control for unverified requests.
//!
//! A client address that keeps sending requests a hook cannot verify is
//! blocked for that hook: twenty unverified requests earn a one-day block.
//! Counting restarts after each block, so a provider that keeps posting with a
//! stale secret is blocked again a day later rather than escalating; the
//! contract defines no permanent block.

use time::{Duration, OffsetDateTime};

/// Unverified requests that trigger a block.
pub const UNVERIFIED_REQUESTS_PER_BLOCK: u32 = 20;
/// Length of a block.
pub const BLOCK_DURATION: Duration = Duration::days(1);

/// Persisted abuse state for one client address on one hook.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IpBlockState {
    /// Unverified requests counted since the last block began.
    pub strikes: u32,
    /// End of the current block, if any.
    pub blocked_until: Option<OffsetDateTime>,
}

/// Whether a request from the address may proceed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockCheck {
    /// The address is not blocked.
    Allowed,
    /// The address is blocked until the given instant.
    BlockedUntil(OffsetDateTime),
}

/// Effect of one more unverified request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrikeOutcome {
    /// The request was counted and the address remains allowed.
    Counted {
        /// Strikes accumulated since the last block.
        strikes: u32,
    },
    /// The request completed a strike window and started a block.
    Blocked {
        /// End of the new block.
        until: OffsetDateTime,
    },
}

impl IpBlockState {
    /// Evaluates the block at an authoritative instant.
    #[must_use]
    pub fn check(&self, now: OffsetDateTime) -> BlockCheck {
        match self.blocked_until {
            Some(until) if now < until => BlockCheck::BlockedUntil(until),
            _ => BlockCheck::Allowed,
        }
    }

    /// Records an unverified request from an address that is currently allowed.
    ///
    /// An expired block is cleared before counting.
    pub fn record_unverified(&mut self, now: OffsetDateTime) -> StrikeOutcome {
        if self.blocked_until.is_some_and(|until| now >= until) {
            self.blocked_until = None;
        }
        self.strikes = self.strikes.saturating_add(1);
        if self.strikes < UNVERIFIED_REQUESTS_PER_BLOCK {
            return StrikeOutcome::Counted {
                strikes: self.strikes,
            };
        }
        self.strikes = 0;
        let until = now.saturating_add(BLOCK_DURATION);
        self.blocked_until = Some(until);
        StrikeOutcome::Blocked { until }
    }
}

#[cfg(test)]
mod tests {
    use time::{Duration, macros::datetime};

    use super::{BlockCheck, IpBlockState, StrikeOutcome, UNVERIFIED_REQUESTS_PER_BLOCK};

    #[test]
    fn twenty_unverified_requests_block_for_one_day() {
        let now = datetime!(2026-09-02 10:00 UTC);
        let mut state = IpBlockState::default();
        for expected in 1..UNVERIFIED_REQUESTS_PER_BLOCK {
            assert_eq!(
                state.record_unverified(now),
                StrikeOutcome::Counted { strikes: expected }
            );
            assert_eq!(state.check(now), BlockCheck::Allowed);
        }
        let until = now + Duration::days(1);
        assert_eq!(
            state.record_unverified(now),
            StrikeOutcome::Blocked { until }
        );
        assert_eq!(state.check(now), BlockCheck::BlockedUntil(until));
        assert_eq!(
            state.check(until - Duration::microseconds(1)),
            BlockCheck::BlockedUntil(until)
        );
        assert_eq!(state.check(until), BlockCheck::Allowed);
        assert_eq!(state.strikes, 0);
    }

    #[test]
    fn blocks_repeat_without_escalating() {
        let mut now = datetime!(2026-09-02 10:00 UTC);
        let mut state = IpBlockState::default();
        for _ in 0..25 {
            for _ in 1..UNVERIFIED_REQUESTS_PER_BLOCK {
                state.record_unverified(now);
            }
            let until = now + Duration::days(1);
            assert_eq!(
                state.record_unverified(now),
                StrikeOutcome::Blocked { until }
            );
            assert_eq!(state.check(now), BlockCheck::BlockedUntil(until));
            now += Duration::days(2);
            assert_eq!(state.check(now), BlockCheck::Allowed);
        }
        assert_eq!(state.strikes, 0);
    }
}
