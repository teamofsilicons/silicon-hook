//! Per-endpoint abuse control for unverified requests.
//!
//! A client address that keeps sending requests a hook cannot verify is
//! blocked for that hook: twenty unverified requests earn a one-day block,
//! and the tenth block is permanent. Counting restarts after each block so a
//! legitimate provider with a rotated secret is not punished forever, while a
//! persistent attacker still converges on a permanent block.

use time::{Duration, OffsetDateTime};

/// Unverified requests that trigger a temporary block.
pub const UNVERIFIED_REQUESTS_PER_BLOCK: u32 = 20;
/// Length of a temporary block.
pub const BLOCK_DURATION: Duration = Duration::days(1);
/// Temporary blocks after which the address is blocked permanently.
pub const BLOCKS_BEFORE_PERMANENT: u32 = 10;

/// Persisted abuse state for one client address on one hook.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IpBlockState {
    /// Unverified requests counted since the last block began.
    pub strikes: u32,
    /// Temporary blocks applied so far.
    pub blocks: u32,
    /// End of the current temporary block, if any.
    pub blocked_until: Option<OffsetDateTime>,
    /// Whether the address is blocked permanently for this hook.
    pub permanent: bool,
}

/// Whether a request from the address may proceed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockCheck {
    /// The address is not blocked.
    Allowed,
    /// The address is blocked until the given instant.
    BlockedUntil(OffsetDateTime),
    /// The address is blocked permanently.
    BlockedPermanently,
}

/// Effect of one more unverified request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrikeOutcome {
    /// The request was counted and the address remains allowed.
    Counted {
        /// Strikes accumulated since the last block.
        strikes: u32,
    },
    /// The request completed a strike window and started a temporary block.
    Blocked {
        /// End of the new block.
        until: OffsetDateTime,
        /// Total blocks applied, including this one.
        blocks: u32,
    },
    /// The request completed the final strike window.
    PermanentlyBlocked {
        /// Total blocks applied, including this one.
        blocks: u32,
    },
}

impl IpBlockState {
    /// Evaluates the block at an authoritative instant.
    #[must_use]
    pub fn check(&self, now: OffsetDateTime) -> BlockCheck {
        if self.permanent {
            return BlockCheck::BlockedPermanently;
        }
        match self.blocked_until {
            Some(until) if now < until => BlockCheck::BlockedUntil(until),
            _ => BlockCheck::Allowed,
        }
    }

    /// Records an unverified request from an address that is currently allowed.
    ///
    /// An expired temporary block is cleared before counting. A permanently
    /// blocked address is left unchanged.
    pub fn record_unverified(&mut self, now: OffsetDateTime) -> StrikeOutcome {
        if self.permanent {
            return StrikeOutcome::PermanentlyBlocked {
                blocks: self.blocks,
            };
        }
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
        self.blocks = self.blocks.saturating_add(1);
        if self.blocks >= BLOCKS_BEFORE_PERMANENT {
            self.permanent = true;
            self.blocked_until = None;
            return StrikeOutcome::PermanentlyBlocked {
                blocks: self.blocks,
            };
        }
        let until = now.saturating_add(BLOCK_DURATION);
        self.blocked_until = Some(until);
        StrikeOutcome::Blocked {
            until,
            blocks: self.blocks,
        }
    }
}

#[cfg(test)]
mod tests {
    use time::{Duration, macros::datetime};

    use super::{
        BLOCKS_BEFORE_PERMANENT, BlockCheck, IpBlockState, StrikeOutcome,
        UNVERIFIED_REQUESTS_PER_BLOCK,
    };

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
            StrikeOutcome::Blocked { until, blocks: 1 }
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
    fn the_tenth_block_is_permanent() {
        let mut now = datetime!(2026-09-02 10:00 UTC);
        let mut state = IpBlockState::default();
        for block in 1..BLOCKS_BEFORE_PERMANENT {
            for _ in 1..UNVERIFIED_REQUESTS_PER_BLOCK {
                state.record_unverified(now);
            }
            assert!(matches!(
                state.record_unverified(now),
                StrikeOutcome::Blocked { blocks, .. } if blocks == block
            ));
            now += Duration::days(2);
            assert_eq!(state.check(now), BlockCheck::Allowed);
        }
        for _ in 1..UNVERIFIED_REQUESTS_PER_BLOCK {
            state.record_unverified(now);
        }
        assert_eq!(
            state.record_unverified(now),
            StrikeOutcome::PermanentlyBlocked {
                blocks: BLOCKS_BEFORE_PERMANENT
            }
        );
        assert_eq!(state.check(now), BlockCheck::BlockedPermanently);
        assert_eq!(
            state.check(now + Duration::days(400)),
            BlockCheck::BlockedPermanently
        );
        assert_eq!(
            state.record_unverified(now),
            StrikeOutcome::PermanentlyBlocked {
                blocks: BLOCKS_BEFORE_PERMANENT
            }
        );
    }
}
