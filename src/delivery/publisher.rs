//! Background publication of committed Hook events through Ting.

use std::time::Duration;

use time::OffsetDateTime;
use tokio::sync::watch;

use super::adapter::{DeliveryError, TingAdapter};
use crate::infrastructure::{
    postgres::{PostgresStore, StoreError, TingOutboxClaim, TingSendFailure},
    ting::TingError,
};

/// Claims queued sends and publishes them. Claims and progress are durable
/// across restarts.
#[derive(Clone, Debug)]
pub struct Publisher {
    store: PostgresStore,
    ting: TingAdapter,
}

impl Publisher {
    /// Composes a sender from trusted service configuration, never caller URLs.
    #[must_use]
    pub const fn new(store: PostgresStore, ting: TingAdapter) -> Self {
        Self { store, ting }
    }

    /// Publishes at most one claim, with no database transaction across network I/O.
    ///
    /// # Errors
    /// Returns storage failures. Uncertain external outcomes stay retryable
    /// with the same persisted bytes and producer key.
    pub async fn publish_one(&self) -> Result<bool, StoreError> {
        let Some(claim) = self
            .store
            .claim_ting(1, Duration::from_secs(180))
            .await?
            .pop()
        else {
            return Ok(false);
        };
        if !self.store.ting_claim_is_current(&claim).await? {
            return Ok(true);
        }
        let result =
            tokio::time::timeout(Duration::from_secs(60), self.ting.send(&claim.request_body))
                .await
                .unwrap_or(Err(DeliveryError::Ting(TingError::Transport)));
        match result {
            Ok(accepted) => {
                self.store
                    .complete_ting(&claim, &accepted.id, accepted.silent)
                    .await?;
            }
            Err(DeliveryError::Proof(error)) => {
                tracing::warn!(%error, "Hook could not get a Silicon Accounts proof for Ting");
                self.retry(
                    &claim,
                    TingSendFailure::ProofUnavailable,
                    Duration::from_secs(30),
                )
                .await?;
            }
            Err(DeliveryError::Ting(error)) => {
                let delay = error
                    .retry_after()
                    .unwrap_or_else(|| retry_delay(claim.attempts, error.retryable()));
                self.retry(&claim, failure(&error), delay).await?;
            }
        }
        Ok(true)
    }

    async fn retry(
        &self,
        claim: &TingOutboxClaim,
        failure: TingSendFailure,
        delay: Duration,
    ) -> Result<(), StoreError> {
        let delay =
            time::Duration::seconds(i64::try_from(delay.as_secs().min(3_600)).unwrap_or(3_600));
        self.store
            .retry_ting(claim, failure, OffsetDateTime::now_utc() + delay)
            .await?;
        Ok(())
    }
}

fn retry_delay(attempts: i64, transient: bool) -> Duration {
    if !transient {
        return Duration::from_secs(300);
    }
    let exponent = u32::try_from(attempts.saturating_sub(1).clamp(0, 8)).unwrap_or(8);
    Duration::from_secs((2_u64 << exponent).min(300))
}

fn failure(error: &TingError) -> TingSendFailure {
    match error {
        TingError::Transport => TingSendFailure::TransportUnavailable,
        TingError::InvalidResponse | TingError::ResponseTooLarge => {
            TingSendFailure::InvalidResponse
        }
        TingError::Rejected { status: 429, .. } => TingSendFailure::RateLimited,
        TingError::Rejected {
            status: 500..=599, ..
        } => TingSendFailure::TingUnavailable,
        TingError::Rejected {
            code: "recipient_not_registered",
            ..
        } => TingSendFailure::RecipientNotRegistered,
        TingError::Rejected {
            code: "required_delivery_not_enabled",
            ..
        } => TingSendFailure::RequiredDeliveryNotEnabled,
        TingError::Rejected {
            code: "idempotency_conflict",
            ..
        } => TingSendFailure::IdempotencyConflict,
        TingError::Rejected {
            code: "permission_denied",
            ..
        } => TingSendFailure::ConsentRequired,
        TingError::Rejected {
            status: 401 | 403, ..
        } => TingSendFailure::TingUnauthorized,
        TingError::Rejected { status: 404, .. } => TingSendFailure::TypeNotRegistered,
        _ => TingSendFailure::RequestRejected,
    }
}

/// Runs the queue until shutdown. Cancellation leaves reclaimable leases.
pub async fn run(publisher: Publisher, interval: Duration, mut shutdown: watch::Receiver<bool>) {
    let mut ticks = tokio::time::interval(interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = wait_for_shutdown(&mut shutdown) => break,
            _ = ticks.tick() => {
                tokio::select! {
                    () = wait_for_shutdown(&mut shutdown) => break,
                    result = publisher.publish_one() => {
                        if let Err(error) = result {
                            tracing::warn!(error_code=error.diagnostic_code(), "Ting publication storage unavailable");
                        }
                    }
                }
            }
        }
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow_and_update() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TingSendFailure, failure, retry_delay};
    use crate::infrastructure::ting::TingError;

    #[test]
    fn failures_map_to_bounded_diagnostics_and_backoff() {
        assert_eq!(
            failure(&TingError::Rejected {
                status: 409,
                code: "idempotency_conflict",
                retryable: false,
                retry_after: None
            }),
            TingSendFailure::IdempotencyConflict
        );
        assert_eq!(
            failure(&TingError::Transport),
            TingSendFailure::TransportUnavailable
        );
        assert_eq!(retry_delay(1, true).as_secs(), 2);
        assert_eq!(retry_delay(20, true).as_secs(), 300);
        assert_eq!(retry_delay(1, false).as_secs(), 300);
    }
}
