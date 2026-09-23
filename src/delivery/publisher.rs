//! Background publication of committed Hook events through Ting.

use std::time::Duration;

use time::OffsetDateTime;
use tokio::sync::watch;

use super::credentials::{PublisherCredentialError, PublisherCredentials};
use super::observer_authority::ObserverFailure;
use crate::{
    application::{HookApplication, environments::EnvironmentService},
    domain::OrganizationId,
    infrastructure::{
        iam::{IamClient, IamError},
        postgres::{StoreError, TingOutboxClaim, TingSendFailure},
        ting::{TingClient, TingError},
    },
};

/// A generation-scoped sender. Claims and progress are durable across restarts.
#[derive(Clone, Debug)]
pub struct Publisher {
    application: HookApplication,
    iam: IamClient,
    ting: TingClient,
    credentials: PublisherCredentials,
}

impl Publisher {
    /// Composes a sender from trusted service configuration, never caller URLs.
    #[must_use]
    pub fn new(application: HookApplication, iam: IamClient, ting: TingClient) -> Self {
        let credentials = application.publisher_credentials(iam.clone());
        Self {
            application,
            iam,
            ting,
            credentials,
        }
    }

    /// Publishes at most one claim, with no database transaction across credential refresh.
    ///
    /// # Errors
    /// Returns storage failures. Uncertain external outcomes remain retryable
    /// using the same persisted bytes and producer key, with a fresh proof.
    pub async fn publish_one(&self) -> Result<bool, StoreError> {
        let store = self.application.store();
        let Some(claim) = store.claim_ting(1, Duration::from_secs(180)).await?.pop() else {
            return Ok(false);
        };
        let org =
            OrganizationId::new(claim.org_id.clone()).map_err(|_| StoreError::CorruptData {
                entity: "ting_outbox.org_id",
                reason: "invalid organization".into(),
            })?;
        let token = match tokio::time::timeout(
            Duration::from_secs(60),
            self.credentials.access_token(&org),
        )
        .await
        {
            Ok(Ok(token)) => token,
            result => {
                let failure = match result {
                    Ok(Err(PublisherCredentialError::NotConfigured)) => {
                        TingSendFailure::PublisherNotConfigured
                    }
                    Ok(Err(
                        PublisherCredentialError::Forbidden
                        | PublisherCredentialError::SessionRejected,
                    )) => TingSendFailure::PublisherUnauthorized,
                    _ => TingSendFailure::PublisherUnavailable,
                };
                self.retry(&claim, failure, Duration::from_secs(30)).await?;
                return Ok(true);
            }
        };
        let observers = self.application.observer_authorities(self.iam.clone());
        let observer_permit = if claim.recipient_binding_id.is_some() {
            match tokio::time::timeout(Duration::from_secs(25), observers.authorize(&claim)).await {
                Ok(Ok(permit)) => Some(permit),
                Ok(Err(ObserverFailure::Revoked(permit))) => {
                    observers.revoke(&permit).await?;
                    return Ok(true);
                }
                failure => {
                    let reason = if matches!(failure, Ok(Err(ObserverFailure::RefreshRequired))) {
                        TingSendFailure::ObserverAuthorityRefreshRequired
                    } else {
                        TingSendFailure::ObserverAuthorizationUnavailable
                    };
                    self.retry(&claim, reason, Duration::from_secs(30)).await?;
                    return Ok(true);
                }
            }
        } else {
            None
        };
        // The shared lifecycle guard prevents a local test clean from racing
        // the external send. Drop it before any write (which takes FOR UPDATE).
        let Ok(guard) = self.application.delivery_guard().await else {
            return Ok(true);
        };
        if !store.ting_claim_is_current(&claim).await? {
            return Ok(true);
        }
        if let Some(permit) = &observer_permit
            && !observers.is_current(permit).await?
        {
            return Ok(true);
        }
        let result = tokio::time::timeout(
            Duration::from_secs(40),
            self.ting.send(&self.iam, &token, &claim.request_body),
        )
        .await
        .unwrap_or(Err(TingError::Transport));
        drop(guard);
        match result {
            Ok(accepted) => {
                store
                    .complete_ting(&claim, &accepted.id, accepted.silent)
                    .await?;
            }
            Err(error) => {
                if matches!(error, TingError::Iam(IamError::InvalidCredential)) {
                    let _ = self.credentials.invalidate_access_token(&org, &token).await;
                }
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
        self.application
            .store()
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
        TingError::Iam(IamError::Forbidden) => TingSendFailure::ConsentRequired,
        TingError::Iam(IamError::InvalidCredential) => TingSendFailure::PublisherUnauthorized,
        TingError::Iam(_) => TingSendFailure::AuthorizationUnavailable,
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
            status: 401 | 403, ..
        } => TingSendFailure::TingUnauthorized,
        TingError::Rejected { status: 404, .. } => TingSendFailure::TypeNotRegistered,
        _ => TingSendFailure::RequestRejected,
    }
}

/// Runs the production queue until shutdown. Cancellation leaves reclaimable leases.
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

/// Fair, bounded background publication for isolated test environments.
pub async fn run_tests(
    application: HookApplication,
    service: EnvironmentService,
    ting: TingClient,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut after = None;
    let mut ticks = tokio::time::interval(interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = wait_for_shutdown(&mut shutdown) => break,
            _ = ticks.tick() => {},
        }
        let pass = async {
            let ids = service.delivery_environment_ids(after).await?;
            after = ids.last().copied();
            // Each context has only one in-flight send; its two-connection pool
            // can hold the lifecycle guard and perform the current-claim read.
            let jobs = ids.into_iter().map(|id| {
                let application = application.clone();
                let service = service.clone();
                let ting = ting.clone();
                async move {
                    let work = async {
                        if !service.delivery_pending(id).await? {
                            return Ok(());
                        }
                        let context = service.delivery_context(id).await?;
                        let scoped = application.for_test_environment(
                            context.store,
                            id,
                            context.environment.generation,
                        );
                        Publisher::new(scoped, context.iam, ting)
                            .publish_one()
                            .await
                            .map_err(|_| crate::error::AppError::ProviderUnavailable)?;
                        Ok::<(), crate::error::AppError>(())
                    };
                    if !matches!(
                        tokio::time::timeout(Duration::from_secs(175), work).await,
                        Ok(Ok(()))
                    ) {
                        tracing::warn!(environment_id=%id, "Ting test publication deferred");
                    }
                }
            });
            futures::future::join_all(jobs).await;
            Ok::<(), crate::error::AppError>(())
        };
        tokio::select! {
            () = wait_for_shutdown(&mut shutdown) => break,
            result = pass => {
                if result.is_err() { tracing::warn!("Ting test environment discovery unavailable"); }
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
