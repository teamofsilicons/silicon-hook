//! One bounded concurrent pass over due DM outbox work.

use std::{future::Future, time::Duration};

use futures::{StreamExt as _, stream};

use crate::{
    config::WorkerSettings,
    domain::{DeliveryDecision, DeliveryPolicy},
    infrastructure::{
        dm::{DeliveryFailureReason, DeliveryOutcome as DmDeliveryOutcome, DmClient, SystemEvent},
        postgres::{
            ClaimedDelivery, DeliveryAttempt, DeliveryOutcome as StoreDeliveryOutcome,
            PostgresStore, StoreError,
        },
    },
};

pub(super) async fn process_delivery_batch(
    store: &PostgresStore,
    dm: &DmClient,
    settings: &WorkerSettings,
) -> Result<usize, StoreError> {
    let limit = delivery_claim_limit(
        settings.batch_size.get(),
        settings.delivery_concurrency.get(),
    )?;
    let deliveries = store
        .claim_due_deliveries(limit, settings.lease_duration)
        .await?;
    let count = deliveries.len();
    if deliveries.is_empty() {
        return Ok(0);
    }

    let max_attempts = u32::from(settings.max_attempts.get());
    let policy = DeliveryPolicy::new(
        max_attempts,
        Duration::from_secs(1),
        settings.max_retry_delay,
    )
    .map_err(|_error| StoreError::InvalidArgument {
        field: "delivery_policy",
        reason: "worker settings do not form a valid delivery policy",
    })?;

    stream::iter(deliveries)
        .for_each_concurrent(
            Some(settings.delivery_concurrency.get()),
            |delivery| async move {
                let event_id = delivery.event_id;
                if let Err(error) = deliver_and_complete(
                    store,
                    dm,
                    delivery,
                    policy,
                    settings.lease_duration,
                )
                .await
                {
                    tracing::error!(
                        %event_id,
                        error_code = error.diagnostic_code(),
                        "failed to renew, deliver, or complete claimed DM work; lease recovery will retry"
                    );
                }
            },
        )
        .await;
    Ok(count)
}

fn delivery_claim_limit(batch_size: usize, delivery_concurrency: usize) -> Result<u32, StoreError> {
    u32::try_from(batch_size.min(delivery_concurrency)).map_err(|_| StoreError::NumericRange {
        field: "worker_batch_size",
    })
}

async fn deliver_and_complete(
    store: &PostgresStore,
    dm: &DmClient,
    delivery: ClaimedDelivery,
    policy: DeliveryPolicy,
    lease_duration: Duration,
) -> Result<(), StoreError> {
    let event_id = delivery.event_id;
    let lease_token = delivery.lease_token;
    let operation = async {
        let attempt = attempt_delivery(dm, delivery, policy).await;
        store.complete_delivery(&attempt).await
    };

    run_with_lease_renewal(store, event_id, lease_token, lease_duration, operation).await
}

async fn run_with_lease_renewal<T>(
    store: &PostgresStore,
    event_id: crate::domain::EventId,
    lease_token: uuid::Uuid,
    lease_duration: Duration,
    operation: impl Future<Output = Result<T, StoreError>>,
) -> Result<T, StoreError> {
    store
        .extend_delivery_lease(event_id, lease_token, lease_duration)
        .await?;

    let renewal_interval = lease_renewal_interval(lease_duration);
    let renewal_sleep = tokio::time::sleep(renewal_interval);
    tokio::pin!(operation);
    tokio::pin!(renewal_sleep);

    loop {
        tokio::select! {
            biased;
            result = &mut operation => return result,
            () = &mut renewal_sleep => {
                store
                    .extend_delivery_lease(event_id, lease_token, lease_duration)
                    .await?;
                renewal_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + renewal_interval);
            }
        }
    }
}

fn lease_renewal_interval(lease_duration: Duration) -> Duration {
    lease_duration / 3
}

async fn attempt_delivery(
    dm: &DmClient,
    delivery: ClaimedDelivery,
    policy: DeliveryPolicy,
) -> DeliveryAttempt {
    let ClaimedDelivery {
        event_id,
        request_body,
        attempt_number,
        lease_token,
        ..
    } = delivery;
    let result = serde_json::from_slice::<SystemEvent>(&request_body);
    let outcome = match result {
        Ok(event) if event.event_id == event_id => {
            let dm_outcome = dm.send_serialized(event_id, &request_body).await;
            map_dm_outcome(&dm_outcome, attempt_number, policy)
        }
        Ok(_) => {
            tracing::error!(
                event_id = %event_id,
                "DM outbox body event ID does not match its row"
            );
            StoreDeliveryOutcome::Failed {
                reason: "outbox_event_id_mismatch".to_owned(),
                http_status: None,
            }
        }
        Err(_error) => {
            tracing::error!(
                event_id = %event_id,
                "corrupt DM outbox payload"
            );
            StoreDeliveryOutcome::Failed {
                reason: "outbox_payload_invalid".to_owned(),
                http_status: None,
            }
        }
    };

    DeliveryAttempt {
        event_id,
        lease_token,
        outcome,
    }
}

fn map_dm_outcome(
    outcome: &DmDeliveryOutcome,
    attempt_number: u32,
    policy: DeliveryPolicy,
) -> StoreDeliveryOutcome {
    match outcome {
        DmDeliveryOutcome::Accepted => StoreDeliveryOutcome::Delivered,
        DmDeliveryOutcome::Terminal { reason } => StoreDeliveryOutcome::Failed {
            reason: reason.to_string(),
            http_status: http_status(*reason),
        },
        DmDeliveryOutcome::Retryable {
            retry_after,
            reason,
        } => match policy.classify_transport_failure(attempt_number) {
            DeliveryDecision::Failed => StoreDeliveryOutcome::Failed {
                reason: "dm_attempt_budget_exhausted".to_owned(),
                http_status: http_status(*reason),
            },
            DeliveryDecision::Retry { delay_ceiling } => {
                let retry_after = (*retry_after).unwrap_or_else(|| full_jitter(delay_ceiling));
                StoreDeliveryOutcome::Retry {
                    retry_after,
                    reason: reason.to_string(),
                    http_status: http_status(*reason),
                }
            }
            DeliveryDecision::Delivered => StoreDeliveryOutcome::Failed {
                reason: "delivery_policy_invalid_transition".to_owned(),
                http_status: http_status(*reason),
            },
        },
    }
}

const fn http_status(reason: DeliveryFailureReason) -> Option<u16> {
    match reason {
        DeliveryFailureReason::HttpStatus(status) => Some(status),
        DeliveryFailureReason::RequestTooLarge
        | DeliveryFailureReason::Timeout
        | DeliveryFailureReason::Connection
        | DeliveryFailureReason::Transport => None,
    }
}

fn full_jitter(ceiling: std::time::Duration) -> std::time::Duration {
    let ceiling_millis = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
    if ceiling_millis == 0 {
        return std::time::Duration::ZERO;
    }
    let mut random = [0_u8; 8];
    if getrandom::fill(&mut random).is_err() {
        return ceiling;
    }
    let sample = u64::from_le_bytes(random);
    std::time::Duration::from_millis(sample % ceiling_millis.saturating_add(1))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        domain::DeliveryPolicy,
        infrastructure::{
            dm::{DeliveryFailureReason, DeliveryOutcome as DmDeliveryOutcome},
            postgres::{DeliveryOutcome as StoreDeliveryOutcome, StoreError},
        },
    };

    use super::{delivery_claim_limit, full_jitter, lease_renewal_interval, map_dm_outcome};

    fn policy(max_attempts: u32) -> DeliveryPolicy {
        match DeliveryPolicy::new(
            max_attempts,
            Duration::from_secs(1),
            Duration::from_secs(60),
        ) {
            Ok(policy) => policy,
            Err(error) => panic!("test delivery policy must be valid: {error}"),
        }
    }

    #[test]
    fn jitter_stays_inside_the_ceiling() {
        let ceiling = Duration::from_secs(5);
        for _ in 0..1_000 {
            assert!(full_jitter(ceiling) <= ceiling);
        }
    }

    #[test]
    fn claim_never_leases_more_work_than_can_start_immediately() -> Result<(), StoreError> {
        assert_eq!(delivery_claim_limit(100, 16)?, 16);
        assert_eq!(delivery_claim_limit(8, 16)?, 8);
        Ok(())
    }

    #[test]
    fn lease_is_renewed_with_two_thirds_of_its_duration_remaining() {
        assert_eq!(
            lease_renewal_interval(Duration::from_secs(60)),
            Duration::from_secs(20)
        );
    }

    #[test]
    fn terminal_http_failure_preserves_status() {
        let outcome = DmDeliveryOutcome::Terminal {
            reason: DeliveryFailureReason::HttpStatus(400),
        };

        assert_eq!(
            map_dm_outcome(&outcome, 1, policy(20)),
            StoreDeliveryOutcome::Failed {
                reason: "dm_http_400".to_owned(),
                http_status: Some(400),
            }
        );
    }

    #[test]
    fn retryable_failure_becomes_dead_letter_at_attempt_budget() {
        let outcome = DmDeliveryOutcome::Retryable {
            retry_after: None,
            reason: DeliveryFailureReason::Timeout,
        };

        assert_eq!(
            map_dm_outcome(&outcome, 2, policy(2)),
            StoreDeliveryOutcome::Failed {
                reason: "dm_attempt_budget_exhausted".to_owned(),
                http_status: None,
            }
        );
    }

    #[test]
    fn retry_outcome_keeps_only_a_database_relative_delay() {
        let outcome = DmDeliveryOutcome::Retryable {
            retry_after: Some(Duration::from_secs(7)),
            reason: DeliveryFailureReason::HttpStatus(429),
        };

        assert_eq!(
            map_dm_outcome(&outcome, 1, policy(20)),
            StoreDeliveryOutcome::Retry {
                retry_after: Duration::from_secs(7),
                reason: "dm_http_429".to_owned(),
                http_status: Some(429),
            }
        );
    }
}
