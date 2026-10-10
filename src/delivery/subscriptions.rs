//! Carbons observing a Silicon: copies of its future events through Ting.
//!
//! A Carbon with access to a Silicon's hooks (its custodian, or a view or
//! manage grantee) may ask for copies of the Silicon's future events. Access is
//! checked when subscribing and again inside every event acceptance, and the
//! subscription is removed when the grant is revoked, the custodian changes
//! away, or the Carbon signs out, removes access or is deleted. Earlier events
//! are never backfilled.

use serde::Serialize;
use sqlx::{FromRow, Postgres, Transaction};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{ReferencedSilicon, prepare_event};
use crate::{
    domain::{AccountUuid, EventRecord},
    infrastructure::{
        postgres::{PostgresStore, StoreError, enqueue_ting},
        ting::{TingDeliveryMode, TingRecipient},
    },
};

/// Maximum number of observers receiving each future Silicon event.
pub const MAX_OBSERVERS_PER_SILICON: i64 = 100;

/// One Carbon's receiving interest in a Silicon's events.
#[derive(Clone, Debug, FromRow, Serialize)]
pub struct ObserverSubscription {
    /// Stable identity of this subscription, distinct after unsubscribe/re-subscribe.
    pub id: Uuid,
    /// Silicon whose future events are observed.
    pub silicon_uuid: String,
    /// Carbon receiving the compact Ting references.
    pub recipient_uuid: String,
    /// When the interest began; earlier events are never backfilled.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Bounded failures from subscription management.
#[derive(Debug, Error)]
pub enum SubscriptionError {
    /// Fanout is bounded for every Silicon.
    #[error("this Silicon already has the maximum of 100 observers")]
    LimitReached,
    /// Persistence failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for SubscriptionError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(StoreError::from(error))
    }
}

/// Serializes subscription changes with event acceptance for one Silicon, so
/// a subscription starts exactly between two events.
async fn lock_observers(
    transaction: &mut Transaction<'_, Postgres>,
    silicon: &AccountUuid,
    exclusive: bool,
) -> Result<(), sqlx::Error> {
    let statement = if exclusive {
        "SELECT pg_advisory_xact_lock(hashtext('hook.observers'), hashtext($1))"
    } else {
        "SELECT pg_advisory_xact_lock_shared(hashtext('hook.observers'), hashtext($1))"
    };
    sqlx::query(statement)
        .bind(silicon.as_str())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

/// Reads one Carbon's subscription to a Silicon.
///
/// # Errors
/// Returns database failures.
pub async fn get(
    store: &PostgresStore,
    silicon: &AccountUuid,
    recipient: &AccountUuid,
) -> Result<Option<ObserverSubscription>, SubscriptionError> {
    Ok(sqlx::query_as(
        "SELECT id, silicon_uuid, recipient_uuid, created_at
         FROM hook_private.observer_subscriptions
         WHERE silicon_uuid = $1 AND recipient_uuid = $2",
    )
    .bind(silicon.as_str())
    .bind(recipient.as_str())
    .fetch_optional(store.pool())
    .await?)
}

/// Records a Carbon's interest; the caller already checked its access and
/// enrolled it with Ting.
///
/// # Errors
/// Returns the fanout limit or database failures.
pub async fn subscribe(
    store: &PostgresStore,
    silicon: &AccountUuid,
    recipient: &AccountUuid,
) -> Result<ObserverSubscription, SubscriptionError> {
    let mut transaction = store.pool().begin().await?;
    lock_observers(&mut transaction, silicon, true).await?;
    if let Some(existing) = sqlx::query_as::<_, ObserverSubscription>(
        "SELECT id, silicon_uuid, recipient_uuid, created_at
         FROM hook_private.observer_subscriptions
         WHERE silicon_uuid = $1 AND recipient_uuid = $2",
    )
    .bind(silicon.as_str())
    .bind(recipient.as_str())
    .fetch_optional(&mut *transaction)
    .await?
    {
        transaction.commit().await?;
        return Ok(existing);
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM hook_private.observer_subscriptions WHERE silicon_uuid = $1",
    )
    .bind(silicon.as_str())
    .fetch_one(&mut *transaction)
    .await?;
    if count >= MAX_OBSERVERS_PER_SILICON {
        return Err(SubscriptionError::LimitReached);
    }
    let subscription = sqlx::query_as(
        "INSERT INTO hook_private.observer_subscriptions (id, silicon_uuid, recipient_uuid)
         VALUES ($1, $2, $3)
         RETURNING id, silicon_uuid, recipient_uuid, created_at",
    )
    .bind(Uuid::now_v7())
    .bind(silicon.as_str())
    .bind(recipient.as_str())
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(subscription)
}

/// Removes a Carbon's interest and its queued observer sends (the outbox rows
/// cascade). Ting may already have accepted an in-flight send.
///
/// # Errors
/// Returns database failures.
pub async fn unsubscribe(
    store: &PostgresStore,
    silicon: &AccountUuid,
    recipient: &AccountUuid,
) -> Result<bool, SubscriptionError> {
    let mut transaction = store.pool().begin().await?;
    lock_observers(&mut transaction, silicon, true).await?;
    let deleted = sqlx::query(
        "DELETE FROM hook_private.observer_subscriptions
         WHERE silicon_uuid = $1 AND recipient_uuid = $2",
    )
    .bind(silicon.as_str())
    .bind(recipient.as_str())
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        == 1;
    transaction.commit().await?;
    Ok(deleted)
}

#[derive(FromRow)]
struct ObserverRow {
    id: Uuid,
    recipient_uuid: String,
    public_id: Option<String>,
}

/// Enqueues every current observer's copy inside an event acceptance.
///
/// Only observers who still have access (a grant, or being the custodian)
/// and whose account is not deleted receive a copy. Any failure aborts the
/// whole acceptance.
pub(crate) async fn enqueue_observers(
    transaction: &mut Transaction<'_, Postgres>,
    event: &EventRecord,
    silicon_uuid: &AccountUuid,
    silicon: &ReferencedSilicon,
    app_id: &str,
) -> Result<(), StoreError> {
    lock_observers(transaction, silicon_uuid, false).await?;
    let observers = sqlx::query_as::<_, ObserverRow>(
        "SELECT subscription.id, subscription.recipient_uuid, recipient.public_id
         FROM hook_private.observer_subscriptions AS subscription
         LEFT JOIN hook_private.accounts AS recipient ON recipient.uuid = subscription.recipient_uuid
         WHERE subscription.silicon_uuid = $1
           AND recipient.deleted_at IS NULL
           AND (EXISTS (SELECT 1 FROM hook_private.silicon_grants AS grant_row
                        WHERE grant_row.silicon_uuid = subscription.silicon_uuid
                          AND grant_row.grantee_uuid = subscription.recipient_uuid)
                OR EXISTS (SELECT 1 FROM hook_private.accounts AS owner
                           WHERE owner.uuid = subscription.silicon_uuid
                             AND owner.custodian_uuid = subscription.recipient_uuid))
         ORDER BY subscription.id LIMIT $2",
    )
    .bind(silicon_uuid.as_str())
    .bind(MAX_OBSERVERS_PER_SILICON + 1)
    .fetch_all(&mut **transaction)
    .await?;
    if observers.len() > usize::try_from(MAX_OBSERVERS_PER_SILICON).unwrap_or(100) {
        return Err(StoreError::CorruptData {
            entity: "observer_subscriptions",
            reason: "observer limit exceeded".to_owned(),
        });
    }
    for observer in observers {
        let recipient_uuid = AccountUuid::new(observer.recipient_uuid.clone())
            .map_err(|error| StoreError::corrupt("observer_subscriptions", error))?;
        let recipient = TingRecipient {
            uuid: observer.recipient_uuid,
            id: observer.public_id,
        };
        let body = prepare_event(
            app_id,
            event,
            silicon,
            &recipient,
            TingDeliveryMode::Ordinary,
        )
        .map_err(|error| StoreError::corrupt("ting_outbox", error))?;
        enqueue_ting(
            transaction,
            event,
            &recipient_uuid,
            &body,
            Some(observer.id),
        )
        .await?;
    }
    Ok(())
}
