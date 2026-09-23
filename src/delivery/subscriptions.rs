//! Explicit Carbon receiving interest for future verified Hook events.
//!
//! Public binding metadata excludes its encrypted current Carbon access token.
//! IAM authorization is refreshed at bind, publication and raw-event hydration.
//! Already accepted Ting references may survive later access changes.

use secrecy::SecretString;
use serde::Serialize;
use sqlx::{FromRow, Postgres, Transaction};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    domain::{Action, ActorKind, AuthorizationContext, EventRecord, SiliconId, authorize},
    infrastructure::{
        crypto::SecretCipher,
        postgres::{PostgresStore, StoreError, enqueue_ting_for_subscription},
    },
};

/// Maximum number of Carbon observers receiving each future Silicon event.
pub const MAX_OBSERVERS_PER_SILICON: i64 = 100;

/// Public metadata for the caller's own receiving interest.
#[derive(Clone, Debug, FromRow, Serialize)]
pub struct ReceivingSubscription {
    /// Stable identity of this binding, distinct after unsubscribe/re-subscribe.
    pub id: Uuid,
    /// Organization whose Silicon is observed.
    pub org_id: String,
    /// Silicon whose future events are observed.
    pub silicon_id: String,
    /// Authenticated Carbon receiving the compact Ting references.
    pub recipient_id: String,
    /// Time this receiving interest began; earlier events are never backfilled.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Bounded failures from self-subscription management.
#[derive(Debug, Error)]
pub enum SubscriptionError {
    /// Only Carbons need explicit observer bindings.
    #[error("only Carbon actors can create receiving subscriptions")]
    CarbonRequired,
    /// The target is not visible under current IAM authorization.
    #[error("Silicon is not visible")]
    NotVisible,
    /// Fanout is bounded for every Silicon.
    #[error("receiving subscription limit reached")]
    LimitReached,
    /// Current authority could not be encrypted safely.
    #[error("receiving authority is unavailable")]
    AuthorityUnavailable,
    /// Persistence or the environment lifecycle fence rejected the operation.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for SubscriptionError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(StoreError::from(error))
    }
}

/// Checks the caller's current IAM context before any remote grant or database I/O.
///
/// # Errors
/// Returns a Carbon-only or target-visibility failure.
pub fn authorize_subscription(
    authorization: &AuthorizationContext,
    silicon: &SiliconId,
) -> Result<(), SubscriptionError> {
    if authorization.actor().kind() != ActorKind::Carbon {
        return Err(SubscriptionError::CarbonRequired);
    }
    if authorization.actor().id().as_str() == silicon.as_str()
        || !authorize(authorization, Action::ReadEvents, silicon).is_allowed()
    {
        return Err(SubscriptionError::NotVisible);
    }
    Ok(())
}

/// Reads only the currently authorized Carbon's own receiving interest.
///
/// # Errors
/// Returns authorization or database failures.
pub async fn get(
    store: &PostgresStore,
    authorization: &AuthorizationContext,
    silicon: &SiliconId,
) -> Result<Option<ReceivingSubscription>, SubscriptionError> {
    authorize_subscription(authorization, silicon)?;
    Ok(sqlx::query_as(
        "SELECT id, org_id, silicon_id, recipient_id, created_at
         FROM hook_private.ting_recipient_bindings
         WHERE environment_id = hook_private.environment_id()
           AND hook_private.environment_is_available()
           AND org_id = $1 AND silicon_id = $2 AND recipient_id = $3",
    )
    .bind(authorization.organization_id().as_str())
    .bind(silicon.as_str())
    .bind(authorization.actor().id().as_str())
    .fetch_optional(store.pool())
    .await?)
}

/// Records the caller's receiving interest after its Ting recipient grant succeeds.
///
/// The HTTP boundary must grant Ting using this caller's live Hook access token
/// first. Event acceptance and subscription changes share the Silicon sequence
/// lock, making the start boundary precise and concurrent fanout limits safe.
/// This low-level method leaves authority unset. Production callers use
/// `ObserverAuthorities::subscribe` to retain encrypted current access authority.
/// It never queues historical events or takes ownership of a refresh family.
///
/// # Errors
/// Returns current authorization, fanout-limit, or database failures.
pub async fn subscribe(
    store: &PostgresStore,
    authorization: &AuthorizationContext,
    silicon: &SiliconId,
) -> Result<ReceivingSubscription, SubscriptionError> {
    subscribe_with_authority(store, authorization, silicon, None).await
}

pub(super) async fn subscribe_with_authority(
    store: &PostgresStore,
    authorization: &AuthorizationContext,
    silicon: &SiliconId,
    authority: Option<(&SecretCipher, &SecretString)>,
) -> Result<ReceivingSubscription, SubscriptionError> {
    authorize_subscription(authorization, silicon)?;
    let mut transaction = store.pool().begin().await?;
    lock_stream(&mut transaction, silicon).await?;
    let existing = sqlx::query_as::<_, ReceivingSubscription>(
        "SELECT id, org_id, silicon_id, recipient_id, created_at
         FROM hook_private.ting_recipient_bindings
         WHERE org_id = $1 AND silicon_id = $2 AND recipient_id = $3",
    )
    .bind(authorization.organization_id().as_str())
    .bind(silicon.as_str())
    .bind(authorization.actor().id().as_str())
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(existing) = existing {
        if let Some((cipher, token)) = authority {
            let sealed = super::observer_authority::seal(cipher, existing.id, token)?;
            sqlx::query(
                "UPDATE hook_private.ting_recipient_bindings
                SET encrypted_authority=$2, authority_version=$3 WHERE id=$1",
            )
            .bind(existing.id)
            .bind(sealed)
            .bind(Uuid::now_v7())
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        return Ok(existing);
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM hook_private.ting_recipient_bindings
         WHERE org_id = $1 AND silicon_id = $2",
    )
    .bind(authorization.organization_id().as_str())
    .bind(silicon.as_str())
    .fetch_one(&mut *transaction)
    .await?;
    if count >= MAX_OBSERVERS_PER_SILICON {
        return Err(SubscriptionError::LimitReached);
    }
    let id = Uuid::now_v7();
    let (sealed, version) = if let Some((cipher, token)) = authority {
        (
            Some(super::observer_authority::seal(cipher, id, token)?),
            Some(Uuid::now_v7()),
        )
    } else {
        (None, None)
    };
    let binding = sqlx::query_as(
        "INSERT INTO hook_private.ting_recipient_bindings (id, org_id, silicon_id, recipient_id,
            encrypted_authority, authority_version)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, org_id, silicon_id, recipient_id, created_at",
    )
    .bind(id)
    .bind(authorization.organization_id().as_str())
    .bind(silicon.as_str())
    .bind(authorization.actor().id().as_str())
    .bind(sealed)
    .bind(version)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(binding)
}

/// Deletes the caller's interest and its queued observer sends atomically.
///
/// The primary Silicon send is never linked to this binding. Ting may already
/// have accepted an in-flight send; unsubscribe cannot retract that notification.
/// Removing one's own interest requires a current Carbon identity in the org,
/// but not continued visibility of the Silicon whose events are being stopped.
///
/// # Errors
/// Returns current authorization or database failures.
pub async fn unsubscribe(
    store: &PostgresStore,
    authorization: &AuthorizationContext,
    silicon: &SiliconId,
) -> Result<(), SubscriptionError> {
    if authorization.actor().kind() != ActorKind::Carbon {
        return Err(SubscriptionError::CarbonRequired);
    }
    let mut transaction = store.pool().begin().await?;
    // Existing interests already have a stream lock row. An unsubscribe for an
    // unknown or inaccessible target must not create fresh target state.
    sqlx::query(
        "SELECT last_sequence FROM hook_private.delivery_sequences
        WHERE environment_id=hook_private.environment_id() AND silicon_id=$1 FOR UPDATE",
    )
    .bind(silicon.as_str())
    .fetch_optional(&mut *transaction)
    .await?;
    sqlx::query(
        "DELETE FROM hook_private.ting_recipient_bindings
         WHERE org_id = $1 AND silicon_id = $2 AND recipient_id = $3",
    )
    .bind(authorization.organization_id().as_str())
    .bind(silicon.as_str())
    .bind(authorization.actor().id().as_str())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn lock_stream(
    transaction: &mut Transaction<'_, Postgres>,
    silicon: &SiliconId,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO hook_private.delivery_sequences (silicon_id, last_sequence)
         VALUES ($1, 0) ON CONFLICT (environment_id, silicon_id) DO NOTHING",
    )
    .bind(silicon.as_str())
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "SELECT last_sequence FROM hook_private.delivery_sequences
         WHERE environment_id = hook_private.environment_id() AND silicon_id = $1 FOR UPDATE",
    )
    .bind(silicon.as_str())
    .fetch_one(&mut **transaction)
    .await?;
    Ok(())
}

/// Enqueues all current observer sends inside an already sequence-locked acceptance.
///
/// Any failed reference or insert aborts the caller's entire event acceptance.
pub(crate) async fn enqueue_observers(
    transaction: &mut Transaction<'_, Postgres>,
    event: &EventRecord,
    app_id: &str,
    environment_id: Uuid,
    generation: i64,
) -> Result<(), StoreError> {
    let bindings = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, recipient_id FROM hook_private.ting_recipient_bindings
         WHERE environment_id = $1 AND org_id = $2 AND silicon_id = $3
           AND environment_id = hook_private.environment_id()
           AND hook_private.environment_is_available()
         ORDER BY id LIMIT $4",
    )
    .bind(environment_id)
    .bind(event.organization_id().as_str())
    .bind(event.silicon_id().as_str())
    .bind(MAX_OBSERVERS_PER_SILICON + 1)
    .fetch_all(&mut **transaction)
    .await?;
    if bindings.len() > usize::try_from(MAX_OBSERVERS_PER_SILICON).unwrap_or(100) {
        return Err(StoreError::CorruptData {
            entity: "ting_recipient_bindings",
            reason: "observer limit exceeded".to_owned(),
        });
    }
    for (id, recipient) in bindings {
        let body = super::prepare_event(
            app_id,
            event,
            &recipient,
            environment_id,
            generation,
            crate::infrastructure::ting::TingDeliveryMode::Ordinary,
        )
        .map_err(|error| StoreError::CorruptData {
            entity: "ting_outbox",
            reason: error.to_string(),
        })?;
        enqueue_ting_for_subscription(transaction, event, &recipient, &body, id).await?;
    }
    Ok(())
}
