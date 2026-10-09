//! Applying Silicon Accounts webhook events, deduplicated by `event_id`.
//!
//! Every event is applied in one transaction with its dedupe row, so a failed
//! application is retried by Accounts and a repeated delivery changes nothing.
//! Events arrive in any order: id and custodian changes apply only when newer
//! than what is stored (`occurred_at`), profile updates only with a higher
//! `version`, and revocation instants only move forward.

use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    PostgresStore, StoreError,
    accounts::{remember_public_id, upsert_known_account},
};
use crate::domain::{AccountUuid, ActorKind, PublicId};

/// A verified Accounts event reduced to what Hook acts on.
#[derive(Clone, Debug)]
pub struct AccountsEvent {
    /// Dedupe key; retries and replays reuse it.
    pub event_id: String,
    /// Event type as received.
    pub event_type: String,
    /// When the change happened at Accounts.
    pub occurred_at: OffsetDateTime,
    /// What changed.
    pub change: AccountsChange,
}

/// The effect of one Accounts event.
#[derive(Clone, Debug)]
pub enum AccountsChange {
    /// `account.id_changed`.
    IdChanged {
        /// Account.
        uuid: AccountUuid,
        /// Carbon or Silicon, when the event says.
        kind: Option<ActorKind>,
        /// The previous id.
        old_id: Option<PublicId>,
        /// The new id.
        new_id: PublicId,
    },
    /// `account.updated`.
    Updated {
        /// Account.
        uuid: AccountUuid,
        /// Carbon or Silicon.
        kind: ActorKind,
        /// The id at this version.
        public_id: Option<PublicId>,
        /// Display name at this version.
        display_name: Option<String>,
        /// Photo at this version.
        pfp_url: Option<String>,
        /// A Silicon's custodian at this version.
        custodian: Option<(AccountUuid, Option<PublicId>)>,
        /// Monotonic account version.
        version: i64,
    },
    /// `silicon.custodian_changed`.
    CustodianChanged {
        /// The Silicon.
        uuid: AccountUuid,
        /// The previous custodian.
        from: Option<AccountUuid>,
        /// The new custodian.
        to: Option<(AccountUuid, Option<PublicId>)>,
    },
    /// `membership.signed_out`.
    SignedOut {
        /// Account.
        uuid: AccountUuid,
        /// Why; `app_revoked` means Hook itself revoked one sign-in.
        reason: Option<String>,
    },
    /// `membership.access_removed`.
    AccessRemoved {
        /// Account.
        uuid: AccountUuid,
    },
    /// `account.deleted`.
    Deleted {
        /// Account.
        uuid: AccountUuid,
    },
    /// `ping` or an event type Hook does not act on.
    Nothing,
}

/// What applying an event did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventOutcome {
    /// The event was applied now.
    Applied,
    /// The event id was applied before; nothing changed.
    Duplicate,
}

impl AccountsChange {
    fn account(&self) -> Option<&AccountUuid> {
        match self {
            Self::IdChanged { uuid, .. }
            | Self::Updated { uuid, .. }
            | Self::CustodianChanged { uuid, .. }
            | Self::SignedOut { uuid, .. }
            | Self::AccessRemoved { uuid }
            | Self::Deleted { uuid } => Some(uuid),
            Self::Nothing => None,
        }
    }
}

type Tx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

impl PostgresStore {
    /// Applies one verified Accounts event exactly once.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure; nothing is recorded then, so the retry
    /// Accounts sends applies it again.
    pub async fn apply_accounts_event(
        &self,
        event: &AccountsEvent,
    ) -> Result<EventOutcome, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let fresh = sqlx::query_scalar::<_, String>(
            "INSERT INTO hook_private.accounts_events (event_id, event_type, account_uuid, occurred_at)
             VALUES ($1, $2, $3, $4) ON CONFLICT (event_id) DO NOTHING RETURNING event_id",
        )
        .bind(&event.event_id)
        .bind(&event.event_type)
        .bind(event.change.account().map(AccountUuid::as_str))
        .bind(event.occurred_at)
        .fetch_optional(&mut *transaction)
        .await?
        .is_some();
        if !fresh {
            return Ok(EventOutcome::Duplicate);
        }
        let at = event.occurred_at;
        match &event.change {
            AccountsChange::IdChanged {
                uuid,
                kind,
                old_id,
                new_id,
            } => id_changed(&mut transaction, uuid, *kind, old_id.as_ref(), new_id, at).await?,
            AccountsChange::Updated {
                uuid,
                kind,
                public_id,
                display_name,
                pfp_url,
                custodian,
                version,
            } => {
                updated(
                    &mut transaction,
                    &Profile {
                        uuid,
                        kind: *kind,
                        public_id: public_id.as_ref(),
                        display_name: display_name.as_deref(),
                        pfp_url: pfp_url.as_deref(),
                        custodian: custodian.as_ref(),
                        version: *version,
                    },
                    at,
                )
                .await?;
            }
            AccountsChange::CustodianChanged { uuid, from, to } => {
                custodian_changed(&mut transaction, uuid, from.as_ref(), to.as_ref(), at).await?;
            }
            AccountsChange::SignedOut { uuid, reason } => {
                // Hook revoking one of its own sign-ins (one machine's logout,
                // the web's sign-out) ends only that sign-in, at Accounts.
                if reason.as_deref() != Some("app_revoked") {
                    revoke(&mut transaction, uuid, at).await?;
                }
            }
            AccountsChange::AccessRemoved { uuid } => revoke(&mut transaction, uuid, at).await?,
            AccountsChange::Deleted { uuid } => deleted(&mut transaction, uuid, at).await?,
            AccountsChange::Nothing => {}
        }
        transaction.commit().await?;
        Ok(EventOutcome::Applied)
    }
}

async fn ensure_account(
    transaction: &mut Tx<'_>,
    uuid: &AccountUuid,
    kind: ActorKind,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO hook_private.accounts (uuid, kind) VALUES ($1, $2)
         ON CONFLICT (uuid) DO UPDATE SET kind = EXCLUDED.kind WHERE accounts.kind IS NULL",
    )
    .bind(uuid.as_str())
    .bind(kind.as_str())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn id_changed(
    transaction: &mut Tx<'_>,
    uuid: &AccountUuid,
    kind: Option<ActorKind>,
    old_id: Option<&PublicId>,
    new_id: &PublicId,
    at: OffsetDateTime,
) -> Result<(), StoreError> {
    ensure_account(transaction, uuid, kind.unwrap_or_else(|| new_id.kind())).await?;
    sqlx::query(
        "UPDATE hook_private.accounts SET public_id = $2, public_id_at = $3, updated_at = clock_timestamp()
         WHERE uuid = $1 AND deleted_at IS NULL AND (public_id_at IS NULL OR public_id_at < $3)",
    )
    .bind(uuid.as_str())
    .bind(new_id.as_str())
    .bind(at)
    .execute(&mut **transaction)
    .await?;
    // Both ids keep working in URLs a provider already holds.
    remember_public_id(transaction, uuid, new_id).await?;
    if let Some(old_id) = old_id {
        remember_public_id(transaction, uuid, old_id).await?;
    }
    Ok(())
}

struct Profile<'a> {
    uuid: &'a AccountUuid,
    kind: ActorKind,
    public_id: Option<&'a PublicId>,
    display_name: Option<&'a str>,
    pfp_url: Option<&'a str>,
    custodian: Option<&'a (AccountUuid, Option<PublicId>)>,
    version: i64,
}

async fn updated(
    transaction: &mut Tx<'_>,
    profile: &Profile<'_>,
    at: OffsetDateTime,
) -> Result<(), StoreError> {
    ensure_account(transaction, profile.uuid, profile.kind).await?;
    let newer = sqlx::query_scalar::<_, bool>(
        "UPDATE hook_private.accounts
         SET display_name = $2, pfp_url = $3, profile_version = $4, updated_at = clock_timestamp()
         WHERE uuid = $1 AND deleted_at IS NULL AND profile_version < $4
         RETURNING true",
    )
    .bind(profile.uuid.as_str())
    .bind(
        profile
            .display_name
            .map(|name| name.chars().take(200).collect::<String>()),
    )
    .bind(profile.pfp_url.filter(|url| url.len() <= 2048))
    .bind(profile.version)
    .fetch_optional(&mut **transaction)
    .await?
    .is_some();
    if let Some(public_id) = profile.public_id {
        upsert_known_account(transaction, profile.uuid, profile.kind, Some(public_id), at).await?;
    }
    if newer && profile.kind == ActorKind::Silicon {
        if let Some((custodian, custodian_id)) = profile.custodian {
            upsert_known_account(
                transaction,
                custodian,
                ActorKind::Carbon,
                custodian_id.as_ref(),
                at,
            )
            .await?;
        }
        sqlx::query(
            "UPDATE hook_private.accounts
             SET custodian_uuid = $2, custodian_checked_at = clock_timestamp()
             WHERE uuid = $1 AND (custodian_changed_at IS NULL OR custodian_changed_at <= $3)",
        )
        .bind(profile.uuid.as_str())
        .bind(profile.custodian.map(|(custodian, _)| custodian.as_str()))
        .bind(at)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn custodian_changed(
    transaction: &mut Tx<'_>,
    uuid: &AccountUuid,
    from: Option<&AccountUuid>,
    to: Option<&(AccountUuid, Option<PublicId>)>,
    at: OffsetDateTime,
) -> Result<(), StoreError> {
    ensure_account(transaction, uuid, ActorKind::Silicon).await?;
    if let Some((custodian, custodian_id)) = to {
        upsert_known_account(
            transaction,
            custodian,
            ActorKind::Carbon,
            custodian_id.as_ref(),
            at,
        )
        .await?;
    }
    let applied = sqlx::query_scalar::<_, bool>(
        "UPDATE hook_private.accounts
         SET custodian_uuid = $2, custodian_changed_at = $3, custodian_checked_at = clock_timestamp(),
             updated_at = clock_timestamp()
         WHERE uuid = $1 AND kind = 'silicon'
           AND (custodian_changed_at IS NULL OR custodian_changed_at < $3)
         RETURNING true",
    )
    .bind(uuid.as_str())
    .bind(to.map(|(custodian, _)| custodian.as_str()))
    .bind(at)
    .fetch_optional(&mut **transaction)
    .await?
    .is_some();
    // The previous custodian stops receiving the Silicon's events unless it
    // still has access through an explicit grant.
    if applied && let Some(previous) = from {
        sqlx::query(
            "DELETE FROM hook_private.observer_subscriptions s
             WHERE s.silicon_uuid = $1 AND s.recipient_uuid = $2
               AND NOT EXISTS (SELECT 1 FROM hook_private.silicon_grants g
                               WHERE g.silicon_uuid = s.silicon_uuid AND g.grantee_uuid = s.recipient_uuid)
               AND $2 IS DISTINCT FROM $3",
        )
        .bind(uuid.as_str())
        .bind(previous.as_str())
        .bind(to.map(|(custodian, _)| custodian.as_str()))
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

/// Ends the account's sign-ins as of `at` and the delivery work Hook holds for
/// it: its observer subscriptions (and their queued sends) go. An account Hook
/// has not met yet is recorded too, so its earlier tokens never work here.
async fn revoke(
    transaction: &mut Tx<'_>,
    uuid: &AccountUuid,
    at: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO hook_private.accounts (uuid, revoked_before) VALUES ($1, $2)
         ON CONFLICT (uuid) DO UPDATE SET
             revoked_before = GREATEST(COALESCE(accounts.revoked_before, $2), $2),
             updated_at = clock_timestamp()",
    )
    .bind(uuid.as_str())
    .bind(at)
    .execute(&mut **transaction)
    .await?;
    sqlx::query("DELETE FROM hook_private.observer_subscriptions WHERE recipient_uuid = $1")
        .bind(uuid.as_str())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

/// A deleted account never comes back. Its personal details are dropped, its
/// grants, allow-list entries and observer subscriptions go, and a deleted
/// Silicon's hooks are soft-deleted at once (purged after the usual 45 days;
/// ingress answers `410 account_deleted`). Other accounts' data stays intact.
async fn deleted(
    transaction: &mut Tx<'_>,
    uuid: &AccountUuid,
    at: OffsetDateTime,
) -> Result<(), StoreError> {
    let kind = sqlx::query_scalar::<_, Option<String>>(
        "INSERT INTO hook_private.accounts (uuid, deleted_at, revoked_before) VALUES ($1, $2, $2)
         ON CONFLICT (uuid) DO UPDATE SET
             deleted_at = COALESCE(accounts.deleted_at, $2), public_id = NULL,
             display_name = NULL, pfp_url = NULL,
             revoked_before = GREATEST(COALESCE(accounts.revoked_before, $2), $2),
             updated_at = clock_timestamp()
         RETURNING kind",
    )
    .bind(uuid.as_str())
    .bind(at)
    .fetch_one(&mut **transaction)
    .await?;
    for statement in [
        "DELETE FROM hook_private.silicon_grants WHERE silicon_uuid = $1 OR grantee_uuid = $1",
        "DELETE FROM hook_private.silicon_allowances WHERE silicon_uuid = $1 OR allowed_uuid = $1",
        "DELETE FROM hook_private.observer_subscriptions WHERE silicon_uuid = $1 OR recipient_uuid = $1",
    ] {
        sqlx::query(statement)
            .bind(uuid.as_str())
            .execute(&mut **transaction)
            .await?;
    }
    if kind.as_deref() != Some("carbon") {
        let hooks = sqlx::query_scalar::<_, Uuid>(
            "UPDATE hook.hooks SET disabled_at = NULL,
                 deleted_at = GREATEST(created_at, clock_timestamp()), updated_at = clock_timestamp()
             WHERE silicon_uuid = $1 AND deleted_at IS NULL RETURNING id",
        )
        .bind(uuid.as_str())
        .fetch_all(&mut **transaction)
        .await?;
        sqlx::query(
            "INSERT INTO hook_private.audit_log (
                 id, occurred_at, action, silicon_id, silicon_uuid, hook_id,
                 actor_kind, actor_id, actor_uuid, request_id
             )
             SELECT audit.id, clock_timestamp(), 'account.deleted', hook.silicon_id, $1, hook.id,
                    'silicon', $1, $1, NULL
             FROM unnest($2::uuid[], $3::uuid[]) AS audit(hook_id, id)
             JOIN hook.hooks AS hook ON hook.id = audit.hook_id",
        )
        .bind(uuid.as_str())
        .bind(&hooks)
        .bind(hooks.iter().map(|_| Uuid::now_v7()).collect::<Vec<_>>())
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}
