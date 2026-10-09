//! What Hook knows about Silicon Accounts accounts: the cache keyed by uuid,
//! every public id seen per account, grants and allow-lists.

use sqlx::FromRow;
use time::OffsetDateTime;

use super::{PostgresStore, StoreError};
use crate::domain::{AccountUuid, ActorKind, GrantLevel, PublicId};

/// One cached account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountRecord {
    /// Permanent uuid.
    pub uuid: AccountUuid,
    /// Carbon or Silicon.
    pub kind: ActorKind,
    /// Current public id, when known and not deleted.
    pub public_id: Option<PublicId>,
    /// When the public id became current.
    pub public_id_at: Option<OffsetDateTime>,
    /// Display name, when an Accounts event shared it.
    pub display_name: Option<String>,
    /// Profile photo URL, when an Accounts event shared it.
    pub pfp_url: Option<String>,
    /// A Silicon's custodian.
    pub custodian_uuid: Option<AccountUuid>,
    /// When the custodian was last confirmed.
    pub custodian_checked_at: Option<OffsetDateTime>,
    /// Tokens issued before this instant are refused.
    pub revoked_before: Option<OffsetDateTime>,
    /// Deletion time.
    pub deleted_at: Option<OffsetDateTime>,
}

/// What Silicon Accounts said about an account at one moment.
#[derive(Clone, Debug)]
pub struct AccountView {
    /// Permanent uuid.
    pub uuid: AccountUuid,
    /// Carbon or Silicon.
    pub kind: ActorKind,
    /// Current public id.
    pub public_id: Option<PublicId>,
    /// A Silicon's custodian, `None` while a self-created Silicon waits for one.
    pub custodian: Option<(AccountUuid, Option<PublicId>)>,
}

/// An explicit grant on a Silicon's hooks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantRecord {
    /// The Silicon whose hooks are shared.
    pub silicon_uuid: AccountUuid,
    /// Who received access.
    pub grantee_uuid: AccountUuid,
    /// Access level.
    pub level: GrantLevel,
    /// Who granted it (the Silicon or its custodian).
    pub granted_by_uuid: AccountUuid,
    /// First granted.
    pub created_at: OffsetDateTime,
    /// Last changed.
    pub updated_at: OffsetDateTime,
}

/// An account a Silicon accepts shares from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowRecord {
    /// The Silicon.
    pub silicon_uuid: AccountUuid,
    /// The allowed account.
    pub allowed_uuid: AccountUuid,
    /// Who added it (the Silicon or its custodian).
    pub added_by_uuid: AccountUuid,
    /// When it was added.
    pub created_at: OffsetDateTime,
}

#[derive(FromRow)]
struct AccountRow {
    uuid: String,
    kind: String,
    public_id: Option<String>,
    public_id_at: Option<OffsetDateTime>,
    display_name: Option<String>,
    pfp_url: Option<String>,
    custodian_uuid: Option<String>,
    custodian_checked_at: Option<OffsetDateTime>,
    revoked_before: Option<OffsetDateTime>,
    deleted_at: Option<OffsetDateTime>,
}

const ACCOUNT_COLUMNS: &str = "uuid, kind, public_id, public_id_at, display_name, pfp_url, \
     custodian_uuid, custodian_checked_at, revoked_before, deleted_at";

impl TryFrom<AccountRow> for AccountRecord {
    type Error = StoreError;

    fn try_from(row: AccountRow) -> Result<Self, Self::Error> {
        Ok(Self {
            uuid: uuid(&row.uuid)?,
            kind: super::parse_actor_kind(&row.kind)?,
            public_id: row
                .public_id
                .map(PublicId::new)
                .transpose()
                .map_err(|error| StoreError::corrupt("account", error))?,
            public_id_at: row.public_id_at,
            display_name: row.display_name,
            pfp_url: row.pfp_url,
            custodian_uuid: row.custodian_uuid.as_deref().map(uuid).transpose()?,
            custodian_checked_at: row.custodian_checked_at,
            revoked_before: row.revoked_before,
            deleted_at: row.deleted_at,
        })
    }
}

#[derive(FromRow)]
pub(super) struct GrantRow {
    silicon_uuid: String,
    grantee_uuid: String,
    level: String,
    granted_by_uuid: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl TryFrom<GrantRow> for GrantRecord {
    type Error = StoreError;

    fn try_from(row: GrantRow) -> Result<Self, Self::Error> {
        Ok(Self {
            silicon_uuid: uuid(&row.silicon_uuid)?,
            grantee_uuid: uuid(&row.grantee_uuid)?,
            level: GrantLevel::parse(&row.level)
                .ok_or_else(|| StoreError::corrupt("silicon_grant", "unknown level"))?,
            granted_by_uuid: uuid(&row.granted_by_uuid)?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(FromRow)]
pub(super) struct AllowRow {
    silicon_uuid: String,
    allowed_uuid: String,
    added_by_uuid: String,
    created_at: OffsetDateTime,
}

impl TryFrom<AllowRow> for AllowRecord {
    type Error = StoreError;

    fn try_from(row: AllowRow) -> Result<Self, Self::Error> {
        Ok(Self {
            silicon_uuid: uuid(&row.silicon_uuid)?,
            allowed_uuid: uuid(&row.allowed_uuid)?,
            added_by_uuid: uuid(&row.added_by_uuid)?,
            created_at: row.created_at,
        })
    }
}

pub(super) fn uuid(value: &str) -> Result<AccountUuid, StoreError> {
    AccountUuid::new(value).map_err(|error| StoreError::corrupt("account uuid", error))
}

impl PostgresStore {
    /// Reads one cached account.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or a corrupt row.
    pub async fn account(&self, uuid: &AccountUuid) -> Result<Option<AccountRecord>, StoreError> {
        sqlx::query_as::<_, AccountRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {ACCOUNT_COLUMNS} FROM hook_private.accounts
             WHERE uuid = $1 AND kind IS NOT NULL"
        )))
        .bind(uuid.as_str())
        .fetch_optional(&self.pool)
        .await?
        .map(AccountRecord::try_from)
        .transpose()
    }

    /// Reads the account whose current public id is `id` (the freshest when a
    /// stale row still names an id that moved).
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or a corrupt row.
    pub async fn account_by_public_id(
        &self,
        id: &PublicId,
    ) -> Result<Option<AccountRecord>, StoreError> {
        sqlx::query_as::<_, AccountRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {ACCOUNT_COLUMNS} FROM hook_private.accounts
             WHERE public_id = $1 AND deleted_at IS NULL AND kind IS NOT NULL
             ORDER BY public_id_at DESC NULLS LAST, updated_at DESC LIMIT 1"
        )))
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await?
        .map(AccountRecord::try_from)
        .transpose()
    }

    /// Records what a verified access token says about its account. The
    /// public id moves forward only when the token is newer than what is
    /// stored, and every id seen is remembered for ingress.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or a corrupt row.
    pub async fn observe_token_account(
        &self,
        uuid: &AccountUuid,
        kind: ActorKind,
        public_id: Option<&PublicId>,
        issued_at: OffsetDateTime,
    ) -> Result<AccountRecord, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query_as::<_, AccountRow>(sqlx::AssertSqlSafe(format!(
            "INSERT INTO hook_private.accounts (uuid, kind, public_id, public_id_at)
             VALUES ($1, $2, $3, CASE WHEN $3::text IS NULL THEN NULL ELSE $4 END)
             ON CONFLICT (uuid) DO UPDATE SET
                 kind = COALESCE(accounts.kind, EXCLUDED.kind),
                 public_id = CASE
                     WHEN accounts.deleted_at IS NULL AND $3::text IS NOT NULL
                      AND (accounts.public_id_at IS NULL OR accounts.public_id_at < $4)
                     THEN $3 ELSE accounts.public_id END,
                 public_id_at = CASE
                     WHEN accounts.deleted_at IS NULL AND $3::text IS NOT NULL
                      AND (accounts.public_id_at IS NULL OR accounts.public_id_at < $4)
                     THEN $4 ELSE accounts.public_id_at END,
                 updated_at = clock_timestamp()
             RETURNING {ACCOUNT_COLUMNS}"
        )))
        .bind(uuid.as_str())
        .bind(kind.as_str())
        .bind(public_id.map(PublicId::as_str))
        .bind(issued_at)
        .fetch_one(&mut *transaction)
        .await?;
        if let Some(public_id) = public_id {
            remember_public_id(&mut transaction, uuid, public_id).await?;
        }
        transaction.commit().await?;
        AccountRecord::try_from(row)
    }

    /// Records an authoritative lookup answer taken at `at`.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or a corrupt row.
    pub async fn record_account_view(
        &self,
        view: &AccountView,
        at: OffsetDateTime,
    ) -> Result<AccountRecord, StoreError> {
        let mut transaction = self.pool.begin().await?;
        if let Some((custodian, custodian_id)) = &view.custodian {
            upsert_known_account(
                &mut transaction,
                custodian,
                ActorKind::Carbon,
                custodian_id.as_ref(),
                at,
            )
            .await?;
        }
        let row = sqlx::query_as::<_, AccountRow>(sqlx::AssertSqlSafe(format!(
            "INSERT INTO hook_private.accounts
                 (uuid, kind, public_id, public_id_at, custodian_uuid, custodian_checked_at)
             VALUES ($1, $2, $3, $4, $5, CASE WHEN $2 = 'silicon' THEN $4 END)
             ON CONFLICT (uuid) DO UPDATE SET
                 kind = COALESCE(accounts.kind, EXCLUDED.kind),
                 public_id = CASE WHEN accounts.deleted_at IS NULL
                     THEN COALESCE($3, accounts.public_id) ELSE accounts.public_id END,
                 public_id_at = CASE WHEN accounts.deleted_at IS NULL AND $3::text IS NOT NULL
                     THEN $4 ELSE accounts.public_id_at END,
                 custodian_uuid = CASE
                     WHEN accounts.deleted_at IS NOT NULL THEN accounts.custodian_uuid
                     WHEN COALESCE(accounts.kind, EXCLUDED.kind) = 'silicon' THEN $5 END,
                 custodian_checked_at = CASE
                     WHEN accounts.deleted_at IS NOT NULL THEN accounts.custodian_checked_at
                     WHEN COALESCE(accounts.kind, EXCLUDED.kind) = 'silicon' THEN $4 END,
                 updated_at = clock_timestamp()
             RETURNING {ACCOUNT_COLUMNS}"
        )))
        .bind(view.uuid.as_str())
        .bind(view.kind.as_str())
        .bind(view.public_id.as_ref().map(PublicId::as_str))
        .bind(at)
        .bind(
            view.custodian
                .as_ref()
                .map(|(custodian, _)| custodian.as_str()),
        )
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(public_id) = &view.public_id {
            remember_public_id(&mut transaction, &view.uuid, public_id).await?;
        }
        transaction.commit().await?;
        match row {
            Some(row) => AccountRecord::try_from(row),
            // A deleted account never comes back: report the stored state.
            None => self
                .account(&view.uuid)
                .await?
                .ok_or(StoreError::NotFound { entity: "account" }),
        }
    }

    /// Records that a lookup found the account deleted.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure.
    pub async fn record_account_deleted_by_lookup(
        &self,
        uuid: &AccountUuid,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO hook_private.accounts (uuid, deleted_at, revoked_before)
             VALUES ($1, $2, $2)
             ON CONFLICT (uuid) DO UPDATE SET
                 deleted_at = COALESCE(accounts.deleted_at, $2), public_id = NULL,
                 revoked_before = GREATEST(COALESCE(accounts.revoked_before, $2), $2),
                 updated_at = clock_timestamp()",
        )
        .bind(uuid.as_str())
        .bind(at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Lists the Silicons Hook knows `custodian` looks after.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or a corrupt row.
    pub async fn silicons_looked_after_by(
        &self,
        custodian: &AccountUuid,
    ) -> Result<Vec<AccountRecord>, StoreError> {
        sqlx::query_as::<_, AccountRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {ACCOUNT_COLUMNS} FROM hook_private.accounts
             WHERE custodian_uuid = $1 AND kind = 'silicon' AND deleted_at IS NULL
             ORDER BY public_id NULLS LAST, uuid LIMIT 1000"
        )))
        .bind(custodian.as_str())
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(AccountRecord::try_from)
        .collect()
    }

    /// Reads cached accounts by uuid (unknown ones are absent from the result).
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or a corrupt row.
    pub async fn accounts(&self, uuids: &[AccountUuid]) -> Result<Vec<AccountRecord>, StoreError> {
        let uuids = uuids.iter().map(AccountUuid::as_str).collect::<Vec<_>>();
        sqlx::query_as::<_, AccountRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {ACCOUNT_COLUMNS} FROM hook_private.accounts
             WHERE uuid = ANY($1) AND kind IS NOT NULL"
        )))
        .bind(&uuids)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(AccountRecord::try_from)
        .collect()
    }
}

pub(super) async fn remember_public_id(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    uuid: &AccountUuid,
    public_id: &PublicId,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO hook_private.account_ids (account_uuid, public_id) VALUES ($1, $2)
         ON CONFLICT (account_uuid, public_id) DO UPDATE SET last_seen_at = clock_timestamp()
         WHERE account_ids.last_seen_at < clock_timestamp() - INTERVAL '1 hour'",
    )
    .bind(uuid.as_str())
    .bind(public_id.as_str())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Makes sure a referenced account exists; a stored public id only moves
/// forward in time.
pub(super) async fn upsert_known_account(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    uuid: &AccountUuid,
    kind: ActorKind,
    public_id: Option<&PublicId>,
    at: OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO hook_private.accounts (uuid, kind, public_id, public_id_at)
         VALUES ($1, $2, $3, CASE WHEN $3::text IS NULL THEN NULL ELSE $4 END)
         ON CONFLICT (uuid) DO UPDATE SET
             kind = COALESCE(accounts.kind, EXCLUDED.kind),
             public_id = CASE
                 WHEN accounts.deleted_at IS NULL AND $3::text IS NOT NULL
                  AND (accounts.public_id_at IS NULL OR accounts.public_id_at < $4)
                 THEN $3 ELSE accounts.public_id END,
             public_id_at = CASE
                 WHEN accounts.deleted_at IS NULL AND $3::text IS NOT NULL
                  AND (accounts.public_id_at IS NULL OR accounts.public_id_at < $4)
                 THEN $4 ELSE accounts.public_id_at END",
    )
    .bind(uuid.as_str())
    .bind(kind.as_str())
    .bind(public_id.map(PublicId::as_str))
    .bind(at)
    .execute(&mut **transaction)
    .await?;
    if let Some(public_id) = public_id {
        remember_public_id(transaction, uuid, public_id).await?;
    }
    Ok(())
}
