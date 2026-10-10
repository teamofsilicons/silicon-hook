//! Grants on a Silicon's hooks and the accounts a Silicon accepts shares from.

use uuid::Uuid;

use super::{
    PostgresStore, StoreError,
    accounts::{AllowRecord, GrantRecord},
    types::AuditAction,
};
use crate::domain::{AccountUuid, Actor, GrantLevel};

const GRANT_COLUMNS: &str =
    "silicon_uuid, grantee_uuid, level, granted_by_uuid, created_at, updated_at";

impl PostgresStore {
    /// Reads one grant.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or a corrupt row.
    pub async fn grant(
        &self,
        silicon: &AccountUuid,
        grantee: &AccountUuid,
    ) -> Result<Option<GrantRecord>, StoreError> {
        sqlx::query_as::<_, super::accounts::GrantRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {GRANT_COLUMNS} FROM hook_private.silicon_grants
             WHERE silicon_uuid = $1 AND grantee_uuid = $2"
        )))
        .bind(silicon.as_str())
        .bind(grantee.as_str())
        .fetch_optional(&self.pool)
        .await?
        .map(GrantRecord::try_from)
        .transpose()
    }

    /// Lists the grants on a Silicon's hooks, oldest first.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or a corrupt row.
    pub async fn grants_on(&self, silicon: &AccountUuid) -> Result<Vec<GrantRecord>, StoreError> {
        sqlx::query_as::<_, super::accounts::GrantRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {GRANT_COLUMNS} FROM hook_private.silicon_grants
             WHERE silicon_uuid = $1 ORDER BY created_at, grantee_uuid LIMIT 1000"
        )))
        .bind(silicon.as_str())
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(GrantRecord::try_from)
        .collect()
    }

    /// Lists the grants an account received.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or a corrupt row.
    pub async fn grants_to(&self, grantee: &AccountUuid) -> Result<Vec<GrantRecord>, StoreError> {
        sqlx::query_as::<_, super::accounts::GrantRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {GRANT_COLUMNS} FROM hook_private.silicon_grants
             WHERE grantee_uuid = $1 ORDER BY created_at, silicon_uuid LIMIT 1000"
        )))
        .bind(grantee.as_str())
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(GrantRecord::try_from)
        .collect()
    }

    /// Creates or changes a grant and audits it.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or a corrupt row.
    pub async fn put_grant(
        &self,
        silicon: &AccountUuid,
        grantee: &AccountUuid,
        level: GrantLevel,
        actor: &Actor,
        request_id: Option<&str>,
    ) -> Result<GrantRecord, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query_as::<_, super::accounts::GrantRow>(sqlx::AssertSqlSafe(format!(
            "INSERT INTO hook_private.silicon_grants (silicon_uuid, grantee_uuid, level, granted_by_uuid)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (silicon_uuid, grantee_uuid) DO UPDATE
             SET level = EXCLUDED.level, granted_by_uuid = EXCLUDED.granted_by_uuid,
                 updated_at = clock_timestamp()
             RETURNING {GRANT_COLUMNS}"
        )))
        .bind(silicon.as_str())
        .bind(grantee.as_str())
        .bind(level.as_str())
        .bind(actor.uuid().as_str())
        .fetch_one(&mut *transaction)
        .await?;
        insert_access_audit(
            &mut transaction,
            AuditAction::AccessGranted,
            silicon,
            actor,
            request_id,
        )
        .await?;
        transaction.commit().await?;
        GrantRecord::try_from(row)
    }

    /// Removes a grant, the grantee's observer subscription to the Silicon
    /// and its queued observer sends, and audits it. Returns whether a grant
    /// existed.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure.
    pub async fn delete_grant(
        &self,
        silicon: &AccountUuid,
        grantee: &AccountUuid,
        actor: &Actor,
        request_id: Option<&str>,
        grantee_keeps_access: bool,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let deleted = sqlx::query(
            "DELETE FROM hook_private.silicon_grants WHERE silicon_uuid = $1 AND grantee_uuid = $2",
        )
        .bind(silicon.as_str())
        .bind(grantee.as_str())
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1;
        if deleted {
            if !grantee_keeps_access {
                sqlx::query(
                    "DELETE FROM hook_private.observer_subscriptions
                     WHERE silicon_uuid = $1 AND recipient_uuid = $2",
                )
                .bind(silicon.as_str())
                .bind(grantee.as_str())
                .execute(&mut *transaction)
                .await?;
            }
            insert_access_audit(
                &mut transaction,
                AuditAction::AccessRevoked,
                silicon,
                actor,
                request_id,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(deleted)
    }

    /// Lists the accounts a Silicon accepts shares from.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or a corrupt row.
    pub async fn allow_list(&self, silicon: &AccountUuid) -> Result<Vec<AllowRecord>, StoreError> {
        sqlx::query_as::<_, super::accounts::AllowRow>(
            "SELECT silicon_uuid, allowed_uuid, added_by_uuid, created_at
             FROM hook_private.silicon_allowances
             WHERE silicon_uuid = $1 ORDER BY created_at, allowed_uuid LIMIT 1000",
        )
        .bind(silicon.as_str())
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(AllowRecord::try_from)
        .collect()
    }

    /// Reports whether a Silicon's allow-list contains any of `candidates`.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure.
    pub async fn allows_any(
        &self,
        silicon: &AccountUuid,
        candidates: &[&AccountUuid],
    ) -> Result<bool, StoreError> {
        let candidates = candidates
            .iter()
            .map(|uuid| uuid.as_str())
            .collect::<Vec<_>>();
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM hook_private.silicon_allowances
                            WHERE silicon_uuid = $1 AND allowed_uuid = ANY($2))",
        )
        .bind(silicon.as_str())
        .bind(&candidates)
        .fetch_one(&self.pool)
        .await?)
    }

    /// Adds an account to a Silicon's allow-list and audits it.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or a corrupt row.
    pub async fn put_allowance(
        &self,
        silicon: &AccountUuid,
        allowed: &AccountUuid,
        actor: &Actor,
        request_id: Option<&str>,
    ) -> Result<AllowRecord, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query_as::<_, super::accounts::AllowRow>(
            "INSERT INTO hook_private.silicon_allowances (silicon_uuid, allowed_uuid, added_by_uuid)
             VALUES ($1, $2, $3)
             ON CONFLICT (silicon_uuid, allowed_uuid) DO UPDATE SET silicon_uuid = EXCLUDED.silicon_uuid
             RETURNING silicon_uuid, allowed_uuid, added_by_uuid, created_at",
        )
        .bind(silicon.as_str())
        .bind(allowed.as_str())
        .bind(actor.uuid().as_str())
        .fetch_one(&mut *transaction)
        .await?;
        insert_access_audit(
            &mut transaction,
            AuditAction::AllowListAdded,
            silicon,
            actor,
            request_id,
        )
        .await?;
        transaction.commit().await?;
        AllowRecord::try_from(row)
    }

    /// Removes an account from a Silicon's allow-list and audits it. Grants
    /// already made stay; the allow-list only gates new ones.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure.
    pub async fn delete_allowance(
        &self,
        silicon: &AccountUuid,
        allowed: &AccountUuid,
        actor: &Actor,
        request_id: Option<&str>,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let deleted = sqlx::query(
            "DELETE FROM hook_private.silicon_allowances WHERE silicon_uuid = $1 AND allowed_uuid = $2",
        )
        .bind(silicon.as_str())
        .bind(allowed.as_str())
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1;
        if deleted {
            insert_access_audit(
                &mut transaction,
                AuditAction::AllowListRemoved,
                silicon,
                actor,
                request_id,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(deleted)
    }
}

async fn insert_access_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    action: AuditAction,
    silicon: &AccountUuid,
    actor: &Actor,
    request_id: Option<&str>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO hook_private.audit_log (
             id, occurred_at, action, silicon_id, silicon_uuid, hook_id,
             actor_kind, actor_id, actor_uuid, request_id
         ) VALUES ($1, clock_timestamp(), $2, $3, $3, NULL, $4, $5, $5, $6)",
    )
    .bind(Uuid::now_v7())
    .bind(action.as_db_str())
    .bind(silicon.as_str())
    .bind(actor.kind().as_str())
    .bind(actor.uuid().as_str())
    .bind(request_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
