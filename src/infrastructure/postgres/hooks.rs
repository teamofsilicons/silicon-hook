//! Hook aggregate persistence and audited lifecycle transactions.

use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::domain::{
    ActorId, ActorKind, ActorRef, ApplicationId, EncryptedSecret, EncryptionKeyId, EndpointKey,
    HOOK_RECOVERY_DAYS, Hook, HookDescription, HookId, HookName, HookSnapshot, HookStatus,
    OrganizationId, SiliconId,
};

use super::{
    PostgresStore, StoreError,
    idempotency::{ManagementReservation, finish_management_key, reserve_management_key},
    models::{HookRow, IngressHookRow},
    types::{
        AuditAction, AuditContext, CreateHook, CreateHookOutcome, HookMutation,
        IngressHookResolution, RestoreHook, RestoreHookOutcome, RotateSecret, RotateSecretOutcome,
    },
};

const MAX_RETAINED_HOOKS_PER_SILICON: i64 = 1_000;

impl PostgresStore {
    /// Returns one hook within its complete tenant scope.
    ///
    /// # Errors
    ///
    /// Returns an error when PostgreSQL fails or a stored row violates domain
    /// invariants.
    pub async fn get_hook(
        &self,
        organization_id: &OrganizationId,
        silicon_id: &SiliconId,
        hook_id: HookId,
    ) -> Result<Option<Hook>, StoreError> {
        let row = sqlx::query_as::<_, HookRow>(
            r"
            SELECT id, org_id, silicon_id, endpoint_key, name, description,
                   created_by_kind, created_by_id, created_via_app_id,
                   encryption_key_id, secret_nonce, encrypted_signing_secret,
                   created_at, deleted_at
            FROM hook.hooks
            WHERE org_id = $1 AND silicon_id = $2 AND id = $3
            ",
        )
        .bind(organization_id.as_str())
        .bind(silicon_id.as_str())
        .bind(hook_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;
        row.map(Hook::try_from).transpose()
    }

    /// Resolves an active ingress route, its encrypted secret, and one
    /// authoritative PostgreSQL timestamp in the same statement.
    ///
    /// Deleted hooks are indistinguishable from unknown routes at this layer.
    ///
    /// # Errors
    ///
    /// Returns an error when PostgreSQL fails or persisted data is invalid.
    pub async fn find_active_hook_by_endpoint(
        &self,
        silicon_id: &SiliconId,
        endpoint_key: &EndpointKey,
    ) -> Result<Option<IngressHookResolution>, StoreError> {
        let row = sqlx::query_as::<_, IngressHookRow>(
            r"
            WITH ingress_clock AS MATERIALIZED (
                SELECT clock_timestamp() AS database_time
            )
            SELECT id, org_id, silicon_id, endpoint_key, name, description,
                   created_by_kind, created_by_id, created_via_app_id,
                   encryption_key_id, secret_nonce, encrypted_signing_secret,
                   created_at, deleted_at, ingress_clock.database_time
            FROM hook.hooks
            CROSS JOIN ingress_clock
            WHERE silicon_id = $1 AND endpoint_key = $2 AND deleted_at IS NULL
            ",
        )
        .bind(silicon_id.as_str())
        .bind(endpoint_key.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(IngressHookResolution {
                hook: Hook::try_from(row.hook)?,
                database_time: row.database_time,
            })
        })
        .transpose()
    }

    /// Lists recoverable hooks in deterministic newest-first order.
    ///
    /// Expired soft-deleted rows are excluded at `retained_at` even when the
    /// asynchronous maintenance worker has not physically purged them yet.
    ///
    /// # Errors
    ///
    /// Returns an error when PostgreSQL fails or persisted data is invalid.
    pub async fn list_hooks(
        &self,
        organization_id: &OrganizationId,
        silicon_id: &SiliconId,
        include_deleted: bool,
        retained_at: time::OffsetDateTime,
    ) -> Result<Vec<Hook>, StoreError> {
        let recovery_cutoff = recovery_cutoff(retained_at)?;
        let rows = sqlx::query_as::<_, HookRow>(
            r"
            SELECT id, org_id, silicon_id, endpoint_key, name, description,
                   created_by_kind, created_by_id, created_via_app_id,
                   encryption_key_id, secret_nonce, encrypted_signing_secret,
                   created_at, deleted_at
            FROM hook.hooks
            WHERE org_id = $1
              AND silicon_id = $2
              AND (deleted_at IS NULL OR ($3 AND deleted_at >= $4))
            ORDER BY created_at DESC, id DESC
            LIMIT $5
            ",
        )
        .bind(organization_id.as_str())
        .bind(silicon_id.as_str())
        .bind(include_deleted)
        .bind(recovery_cutoff)
        .bind(MAX_RETAINED_HOOKS_PER_SILICON + 1)
        .fetch_all(&self.pool)
        .await?;
        if i64::try_from(rows.len()).unwrap_or(i64::MAX) > MAX_RETAINED_HOOKS_PER_SILICON {
            return Err(StoreError::corrupt(
                "hook collection",
                "retained hook count exceeds the enforced limit",
            ));
        }
        rows.into_iter().map(Hook::try_from).collect()
    }

    /// Creates a hook, idempotency record, and audit entry atomically.
    ///
    /// A concurrent identical key waits for the winner and replays its encrypted
    /// result. Different content returns [`StoreError::IdempotencyConflict`].
    ///
    /// # Errors
    ///
    /// Returns a semantic conflict, corrupt-data error, or PostgreSQL failure.
    pub async fn create_hook(&self, command: CreateHook) -> Result<CreateHookOutcome, StoreError> {
        validate_create_command(&command)?;

        let mut transaction = self.pool.begin().await?;
        match reserve_management_key(&mut transaction, &command.idempotency, command.recorded_at)
            .await?
        {
            ManagementReservation::Replayed(response) => {
                let hook = select_replayed_scoped_hook(
                    &mut transaction,
                    command.hook.organization_id(),
                    command.hook.silicon_id(),
                    &response,
                )
                .await?;
                if hook.status() != HookStatus::Active {
                    return Err(StoreError::StateConflict { entity: "hook" });
                }
                if response.encrypted_secret.as_ref() != Some(hook.encrypted_signing_secret()) {
                    return Err(StoreError::SecretSuperseded);
                }
                transaction.commit().await?;
                return Ok(CreateHookOutcome::Replayed { hook, response });
            }
            ManagementReservation::Reserved => {}
        }

        if command.is_iam_default {
            reserve_iam_hook_registration(&mut transaction, &command.hook, command.recorded_at)
                .await?;
        }

        reserve_retained_hook_slot(
            &mut transaction,
            command.hook.organization_id(),
            command.hook.silicon_id(),
            command.recorded_at,
        )
        .await?;

        if let Err(error) =
            insert_hook(&mut transaction, &command.hook, command.is_iam_default).await
        {
            return Err(classify_hook_insert_error(error));
        }
        let action = if command.is_iam_default {
            AuditAction::IamProvisioned
        } else {
            AuditAction::Created
        };
        insert_audit(
            &mut transaction,
            action,
            &command.hook,
            &command.audit,
            command.recorded_at,
        )
        .await?;
        finish_management_key(&mut transaction, &command.idempotency, &command.response).await?;
        transaction.commit().await?;

        Ok(CreateHookOutcome::Created(command.hook))
    }

    /// Soft-deletes an active hook and appends its audit record atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] for a mismatched tenant scope and
    /// [`StoreError::StateConflict`] when the hook is already deleted.
    pub async fn delete_hook(&self, command: &HookMutation) -> Result<Hook, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let mut hook = select_scoped_hook_for_update(
            &mut transaction,
            &command.organization_id,
            &command.silicon_id,
            command.hook_id,
        )
        .await?
        .ok_or(StoreError::NotFound { entity: "hook" })?;
        hook.delete(command.occurred_at)
            .map_err(|_| StoreError::StateConflict { entity: "hook" })?;

        let updated = sqlx::query(
            r"
            UPDATE hook.hooks
            SET deleted_at = $2, updated_at = $2
            WHERE id = $1 AND deleted_at IS NULL
            ",
        )
        .bind(command.hook_id.as_uuid())
        .bind(command.occurred_at)
        .execute(&mut *transaction)
        .await?;
        ensure_one_row(updated.rows_affected(), "hook")?;
        insert_audit(
            &mut transaction,
            AuditAction::Deleted,
            &hook,
            &command.audit,
            command.occurred_at,
        )
        .await?;
        transaction.commit().await?;
        Ok(hook)
    }

    /// Restores a hook that is still inside its 45-day recovery window.
    ///
    /// # Errors
    ///
    /// Returns a not-found or lifecycle conflict without writing an audit row.
    pub async fn restore_hook(
        &self,
        command: &RestoreHook,
    ) -> Result<RestoreHookOutcome, StoreError> {
        validate_restore_command(command)?;
        let mut transaction = self.pool.begin().await?;
        match reserve_management_key(&mut transaction, &command.idempotency, command.occurred_at)
            .await?
        {
            ManagementReservation::Replayed(response) => {
                let hook = select_replayed_scoped_hook(
                    &mut transaction,
                    &command.organization_id,
                    &command.silicon_id,
                    &response,
                )
                .await?;
                if hook.status() != HookStatus::Active {
                    return Err(StoreError::StateConflict { entity: "hook" });
                }
                transaction.commit().await?;
                return Ok(RestoreHookOutcome::Replayed { hook, response });
            }
            ManagementReservation::Reserved => {}
        }
        let mut hook = select_scoped_hook_for_update(
            &mut transaction,
            &command.organization_id,
            &command.silicon_id,
            command.hook_id,
        )
        .await?
        .ok_or(StoreError::NotFound { entity: "hook" })?;
        hook.restore(command.occurred_at)
            .map_err(|_| StoreError::StateConflict { entity: "hook" })?;

        let updated = sqlx::query(
            r"
            UPDATE hook.hooks
            SET deleted_at = NULL, updated_at = $2
            WHERE id = $1 AND deleted_at IS NOT NULL
            ",
        )
        .bind(command.hook_id.as_uuid())
        .bind(command.occurred_at)
        .execute(&mut *transaction)
        .await?;
        ensure_one_row(updated.rows_affected(), "hook")?;
        insert_audit(
            &mut transaction,
            AuditAction::Restored,
            &hook,
            &command.audit,
            command.occurred_at,
        )
        .await?;
        finish_management_key(&mut transaction, &command.idempotency, &command.response).await?;
        transaction.commit().await?;
        Ok(RestoreHookOutcome::Restored(hook))
    }

    /// Immediately rotates an active hook's encrypted signing secret.
    ///
    /// # Errors
    ///
    /// Returns a not-found or lifecycle conflict without partially updating the
    /// aggregate or audit log.
    pub async fn rotate_hook_secret(
        &self,
        command: &RotateSecret,
    ) -> Result<RotateSecretOutcome, StoreError> {
        validate_rotate_command(command)?;
        let mut transaction = self.pool.begin().await?;
        match reserve_management_key(&mut transaction, &command.idempotency, command.occurred_at)
            .await?
        {
            ManagementReservation::Replayed(response) => {
                let hook = select_replayed_scoped_hook(
                    &mut transaction,
                    &command.organization_id,
                    &command.silicon_id,
                    &response,
                )
                .await?;
                if hook.status() != HookStatus::Active {
                    return Err(StoreError::StateConflict { entity: "hook" });
                }
                if response.encrypted_secret.as_ref() != Some(hook.encrypted_signing_secret()) {
                    return Err(StoreError::SecretSuperseded);
                }
                transaction.commit().await?;
                return Ok(RotateSecretOutcome::Replayed { hook, response });
            }
            ManagementReservation::Reserved => {}
        }
        let mut hook = select_scoped_hook_for_update(
            &mut transaction,
            &command.organization_id,
            &command.silicon_id,
            command.hook_id,
        )
        .await?
        .ok_or(StoreError::NotFound { entity: "hook" })?;
        hook.rotate_secret(command.encrypted_secret.clone())
            .map_err(|_| StoreError::StateConflict { entity: "hook" })?;

        let secret = hook.encrypted_signing_secret();
        let updated = sqlx::query(
            r"
            UPDATE hook.hooks
            SET encryption_key_id = $2,
                secret_nonce = $3,
                encrypted_signing_secret = $4,
                secret_generation = secret_generation + 1,
                updated_at = $5
            WHERE id = $1 AND deleted_at IS NULL
            ",
        )
        .bind(command.hook_id.as_uuid())
        .bind(secret.key_id().as_str())
        .bind(secret.nonce().as_slice())
        .bind(secret.ciphertext())
        .bind(command.occurred_at)
        .execute(&mut *transaction)
        .await?;
        ensure_one_row(updated.rows_affected(), "hook")?;
        insert_audit(
            &mut transaction,
            AuditAction::SecretRotated,
            &hook,
            &command.audit,
            command.occurred_at,
        )
        .await?;
        finish_management_key(&mut transaction, &command.idempotency, &command.response).await?;
        transaction.commit().await?;
        Ok(RotateSecretOutcome::Rotated(hook))
    }
}

async fn reserve_retained_hook_slot(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &OrganizationId,
    silicon_id: &SiliconId,
    retained_at: time::OffsetDateTime,
) -> Result<(), StoreError> {
    // The inclusive cutoff matches `Hook::restore`: a hook is recoverable at
    // its exact deadline and stops consuming a slot immediately afterwards.
    let recovery_cutoff = recovery_cutoff(retained_at)?;
    // Every creator takes the same transaction-scoped pair lock before
    // counting. Hash collisions only serialize unrelated tenants; they cannot
    // permit an over-limit insert.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
        .bind(organization_id.as_str())
        .bind(silicon_id.as_str())
        .execute(&mut **transaction)
        .await?;
    let retained = sqlx::query_scalar::<_, i64>(
        r"
        SELECT count(*)
        FROM hook.hooks
        WHERE org_id = $1 AND silicon_id = $2
          AND (deleted_at IS NULL OR deleted_at >= $3)
        ",
    )
    .bind(organization_id.as_str())
    .bind(silicon_id.as_str())
    .bind(recovery_cutoff)
    .fetch_one(&mut **transaction)
    .await?;
    if retained >= MAX_RETAINED_HOOKS_PER_SILICON {
        return Err(StoreError::HookLimitReached);
    }
    Ok(())
}

fn recovery_cutoff(retained_at: time::OffsetDateTime) -> Result<time::OffsetDateTime, StoreError> {
    retained_at
        .checked_sub(time::Duration::days(HOOK_RECOVERY_DAYS))
        .ok_or(StoreError::NumericRange {
            field: "retained_at",
        })
}

impl TryFrom<HookRow> for Hook {
    type Error = StoreError;

    fn try_from(row: HookRow) -> Result<Self, Self::Error> {
        let status = if row.deleted_at.is_some() {
            HookStatus::Deleted
        } else {
            HookStatus::Active
        };
        let nonce: [u8; 12] = row
            .secret_nonce
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::corrupt("hook", "invalid secret nonce length"))?;
        let key_id = EncryptionKeyId::new(row.encryption_key_id)
            .map_err(|error| StoreError::corrupt("hook", error))?;
        let encrypted_signing_secret =
            EncryptedSecret::new(key_id, nonce, row.encrypted_signing_secret)
                .map_err(|error| StoreError::corrupt("hook", error))?;
        let actor_kind = parse_actor_kind(&row.created_by_kind)?;
        let created_by = ActorRef::new(
            actor_kind,
            ActorId::new(row.created_by_id).map_err(|error| StoreError::corrupt("hook", error))?,
        );

        Hook::rehydrate(HookSnapshot {
            id: row.id.into(),
            organization_id: OrganizationId::new(row.org_id)
                .map_err(|error| StoreError::corrupt("hook", error))?,
            silicon_id: SiliconId::new(row.silicon_id)
                .map_err(|error| StoreError::corrupt("hook", error))?,
            name: HookName::new(row.name).map_err(|error| StoreError::corrupt("hook", error))?,
            description: row
                .description
                .map(HookDescription::new)
                .transpose()
                .map_err(|error| StoreError::corrupt("hook", error))?,
            endpoint_key: EndpointKey::parse(&row.endpoint_key)
                .map_err(|error| StoreError::corrupt("hook", error))?,
            status,
            created_by,
            created_via_application: row
                .created_via_app_id
                .map(ApplicationId::new)
                .transpose()
                .map_err(|error| StoreError::corrupt("hook", error))?,
            created_at: row.created_at,
            deleted_at: row.deleted_at,
            encrypted_signing_secret,
        })
        .map_err(|error| StoreError::corrupt("hook", error))
    }
}

async fn insert_hook(
    transaction: &mut Transaction<'_, Postgres>,
    hook: &Hook,
    is_iam_default: bool,
) -> Result<(), sqlx::Error> {
    let secret = hook.encrypted_signing_secret();
    sqlx::query(
        r"
        INSERT INTO hook.hooks (
            id,
            org_id,
            silicon_id,
            endpoint_key,
            name,
            description,
            created_by_kind,
            created_by_id,
            created_via_app_id,
            encryption_key_id,
            secret_nonce,
            encrypted_signing_secret,
            is_iam_default,
            created_at,
            updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)
        ",
    )
    .bind(hook.id().as_uuid())
    .bind(hook.organization_id().as_str())
    .bind(hook.silicon_id().as_str())
    .bind(hook.endpoint_key().as_str())
    .bind(hook.name().as_str())
    .bind(hook.description().map(HookDescription::as_str))
    .bind(super::actor_kind_as_str(hook.created_by().kind()))
    .bind(hook.created_by().id().as_str())
    .bind(hook.created_via_application().map(ApplicationId::as_str))
    .bind(secret.key_id().as_str())
    .bind(secret.nonce().as_slice())
    .bind(secret.ciphertext())
    .bind(is_iam_default)
    .bind(hook.created_at())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn reserve_iam_hook_registration(
    transaction: &mut Transaction<'_, Postgres>,
    hook: &Hook,
    created_at: time::OffsetDateTime,
) -> Result<(), StoreError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO hook_private.iam_hook_registrations (
            org_id,
            silicon_id,
            original_hook_id,
            created_at
        )
        VALUES ($1, $2, $3, $4)
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(hook.organization_id().as_str())
    .bind(hook.silicon_id().as_str())
    .bind(hook.id().as_uuid())
    .bind(created_at)
    .execute(&mut **transaction)
    .await?;
    if inserted.rows_affected() == 1 {
        Ok(())
    } else {
        Err(StoreError::IamDefaultExists)
    }
}

async fn select_scoped_hook_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &OrganizationId,
    silicon_id: &SiliconId,
    hook_id: HookId,
) -> Result<Option<Hook>, StoreError> {
    sqlx::query_as::<_, HookRow>(
        r"
        SELECT id, org_id, silicon_id, endpoint_key, name, description,
               created_by_kind, created_by_id, created_via_app_id,
               encryption_key_id, secret_nonce, encrypted_signing_secret,
               created_at, deleted_at
        FROM hook.hooks
        WHERE org_id = $1 AND silicon_id = $2 AND id = $3
        FOR UPDATE
        ",
    )
    .bind(organization_id.as_str())
    .bind(silicon_id.as_str())
    .bind(hook_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await?
    .map(Hook::try_from)
    .transpose()
}

async fn select_replayed_scoped_hook(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &OrganizationId,
    silicon_id: &SiliconId,
    response: &super::types::PersistedResponse,
) -> Result<Hook, StoreError> {
    let hook_id = response
        .resource_id
        .ok_or_else(|| StoreError::corrupt("management idempotency", "missing hook resource ID"))?;
    select_scoped_hook_for_update(transaction, organization_id, silicon_id, hook_id)
        .await?
        .ok_or_else(|| {
            StoreError::corrupt(
                "management idempotency",
                "replayed hook no longer exists in its tenant scope",
            )
        })
}

pub(super) async fn insert_audit(
    transaction: &mut Transaction<'_, Postgres>,
    action: AuditAction,
    hook: &Hook,
    context: &AuditContext,
    occurred_at: time::OffsetDateTime,
) -> Result<(), StoreError> {
    sqlx::query(
        r"
        INSERT INTO hook_private.audit_log (
            id,
            occurred_at,
            action,
            org_id,
            silicon_id,
            hook_id,
            actor_kind,
            actor_id,
            calling_app_id,
            request_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ",
    )
    .bind(Uuid::now_v7())
    .bind(occurred_at)
    .bind(action.as_db_str())
    .bind(hook.organization_id().as_str())
    .bind(hook.silicon_id().as_str())
    .bind(hook.id().as_uuid())
    .bind(super::actor_kind_as_str(context.actor.kind()))
    .bind(context.actor.id().as_str())
    .bind(
        context
            .calling_application_id
            .as_ref()
            .map(ApplicationId::as_str),
    )
    .bind(&context.request_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn validate_create_command(command: &CreateHook) -> Result<(), StoreError> {
    if command.hook.status() != HookStatus::Active {
        return Err(StoreError::InvalidArgument {
            field: "hook.status",
            reason: "new hooks must be active",
        });
    }
    if command.idempotency.organization_id != *command.hook.organization_id() {
        return Err(StoreError::InvalidArgument {
            field: "idempotency.organization_id",
            reason: "must match the hook organization",
        });
    }
    if command.idempotency.actor != command.audit.actor
        || command.idempotency.calling_application_id != command.audit.calling_application_id
        || command.audit.actor != *command.hook.created_by()
        || command.audit.calling_application_id.as_ref() != command.hook.created_via_application()
    {
        return Err(StoreError::InvalidArgument {
            field: "audit.actor",
            reason: "must match the effective creator and idempotency actor",
        });
    }
    if command.response.resource_id != Some(command.hook.id()) {
        return Err(StoreError::InvalidArgument {
            field: "response.resource_id",
            reason: "must identify the created hook",
        });
    }
    if command.response.encrypted_secret.as_ref() != Some(command.hook.encrypted_signing_secret())
        || !has_normative_secret_deadline(&command.response, command.recorded_at)
    {
        return Err(StoreError::InvalidArgument {
            field: "response.encrypted_secret",
            reason: "must contain the created hook secret and a replay deadline",
        });
    }
    Ok(())
}

fn validate_restore_command(command: &RestoreHook) -> Result<(), StoreError> {
    validate_mutation_scope(
        &command.organization_id,
        command.hook_id,
        &command.idempotency,
        &command.response,
        &command.audit,
    )?;
    if command.response.encrypted_secret.is_some() || command.response.secret_replay_until.is_some()
    {
        return Err(StoreError::InvalidArgument {
            field: "response.encrypted_secret",
            reason: "restore responses must not contain secret material",
        });
    }
    Ok(())
}

fn validate_rotate_command(command: &RotateSecret) -> Result<(), StoreError> {
    validate_mutation_scope(
        &command.organization_id,
        command.hook_id,
        &command.idempotency,
        &command.response,
        &command.audit,
    )?;
    if command.response.encrypted_secret.as_ref() != Some(&command.encrypted_secret)
        || !has_normative_secret_deadline(&command.response, command.occurred_at)
    {
        return Err(StoreError::InvalidArgument {
            field: "response.encrypted_secret",
            reason: "must contain the rotated secret and a replay deadline",
        });
    }
    Ok(())
}

fn validate_mutation_scope(
    organization_id: &OrganizationId,
    hook_id: HookId,
    idempotency: &super::types::IdempotencyScope,
    response: &super::types::PersistedResponse,
    audit: &AuditContext,
) -> Result<(), StoreError> {
    if &idempotency.organization_id != organization_id {
        return Err(StoreError::InvalidArgument {
            field: "idempotency.organization_id",
            reason: "must match the hook organization",
        });
    }
    if idempotency.actor != audit.actor
        || idempotency.calling_application_id != audit.calling_application_id
    {
        return Err(StoreError::InvalidArgument {
            field: "audit.actor",
            reason: "must match the idempotency actor",
        });
    }
    if response.resource_id != Some(hook_id) {
        return Err(StoreError::InvalidArgument {
            field: "response.resource_id",
            reason: "must identify the mutated hook",
        });
    }
    Ok(())
}

fn has_normative_secret_deadline(
    response: &super::types::PersistedResponse,
    operation_time: time::OffsetDateTime,
) -> bool {
    operation_time
        .checked_add(super::SECRET_REPLAY_WINDOW)
        .is_some_and(|deadline| response.secret_replay_until == Some(deadline))
}

fn parse_actor_kind(value: &str) -> Result<ActorKind, StoreError> {
    match value {
        "carbon" => Ok(ActorKind::Carbon),
        "silicon" => Ok(ActorKind::Silicon),
        "application" => Ok(ActorKind::Application),
        "service" => Ok(ActorKind::Service),
        _ => Err(StoreError::corrupt("hook", "unknown creator actor kind")),
    }
}

fn classify_hook_insert_error(error: sqlx::Error) -> StoreError {
    if let sqlx::Error::Database(database) = &error {
        match database.constraint() {
            Some("hooks_endpoint_key_unique") => return StoreError::EndpointKeyConflict,
            Some("hooks_one_iam_default_per_silicon") => return StoreError::IamDefaultExists,
            _ => {}
        }
    }
    StoreError::Database(error)
}

fn ensure_one_row(rows_affected: u64, entity: &'static str) -> Result<(), StoreError> {
    if rows_affected == 1 {
        Ok(())
    } else {
        Err(StoreError::StateConflict { entity })
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::{StoreError, recovery_cutoff};

    #[test]
    fn recovery_cutoff_is_exact() -> Result<(), StoreError> {
        assert_eq!(
            recovery_cutoff(datetime!(2026-08-31 12:01:00 UTC))?,
            datetime!(2026-07-17 12:01:00 UTC)
        );
        Ok(())
    }
}
