//! Hook aggregate persistence and audited lifecycle transactions.

use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::domain::{
    EncryptedSecret, EndpointKey, HOOK_RECOVERY_DAYS, Hook, HookDescription, HookId, HookStatus,
    OrganizationId, SiliconId, TransitionError,
};

use super::{
    PostgresStore, StoreError,
    idempotency::{ManagementReservation, finish_management_key, reserve_management_key},
    models::{ClockedHookRow, HookRow, hook_columns},
    types::{
        AuditAction, AuditContext, BatchHookActivation, CreateHook, CreateHookOutcome,
        EndpointResolution, HookMutation, RestoreHook, RestoreHookOutcome, RotateEndpoint,
        RotateEndpointOutcome, RotateSecret, RotateSecretOutcome, UpdateHook,
    },
};

const MAX_RETAINED_HOOKS_PER_SILICON: i64 = 1_000;
const MAX_HOOK_ACTIVATION_BATCH_SIZE: usize = 1_000;

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
        let row = sqlx::query_as::<_, HookRow>(concat!(
            "SELECT ",
            hook_columns!(),
            " FROM hook.hooks WHERE org_id = $1 AND silicon_id = $2 AND id = $3"
        ))
        .bind(organization_id.as_str())
        .bind(silicon_id.as_str())
        .bind(hook_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;
        row.map(Hook::try_from).transpose()
    }

    /// Routes a public endpoint key and samples one authoritative PostgreSQL
    /// timestamp in the same statement.
    ///
    /// # Errors
    ///
    /// Returns an error when PostgreSQL fails or persisted data is invalid.
    pub async fn resolve_endpoint(
        &self,
        silicon_id: &SiliconId,
        endpoint_key: &EndpointKey,
    ) -> Result<EndpointResolution, StoreError> {
        let row = sqlx::query_as::<_, ClockedHookRow>(concat!(
            "WITH ingress_clock AS MATERIALIZED (SELECT clock_timestamp() AS database_time) ",
            "SELECT ",
            hook_columns!(),
            ", ingress_clock.database_time FROM hook.hooks CROSS JOIN ingress_clock ",
            "WHERE silicon_id = $1 AND endpoint_key = $2"
        ))
        .bind(silicon_id.as_str())
        .bind(endpoint_key.as_str())
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = row {
            let database_time = row.database_time;
            let hook = Hook::try_from(row.hook)?;
            return Ok(if hook.is_enabled() {
                EndpointResolution::Active {
                    hook: Box::new(hook),
                    database_time,
                }
            } else {
                EndpointResolution::Inactive
            });
        }
        let retired = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
                 SELECT 1 FROM hook_private.retired_endpoint_keys
                 WHERE silicon_id = $1 AND endpoint_key = $2
             )",
        )
        .bind(silicon_id.as_str())
        .bind(endpoint_key.as_str())
        .fetch_one(&self.pool)
        .await?;
        Ok(if retired {
            EndpointResolution::Retired
        } else {
            EndpointResolution::Unknown
        })
    }

    /// Finds the Silicon's IAM hook in any lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL failure or a corrupt row.
    pub async fn find_iam_hook(
        &self,
        organization_id: &OrganizationId,
        silicon_id: &SiliconId,
    ) -> Result<Option<Hook>, StoreError> {
        sqlx::query_as::<_, HookRow>(concat!(
            "SELECT ",
            hook_columns!(),
            " FROM hook.hooks WHERE org_id = $1 AND silicon_id = $2 AND is_iam_default"
        ))
        .bind(organization_id.as_str())
        .bind(silicon_id.as_str())
        .fetch_optional(&self.pool)
        .await?
        .map(Hook::try_from)
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
        let rows = sqlx::query_as::<_, HookRow>(concat!(
            "SELECT ",
            hook_columns!(),
            " FROM hook.hooks WHERE org_id = $1 AND silicon_id = $2 ",
            "AND (deleted_at IS NULL OR ($3 AND deleted_at >= $4)) ",
            "ORDER BY created_at DESC, id DESC LIMIT $5"
        ))
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

    /// Returns the requested hooks in deterministic UUID order within one
    /// tenant scope. Disabled and soft-deleted hooks are included.
    ///
    /// # Errors
    ///
    /// Returns an error when PostgreSQL fails or a stored row violates domain
    /// invariants.
    pub async fn get_hooks_by_ids(
        &self,
        organization_id: &OrganizationId,
        silicon_id: &SiliconId,
        hook_ids: &[HookId],
    ) -> Result<Vec<Hook>, StoreError> {
        if hook_ids.is_empty() {
            return Ok(Vec::new());
        }
        let hook_ids = hook_ids
            .iter()
            .copied()
            .map(HookId::as_uuid)
            .collect::<Vec<_>>();
        let rows = sqlx::query_as::<_, HookRow>(concat!(
            "SELECT ",
            hook_columns!(),
            " FROM hook.hooks WHERE org_id = $1 AND silicon_id = $2 AND id = ANY($3) ORDER BY id"
        ))
        .bind(organization_id.as_str())
        .bind(silicon_id.as_str())
        .bind(&hook_ids)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(Hook::try_from).collect()
    }

    /// Atomically sets the desired ingress state for a unique hook batch.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an empty or duplicate batch, not-found for
    /// an incomplete tenant-scoped set, or a state conflict when any hook is
    /// soft-deleted.
    pub async fn set_hooks_enabled(
        &self,
        command: &BatchHookActivation,
    ) -> Result<Vec<Hook>, StoreError> {
        let hook_ids = activation_hook_ids(command)?;
        let mut transaction = self.pool.begin().await?;
        let mut hooks = lock_hooks_for_activation(&mut transaction, command, &hook_ids).await?;
        let expected_changes = apply_activation_transitions(&mut hooks, command)?;
        let changed_ids = update_hook_activation(&mut transaction, command, &hook_ids).await?;
        if changed_ids != expected_changes {
            return Err(StoreError::StateConflict { entity: "hook" });
        }
        insert_activation_audits(&mut transaction, command, &changed_ids).await?;
        transaction.commit().await?;
        Ok(hooks)
    }

    /// Creates a hook, idempotency record, and audit entry atomically.
    ///
    /// A concurrent identical key waits for the winner and replays its encrypted
    /// result. Different content returns [`StoreError::IdempotencyConflict`].
    /// A generated key that collides with a live or retired key for the Silicon
    /// returns [`StoreError::EndpointKeyConflict`] so the caller can retry.
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
                if hook.status() == HookStatus::Deleted {
                    return Err(StoreError::StateConflict { entity: "hook" });
                }
                if response.encrypted_secret.as_ref() != hook.encrypted_signing_secret() {
                    return Err(StoreError::SecretSuperseded);
                }
                transaction.commit().await?;
                return Ok(CreateHookOutcome::Replayed { hook, response });
            }
            ManagementReservation::Reserved => {}
        }

        reserve_retained_hook_slot(
            &mut transaction,
            command.hook.organization_id(),
            command.hook.silicon_id(),
            command.recorded_at,
        )
        .await?;
        ensure_endpoint_key_unused(
            &mut transaction,
            command.hook.silicon_id(),
            command.hook.endpoint_key(),
        )
        .await?;
        if let Err(error) =
            insert_hook(&mut transaction, &command.hook, command.is_iam_default).await
        {
            return Err(classify_hook_insert_error(error));
        }
        let action = if command.is_iam_default {
            AuditAction::IamConnected
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

    /// Soft-deletes a non-deleted hook and appends its audit record atomically.
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
            "UPDATE hook.hooks SET disabled_at = NULL, deleted_at = $2, updated_at = $2
             WHERE id = $1 AND deleted_at IS NULL",
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

    /// Replaces hook metadata and signing policy atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] for a mismatched tenant scope and
    /// [`StoreError::StateConflict`] when the hook is deleted.
    pub async fn update_hook(&self, command: UpdateHook) -> Result<Hook, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let mut hook = select_scoped_hook_for_update(
            &mut transaction,
            &command.organization_id,
            &command.silicon_id,
            command.hook_id,
        )
        .await?
        .ok_or(StoreError::NotFound { entity: "hook" })?;
        let replaces_secret = command
            .update
            .signing
            .as_ref()
            .is_some_and(|signing| signing.encrypted_secret != hook.signing().encrypted_secret);
        hook.update(command.update)
            .map_err(|_| StoreError::StateConflict { entity: "hook" })?;

        let config = serde_json::to_value(&hook.signing().config)
            .map_err(|error| StoreError::corrupt("hook", error))?;
        let secret = hook.encrypted_signing_secret();
        let updated = sqlx::query(
            "UPDATE hook.hooks
             SET name = $2,
                 description = $3,
                 time_zone = $4,
                 signature_required = $5,
                 signature_config = $6,
                 encryption_key_id = $7,
                 secret_nonce = $8,
                 encrypted_signing_secret = $9,
                 secret_generation = secret_generation + CASE WHEN $10 THEN 1 ELSE 0 END,
                 updated_at = $11
             WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(command.hook_id.as_uuid())
        .bind(hook.name().as_str())
        .bind(hook.description().map(HookDescription::as_str))
        .bind(hook.time_zone().as_str())
        .bind(hook.signing().required)
        .bind(config)
        .bind(secret.map(|secret| secret.key_id().as_str()))
        .bind(secret.map(|secret| secret.nonce().as_slice()))
        .bind(secret.map(EncryptedSecret::ciphertext))
        .bind(replaces_secret)
        .bind(command.occurred_at)
        .execute(&mut *transaction)
        .await?;
        ensure_one_row(updated.rows_affected(), "hook")?;
        insert_audit(
            &mut transaction,
            AuditAction::Updated,
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
                if hook.status() == HookStatus::Deleted {
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
            "UPDATE hook.hooks SET deleted_at = NULL, updated_at = $2
             WHERE id = $1 AND deleted_at IS NOT NULL",
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

    /// Immediately rotates a non-deleted hook's encrypted signing secret.
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
                if hook.status() == HookStatus::Deleted {
                    return Err(StoreError::StateConflict { entity: "hook" });
                }
                if response.encrypted_secret.as_ref() != hook.encrypted_signing_secret() {
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

        let secret = &command.encrypted_secret;
        let updated = sqlx::query(
            "UPDATE hook.hooks
             SET encryption_key_id = $2,
                 secret_nonce = $3,
                 encrypted_signing_secret = $4,
                 secret_generation = secret_generation + 1,
                 updated_at = $5
             WHERE id = $1 AND deleted_at IS NULL",
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

    /// Replaces a non-deleted hook's endpoint key and permanently retires the
    /// previous key for the Silicon.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::EndpointKeyConflict`] when the replacement is
    /// already live or retired, a not-found or lifecycle conflict, or a
    /// PostgreSQL failure.
    pub async fn rotate_hook_endpoint(
        &self,
        command: &RotateEndpoint,
    ) -> Result<RotateEndpointOutcome, StoreError> {
        validate_endpoint_rotation_command(command)?;
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
                if hook.status() == HookStatus::Deleted {
                    return Err(StoreError::StateConflict { entity: "hook" });
                }
                transaction.commit().await?;
                return Ok(RotateEndpointOutcome::Replayed { hook, response });
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
        ensure_endpoint_key_unused(&mut transaction, &command.silicon_id, &command.replacement)
            .await?;
        let retired = hook
            .rotate_endpoint(command.replacement.clone(), command.occurred_at)
            .map_err(|error| match error {
                TransitionError::HookAlreadyDeleted => StoreError::StateConflict { entity: "hook" },
                _ => StoreError::InvalidArgument {
                    field: "occurred_at",
                    reason: "must not precede hook creation",
                },
            })?;

        let updated = sqlx::query(
            "UPDATE hook.hooks
             SET endpoint_key = $2, endpoint_rotated_at = $3, updated_at = $3
             WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(command.hook_id.as_uuid())
        .bind(hook.endpoint_key().as_str())
        .bind(command.occurred_at)
        .execute(&mut *transaction)
        .await
        .map_err(classify_hook_insert_error)?;
        ensure_one_row(updated.rows_affected(), "hook")?;
        sqlx::query(
            "INSERT INTO hook_private.retired_endpoint_keys (
                 silicon_id, endpoint_key, hook_id, retired_at
             ) VALUES ($1, $2, $3, $4)",
        )
        .bind(command.silicon_id.as_str())
        .bind(retired.as_str())
        .bind(command.hook_id.as_uuid())
        .bind(command.occurred_at)
        .execute(&mut *transaction)
        .await?;
        insert_audit(
            &mut transaction,
            AuditAction::EndpointRotated,
            &hook,
            &command.audit,
            command.occurred_at,
        )
        .await?;
        finish_management_key(&mut transaction, &command.idempotency, &command.response).await?;
        transaction.commit().await?;
        Ok(RotateEndpointOutcome::Rotated(hook))
    }
}

fn activation_hook_ids(command: &BatchHookActivation) -> Result<Vec<Uuid>, StoreError> {
    let mut hook_ids = command
        .hook_ids
        .iter()
        .copied()
        .map(HookId::as_uuid)
        .collect::<Vec<_>>();
    if hook_ids.is_empty() || hook_ids.len() > MAX_HOOK_ACTIVATION_BATCH_SIZE {
        return Err(StoreError::InvalidArgument {
            field: "hook_ids",
            reason: "must contain between one and 1000 hooks",
        });
    }
    hook_ids.sort_unstable();
    if hook_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(StoreError::InvalidArgument {
            field: "hook_ids",
            reason: "must not contain duplicates",
        });
    }
    Ok(hook_ids)
}

async fn lock_hooks_for_activation(
    transaction: &mut Transaction<'_, Postgres>,
    command: &BatchHookActivation,
    hook_ids: &[Uuid],
) -> Result<Vec<Hook>, StoreError> {
    let rows = sqlx::query_as::<_, HookRow>(concat!(
        "SELECT ",
        hook_columns!(),
        " FROM hook.hooks WHERE org_id = $1 AND silicon_id = $2 AND id = ANY($3) ",
        "ORDER BY id FOR UPDATE"
    ))
    .bind(command.organization_id.as_str())
    .bind(command.silicon_id.as_str())
    .bind(hook_ids)
    .fetch_all(&mut **transaction)
    .await?;
    if rows.len() != hook_ids.len() {
        return Err(StoreError::NotFound { entity: "hook" });
    }
    rows.into_iter().map(Hook::try_from).collect()
}

fn apply_activation_transitions(
    hooks: &mut [Hook],
    command: &BatchHookActivation,
) -> Result<Vec<Uuid>, StoreError> {
    let mut changed_ids = Vec::with_capacity(hooks.len());
    for hook in hooks {
        if hook.is_enabled() != command.enabled {
            changed_ids.push(hook.id().as_uuid());
        }
        let transition = if command.enabled {
            hook.enable(command.occurred_at)
        } else {
            hook.disable(command.occurred_at)
        };
        if let Err(error) = transition {
            return Err(match error {
                TransitionError::TimestampOutOfOrder { .. } => StoreError::InvalidArgument {
                    field: "occurred_at",
                    reason: "must not precede the prior lifecycle transition",
                },
                _ => StoreError::StateConflict { entity: "hook" },
            });
        }
    }
    Ok(changed_ids)
}

async fn update_hook_activation(
    transaction: &mut Transaction<'_, Postgres>,
    command: &BatchHookActivation,
    hook_ids: &[Uuid],
) -> Result<Vec<Uuid>, StoreError> {
    let mut changed_ids = sqlx::query_scalar::<_, Uuid>(
        "UPDATE hook.hooks
         SET disabled_at = CASE WHEN $4 THEN NULL ELSE $5 END,
             updated_at = $5
         WHERE org_id = $1
           AND silicon_id = $2
           AND id = ANY($3)
           AND deleted_at IS NULL
           AND (($4 AND disabled_at IS NOT NULL) OR (NOT $4 AND disabled_at IS NULL))
         RETURNING id",
    )
    .bind(command.organization_id.as_str())
    .bind(command.silicon_id.as_str())
    .bind(hook_ids)
    .bind(command.enabled)
    .bind(command.occurred_at)
    .fetch_all(&mut **transaction)
    .await?;
    changed_ids.sort_unstable();
    Ok(changed_ids)
}

async fn insert_activation_audits(
    transaction: &mut Transaction<'_, Postgres>,
    command: &BatchHookActivation,
    changed_ids: &[Uuid],
) -> Result<(), StoreError> {
    if changed_ids.is_empty() {
        return Ok(());
    }
    let audit_ids = changed_ids
        .iter()
        .map(|_| Uuid::now_v7())
        .collect::<Vec<_>>();
    let action = if command.enabled {
        AuditAction::Enabled
    } else {
        AuditAction::Disabled
    };
    let inserted = sqlx::query(
        "INSERT INTO hook_private.audit_log (
             id, occurred_at, action, org_id, silicon_id, hook_id,
             actor_kind, actor_id, request_id
         )
         SELECT audit.audit_id, $3, $4, hook.org_id, hook.silicon_id, hook.id, $5, $6, $7
         FROM unnest($1::uuid[], $2::uuid[]) AS audit(hook_id, audit_id)
         JOIN hook.hooks AS hook ON hook.id = audit.hook_id
         WHERE hook.org_id = $8 AND hook.silicon_id = $9",
    )
    .bind(changed_ids)
    .bind(&audit_ids)
    .bind(command.occurred_at)
    .bind(action.as_db_str())
    .bind(super::actor_kind_as_str(command.audit.actor.kind()))
    .bind(command.audit.actor.id().as_str())
    .bind(&command.audit.request_id)
    .bind(command.organization_id.as_str())
    .bind(command.silicon_id.as_str())
    .execute(&mut **transaction)
    .await?;
    if usize::try_from(inserted.rows_affected()).ok() != Some(changed_ids.len()) {
        return Err(StoreError::StateConflict { entity: "hook" });
    }
    Ok(())
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
        "SELECT count(*) FROM hook.hooks
         WHERE org_id = $1 AND silicon_id = $2
           AND (deleted_at IS NULL OR deleted_at >= $3)",
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

/// Rejects a key that is live for the Silicon or was retired by an earlier
/// rotation. Live uniqueness is also enforced by the table constraint.
async fn ensure_endpoint_key_unused(
    transaction: &mut Transaction<'_, Postgres>,
    silicon_id: &SiliconId,
    endpoint_key: &EndpointKey,
) -> Result<(), StoreError> {
    let in_use = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (
             SELECT 1 FROM hook_private.retired_endpoint_keys
             WHERE silicon_id = $1 AND endpoint_key = $2
         ) OR EXISTS (
             SELECT 1 FROM hook.hooks WHERE silicon_id = $1 AND endpoint_key = $2
         )",
    )
    .bind(silicon_id.as_str())
    .bind(endpoint_key.as_str())
    .fetch_one(&mut **transaction)
    .await?;
    if in_use {
        return Err(StoreError::EndpointKeyConflict);
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

async fn insert_hook(
    transaction: &mut Transaction<'_, Postgres>,
    hook: &Hook,
    is_iam_default: bool,
) -> Result<(), sqlx::Error> {
    let secret = hook.encrypted_signing_secret();
    let config: Value = serde_json::to_value(&hook.signing().config)
        .map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
    sqlx::query(
        "INSERT INTO hook.hooks (
             id, org_id, silicon_id, endpoint_key, name, description,
             signature_required, signature_config, encryption_key_id, secret_nonce,
             encrypted_signing_secret, time_zone, is_iam_default,
             created_by_kind, created_by_id, created_at, updated_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $16)",
    )
    .bind(hook.id().as_uuid())
    .bind(hook.organization_id().as_str())
    .bind(hook.silicon_id().as_str())
    .bind(hook.endpoint_key().as_str())
    .bind(hook.name().as_str())
    .bind(hook.description().map(HookDescription::as_str))
    .bind(hook.signing().required)
    .bind(config)
    .bind(secret.map(|secret| secret.key_id().as_str()))
    .bind(secret.map(|secret| secret.nonce().as_slice()))
    .bind(secret.map(EncryptedSecret::ciphertext))
    .bind(hook.time_zone().as_str())
    .bind(is_iam_default)
    .bind(super::actor_kind_as_str(hook.created_by().kind()))
    .bind(hook.created_by().id().as_str())
    .bind(hook.created_at())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(super) async fn select_scoped_hook_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &OrganizationId,
    silicon_id: &SiliconId,
    hook_id: HookId,
) -> Result<Option<Hook>, StoreError> {
    sqlx::query_as::<_, HookRow>(concat!(
        "SELECT ",
        hook_columns!(),
        " FROM hook.hooks WHERE org_id = $1 AND silicon_id = $2 AND id = $3 FOR UPDATE"
    ))
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
        "INSERT INTO hook_private.audit_log (
             id, occurred_at, action, org_id, silicon_id, hook_id,
             actor_kind, actor_id, request_id
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(Uuid::now_v7())
    .bind(occurred_at)
    .bind(action.as_db_str())
    .bind(hook.organization_id().as_str())
    .bind(hook.silicon_id().as_str())
    .bind(hook.id().as_uuid())
    .bind(super::actor_kind_as_str(context.actor.kind()))
    .bind(context.actor.id().as_str())
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
        || command.audit.actor != *command.hook.created_by()
    {
        return Err(StoreError::InvalidArgument {
            field: "audit.actor",
            reason: "must match the creator and idempotency actor",
        });
    }
    if command.response.resource_id != Some(command.hook.id()) {
        return Err(StoreError::InvalidArgument {
            field: "response.resource_id",
            reason: "must identify the created hook",
        });
    }
    if command.response.encrypted_secret.as_ref() != command.hook.encrypted_signing_secret() {
        return Err(StoreError::InvalidArgument {
            field: "response.encrypted_secret",
            reason: "must match the created hook secret",
        });
    }
    let has_secret = command.response.encrypted_secret.is_some();
    if has_secret != has_normative_secret_deadline(&command.response, command.recorded_at) {
        return Err(StoreError::InvalidArgument {
            field: "response.secret_replay_until",
            reason: "must accompany exactly a secret-bearing response",
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
    ensure_non_secret_response(&command.response, "restore")
}

fn validate_endpoint_rotation_command(command: &RotateEndpoint) -> Result<(), StoreError> {
    validate_mutation_scope(
        &command.organization_id,
        command.hook_id,
        &command.idempotency,
        &command.response,
        &command.audit,
    )?;
    ensure_non_secret_response(&command.response, "endpoint rotation")
}

fn ensure_non_secret_response(
    response: &super::types::PersistedResponse,
    operation: &'static str,
) -> Result<(), StoreError> {
    if response.encrypted_secret.is_some() || response.secret_replay_until.is_some() {
        return Err(StoreError::InvalidArgument {
            field: "response.encrypted_secret",
            reason: match operation {
                "restore" => "restore responses must not contain secret material",
                _ => "endpoint rotation responses must not contain secret material",
            },
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
    if idempotency.actor != audit.actor {
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
