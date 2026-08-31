//! Transaction-scoped management idempotency primitives.

use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;

use super::{
    StoreError,
    models::ManagementIdempotencyRow,
    types::{IdempotencyScope, PersistedResponse},
};

pub(super) enum ManagementReservation {
    Reserved,
    Replayed(PersistedResponse),
}

pub(super) async fn reserve_management_key(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &IdempotencyScope,
    now: OffsetDateTime,
) -> Result<ManagementReservation, StoreError> {
    let actor_kind = super::actor_kind_as_str(scope.actor.kind());
    let calling_app_id = scope
        .calling_application_id
        .as_ref()
        .map_or("", crate::domain::ApplicationId::as_str);

    // Expired rows are reusable even when the asynchronous sweeper has not run.
    // The row lock acquired by DELETE/INSERT also serializes identical keys.
    sqlx::query(
        r"
        DELETE FROM hook_private.management_idempotency
        WHERE operation = $1
          AND actor_kind = $2
          AND actor_id = $3
          AND calling_app_id = $4
          AND org_id = $5
          AND target_id = $6
          AND idempotency_key = $7
          AND expires_at <= $8
        ",
    )
    .bind(&scope.operation)
    .bind(actor_kind)
    .bind(scope.actor.id().as_str())
    .bind(calling_app_id)
    .bind(scope.organization_id.as_str())
    .bind(&scope.target_id)
    .bind(&scope.key)
    .bind(now)
    .execute(&mut **transaction)
    .await?;

    let inserted = sqlx::query(
        r"
        INSERT INTO hook_private.management_idempotency (
            operation,
            actor_kind,
            actor_id,
            calling_app_id,
            org_id,
            target_id,
            idempotency_key,
            request_digest,
            created_at,
            expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                $9 + INTERVAL '24 hours')
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(&scope.operation)
    .bind(actor_kind)
    .bind(scope.actor.id().as_str())
    .bind(calling_app_id)
    .bind(scope.organization_id.as_str())
    .bind(&scope.target_id)
    .bind(&scope.key)
    .bind(scope.request_digest.as_slice())
    .bind(now)
    .execute(&mut **transaction)
    .await?;

    if inserted.rows_affected() == 1 {
        return Ok(ManagementReservation::Reserved);
    }

    let existing = sqlx::query_as::<_, ManagementIdempotencyRow>(
        r"
        SELECT request_digest,
               response_status,
               resource_id,
               response_secret_key_id,
               response_secret_nonce,
               response_encrypted_secret,
               secret_replay_until
        FROM hook_private.management_idempotency
        WHERE operation = $1
          AND actor_kind = $2
          AND actor_id = $3
          AND calling_app_id = $4
          AND org_id = $5
          AND target_id = $6
          AND idempotency_key = $7
        FOR UPDATE
        ",
    )
    .bind(&scope.operation)
    .bind(actor_kind)
    .bind(scope.actor.id().as_str())
    .bind(calling_app_id)
    .bind(scope.organization_id.as_str())
    .bind(&scope.target_id)
    .bind(&scope.key)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| StoreError::corrupt("management idempotency", "conflict row disappeared"))?;

    replay_from_row(&existing, scope, now)
}

pub(super) async fn finish_management_key(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &IdempotencyScope,
    response: &PersistedResponse,
) -> Result<(), StoreError> {
    if !(100..=599).contains(&response.status) {
        return Err(StoreError::InvalidArgument {
            field: "status",
            reason: "must be between 100 and 599",
        });
    }
    let response_status =
        i16::try_from(response.status).map_err(|_| StoreError::NumericRange { field: "status" })?;
    let actor_kind = super::actor_kind_as_str(scope.actor.kind());
    let calling_app_id = scope
        .calling_application_id
        .as_ref()
        .map_or("", crate::domain::ApplicationId::as_str);
    let result = sqlx::query(
        r"
        UPDATE hook_private.management_idempotency
        SET response_status = $8,
            resource_id = $9,
            response_secret_key_id = $10,
            response_secret_nonce = $11,
            response_encrypted_secret = $12,
            secret_replay_until = $13
        WHERE operation = $1
          AND actor_kind = $2
          AND actor_id = $3
          AND calling_app_id = $4
          AND org_id = $5
          AND target_id = $6
          AND idempotency_key = $7
          AND request_digest = $14
          AND response_status IS NULL
        ",
    )
    .bind(&scope.operation)
    .bind(actor_kind)
    .bind(scope.actor.id().as_str())
    .bind(calling_app_id)
    .bind(scope.organization_id.as_str())
    .bind(&scope.target_id)
    .bind(&scope.key)
    .bind(response_status)
    .bind(response.resource_id.map(crate::domain::HookId::as_uuid))
    .bind(
        response
            .encrypted_secret
            .as_ref()
            .map(|secret| secret.key_id().as_str()),
    )
    .bind(
        response
            .encrypted_secret
            .as_ref()
            .map(|secret| secret.nonce().as_slice()),
    )
    .bind(
        response
            .encrypted_secret
            .as_ref()
            .map(crate::domain::EncryptedSecret::ciphertext),
    )
    .bind(response.secret_replay_until)
    .bind(scope.request_digest.as_slice())
    .execute(&mut **transaction)
    .await?;

    if result.rows_affected() != 1 {
        return Err(StoreError::StateConflict {
            entity: "management idempotency reservation",
        });
    }
    Ok(())
}

fn rehydrate_replay_secret(
    row: &ManagementIdempotencyRow,
) -> Result<Option<crate::domain::EncryptedSecret>, StoreError> {
    let fields = (
        row.response_secret_key_id.as_deref(),
        row.response_secret_nonce.as_deref(),
        row.response_encrypted_secret.as_deref(),
    );
    let (Some(key_id), Some(nonce), Some(ciphertext)) = fields else {
        if fields.0.is_none() && fields.1.is_none() && fields.2.is_none() {
            return Ok(None);
        }
        return Err(StoreError::corrupt(
            "management idempotency",
            "incomplete encrypted replay secret",
        ));
    };

    let nonce: [u8; 12] = nonce.try_into().map_err(|_| {
        StoreError::corrupt("management idempotency", "invalid replay-secret nonce")
    })?;
    let key_id = crate::domain::EncryptionKeyId::new(key_id.to_owned())
        .map_err(|error| StoreError::corrupt("management idempotency", error))?;
    crate::domain::EncryptedSecret::new(key_id, nonce, ciphertext.to_vec())
        .map(Some)
        .map_err(|error| StoreError::corrupt("management idempotency", error))
}

fn replay_from_row(
    row: &ManagementIdempotencyRow,
    scope: &IdempotencyScope,
    now: OffsetDateTime,
) -> Result<ManagementReservation, StoreError> {
    if row.request_digest.as_slice() != scope.request_digest.as_slice() {
        return Err(StoreError::IdempotencyConflict);
    }
    if row
        .secret_replay_until
        .is_some_and(|replay_until| replay_until < now)
    {
        return Err(StoreError::SecretReplayExpired);
    }

    let status = row
        .response_status
        .ok_or_else(|| StoreError::corrupt("management idempotency", "missing response status"))?;
    let status = u16::try_from(status)
        .map_err(|error| StoreError::corrupt("management idempotency", error))?;
    let encrypted_secret = rehydrate_replay_secret(row)?;
    Ok(ManagementReservation::Replayed(PersistedResponse {
        status,
        resource_id: row.resource_id.map(Into::into),
        encrypted_secret,
        secret_replay_until: row.secret_replay_until,
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn management_replay_schema_cannot_store_plaintext_response_json() {
        let migration = include_str!("../../../migrations/0001_initial.sql");

        assert!(!migration.contains("response_body"));
        assert!(migration.contains("response_encrypted_secret bytea"));
        assert!(migration.contains("plaintext signing secrets are forbidden"));
    }
}
