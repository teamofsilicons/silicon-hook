//! Schema-aware PostgreSQL readiness checks.

use std::collections::BTreeMap;

use super::{MIGRATOR, PostgresStore, StoreError, schema_contract};

const REQUIRED_RELATIONS: &[&str] = &[
    "hook.events",
    "hook.hooks",
    "hook_private.audit_log",
    "hook_private.dm_outbox",
    "hook_private.event_retention_state",
    "hook_private.iam_hook_registrations",
    "hook_private.ingress_authenticated_requests",
    "hook_private.ingress_idempotency",
    "hook_private.management_idempotency",
];

const REQUIRED_SCHEMAS: &[&str] = &["hook|USAGE", "hook_private|USAGE"];

const API_TABLE_PRIVILEGES: &[&str] = &[
    "public._sqlx_migrations|SELECT",
    "hook.hooks|SELECT",
    "hook.hooks|INSERT",
    "hook.hooks|UPDATE",
    "hook.events|SELECT",
    "hook.events|INSERT",
    "hook_private.ingress_idempotency|SELECT",
    "hook_private.ingress_idempotency|INSERT",
    "hook_private.ingress_authenticated_requests|SELECT",
    "hook_private.ingress_authenticated_requests|INSERT",
    "hook_private.ingress_authenticated_requests|DELETE",
    "hook_private.iam_hook_registrations|INSERT",
    "hook_private.dm_outbox|SELECT",
    "hook_private.dm_outbox|INSERT",
    "hook_private.management_idempotency|SELECT",
    "hook_private.management_idempotency|INSERT",
    "hook_private.management_idempotency|UPDATE",
    "hook_private.management_idempotency|DELETE",
    "hook_private.audit_log|INSERT",
];

const WORKER_TABLE_PRIVILEGES: &[&str] = &[
    "public._sqlx_migrations|SELECT",
    "hook.hooks|SELECT",
    "hook.hooks|DELETE",
    "hook.events|SELECT",
    "hook.events|DELETE",
    "hook_private.event_retention_state|SELECT",
    "hook_private.event_retention_state|UPDATE",
    "hook_private.dm_outbox|SELECT",
    "hook_private.dm_outbox|UPDATE",
    "hook_private.dm_outbox|DELETE",
    "hook_private.management_idempotency|SELECT",
    "hook_private.management_idempotency|DELETE",
];

const API_FUNCTION_PRIVILEGES: &[&str] = &["hook_private.track_event_retention_inserts()|EXECUTE"];

const WORKER_FUNCTION_PRIVILEGES: &[&str] = &[
    "hook_private.protect_dm_outbox_payload()|EXECUTE",
    "hook_private.track_event_retention_deletes()|EXECUTE",
];

/// Runtime process whose exact PostgreSQL grants must be available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeDatabaseRole {
    /// HTTP management and ingress process.
    Api,
    /// Delivery and retention process.
    Worker,
}

#[derive(Debug, sqlx::FromRow)]
struct AppliedMigration {
    version: i64,
    checksum: Vec<u8>,
    success: bool,
}

impl PostgresStore {
    /// Verifies connectivity and the exact embedded migration contract.
    ///
    /// Readiness is deliberately stricter than a connection probe. A reachable
    /// empty, stale, newer, checksum-divergent, partially migrated, or damaged
    /// database must not receive traffic from this build.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Database`] when PostgreSQL cannot be queried, or
    /// [`StoreError::SchemaNotReady`] with an operator-facing reason when the
    /// database schema is incompatible with this binary.
    pub async fn ready(&self) -> Result<(), StoreError> {
        let migrations_table =
            sqlx::query_scalar::<_, Option<String>>("SELECT to_regclass('_sqlx_migrations')::text")
                .fetch_one(&self.pool)
                .await?;
        if migrations_table.is_none() {
            return Err(schema_not_ready(
                "migration metadata table is missing; run hook-migrate",
            ));
        }

        let applied = sqlx::query_as::<_, AppliedMigration>(
            r"
            SELECT version, checksum, success
            FROM _sqlx_migrations
            ORDER BY version
            ",
        )
        .fetch_all(&self.pool)
        .await?;
        validate_migrations(&applied)?;

        let missing_relations = sqlx::query_scalar::<_, String>(
            r"
            SELECT relation_name
            FROM unnest($1::text[]) AS required(relation_name)
            WHERE to_regclass(relation_name) IS NULL
            ORDER BY relation_name
            ",
        )
        .bind(REQUIRED_RELATIONS)
        .fetch_all(&self.pool)
        .await?;
        if !missing_relations.is_empty() {
            return Err(schema_not_ready(format!(
                "required relations are missing: {}",
                missing_relations.join(", ")
            )));
        }

        schema_contract::validate(&self.pool).await?;

        Ok(())
    }

    /// Verifies both the schema contract and process-specific runtime grants.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SchemaNotReady`] when the connected role lacks a
    /// required least-privilege grant, in addition to the failures documented
    /// by [`Self::ready`].
    pub async fn ready_for(&self, role: RuntimeDatabaseRole) -> Result<(), StoreError> {
        self.ready().await?;
        ensure_privileges(
            &self.pool,
            "schema",
            REQUIRED_SCHEMAS,
            MISSING_SCHEMA_PRIVILEGES_SQL,
        )
        .await?;
        let table_privileges = match role {
            RuntimeDatabaseRole::Api => API_TABLE_PRIVILEGES,
            RuntimeDatabaseRole::Worker => WORKER_TABLE_PRIVILEGES,
        };
        ensure_privileges(
            &self.pool,
            "table",
            table_privileges,
            MISSING_TABLE_PRIVILEGES_SQL,
        )
        .await?;
        let function_privileges = match role {
            RuntimeDatabaseRole::Api => API_FUNCTION_PRIVILEGES,
            RuntimeDatabaseRole::Worker => WORKER_FUNCTION_PRIVILEGES,
        };
        ensure_privileges(
            &self.pool,
            "function",
            function_privileges,
            MISSING_FUNCTION_PRIVILEGES_SQL,
        )
        .await?;
        Ok(())
    }
}

const MISSING_SCHEMA_PRIVILEGES_SQL: &str = r"
    WITH required(descriptor) AS (SELECT unnest($1::text[]))
    SELECT descriptor
    FROM required
    WHERE NOT has_schema_privilege(
        current_user,
        split_part(descriptor, '|', 1),
        split_part(descriptor, '|', 2)
    )
    ORDER BY descriptor
    ";

const MISSING_TABLE_PRIVILEGES_SQL: &str = r"
    WITH required(descriptor) AS (SELECT unnest($1::text[]))
    SELECT descriptor
    FROM required
    WHERE NOT has_table_privilege(
        current_user,
        split_part(descriptor, '|', 1),
        split_part(descriptor, '|', 2)
    )
    ORDER BY descriptor
    ";

const MISSING_FUNCTION_PRIVILEGES_SQL: &str = r"
    WITH required(descriptor) AS (SELECT unnest($1::text[]))
    SELECT descriptor
    FROM required
    WHERE NOT has_function_privilege(
        current_user,
        split_part(descriptor, '|', 1),
        split_part(descriptor, '|', 2)
    )
    ORDER BY descriptor
    ";

async fn ensure_privileges(
    pool: &sqlx::PgPool,
    object_kind: &'static str,
    required: &[&str],
    query: &'static str,
) -> Result<(), StoreError> {
    let missing = sqlx::query_scalar::<_, String>(query)
        .bind(required)
        .fetch_all(pool)
        .await?;
    if missing.is_empty() {
        return Ok(());
    }
    Err(schema_not_ready(format!(
        "database role lacks required {object_kind} privileges: {}",
        missing.join(", ")
    )))
}

fn validate_migrations(applied: &[AppliedMigration]) -> Result<(), StoreError> {
    let expected = MIGRATOR
        .iter()
        .filter(|migration| migration.migration_type.is_up_migration())
        .map(|migration| (migration.version, migration))
        .collect::<BTreeMap<_, _>>();

    if expected.is_empty() {
        return Err(schema_not_ready(
            "this binary contains no migration contract",
        ));
    }

    for migration in applied {
        if !migration.success {
            return Err(schema_not_ready(format!(
                "migration version {} is partially applied",
                migration.version
            )));
        }
        let Some(expected_migration) = expected.get(&migration.version) else {
            return Err(schema_not_ready(format!(
                "database migration version {} is unknown to this build",
                migration.version
            )));
        };
        if migration.checksum.as_slice() != expected_migration.checksum.as_ref() {
            return Err(schema_not_ready(format!(
                "migration version {} checksum differs from this build",
                migration.version
            )));
        }
    }

    let missing_versions = expected
        .keys()
        .filter(|version| {
            !applied
                .iter()
                .any(|migration| migration.version == **version)
        })
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if !missing_versions.is_empty() {
        return Err(schema_not_ready(format!(
            "pending migration versions: {}; run hook-migrate",
            missing_versions.join(", ")
        )));
    }

    Ok(())
}

fn schema_not_ready(reason: impl Into<String>) -> StoreError {
    StoreError::SchemaNotReady {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{AppliedMigration, MIGRATOR, StoreError, validate_migrations};

    fn expected_migrations() -> Vec<AppliedMigration> {
        MIGRATOR
            .iter()
            .map(|migration| AppliedMigration {
                version: migration.version,
                checksum: migration.checksum.to_vec(),
                success: true,
            })
            .collect()
    }

    #[test]
    fn exact_embedded_migration_is_ready() {
        assert!(validate_migrations(&expected_migrations()).is_ok());
    }

    #[test]
    fn stale_unknown_failed_and_changed_migrations_are_rejected() {
        assert!(matches!(
            validate_migrations(&[]),
            Err(StoreError::SchemaNotReady { .. })
        ));

        let mut unknown = expected_migrations();
        unknown[0].version = i64::MAX;
        assert!(validate_migrations(&unknown).is_err());

        let mut failed = expected_migrations();
        failed[0].success = false;
        assert!(validate_migrations(&failed).is_err());

        let mut changed = expected_migrations();
        changed[0].checksum.fill(0);
        assert!(validate_migrations(&changed).is_err());
    }
}
