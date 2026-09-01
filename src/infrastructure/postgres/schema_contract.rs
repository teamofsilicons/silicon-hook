//! Runtime verification of migration-created PostgreSQL objects.

use sqlx::PgPool;

use super::StoreError;

const REQUIRED_COLUMNS: &[&str] = &[
    "hook.hooks.id|uuid|true",
    "hook.hooks.org_id|text|true",
    "hook.hooks.silicon_id|text|true",
    "hook.hooks.endpoint_key|text|true",
    "hook.hooks.name|text|true",
    "hook.hooks.description|text|false",
    "hook.hooks.created_by_kind|text|true",
    "hook.hooks.created_by_id|text|true",
    "hook.hooks.created_via_app_id|text|false",
    "hook.hooks.encryption_key_id|text|true",
    "hook.hooks.secret_nonce|bytea|true",
    "hook.hooks.encrypted_signing_secret|bytea|true",
    "hook.hooks.secret_generation|integer|true",
    "hook.hooks.is_iam_default|boolean|true",
    "hook.hooks.created_at|timestamp with time zone|true",
    "hook.hooks.updated_at|timestamp with time zone|true",
    "hook.hooks.disabled_at|timestamp with time zone|false",
    "hook.hooks.deleted_at|timestamp with time zone|false",
    "hook.events.id|uuid|true",
    "hook.events.hook_id|uuid|true",
    "hook.events.org_id|text|true",
    "hook.events.silicon_id|text|true",
    "hook.events.event_type|text|true",
    "hook.events.source|text|false",
    "hook.events.subject|text|false",
    "hook.events.occurred_at|timestamp with time zone|true",
    "hook.events.schema_version|text|true",
    "hook.events.trace_id|text|true",
    "hook.events.payload|jsonb|true",
    "hook.events.request_digest|bytea|true",
    "hook.events.received_at|timestamp with time zone|true",
    "hook.events.replay_protected_until|timestamp with time zone|true",
    "hook_private.iam_hook_registrations.org_id|text|true",
    "hook_private.iam_hook_registrations.silicon_id|text|true",
    "hook_private.iam_hook_registrations.original_hook_id|uuid|true",
    "hook_private.iam_hook_registrations.created_at|timestamp with time zone|true",
    "hook_private.event_retention_state.hook_id|uuid|true",
    "hook_private.event_retention_state.event_count|bigint|true",
    "hook_private.event_retention_state.maintenance_due_at|timestamp with time zone|false",
    "hook_private.ingress_idempotency.hook_id|uuid|true",
    "hook_private.ingress_idempotency.idempotency_key|text|true",
    "hook_private.ingress_idempotency.request_digest|bytea|true",
    "hook_private.ingress_idempotency.event_id|uuid|true",
    "hook_private.ingress_idempotency.created_at|timestamp with time zone|true",
    "hook_private.ingress_authenticated_requests.hook_id|uuid|true",
    "hook_private.ingress_authenticated_requests.authenticated_request_digest|bytea|true",
    "hook_private.ingress_authenticated_requests.request_digest|bytea|true",
    "hook_private.ingress_authenticated_requests.event_id|uuid|true",
    "hook_private.ingress_authenticated_requests.created_at|timestamp with time zone|true",
    "hook_private.dm_outbox.event_id|uuid|true",
    "hook_private.dm_outbox.org_id|text|true",
    "hook_private.dm_outbox.silicon_id|text|true",
    "hook_private.dm_outbox.request_body|bytea|true",
    "hook_private.dm_outbox.status|text|true",
    "hook_private.dm_outbox.attempts|integer|true",
    "hook_private.dm_outbox.available_at|timestamp with time zone|true",
    "hook_private.dm_outbox.lease_token|uuid|false",
    "hook_private.dm_outbox.leased_until|timestamp with time zone|false",
    "hook_private.dm_outbox.last_attempt_at|timestamp with time zone|false",
    "hook_private.dm_outbox.delivered_at|timestamp with time zone|false",
    "hook_private.dm_outbox.failed_at|timestamp with time zone|false",
    "hook_private.dm_outbox.failure_reason|text|false",
    "hook_private.dm_outbox.last_http_status|smallint|false",
    "hook_private.dm_outbox.created_at|timestamp with time zone|true",
    "hook_private.dm_outbox.updated_at|timestamp with time zone|true",
    "hook_private.management_idempotency.operation|text|true",
    "hook_private.management_idempotency.actor_kind|text|true",
    "hook_private.management_idempotency.actor_id|text|true",
    "hook_private.management_idempotency.calling_app_id|text|true",
    "hook_private.management_idempotency.org_id|text|true",
    "hook_private.management_idempotency.target_id|text|true",
    "hook_private.management_idempotency.idempotency_key|text|true",
    "hook_private.management_idempotency.request_digest|bytea|true",
    "hook_private.management_idempotency.response_status|smallint|false",
    "hook_private.management_idempotency.resource_id|uuid|false",
    "hook_private.management_idempotency.response_secret_key_id|text|false",
    "hook_private.management_idempotency.response_secret_nonce|bytea|false",
    "hook_private.management_idempotency.response_encrypted_secret|bytea|false",
    "hook_private.management_idempotency.created_at|timestamp with time zone|true",
    "hook_private.management_idempotency.expires_at|timestamp with time zone|true",
    "hook_private.management_idempotency.secret_replay_until|timestamp with time zone|false",
    "hook_private.audit_log.id|uuid|true",
    "hook_private.audit_log.occurred_at|timestamp with time zone|true",
    "hook_private.audit_log.action|text|true",
    "hook_private.audit_log.org_id|text|true",
    "hook_private.audit_log.silicon_id|text|true",
    "hook_private.audit_log.hook_id|uuid|false",
    "hook_private.audit_log.actor_kind|text|true",
    "hook_private.audit_log.actor_id|text|true",
    "hook_private.audit_log.calling_app_id|text|false",
    "hook_private.audit_log.request_id|text|false",
];

const REQUIRED_CONSTRAINTS: &[&str] = &[
    "hook.hooks.hooks_pkey|p",
    "hook.hooks.hooks_org_id_length|c",
    "hook.hooks.hooks_silicon_id_length|c",
    "hook.hooks.hooks_endpoint_key_format|c",
    "hook.hooks.hooks_name_length|c",
    "hook.hooks.hooks_description_length|c",
    "hook.hooks.hooks_created_by_kind|c",
    "hook.hooks.hooks_created_by_id_length|c",
    "hook.hooks.hooks_created_via_app_id_length|c",
    "hook.hooks.hooks_encryption_key_id_length|c",
    "hook.hooks.hooks_secret_nonce_length|c",
    "hook.hooks.hooks_encrypted_secret_length|c",
    "hook.hooks.hooks_secret_generation_positive|c",
    "hook.hooks.hooks_created_at_finite|c",
    "hook.hooks.hooks_updated_at_finite|c",
    "hook.hooks.hooks_disabled_at_valid|c",
    "hook.hooks.hooks_deleted_at_valid|c",
    "hook.hooks.hooks_lifecycle_timestamps_mutually_exclusive|c",
    "hook.hooks.hooks_updated_at_valid|c",
    "hook.hooks.hooks_identity_unique|u",
    "hook.hooks.hooks_endpoint_key_unique|u",
    "hook.events.events_pkey|p",
    "hook.events.events_hook_identity_fk|f",
    "hook.events.events_org_id_length|c",
    "hook.events.events_silicon_id_length|c",
    "hook.events.events_type_format|c",
    "hook.events.events_source_length|c",
    "hook.events.events_subject_length|c",
    "hook.events.events_schema_version_length|c",
    "hook.events.events_trace_id_length|c",
    "hook.events.events_payload_object|c",
    "hook.events.events_request_digest_length|c",
    "hook.events.events_occurred_at_finite|c",
    "hook.events.events_received_at_finite|c",
    "hook.events.events_replay_protected_until_finite|c",
    "hook.events.events_hook_id_unique|u",
    "hook_private.iam_hook_registrations.iam_hook_registrations_pk|p",
    "hook_private.iam_hook_registrations.iam_hook_registrations_org_id_length|c",
    "hook_private.iam_hook_registrations.iam_hook_registrations_silicon_id_length|c",
    "hook_private.iam_hook_registrations.iam_hook_registrations_created_at_finite|c",
    "hook_private.event_retention_state.event_retention_state_pkey|p",
    "hook_private.event_retention_state.event_retention_state_hook_id_fkey|f",
    "hook_private.event_retention_state.event_retention_state_count_nonnegative|c",
    "hook_private.event_retention_state.event_retention_state_due_at_finite|c",
    "hook_private.event_retention_state.event_retention_state_queue_consistent|c",
    "hook_private.ingress_idempotency.ingress_idempotency_pk|p",
    "hook_private.ingress_idempotency.ingress_idempotency_event_fk|f",
    "hook_private.ingress_idempotency.ingress_idempotency_key_length|c",
    "hook_private.ingress_idempotency.ingress_idempotency_digest_length|c",
    "hook_private.ingress_idempotency.ingress_idempotency_created_at_finite|c",
    "hook_private.ingress_authenticated_requests.ingress_authenticated_requests_pk|p",
    "hook_private.ingress_authenticated_requests.ingress_authenticated_requests_event_unique|u",
    "hook_private.ingress_authenticated_requests.ingress_authenticated_requests_event_fk|f",
    "hook_private.ingress_authenticated_requests.ingress_authenticated_requests_authenticated_digest_length|c",
    "hook_private.ingress_authenticated_requests.ingress_authenticated_requests_request_digest_length|c",
    "hook_private.ingress_authenticated_requests.ingress_authenticated_requests_created_at_finite|c",
    "hook_private.dm_outbox.dm_outbox_pkey|p",
    "hook_private.dm_outbox.dm_outbox_org_id_length|c",
    "hook_private.dm_outbox.dm_outbox_silicon_id_length|c",
    "hook_private.dm_outbox.dm_outbox_body_length|c",
    "hook_private.dm_outbox.dm_outbox_status|c",
    "hook_private.dm_outbox.dm_outbox_attempts_nonnegative|c",
    "hook_private.dm_outbox.dm_outbox_failure_reason_length|c",
    "hook_private.dm_outbox.dm_outbox_http_status|c",
    "hook_private.dm_outbox.dm_outbox_timestamps_finite|c",
    "hook_private.dm_outbox.dm_outbox_lease_consistent|c",
    "hook_private.dm_outbox.dm_outbox_terminal_state_consistent|c",
    "hook_private.dm_outbox.dm_outbox_terminal_not_leased|c",
    "hook_private.dm_outbox.dm_outbox_created_updated_order|c",
    "hook_private.management_idempotency.management_idempotency_pk|p",
    "hook_private.management_idempotency.management_idempotency_operation_length|c",
    "hook_private.management_idempotency.management_idempotency_actor_kind|c",
    "hook_private.management_idempotency.management_idempotency_actor_id_length|c",
    "hook_private.management_idempotency.management_idempotency_calling_app_id|c",
    "hook_private.management_idempotency.management_idempotency_org_id_length|c",
    "hook_private.management_idempotency.management_idempotency_target_id_length|c",
    "hook_private.management_idempotency.management_idempotency_key_length|c",
    "hook_private.management_idempotency.management_idempotency_digest_length|c",
    "hook_private.management_idempotency.management_idempotency_response_status|c",
    "hook_private.management_idempotency.management_idempotency_reservation_empty|c",
    "hook_private.management_idempotency.management_idempotency_secret_complete|c",
    "hook_private.management_idempotency.management_idempotency_secret_key_id_length|c",
    "hook_private.management_idempotency.management_idempotency_secret_nonce_length|c",
    "hook_private.management_idempotency.management_idempotency_secret_ciphertext_length|c",
    "hook_private.management_idempotency.management_idempotency_timestamps|c",
    "hook_private.audit_log.audit_log_pkey|p",
    "hook_private.audit_log.audit_log_action|c",
    "hook_private.audit_log.audit_log_org_id_length|c",
    "hook_private.audit_log.audit_log_silicon_id_length|c",
    "hook_private.audit_log.audit_log_actor_kind|c",
    "hook_private.audit_log.audit_log_actor_id_length|c",
    "hook_private.audit_log.audit_log_calling_app_id_length|c",
    "hook_private.audit_log.audit_log_request_id_length|c",
    "hook_private.audit_log.audit_log_occurred_at_finite|c",
];

const REQUIRED_INDEXES: &[&str] = &[
    "hook.hooks.hooks_one_iam_default_per_silicon",
    "hook.hooks.hooks_list_active",
    "hook.hooks.hooks_deleted_retention",
    "hook.events.events_per_hook_history",
    "hook.events.events_per_hook_replay_deadline",
    "hook.events.events_per_silicon_history",
    "hook.events.events_per_silicon_type_history",
    "hook_private.event_retention_state.event_retention_state_due",
    "hook_private.dm_outbox.dm_outbox_due_jobs",
    "hook_private.dm_outbox.dm_outbox_terminal_retention",
    "hook_private.management_idempotency.management_idempotency_expiry",
    "hook_private.audit_log.audit_log_resource_history",
];

const REQUIRED_TRIGGERS: &[&str] = &[
    "hook.events.events_are_immutable|hook_private.reject_row_mutation|19",
    "hook.events.events_track_retention_inserts|hook_private.track_event_retention_inserts|4",
    "hook.events.events_track_retention_deletes|hook_private.track_event_retention_deletes|8",
    "hook_private.iam_hook_registrations.iam_hook_registrations_are_immutable|hook_private.reject_row_mutation|27",
    "hook_private.ingress_idempotency.ingress_idempotency_is_immutable|hook_private.reject_row_mutation|19",
    "hook_private.ingress_authenticated_requests.ingress_authenticated_requests_are_immutable|hook_private.reject_row_mutation|19",
    "hook_private.audit_log.audit_log_is_append_only|hook_private.reject_row_mutation|27",
    "hook_private.dm_outbox.dm_outbox_payload_is_immutable|hook_private.protect_dm_outbox_payload|19",
];

const REQUIRED_DEFAULTS: &[&str] = &[
    "hook.hooks.secret_generation|1",
    "hook.hooks.is_iam_default|false",
    "hook.events.replay_protected_until|(clock_timestamp() + '00:10:00'::interval)",
    "hook_private.dm_outbox.status|'pending'::text",
    "hook_private.dm_outbox.attempts|0",
    "hook_private.management_idempotency.calling_app_id|''::text",
];

const MISSING_COLUMNS_SQL: &str = r"
    WITH required(descriptor) AS (SELECT unnest($1::text[]))
    SELECT split_part(descriptor, '|', 1)
    FROM required
    WHERE NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_attribute AS attribute
        JOIN pg_catalog.pg_class AS relation ON relation.oid = attribute.attrelid
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname || '.' || relation.relname || '.' || attribute.attname
                = split_part(descriptor, '|', 1)
          AND relation.relkind IN ('r', 'p')
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND pg_catalog.format_type(attribute.atttypid, attribute.atttypmod)
                = split_part(descriptor, '|', 2)
          AND attribute.attnotnull = split_part(descriptor, '|', 3)::boolean
    )
    ORDER BY descriptor
    ";

const MISSING_CONSTRAINTS_SQL: &str = r"
    WITH required(descriptor) AS (SELECT unnest($1::text[]))
    SELECT split_part(descriptor, '|', 1)
    FROM required
    WHERE NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint AS constraint_record
        JOIN pg_catalog.pg_class AS relation ON relation.oid = constraint_record.conrelid
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname || '.' || relation.relname || '.' || constraint_record.conname
                = split_part(descriptor, '|', 1)
          AND constraint_record.contype::text = split_part(descriptor, '|', 2)
          AND constraint_record.convalidated
    )
    ORDER BY descriptor
    ";

const MISSING_INDEXES_SQL: &str = r"
    WITH required(descriptor) AS (SELECT unnest($1::text[]))
    SELECT descriptor
    FROM required
    WHERE NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_index AS index_record
        JOIN pg_catalog.pg_class AS index_relation
          ON index_relation.oid = index_record.indexrelid
        JOIN pg_catalog.pg_class AS table_relation
          ON table_relation.oid = index_record.indrelid
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = table_relation.relnamespace
        WHERE namespace.nspname || '.' || table_relation.relname || '.' || index_relation.relname
                = descriptor
          AND index_record.indisvalid
          AND index_record.indisready
    )
    ORDER BY descriptor
    ";

const MISSING_TRIGGERS_SQL: &str = r"
    WITH required(descriptor) AS (SELECT unnest($1::text[]))
    SELECT split_part(descriptor, '|', 1)
    FROM required
    WHERE NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_trigger AS trigger_record
        JOIN pg_catalog.pg_class AS relation ON relation.oid = trigger_record.tgrelid
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        JOIN pg_catalog.pg_proc AS function_record
          ON function_record.oid = trigger_record.tgfoid
        JOIN pg_catalog.pg_namespace AS function_namespace
          ON function_namespace.oid = function_record.pronamespace
        WHERE namespace.nspname || '.' || relation.relname || '.' || trigger_record.tgname
                = split_part(descriptor, '|', 1)
          AND function_namespace.nspname || '.' || function_record.proname
                = split_part(descriptor, '|', 2)
          AND trigger_record.tgtype = split_part(descriptor, '|', 3)::smallint
          AND trigger_record.tgenabled = 'O'
          AND NOT trigger_record.tgisinternal
    )
    ORDER BY descriptor
    ";

const MISSING_DEFAULTS_SQL: &str = r"
    WITH required(descriptor) AS (SELECT unnest($1::text[]))
    SELECT split_part(descriptor, '|', 1)
    FROM required
    WHERE NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_attrdef AS default_record
        JOIN pg_catalog.pg_attribute AS attribute
          ON attribute.attrelid = default_record.adrelid
         AND attribute.attnum = default_record.adnum
        JOIN pg_catalog.pg_class AS relation ON relation.oid = attribute.attrelid
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname || '.' || relation.relname || '.' || attribute.attname
                = split_part(descriptor, '|', 1)
          AND pg_catalog.pg_get_expr(default_record.adbin, default_record.adrelid)
                = split_part(descriptor, '|', 2)
    )
    ORDER BY descriptor
    ";

pub(super) async fn validate(pool: &PgPool) -> Result<(), StoreError> {
    ensure_objects(
        "columns",
        &missing_objects(pool, MISSING_COLUMNS_SQL, REQUIRED_COLUMNS).await?,
    )?;
    ensure_objects(
        "constraints",
        &missing_objects(pool, MISSING_CONSTRAINTS_SQL, REQUIRED_CONSTRAINTS).await?,
    )?;
    ensure_objects(
        "indexes",
        &missing_objects(pool, MISSING_INDEXES_SQL, REQUIRED_INDEXES).await?,
    )?;
    ensure_objects(
        "triggers",
        &missing_objects(pool, MISSING_TRIGGERS_SQL, REQUIRED_TRIGGERS).await?,
    )?;
    ensure_objects(
        "defaults",
        &missing_objects(pool, MISSING_DEFAULTS_SQL, REQUIRED_DEFAULTS).await?,
    )
}

async fn missing_objects(
    pool: &PgPool,
    query: &'static str,
    required: &[&str],
) -> Result<Vec<String>, StoreError> {
    sqlx::query_scalar::<_, String>(query)
        .bind(required)
        .fetch_all(pool)
        .await
        .map_err(StoreError::from)
}

fn ensure_objects(kind: &'static str, missing: &[String]) -> Result<(), StoreError> {
    if missing.is_empty() {
        return Ok(());
    }
    Err(StoreError::SchemaNotReady {
        reason: format!(
            "required schema {kind} are missing or incompatible: {}",
            missing.join(", ")
        ),
    })
}
