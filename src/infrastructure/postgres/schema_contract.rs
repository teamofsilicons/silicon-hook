//! Runtime verification of migration-created PostgreSQL objects.

use sqlx::PgPool;

use super::StoreError;

const REQUIRED_COLUMNS: &[&str] = &[
    "hook.hooks.environment_id|uuid|true",
    "hook.events.environment_id|uuid|true",
    "hook.blocked_requests.environment_id|uuid|true",
    "hook_private.retired_endpoint_keys.environment_id|uuid|true",
    "hook_private.delivery_sequences.environment_id|uuid|true",
    "hook_private.delivery_cursors.environment_id|uuid|true",
    "hook_private.ip_blocks.environment_id|uuid|true",
    "hook_private.management_idempotency.environment_id|uuid|true",
    "hook_private.audit_log.environment_id|uuid|true",
    "hook_control.environments.id|uuid|true",
    "hook_control.environments.key_hash|bytea|true",
    "hook_control.environments.iam_key_hash|bytea|true",
    "hook_control.environments.encrypted_credentials|jsonb|true",
    "hook_control.environments.generation|bigint|true",
    "hook_control.endpoint_routes.environment_id|uuid|false",
    "hook_control.mutation_results.environment_id|uuid|true",
    "hook_control.mutation_results.request_hash|bytea|true",
    "hook_control.mutation_results.input_hash|bytea|true",
    "hook_control.mutation_results.metadata|jsonb|true",
    "hook_control.mutation_results.encrypted_credentials|jsonb|false",
    "hook_control.mutation_results.created_at|timestamp with time zone|true",
    "hook.hooks.id|uuid|true",
    "hook.hooks.org_id|text|true",
    "hook.hooks.silicon_id|text|true",
    "hook.hooks.endpoint_key|text|true",
    "hook.hooks.name|text|true",
    "hook.hooks.description|text|false",
    "hook.hooks.signature_required|boolean|true",
    "hook.hooks.signature_config|jsonb|true",
    "hook.hooks.encryption_key_id|text|false",
    "hook.hooks.secret_nonce|bytea|false",
    "hook.hooks.encrypted_signing_secret|bytea|false",
    "hook.hooks.secret_generation|integer|true",
    "hook.hooks.time_zone|text|true",
    "hook.hooks.is_iam_default|boolean|true",
    "hook.hooks.created_by_kind|text|true",
    "hook.hooks.created_by_id|text|true",
    "hook.hooks.created_at|timestamp with time zone|true",
    "hook.hooks.updated_at|timestamp with time zone|true",
    "hook.hooks.disabled_at|timestamp with time zone|false",
    "hook.hooks.deleted_at|timestamp with time zone|false",
    "hook.hooks.last_received_at|timestamp with time zone|false",
    "hook.hooks.last_blocked_at|timestamp with time zone|false",
    "hook.hooks.endpoint_rotated_at|timestamp with time zone|false",
    "hook_private.retired_endpoint_keys.silicon_id|text|true",
    "hook_private.retired_endpoint_keys.endpoint_key|text|true",
    "hook_private.retired_endpoint_keys.hook_id|uuid|true",
    "hook_private.retired_endpoint_keys.retired_at|timestamp with time zone|true",
    "hook.events.id|uuid|true",
    "hook.events.hook_id|uuid|true",
    "hook.events.org_id|text|true",
    "hook.events.silicon_id|text|true",
    "hook.events.provider|text|true",
    "hook.events.summary|text|true",
    "hook.events.delivery_sequence|bigint|true",
    "hook.events.method|text|true",
    "hook.events.url|text|true",
    "hook.events.path|text|true",
    "hook.events.query_string|text|true",
    "hook.events.headers|jsonb|true",
    "hook.events.content_type|text|false",
    "hook.events.body|bytea|true",
    "hook.events.remote_ip|inet|true",
    "hook.events.received_at|timestamp with time zone|true",
    "hook.events.expires_at|timestamp with time zone|true",
    "hook.blocked_requests.id|uuid|true",
    "hook.blocked_requests.hook_id|uuid|true",
    "hook.blocked_requests.org_id|text|true",
    "hook.blocked_requests.silicon_id|text|true",
    "hook.blocked_requests.provider|text|true",
    "hook.blocked_requests.reason_code|text|true",
    "hook.blocked_requests.reason_detail|text|true",
    "hook.blocked_requests.method|text|true",
    "hook.blocked_requests.url|text|true",
    "hook.blocked_requests.path|text|true",
    "hook.blocked_requests.query_string|text|true",
    "hook.blocked_requests.headers|jsonb|true",
    "hook.blocked_requests.content_type|text|false",
    "hook.blocked_requests.body|bytea|true",
    "hook.blocked_requests.remote_ip|inet|true",
    "hook.blocked_requests.received_at|timestamp with time zone|true",
    "hook.blocked_requests.expires_at|timestamp with time zone|true",
    "hook_private.delivery_sequences.silicon_id|text|true",
    "hook_private.delivery_sequences.last_sequence|bigint|true",
    "hook_private.delivery_cursors.silicon_id|text|true",
    "hook_private.delivery_cursors.consumer_kind|text|true",
    "hook_private.delivery_cursors.consumer_id|text|true",
    "hook_private.delivery_cursors.acknowledged_through|bigint|true",
    "hook_private.delivery_cursors.updated_at|timestamp with time zone|true",
    "hook_private.ip_blocks.hook_id|uuid|true",
    "hook_private.ip_blocks.remote_ip|inet|true",
    "hook_private.ip_blocks.strikes|integer|true",
    "hook_private.ip_blocks.blocked_until|timestamp with time zone|false",
    "hook_private.ip_blocks.rejected_requests|bigint|true",
    "hook_private.ip_blocks.first_seen_at|timestamp with time zone|true",
    "hook_private.ip_blocks.updated_at|timestamp with time zone|true",
    "hook_private.management_idempotency.operation|text|true",
    "hook_private.management_idempotency.actor_kind|text|true",
    "hook_private.management_idempotency.actor_id|text|true",
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
    "hook_private.audit_log.request_id|text|false",
];

const REQUIRED_CONSTRAINTS: &[&str] = &[
    "hook.hooks.hooks_pkey|p",
    "hook.hooks.hooks_org_id_length|c",
    "hook.hooks.hooks_silicon_id_length|c",
    "hook.hooks.hooks_endpoint_key_format|c",
    "hook.hooks.hooks_name_length|c",
    "hook.hooks.hooks_description_length|c",
    "hook.hooks.hooks_signature_config_object|c",
    "hook.hooks.hooks_secret_complete|c",
    "hook.hooks.hooks_encryption_key_id_length|c",
    "hook.hooks.hooks_secret_nonce_length|c",
    "hook.hooks.hooks_encrypted_secret_length|c",
    "hook.hooks.hooks_secret_generation_positive|c",
    "hook.hooks.hooks_time_zone_format|c",
    "hook.hooks.hooks_created_by_kind|c",
    "hook.hooks.hooks_created_by_id_length|c",
    "hook.hooks.hooks_created_at_finite|c",
    "hook.hooks.hooks_updated_at_valid|c",
    "hook.hooks.hooks_disabled_at_valid|c",
    "hook.hooks.hooks_deleted_at_valid|c",
    "hook.hooks.hooks_lifecycle_timestamps_mutually_exclusive|c",
    "hook.hooks.hooks_activity_timestamps_valid|c",
    "hook.hooks.hooks_identity_unique|u",
    "hook.hooks.hooks_endpoint_key_unique|u",
    "hook_private.retired_endpoint_keys.retired_endpoint_keys_pk|p",
    "hook_private.retired_endpoint_keys.retired_endpoint_keys_silicon_id_length|c",
    "hook_private.retired_endpoint_keys.retired_endpoint_keys_format|c",
    "hook_private.retired_endpoint_keys.retired_endpoint_keys_retired_at_finite|c",
    "hook.events.events_pkey|p",
    "hook.events.events_hook_identity_fk|f",
    "hook.events.events_org_id_length|c",
    "hook.events.events_silicon_id_length|c",
    "hook.events.events_provider_length|c",
    "hook.events.events_summary_length|c",
    "hook.events.events_delivery_sequence_positive|c",
    "hook.events.events_method_token|c",
    "hook.events.events_url_length|c",
    "hook.events.events_path_length|c",
    "hook.events.events_query_string_length|c",
    "hook.events.events_headers_array|c",
    "hook.events.events_content_type_length|c",
    "hook.events.events_body_length|c",
    "hook.events.events_received_at_finite|c",
    "hook.events.events_expires_after_retention|c",
    "hook.events.events_delivery_stream_unique|u",
    "hook.blocked_requests.blocked_requests_pkey|p",
    "hook.blocked_requests.blocked_requests_hook_identity_fk|f",
    "hook.blocked_requests.blocked_requests_org_id_length|c",
    "hook.blocked_requests.blocked_requests_silicon_id_length|c",
    "hook.blocked_requests.blocked_requests_provider_length|c",
    "hook.blocked_requests.blocked_requests_reason_code_format|c",
    "hook.blocked_requests.blocked_requests_reason_detail_length|c",
    "hook.blocked_requests.blocked_requests_method_token|c",
    "hook.blocked_requests.blocked_requests_url_length|c",
    "hook.blocked_requests.blocked_requests_path_length|c",
    "hook.blocked_requests.blocked_requests_query_string_length|c",
    "hook.blocked_requests.blocked_requests_headers_array|c",
    "hook.blocked_requests.blocked_requests_content_type_length|c",
    "hook.blocked_requests.blocked_requests_body_length|c",
    "hook.blocked_requests.blocked_requests_received_at_finite|c",
    "hook.blocked_requests.blocked_requests_expires_after_retention|c",
    "hook_private.delivery_sequences.delivery_sequences_pkey|p",
    "hook_private.delivery_sequences.delivery_sequences_silicon_id_length|c",
    "hook_private.delivery_sequences.delivery_sequences_nonnegative|c",
    "hook_private.delivery_cursors.delivery_cursors_pk|p",
    "hook_private.delivery_cursors.delivery_cursors_silicon_id_length|c",
    "hook_private.delivery_cursors.delivery_cursors_consumer_kind|c",
    "hook_private.delivery_cursors.delivery_cursors_consumer_id_length|c",
    "hook_private.delivery_cursors.delivery_cursors_nonnegative|c",
    "hook_private.delivery_cursors.delivery_cursors_updated_at_finite|c",
    "hook_private.ip_blocks.ip_blocks_pk|p",
    "hook_private.ip_blocks.ip_blocks_hook_id_fkey|f",
    "hook_private.ip_blocks.ip_blocks_counters_nonnegative|c",
    "hook_private.ip_blocks.ip_blocks_timestamps_finite|c",
    "hook_private.management_idempotency.management_idempotency_pk|p",
    "hook_private.management_idempotency.management_idempotency_operation_length|c",
    "hook_private.management_idempotency.management_idempotency_actor_kind|c",
    "hook_private.management_idempotency.management_idempotency_actor_id_length|c",
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
    "hook_private.audit_log.audit_log_request_id_length|c",
    "hook_private.audit_log.audit_log_occurred_at_finite|c",
];

const REQUIRED_INDEXES: &[&str] = &[
    "hook.hooks.hooks_one_iam_default_per_silicon",
    "hook.hooks.hooks_list_active",
    "hook.hooks.hooks_deleted_retention",
    "hook.events.events_per_hook_history",
    "hook.events.events_per_silicon_history",
    "hook.events.events_expiry",
    "hook.blocked_requests.blocked_requests_per_hook_history",
    "hook.blocked_requests.blocked_requests_per_silicon_history",
    "hook.blocked_requests.blocked_requests_expiry",
    "hook_private.ip_blocks.ip_blocks_stale",
    "hook_private.management_idempotency.management_idempotency_expiry",
    "hook_private.audit_log.audit_log_resource_history",
];

const REQUIRED_TRIGGERS: &[&str] = &[
    "hook.events.events_are_immutable|hook_private.reject_row_mutation|19",
    "hook.blocked_requests.blocked_requests_are_immutable|hook_private.reject_row_mutation|19",
    "hook_private.retired_endpoint_keys.retired_endpoint_keys_are_immutable|hook_private.reject_row_mutation|27",
    "hook_private.audit_log.audit_log_is_append_only|hook_private.reject_row_mutation|27",
];

const REQUIRED_DEFAULTS: &[&str] = &[
    "hook.hooks.signature_required|true",
    "hook.hooks.secret_generation|1",
    "hook.hooks.time_zone|'UTC'::text",
    "hook.hooks.is_iam_default|false",
    "hook_private.delivery_sequences.last_sequence|0",
    "hook_private.delivery_cursors.acknowledged_through|0",
    "hook_private.ip_blocks.strikes|0",
    "hook_private.ip_blocks.rejected_requests|0",
];

const MISSING_COLUMNS_SQL: &str = "
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

const MISSING_CONSTRAINTS_SQL: &str = "
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

const MISSING_INDEXES_SQL: &str = "
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

const MISSING_TRIGGERS_SQL: &str = "
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

const MISSING_DEFAULTS_SQL: &str = "
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
    let missing: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM unnest($1::text[]) name WHERE NOT EXISTS (
            SELECT FROM pg_catalog.pg_class c JOIN pg_catalog.pg_policy p ON p.polrelid = c.oid
            WHERE c.oid = to_regclass(name) AND c.relrowsecurity AND c.relforcerowsecurity
              AND p.polname = 'environment_scope'
        ) ORDER BY name",
    )
    .bind(
        &[
            "hook.hooks",
            "hook.events",
            "hook.blocked_requests",
            "hook_private.retired_endpoint_keys",
            "hook_private.delivery_sequences",
            "hook_private.delivery_cursors",
            "hook_private.ip_blocks",
            "hook_private.management_idempotency",
            "hook_private.audit_log",
        ][..],
    )
    .fetch_all(pool)
    .await?;
    ensure_objects("environment row security", &missing)?;
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
