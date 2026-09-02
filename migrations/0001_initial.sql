-- Silicon Hook's PostgreSQL 16 schema.
--
-- The `hook` schema contains the application records queried by the API. The
-- `hook_private` schema contains coordination and security-sensitive records
-- that must never be exposed by a read-only history role.

DO $migration$
BEGIN
    IF current_setting('server_version_num')::integer < 160000 THEN
        RAISE EXCEPTION 'Silicon Hook requires PostgreSQL 16 or newer';
    END IF;
END;
$migration$;

CREATE SCHEMA IF NOT EXISTS hook;
CREATE SCHEMA IF NOT EXISTS hook_private;

REVOKE ALL ON SCHEMA hook_private FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Hooks
-- ---------------------------------------------------------------------------

CREATE TABLE hook.hooks (
    id uuid PRIMARY KEY,
    org_id text NOT NULL,
    silicon_id text NOT NULL,
    endpoint_key text NOT NULL,
    name text NOT NULL,
    description text,
    signature_required boolean NOT NULL DEFAULT true,
    signature_config jsonb NOT NULL,
    encryption_key_id text,
    secret_nonce bytea,
    encrypted_signing_secret bytea,
    secret_generation integer NOT NULL DEFAULT 1,
    time_zone text NOT NULL DEFAULT 'UTC',
    is_iam_default boolean NOT NULL DEFAULT false,
    created_by_kind text NOT NULL,
    created_by_id text NOT NULL,
    created_via_app_id text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    disabled_at timestamptz,
    deleted_at timestamptz,
    last_received_at timestamptz,
    last_blocked_at timestamptz,
    endpoint_rotated_at timestamptz,

    CONSTRAINT hooks_org_id_length CHECK (
        char_length(org_id) BETWEEN 1 AND 100 AND org_id ~ '^[!-~]+$'
    ),
    CONSTRAINT hooks_silicon_id_length CHECK (
        char_length(silicon_id) BETWEEN 1 AND 255 AND silicon_id ~ '^[!-~]+$'
    ),
    CONSTRAINT hooks_endpoint_key_format CHECK (endpoint_key ~ '^[0-9A-Z]{6}$'),
    CONSTRAINT hooks_name_length CHECK (char_length(name) BETWEEN 1 AND 200),
    CONSTRAINT hooks_description_length CHECK (
        description IS NULL OR char_length(description) <= 2000
    ),
    CONSTRAINT hooks_signature_config_object CHECK (
        jsonb_typeof(signature_config) = 'object'
    ),
    CONSTRAINT hooks_secret_complete CHECK (
        (encryption_key_id IS NULL
            AND secret_nonce IS NULL
            AND encrypted_signing_secret IS NULL)
        OR (encryption_key_id IS NOT NULL
            AND secret_nonce IS NOT NULL
            AND encrypted_signing_secret IS NOT NULL)
    ),
    CONSTRAINT hooks_encryption_key_id_length CHECK (
        encryption_key_id IS NULL OR (
            char_length(encryption_key_id) BETWEEN 1 AND 64
            AND encryption_key_id ~ '^[A-Za-z0-9_-]+$'
        )
    ),
    CONSTRAINT hooks_secret_nonce_length CHECK (
        secret_nonce IS NULL OR octet_length(secret_nonce) = 12
    ),
    -- A secret is 1..4096 bytes of text plus the 16-byte AES-GCM tag.
    CONSTRAINT hooks_encrypted_secret_length CHECK (
        encrypted_signing_secret IS NULL
        OR octet_length(encrypted_signing_secret) BETWEEN 17 AND 4112
    ),
    CONSTRAINT hooks_secret_generation_positive CHECK (secret_generation > 0),
    CONSTRAINT hooks_time_zone_format CHECK (
        char_length(time_zone) BETWEEN 1 AND 64 AND time_zone ~ '^[A-Za-z0-9/_+-]+$'
    ),
    CONSTRAINT hooks_created_by_kind CHECK (
        created_by_kind IN ('carbon', 'silicon', 'application', 'service')
    ),
    CONSTRAINT hooks_created_by_id_length CHECK (
        char_length(created_by_id) BETWEEN 1 AND 255 AND created_by_id ~ '^[!-~]+$'
    ),
    CONSTRAINT hooks_created_via_app_id_length CHECK (
        created_via_app_id IS NULL OR (
            char_length(created_via_app_id) BETWEEN 1 AND 255
            AND created_via_app_id ~ '^[!-~]+$'
        )
    ),
    CONSTRAINT hooks_created_at_finite CHECK (isfinite(created_at)),
    CONSTRAINT hooks_updated_at_valid CHECK (
        isfinite(updated_at) AND updated_at >= created_at
    ),
    CONSTRAINT hooks_disabled_at_valid CHECK (
        disabled_at IS NULL OR (isfinite(disabled_at) AND disabled_at >= created_at)
    ),
    CONSTRAINT hooks_deleted_at_valid CHECK (
        deleted_at IS NULL OR (isfinite(deleted_at) AND deleted_at >= created_at)
    ),
    CONSTRAINT hooks_lifecycle_timestamps_mutually_exclusive CHECK (
        disabled_at IS NULL OR deleted_at IS NULL
    ),
    CONSTRAINT hooks_activity_timestamps_valid CHECK (
        (last_received_at IS NULL OR isfinite(last_received_at))
        AND (last_blocked_at IS NULL OR isfinite(last_blocked_at))
        AND (endpoint_rotated_at IS NULL OR (
            isfinite(endpoint_rotated_at) AND endpoint_rotated_at >= created_at
        ))
    ),
    CONSTRAINT hooks_identity_unique UNIQUE (org_id, silicon_id, id),
    CONSTRAINT hooks_endpoint_key_unique UNIQUE (silicon_id, endpoint_key)
);

CREATE UNIQUE INDEX hooks_one_iam_default_per_silicon
    ON hook.hooks (org_id, silicon_id)
    WHERE is_iam_default;

CREATE INDEX hooks_list_active
    ON hook.hooks (org_id, silicon_id, created_at DESC, id DESC)
    WHERE deleted_at IS NULL;

CREATE INDEX hooks_deleted_retention
    ON hook.hooks (deleted_at, id)
    WHERE deleted_at IS NOT NULL;

COMMENT ON COLUMN hook.hooks.signature_config IS
    'Verification scheme: algorithm, payload and signature expressions, encodings, optional public key.';
COMMENT ON COLUMN hook.hooks.encrypted_signing_secret IS
    'AES-256-GCM ciphertext of the secret text; NULL when the scheme has no shared secret.';

-- A rotated endpoint key is never reused for the same Silicon. This ledger has
-- no foreign key to the hook so it survives permanent hook purge.
CREATE TABLE hook_private.retired_endpoint_keys (
    silicon_id text NOT NULL,
    endpoint_key text NOT NULL,
    hook_id uuid NOT NULL,
    retired_at timestamptz NOT NULL,

    CONSTRAINT retired_endpoint_keys_pk PRIMARY KEY (silicon_id, endpoint_key),
    CONSTRAINT retired_endpoint_keys_silicon_id_length CHECK (
        char_length(silicon_id) BETWEEN 1 AND 255 AND silicon_id ~ '^[!-~]+$'
    ),
    CONSTRAINT retired_endpoint_keys_format CHECK (endpoint_key ~ '^[0-9A-Z]{6}$'),
    CONSTRAINT retired_endpoint_keys_retired_at_finite CHECK (isfinite(retired_at))
);

-- This lifetime ledger deliberately has no foreign key to the recoverable
-- hook row. It remains after permanent purge and prevents silent recreation
-- of IAM's one-time default connection.
CREATE TABLE hook_private.iam_hook_registrations (
    org_id text NOT NULL,
    silicon_id text NOT NULL,
    original_hook_id uuid NOT NULL,
    created_at timestamptz NOT NULL,

    CONSTRAINT iam_hook_registrations_pk PRIMARY KEY (org_id, silicon_id),
    CONSTRAINT iam_hook_registrations_org_id_length CHECK (
        char_length(org_id) BETWEEN 1 AND 100 AND org_id ~ '^[!-~]+$'
    ),
    CONSTRAINT iam_hook_registrations_silicon_id_length CHECK (
        char_length(silicon_id) BETWEEN 1 AND 255 AND silicon_id ~ '^[!-~]+$'
    ),
    CONSTRAINT iam_hook_registrations_created_at_finite CHECK (isfinite(created_at))
);

-- ---------------------------------------------------------------------------
-- Request logs
-- ---------------------------------------------------------------------------

-- Verified provider requests. Each row is also one position in the owning
-- Silicon's ordered delivery stream.
CREATE TABLE hook.events (
    id uuid PRIMARY KEY,
    hook_id uuid NOT NULL,
    org_id text NOT NULL,
    silicon_id text NOT NULL,
    provider text NOT NULL,
    summary text NOT NULL,
    delivery_sequence bigint NOT NULL,
    method text NOT NULL,
    url text NOT NULL,
    path text NOT NULL,
    query_string text NOT NULL,
    headers jsonb NOT NULL,
    content_type text,
    body bytea NOT NULL,
    remote_ip inet NOT NULL,
    received_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,

    CONSTRAINT events_hook_identity_fk
        FOREIGN KEY (org_id, silicon_id, hook_id)
        REFERENCES hook.hooks (org_id, silicon_id, id)
        ON DELETE CASCADE,
    CONSTRAINT events_org_id_length CHECK (
        char_length(org_id) BETWEEN 1 AND 100 AND org_id ~ '^[!-~]+$'
    ),
    CONSTRAINT events_silicon_id_length CHECK (
        char_length(silicon_id) BETWEEN 1 AND 255 AND silicon_id ~ '^[!-~]+$'
    ),
    CONSTRAINT events_provider_length CHECK (char_length(provider) BETWEEN 1 AND 200),
    CONSTRAINT events_summary_length CHECK (char_length(summary) BETWEEN 1 AND 400),
    CONSTRAINT events_delivery_sequence_positive CHECK (delivery_sequence > 0),
    CONSTRAINT events_method_token CHECK (
        char_length(method) BETWEEN 1 AND 32 AND method ~ '^[!#$%&''*+.^_`|~0-9A-Za-z-]+$'
    ),
    CONSTRAINT events_url_length CHECK (char_length(url) BETWEEN 1 AND 16384),
    CONSTRAINT events_path_length CHECK (char_length(path) BETWEEN 1 AND 4096),
    CONSTRAINT events_query_string_length CHECK (char_length(query_string) <= 8192),
    CONSTRAINT events_headers_array CHECK (jsonb_typeof(headers) = 'array'),
    CONSTRAINT events_content_type_length CHECK (
        content_type IS NULL OR char_length(content_type) <= 255
    ),
    CONSTRAINT events_body_length CHECK (octet_length(body) <= 1048576),
    CONSTRAINT events_received_at_finite CHECK (isfinite(received_at)),
    CONSTRAINT events_expires_after_retention CHECK (
        expires_at = received_at + INTERVAL '14 days'
    ),
    CONSTRAINT events_delivery_stream_unique UNIQUE (silicon_id, delivery_sequence)
);

CREATE INDEX events_per_hook_history
    ON hook.events (hook_id, received_at DESC, id DESC);

CREATE INDEX events_per_silicon_history
    ON hook.events (org_id, silicon_id, received_at DESC, id DESC);

CREATE INDEX events_expiry
    ON hook.events (expires_at, id);

-- Requests withheld from delivery because they could not be verified.
CREATE TABLE hook.blocked_requests (
    id uuid PRIMARY KEY,
    hook_id uuid NOT NULL,
    org_id text NOT NULL,
    silicon_id text NOT NULL,
    provider text NOT NULL,
    reason_code text NOT NULL,
    reason_detail text NOT NULL,
    method text NOT NULL,
    url text NOT NULL,
    path text NOT NULL,
    query_string text NOT NULL,
    headers jsonb NOT NULL,
    content_type text,
    body bytea NOT NULL,
    remote_ip inet NOT NULL,
    received_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,

    CONSTRAINT blocked_requests_hook_identity_fk
        FOREIGN KEY (org_id, silicon_id, hook_id)
        REFERENCES hook.hooks (org_id, silicon_id, id)
        ON DELETE CASCADE,
    CONSTRAINT blocked_requests_org_id_length CHECK (
        char_length(org_id) BETWEEN 1 AND 100 AND org_id ~ '^[!-~]+$'
    ),
    CONSTRAINT blocked_requests_silicon_id_length CHECK (
        char_length(silicon_id) BETWEEN 1 AND 255 AND silicon_id ~ '^[!-~]+$'
    ),
    CONSTRAINT blocked_requests_provider_length CHECK (
        char_length(provider) BETWEEN 1 AND 200
    ),
    CONSTRAINT blocked_requests_reason_code_format CHECK (
        char_length(reason_code) BETWEEN 1 AND 64 AND reason_code ~ '^[a-z0-9_]+$'
    ),
    CONSTRAINT blocked_requests_reason_detail_length CHECK (
        char_length(reason_detail) <= 500 AND reason_detail !~ '[[:cntrl:]]'
    ),
    CONSTRAINT blocked_requests_method_token CHECK (
        char_length(method) BETWEEN 1 AND 32 AND method ~ '^[!#$%&''*+.^_`|~0-9A-Za-z-]+$'
    ),
    CONSTRAINT blocked_requests_url_length CHECK (char_length(url) BETWEEN 1 AND 16384),
    CONSTRAINT blocked_requests_path_length CHECK (char_length(path) BETWEEN 1 AND 4096),
    CONSTRAINT blocked_requests_query_string_length CHECK (
        char_length(query_string) <= 8192
    ),
    CONSTRAINT blocked_requests_headers_array CHECK (jsonb_typeof(headers) = 'array'),
    CONSTRAINT blocked_requests_content_type_length CHECK (
        content_type IS NULL OR char_length(content_type) <= 255
    ),
    CONSTRAINT blocked_requests_body_length CHECK (octet_length(body) <= 1048576),
    CONSTRAINT blocked_requests_received_at_finite CHECK (isfinite(received_at)),
    CONSTRAINT blocked_requests_expires_after_retention CHECK (
        expires_at = received_at + INTERVAL '14 days'
    )
);

CREATE INDEX blocked_requests_per_hook_history
    ON hook.blocked_requests (hook_id, received_at DESC, id DESC);

CREATE INDEX blocked_requests_per_silicon_history
    ON hook.blocked_requests (org_id, silicon_id, received_at DESC, id DESC);

CREATE INDEX blocked_requests_expiry
    ON hook.blocked_requests (expires_at, id);

-- ---------------------------------------------------------------------------
-- Delivery coordination
-- ---------------------------------------------------------------------------

-- One monotonic counter per Silicon. The row is locked while an event is
-- accepted so sequences are dense and never reused.
CREATE TABLE hook_private.delivery_sequences (
    silicon_id text PRIMARY KEY,
    last_sequence bigint NOT NULL DEFAULT 0,

    CONSTRAINT delivery_sequences_silicon_id_length CHECK (
        char_length(silicon_id) BETWEEN 1 AND 255 AND silicon_id ~ '^[!-~]+$'
    ),
    CONSTRAINT delivery_sequences_nonnegative CHECK (last_sequence >= 0)
);

-- Highest sequence each consumer has acknowledged for a Silicon stream.
CREATE TABLE hook_private.delivery_cursors (
    silicon_id text NOT NULL,
    consumer_kind text NOT NULL,
    consumer_id text NOT NULL,
    acknowledged_through bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL,

    CONSTRAINT delivery_cursors_pk PRIMARY KEY (silicon_id, consumer_kind, consumer_id),
    CONSTRAINT delivery_cursors_silicon_id_length CHECK (
        char_length(silicon_id) BETWEEN 1 AND 255 AND silicon_id ~ '^[!-~]+$'
    ),
    CONSTRAINT delivery_cursors_consumer_kind CHECK (
        consumer_kind IN ('carbon', 'silicon', 'application', 'service')
    ),
    CONSTRAINT delivery_cursors_consumer_id_length CHECK (
        char_length(consumer_id) BETWEEN 1 AND 255 AND consumer_id ~ '^[!-~]+$'
    ),
    CONSTRAINT delivery_cursors_nonnegative CHECK (acknowledged_through >= 0),
    CONSTRAINT delivery_cursors_updated_at_finite CHECK (isfinite(updated_at))
);

-- ---------------------------------------------------------------------------
-- Abuse control
-- ---------------------------------------------------------------------------

CREATE TABLE hook_private.ip_blocks (
    hook_id uuid NOT NULL
        REFERENCES hook.hooks (id)
        ON DELETE CASCADE,
    remote_ip inet NOT NULL,
    strikes integer NOT NULL DEFAULT 0,
    blocks integer NOT NULL DEFAULT 0,
    blocked_until timestamptz,
    permanent boolean NOT NULL DEFAULT false,
    rejected_requests bigint NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,

    CONSTRAINT ip_blocks_pk PRIMARY KEY (hook_id, remote_ip),
    CONSTRAINT ip_blocks_counters_nonnegative CHECK (
        strikes >= 0 AND blocks >= 0 AND rejected_requests >= 0
    ),
    CONSTRAINT ip_blocks_permanent_has_no_deadline CHECK (
        NOT permanent OR blocked_until IS NULL
    ),
    CONSTRAINT ip_blocks_timestamps_finite CHECK (
        isfinite(first_seen_at)
        AND isfinite(updated_at)
        AND (blocked_until IS NULL OR isfinite(blocked_until))
    )
);

CREATE INDEX ip_blocks_stale
    ON hook_private.ip_blocks (updated_at)
    WHERE NOT permanent;

-- ---------------------------------------------------------------------------
-- Management idempotency and audit
-- ---------------------------------------------------------------------------

CREATE TABLE hook_private.management_idempotency (
    operation text NOT NULL,
    actor_kind text NOT NULL,
    actor_id text NOT NULL,
    calling_app_id text NOT NULL DEFAULT '',
    org_id text NOT NULL,
    target_id text NOT NULL,
    idempotency_key text NOT NULL,
    request_digest bytea NOT NULL,
    response_status smallint,
    resource_id uuid,
    response_secret_key_id text,
    response_secret_nonce bytea,
    response_encrypted_secret bytea,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    secret_replay_until timestamptz,

    CONSTRAINT management_idempotency_pk PRIMARY KEY (
        operation,
        actor_kind,
        actor_id,
        calling_app_id,
        org_id,
        target_id,
        idempotency_key
    ),
    CONSTRAINT management_idempotency_operation_length CHECK (
        char_length(operation) BETWEEN 1 AND 100
        AND operation ~ '^[a-z0-9_.-]+$'
    ),
    CONSTRAINT management_idempotency_actor_kind CHECK (
        actor_kind IN ('carbon', 'silicon', 'application', 'service')
    ),
    CONSTRAINT management_idempotency_actor_id_length CHECK (
        char_length(actor_id) BETWEEN 1 AND 255 AND actor_id ~ '^[!-~]+$'
    ),
    CONSTRAINT management_idempotency_calling_app_id CHECK (
        calling_app_id = '' OR (
            char_length(calling_app_id) BETWEEN 1 AND 255
            AND calling_app_id ~ '^[!-~]+$'
        )
    ),
    CONSTRAINT management_idempotency_org_id_length CHECK (
        char_length(org_id) BETWEEN 1 AND 100 AND org_id ~ '^[!-~]+$'
    ),
    CONSTRAINT management_idempotency_target_id_length CHECK (
        char_length(target_id) BETWEEN 1 AND 512 AND target_id ~ '^[!-~]+$'
    ),
    CONSTRAINT management_idempotency_key_length CHECK (
        char_length(idempotency_key) BETWEEN 8 AND 255
        AND idempotency_key ~ '^[!-~]+$'
    ),
    CONSTRAINT management_idempotency_digest_length CHECK (
        octet_length(request_digest) = 32
    ),
    CONSTRAINT management_idempotency_response_status CHECK (
        response_status IS NULL OR response_status BETWEEN 100 AND 599
    ),
    CONSTRAINT management_idempotency_reservation_empty CHECK (
        response_status IS NOT NULL OR (
            resource_id IS NULL
            AND response_secret_key_id IS NULL
            AND response_secret_nonce IS NULL
            AND response_encrypted_secret IS NULL
            AND secret_replay_until IS NULL
        )
    ),
    CONSTRAINT management_idempotency_secret_complete CHECK (
        (response_secret_key_id IS NULL
            AND response_secret_nonce IS NULL
            AND response_encrypted_secret IS NULL
            AND secret_replay_until IS NULL)
        OR (response_secret_key_id IS NOT NULL
            AND response_secret_nonce IS NOT NULL
            AND response_encrypted_secret IS NOT NULL
            AND secret_replay_until IS NOT NULL)
    ),
    CONSTRAINT management_idempotency_secret_key_id_length CHECK (
        response_secret_key_id IS NULL
        OR (
            char_length(response_secret_key_id) BETWEEN 1 AND 64
            AND response_secret_key_id ~ '^[A-Za-z0-9_-]+$'
        )
    ),
    CONSTRAINT management_idempotency_secret_nonce_length CHECK (
        response_secret_nonce IS NULL OR octet_length(response_secret_nonce) = 12
    ),
    CONSTRAINT management_idempotency_secret_ciphertext_length CHECK (
        response_encrypted_secret IS NULL
        OR octet_length(response_encrypted_secret) BETWEEN 17 AND 4112
    ),
    CONSTRAINT management_idempotency_timestamps CHECK (
        isfinite(created_at)
        AND isfinite(expires_at)
        AND expires_at = created_at + INTERVAL '24 hours'
        AND (secret_replay_until IS NULL OR (
            isfinite(secret_replay_until)
            AND secret_replay_until = created_at + INTERVAL '10 minutes'
        ))
    )
);

CREATE INDEX management_idempotency_expiry
    ON hook_private.management_idempotency (expires_at);

COMMENT ON TABLE hook_private.management_idempotency IS
    'Idempotent result metadata; plaintext signing secrets are forbidden.';
COMMENT ON COLUMN hook_private.management_idempotency.response_encrypted_secret IS
    'AEAD ciphertext only. The signing secret is never persisted as response JSON.';

CREATE TABLE hook_private.audit_log (
    id uuid PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    action text NOT NULL,
    org_id text NOT NULL,
    silicon_id text NOT NULL,
    hook_id uuid,
    actor_kind text NOT NULL,
    actor_id text NOT NULL,
    calling_app_id text,
    request_id text,

    CONSTRAINT audit_log_action CHECK (
        action IN (
            'hook.created',
            'hook.updated',
            'hook.disabled',
            'hook.enabled',
            'hook.deleted',
            'hook.restored',
            'hook.secret_rotated',
            'hook.endpoint_rotated',
            'hook.iam_provisioned'
        )
    ),
    CONSTRAINT audit_log_org_id_length CHECK (
        char_length(org_id) BETWEEN 1 AND 100 AND org_id ~ '^[!-~]+$'
    ),
    CONSTRAINT audit_log_silicon_id_length CHECK (
        char_length(silicon_id) BETWEEN 1 AND 255 AND silicon_id ~ '^[!-~]+$'
    ),
    CONSTRAINT audit_log_actor_kind CHECK (
        actor_kind IN ('carbon', 'silicon', 'application', 'service')
    ),
    CONSTRAINT audit_log_actor_id_length CHECK (
        char_length(actor_id) BETWEEN 1 AND 255 AND actor_id ~ '^[!-~]+$'
    ),
    CONSTRAINT audit_log_calling_app_id_length CHECK (
        calling_app_id IS NULL OR (
            char_length(calling_app_id) BETWEEN 1 AND 255
            AND calling_app_id ~ '^[!-~]+$'
        )
    ),
    CONSTRAINT audit_log_request_id_length CHECK (
        request_id IS NULL OR (
            char_length(request_id) BETWEEN 1 AND 255
            AND request_id ~ '^[!-~]+$'
        )
    ),
    CONSTRAINT audit_log_occurred_at_finite CHECK (isfinite(occurred_at))
);

CREATE INDEX audit_log_resource_history
    ON hook_private.audit_log (org_id, silicon_id, occurred_at DESC, id DESC);

COMMENT ON TABLE hook_private.audit_log IS
    'Append-only attribution. Free-form payload, credential, and authorization data are intentionally absent.';

-- ---------------------------------------------------------------------------
-- Immutability
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION hook_private.reject_row_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER events_are_immutable
    BEFORE UPDATE ON hook.events
    FOR EACH ROW
    EXECUTE FUNCTION hook_private.reject_row_mutation();

CREATE TRIGGER blocked_requests_are_immutable
    BEFORE UPDATE ON hook.blocked_requests
    FOR EACH ROW
    EXECUTE FUNCTION hook_private.reject_row_mutation();

CREATE TRIGGER retired_endpoint_keys_are_immutable
    BEFORE UPDATE OR DELETE ON hook_private.retired_endpoint_keys
    FOR EACH ROW
    EXECUTE FUNCTION hook_private.reject_row_mutation();

CREATE TRIGGER iam_hook_registrations_are_immutable
    BEFORE UPDATE OR DELETE ON hook_private.iam_hook_registrations
    FOR EACH ROW
    EXECUTE FUNCTION hook_private.reject_row_mutation();

CREATE TRIGGER audit_log_is_append_only
    BEFORE UPDATE OR DELETE ON hook_private.audit_log
    FOR EACH ROW
    EXECUTE FUNCTION hook_private.reject_row_mutation();
