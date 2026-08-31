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

CREATE TABLE hook.hooks (
    id uuid PRIMARY KEY,
    org_id text NOT NULL,
    silicon_id text NOT NULL,
    endpoint_key text NOT NULL,
    name text NOT NULL,
    description text,
    created_by_kind text NOT NULL,
    created_by_id text NOT NULL,
    created_via_app_id text,
    encryption_key_id text NOT NULL,
    secret_nonce bytea NOT NULL,
    encrypted_signing_secret bytea NOT NULL,
    secret_generation integer NOT NULL DEFAULT 1,
    is_iam_default boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,

    CONSTRAINT hooks_org_id_length CHECK (
        char_length(org_id) BETWEEN 1 AND 100 AND org_id ~ '^[!-~]+$'
    ),
    CONSTRAINT hooks_silicon_id_length CHECK (
        char_length(silicon_id) BETWEEN 1 AND 255 AND silicon_id ~ '^[!-~]+$'
    ),
    CONSTRAINT hooks_endpoint_key_format CHECK (endpoint_key ~ '^[0-9A-F]{6}$'),
    CONSTRAINT hooks_name_length CHECK (char_length(name) BETWEEN 1 AND 200),
    CONSTRAINT hooks_description_length CHECK (
        description IS NULL OR char_length(description) <= 2000
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
    CONSTRAINT hooks_encryption_key_id_length CHECK (
        char_length(encryption_key_id) BETWEEN 1 AND 64
        AND encryption_key_id ~ '^[A-Za-z0-9_-]+$'
    ),
    CONSTRAINT hooks_secret_nonce_length CHECK (octet_length(secret_nonce) = 12),
    CONSTRAINT hooks_encrypted_secret_length CHECK (
        octet_length(encrypted_signing_secret) = 48
    ),
    CONSTRAINT hooks_secret_generation_positive CHECK (secret_generation > 0),
    CONSTRAINT hooks_created_at_finite CHECK (isfinite(created_at)),
    CONSTRAINT hooks_updated_at_finite CHECK (isfinite(updated_at)),
    CONSTRAINT hooks_deleted_at_valid CHECK (
        deleted_at IS NULL OR (isfinite(deleted_at) AND deleted_at >= created_at)
    ),
    CONSTRAINT hooks_updated_at_valid CHECK (updated_at >= created_at),
    CONSTRAINT hooks_identity_unique UNIQUE (org_id, silicon_id, id),
    CONSTRAINT hooks_endpoint_key_unique UNIQUE (silicon_id, endpoint_key)
);

-- This secondary invariant prevents duplicates while the recoverable row is
-- present; the lifetime ledger below remains authoritative after hard purge.
CREATE UNIQUE INDEX hooks_one_iam_default_per_silicon
    ON hook.hooks (org_id, silicon_id)
    WHERE is_iam_default;

CREATE INDEX hooks_list_active
    ON hook.hooks (org_id, silicon_id, created_at DESC, id DESC)
    WHERE deleted_at IS NULL;

CREATE INDEX hooks_deleted_retention
    ON hook.hooks (deleted_at, id)
    WHERE deleted_at IS NOT NULL;

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

CREATE TABLE hook.events (
    id uuid PRIMARY KEY,
    hook_id uuid NOT NULL,
    org_id text NOT NULL,
    silicon_id text NOT NULL,
    event_type text NOT NULL,
    source text,
    subject text,
    occurred_at timestamptz NOT NULL,
    schema_version text NOT NULL,
    trace_id text NOT NULL,
    payload jsonb NOT NULL,
    request_digest bytea NOT NULL,
    received_at timestamptz NOT NULL,
    replay_protected_until timestamptz NOT NULL DEFAULT (
        clock_timestamp() + INTERVAL '10 minutes'
    ),

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
    CONSTRAINT events_type_format CHECK (
        char_length(event_type) BETWEEN 1 AND 200
        AND event_type ~ '^[a-z0-9_.-]+$'
    ),
    CONSTRAINT events_source_length CHECK (
        source IS NULL OR (
            char_length(source) <= 500 AND source !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT events_subject_length CHECK (
        subject IS NULL OR (
            char_length(subject) <= 500 AND subject !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT events_schema_version_length CHECK (
        char_length(schema_version) BETWEEN 1 AND 50 AND schema_version ~ '^[!-~]+$'
    ),
    CONSTRAINT events_trace_id_length CHECK (
        char_length(trace_id) <= 255 AND trace_id ~ '^[!-~]*$'
    ),
    CONSTRAINT events_payload_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT events_request_digest_length CHECK (octet_length(request_digest) = 32),
    CONSTRAINT events_occurred_at_finite CHECK (isfinite(occurred_at)),
    CONSTRAINT events_received_at_finite CHECK (isfinite(received_at)),
    CONSTRAINT events_replay_protected_until_finite CHECK (
        isfinite(replay_protected_until)
    ),
    CONSTRAINT events_hook_id_unique UNIQUE (hook_id, id)
);

CREATE INDEX events_per_hook_history
    ON hook.events (hook_id, received_at DESC, id DESC);

CREATE INDEX events_per_hook_replay_deadline
    ON hook.events (hook_id, replay_protected_until, id);

CREATE INDEX events_per_silicon_history
    ON hook.events (org_id, silicon_id, received_at DESC, id DESC);

CREATE INDEX events_per_silicon_type_history
    ON hook.events (org_id, silicon_id, event_type, received_at DESC, id DESC);

-- The counter makes retention discovery proportional to overfull hooks rather
-- than to the complete event table. It is maintained transactionally by the
-- statement triggers below and is never a public API record.
CREATE TABLE hook_private.event_retention_state (
    hook_id uuid PRIMARY KEY
        REFERENCES hook.hooks (id)
        ON DELETE CASCADE,
    event_count bigint NOT NULL,
    maintenance_due_at timestamptz,

    CONSTRAINT event_retention_state_count_nonnegative CHECK (event_count >= 0),
    CONSTRAINT event_retention_state_due_at_finite CHECK (
        maintenance_due_at IS NULL OR isfinite(maintenance_due_at)
    ),
    CONSTRAINT event_retention_state_queue_consistent CHECK (
        (event_count > 10000) = (maintenance_due_at IS NOT NULL)
    )
);

CREATE INDEX event_retention_state_due
    ON hook_private.event_retention_state (maintenance_due_at, hook_id)
    WHERE maintenance_due_at IS NOT NULL;

CREATE TABLE hook_private.ingress_idempotency (
    hook_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    request_digest bytea NOT NULL,
    event_id uuid NOT NULL,
    created_at timestamptz NOT NULL,

    CONSTRAINT ingress_idempotency_pk PRIMARY KEY (hook_id, idempotency_key),
    CONSTRAINT ingress_idempotency_event_fk
        FOREIGN KEY (hook_id, event_id)
        REFERENCES hook.events (hook_id, id)
        ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ingress_idempotency_key_length CHECK (
        char_length(idempotency_key) BETWEEN 8 AND 255
        AND idempotency_key ~ '^[!-~]+$'
    ),
    CONSTRAINT ingress_idempotency_digest_length CHECK (
        octet_length(request_digest) = 32
    ),
    CONSTRAINT ingress_idempotency_created_at_finite CHECK (isfinite(created_at))
);

-- The replay guard is separate from caller key bindings. Multiple keys may
-- safely alias one authenticated request while every key remains permanently
-- content-bound for the lifetime of the retained event.
CREATE TABLE hook_private.ingress_authenticated_requests (
    hook_id uuid NOT NULL,
    authenticated_request_digest bytea NOT NULL,
    request_digest bytea NOT NULL,
    event_id uuid NOT NULL,
    created_at timestamptz NOT NULL,

    CONSTRAINT ingress_authenticated_requests_pk PRIMARY KEY (
        hook_id,
        authenticated_request_digest
    ),
    CONSTRAINT ingress_authenticated_requests_event_unique UNIQUE (event_id),
    CONSTRAINT ingress_authenticated_requests_event_fk
        FOREIGN KEY (hook_id, event_id)
        REFERENCES hook.events (hook_id, id)
        ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT ingress_authenticated_requests_authenticated_digest_length CHECK (
        octet_length(authenticated_request_digest) = 32
    ),
    CONSTRAINT ingress_authenticated_requests_request_digest_length CHECK (
        octet_length(request_digest) = 32
    ),
    CONSTRAINT ingress_authenticated_requests_created_at_finite CHECK (
        isfinite(created_at)
    )
);

-- DM delivery deliberately has no foreign key to retained event history or to
-- hooks. Accepted work survives history eviction and permanent hook purging.
CREATE TABLE hook_private.dm_outbox (
    event_id uuid PRIMARY KEY,
    org_id text NOT NULL,
    silicon_id text NOT NULL,
    request_body bytea NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    attempts integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL,
    lease_token uuid,
    leased_until timestamptz,
    last_attempt_at timestamptz,
    delivered_at timestamptz,
    failed_at timestamptz,
    failure_reason text,
    last_http_status smallint,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,

    CONSTRAINT dm_outbox_org_id_length CHECK (
        char_length(org_id) BETWEEN 1 AND 100 AND org_id ~ '^[!-~]+$'
    ),
    CONSTRAINT dm_outbox_silicon_id_length CHECK (
        char_length(silicon_id) BETWEEN 1 AND 255 AND silicon_id ~ '^[!-~]+$'
    ),
    CONSTRAINT dm_outbox_body_length CHECK (
        octet_length(request_body) BETWEEN 2 AND 1114112
    ),
    CONSTRAINT dm_outbox_status CHECK (
        status IN ('pending', 'retrying', 'delivered', 'failed')
    ),
    CONSTRAINT dm_outbox_attempts_nonnegative CHECK (attempts >= 0),
    CONSTRAINT dm_outbox_failure_reason_length CHECK (
        failure_reason IS NULL OR (
            char_length(failure_reason) <= 2000
            AND failure_reason !~ '[[:cntrl:]]'
        )
    ),
    CONSTRAINT dm_outbox_http_status CHECK (
        last_http_status IS NULL OR last_http_status BETWEEN 100 AND 599
    ),
    CONSTRAINT dm_outbox_timestamps_finite CHECK (
        isfinite(available_at)
        AND isfinite(created_at)
        AND isfinite(updated_at)
        AND (leased_until IS NULL OR isfinite(leased_until))
        AND (last_attempt_at IS NULL OR isfinite(last_attempt_at))
        AND (delivered_at IS NULL OR isfinite(delivered_at))
        AND (failed_at IS NULL OR isfinite(failed_at))
    ),
    CONSTRAINT dm_outbox_lease_consistent CHECK (
        (lease_token IS NULL) = (leased_until IS NULL)
    ),
    CONSTRAINT dm_outbox_terminal_state_consistent CHECK (
        (status = 'delivered' AND delivered_at IS NOT NULL AND failed_at IS NULL)
        OR (status = 'failed' AND failed_at IS NOT NULL AND delivered_at IS NULL)
        OR (
            status IN ('pending', 'retrying')
            AND delivered_at IS NULL
            AND failed_at IS NULL
        )
    ),
    CONSTRAINT dm_outbox_terminal_not_leased CHECK (
        status IN ('pending', 'retrying') OR lease_token IS NULL
    ),
    CONSTRAINT dm_outbox_created_updated_order CHECK (updated_at >= created_at)
);

CREATE INDEX dm_outbox_due_jobs
    ON hook_private.dm_outbox (available_at, event_id)
    WHERE status IN ('pending', 'retrying');

CREATE INDEX dm_outbox_terminal_retention
    ON hook_private.dm_outbox (updated_at, event_id)
    WHERE status IN ('delivered', 'failed');

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
        OR octet_length(response_encrypted_secret) = 48
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
            'hook.deleted',
            'hook.restored',
            'hook.secret_rotated',
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

CREATE OR REPLACE FUNCTION hook_private.reject_row_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME
        USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION hook_private.protect_dm_outbox_payload()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.event_id IS DISTINCT FROM OLD.event_id
        OR NEW.org_id IS DISTINCT FROM OLD.org_id
        OR NEW.silicon_id IS DISTINCT FROM OLD.silicon_id
        OR NEW.request_body IS DISTINCT FROM OLD.request_body
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION 'DM outbox delivery payload is immutable'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION hook_private.track_event_retention_inserts()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    INSERT INTO hook_private.event_retention_state AS retention (
        hook_id,
        event_count,
        maintenance_due_at
    )
    SELECT inserted.hook_id,
           count(*)::bigint,
           CASE WHEN count(*) > 10000 THEN clock_timestamp() ELSE NULL END
    FROM inserted_events AS inserted
    GROUP BY inserted.hook_id
    ON CONFLICT (hook_id) DO UPDATE
    SET event_count = retention.event_count + EXCLUDED.event_count,
        maintenance_due_at = CASE
            WHEN retention.event_count + EXCLUDED.event_count > 10000
            THEN COALESCE(retention.maintenance_due_at, clock_timestamp())
            ELSE NULL
        END;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION hook_private.track_event_retention_deletes()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    UPDATE hook_private.event_retention_state AS retention
    SET event_count = retention.event_count - removed.removed_count,
        maintenance_due_at = CASE
            WHEN retention.event_count - removed.removed_count > 10000
            THEN retention.maintenance_due_at
            ELSE NULL
        END
    FROM (
        SELECT deleted.hook_id, count(*)::bigint AS removed_count
        FROM deleted_events AS deleted
        GROUP BY deleted.hook_id
    ) AS removed
    WHERE retention.hook_id = removed.hook_id;
    RETURN NULL;
END;
$$;

CREATE TRIGGER events_are_immutable
    BEFORE UPDATE ON hook.events
    FOR EACH ROW
    EXECUTE FUNCTION hook_private.reject_row_mutation();

CREATE TRIGGER events_track_retention_inserts
    AFTER INSERT ON hook.events
    REFERENCING NEW TABLE AS inserted_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION hook_private.track_event_retention_inserts();

CREATE TRIGGER events_track_retention_deletes
    AFTER DELETE ON hook.events
    REFERENCING OLD TABLE AS deleted_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION hook_private.track_event_retention_deletes();

CREATE TRIGGER ingress_idempotency_is_immutable
    BEFORE UPDATE ON hook_private.ingress_idempotency
    FOR EACH ROW
    EXECUTE FUNCTION hook_private.reject_row_mutation();

CREATE TRIGGER ingress_authenticated_requests_are_immutable
    BEFORE UPDATE ON hook_private.ingress_authenticated_requests
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

CREATE TRIGGER dm_outbox_payload_is_immutable
    BEFORE UPDATE ON hook_private.dm_outbox
    FOR EACH ROW
    EXECUTE FUNCTION hook_private.protect_dm_outbox_payload();
