-- One shared test database uses the same application schema and code as
-- production. Its pools pin a test UUID and generation for their entire life.
-- The zero UUID is reserved for production and is never a test environment.
CREATE SCHEMA hook_control;
REVOKE ALL ON SCHEMA hook_control FROM PUBLIC;

CREATE TABLE hook_control.environments (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    org_id text NOT NULL,
    creator_kind text NOT NULL CHECK (creator_kind IN ('carbon', 'silicon')),
    creator_id text NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    description text CHECK (char_length(description) <= 2000),
    key_hash bytea NOT NULL UNIQUE CHECK (octet_length(key_hash) = 32),
    iam_key_hash bytea NOT NULL UNIQUE CHECK (octet_length(iam_key_hash) = 32),
    creation_request_hash bytea NOT NULL UNIQUE,
    creation_input_hash bytea NOT NULL,
    encrypted_credentials jsonb NOT NULL,
    generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_activity_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_maintained_at timestamptz,
    deleted_at timestamptz
);
CREATE INDEX environments_by_org ON hook_control.environments (org_id, created_at DESC, id);
CREATE INDEX environments_retention ON hook_control.environments (deleted_at, last_activity_at);

-- This routing ledger is deliberately outside row-level filtering: it maps a
-- public test endpoint to exactly one environment before choosing its pool.
-- It contains no request bodies or credentials and prevents cross-environment
-- endpoint reuse, including after a hook has been rotated or permanently purged.
CREATE TABLE hook_control.endpoint_routes (
    silicon_id text NOT NULL,
    endpoint_key text NOT NULL,
    environment_id uuid NOT NULL REFERENCES hook_control.environments(id) ON DELETE CASCADE,
    hook_id uuid NOT NULL,
    PRIMARY KEY (silicon_id, endpoint_key)
);

CREATE FUNCTION hook_private.environment_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
    SELECT COALESCE(NULLIF(current_setting('hook.environment_id', true), ''),
        '00000000-0000-0000-0000-000000000000')::uuid
$$;

CREATE FUNCTION hook_private.environment_is_available() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT hook_private.environment_id() = '00000000-0000-0000-0000-000000000000'::uuid
        OR current_setting('hook.clean_environment', true) = hook_private.environment_id()::text
        OR EXISTS (
            SELECT FROM hook_control.environments e
            WHERE e.id = hook_private.environment_id() AND e.deleted_at IS NULL
              AND e.generation::text = current_setting('hook.environment_generation', true)
        )
$$;
REVOKE ALL ON FUNCTION hook_private.environment_is_available() FROM PUBLIC;

DO $scope$
DECLARE relation text;
BEGIN
    FOREACH relation IN ARRAY ARRAY[
        'hook.hooks', 'hook.events', 'hook.blocked_requests',
        'hook_private.retired_endpoint_keys', 'hook_private.delivery_sequences',
        'hook_private.delivery_cursors', 'hook_private.ip_blocks',
        'hook_private.management_idempotency', 'hook_private.audit_log'
    ] LOOP
        EXECUTE format('ALTER TABLE %s ADD COLUMN environment_id uuid NOT NULL DEFAULT hook_private.environment_id()', relation);
        EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', relation);
        EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', relation);
        EXECUTE format('CREATE POLICY environment_scope ON %s USING (environment_id = hook_private.environment_id() AND hook_private.environment_is_available()) WITH CHECK (environment_id = hook_private.environment_id() AND hook_private.environment_is_available())', relation);
        EXECUTE format('CREATE INDEX ON %s (environment_id)', relation);
    END LOOP;
END
$scope$;

ALTER TABLE hook_private.delivery_sequences DROP CONSTRAINT delivery_sequences_pkey;
ALTER TABLE hook_private.delivery_sequences ADD CONSTRAINT delivery_sequences_pkey PRIMARY KEY (environment_id, silicon_id);
ALTER TABLE hook_private.delivery_cursors DROP CONSTRAINT delivery_cursors_pk;
ALTER TABLE hook_private.delivery_cursors ADD CONSTRAINT delivery_cursors_pk PRIMARY KEY (environment_id, silicon_id, consumer_kind, consumer_id);
ALTER TABLE hook_private.management_idempotency DROP CONSTRAINT management_idempotency_pk;
ALTER TABLE hook_private.management_idempotency ADD CONSTRAINT management_idempotency_pk PRIMARY KEY (
    environment_id, operation, actor_kind, actor_id, org_id, target_id, idempotency_key
);
ALTER TABLE hook.events DROP CONSTRAINT events_delivery_stream_unique;
ALTER TABLE hook.events ADD CONSTRAINT events_delivery_stream_unique UNIQUE (environment_id, silicon_id, delivery_sequence);
DROP INDEX hook.hooks_one_iam_default_per_silicon;
CREATE UNIQUE INDEX hooks_one_iam_default_per_silicon ON hook.hooks (environment_id, org_id, silicon_id) WHERE is_iam_default;

-- The environment lock serializes the ten-hook quota across all Silicons and
-- serializes hook creation with reset/deletion. Retained deleted hooks still
-- count until permanently removed, so delete/restore cannot evade the quota.
CREATE FUNCTION hook_private.guard_test_hook() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE live_generation bigint;
BEGIN
    IF NEW.environment_id = '00000000-0000-0000-0000-000000000000'::uuid THEN RETURN NEW; END IF;
    SELECT generation INTO live_generation FROM hook_control.environments
        WHERE id = NEW.environment_id AND deleted_at IS NULL FOR UPDATE;
    IF live_generation IS NULL OR live_generation::text IS DISTINCT FROM current_setting('hook.environment_generation', true) THEN
        RAISE EXCEPTION 'test environment is inactive or reset' USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'INSERT' AND (SELECT count(*) FROM hook.hooks WHERE environment_id = NEW.environment_id) >= 10 THEN
        RAISE EXCEPTION 'test environments are limited to ten hooks' USING ERRCODE = '23514', CONSTRAINT = 'test_environment_hook_limit';
    END IF;
    IF EXISTS (SELECT FROM hook_control.endpoint_routes WHERE silicon_id = NEW.silicon_id AND endpoint_key = NEW.endpoint_key AND hook_id <> NEW.id) THEN
        RAISE EXCEPTION 'endpoint was already allocated' USING ERRCODE = '23505', CONSTRAINT = 'hooks_endpoint_key_unique';
    END IF;
    INSERT INTO hook_control.endpoint_routes (silicon_id, endpoint_key, environment_id, hook_id)
        VALUES (NEW.silicon_id, NEW.endpoint_key, NEW.environment_id, NEW.id)
        ON CONFLICT (silicon_id, endpoint_key) DO NOTHING;
    RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION hook_private.guard_test_hook() FROM PUBLIC;
CREATE TRIGGER guard_test_hook BEFORE INSERT OR UPDATE ON hook.hooks
    FOR EACH ROW EXECUTE FUNCTION hook_private.guard_test_hook();

-- Append-only history remains immutable outside an explicit environment reset.
CREATE OR REPLACE FUNCTION hook_private.reject_row_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.environment_id <> '00000000-0000-0000-0000-000000000000'::uuid
        AND current_setting('hook.clean_environment', true) = OLD.environment_id::text THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'rows in % are immutable', TG_TABLE_NAME USING ERRCODE = '55000';
END
$$;

-- This function is granted only to backend roles. HTTP authorization is checked
-- before it is invoked. The pinned generation invalidates old pools/WebSockets
-- after reset so old ACKs cannot acknowledge a new stream with reused sequences.
CREATE FUNCTION hook_control.clean_environment(target uuid) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE new_generation bigint;
BEGIN
    IF target = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'production cannot be cleaned' USING ERRCODE = '42501';
    END IF;
    PERFORM 1 FROM hook_control.environments WHERE id = target FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'environment missing' USING ERRCODE = 'P0002'; END IF;
    PERFORM set_config('hook.environment_id', target::text, true);
    PERFORM set_config('hook.clean_environment', target::text, true);
    DELETE FROM hook.events WHERE environment_id = target;
    DELETE FROM hook.blocked_requests WHERE environment_id = target;
    DELETE FROM hook_private.ip_blocks WHERE environment_id = target;
    DELETE FROM hook.hooks WHERE environment_id = target;
    DELETE FROM hook_private.retired_endpoint_keys WHERE environment_id = target;
    DELETE FROM hook_private.delivery_sequences WHERE environment_id = target;
    DELETE FROM hook_private.delivery_cursors WHERE environment_id = target;
    DELETE FROM hook_private.management_idempotency WHERE environment_id = target;
    DELETE FROM hook_private.audit_log WHERE environment_id = target;
    -- Keep routing tombstones during reset; old provider URLs must never reach
    -- a subsequently created hook, even if an endpoint generator collides.
    UPDATE hook_control.environments SET generation = generation + 1,
        last_activity_at = clock_timestamp() WHERE id = target RETURNING generation INTO new_generation;
    RETURN new_generation;
END
$$;
REVOKE ALL ON FUNCTION hook_control.clean_environment(uuid) FROM PUBLIC;
