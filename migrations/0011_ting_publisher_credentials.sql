-- A publisher owns a separate Hook IAM session. Neither recipient sessions nor
-- the configuring administrator's refresh-token family are stored here.
CREATE TABLE hook_private.ting_publisher_credentials (
    environment_id uuid NOT NULL DEFAULT hook_private.environment_id(),
    environment_generation bigint NOT NULL DEFAULT (
        CASE WHEN hook_private.environment_id() = '00000000-0000-0000-0000-000000000000'::uuid
             THEN 0 ELSE current_setting('hook.environment_generation')::bigint END
    ),
    org_id text NOT NULL CHECK (octet_length(org_id) BETWEEN 1 AND 255),
    id uuid NOT NULL UNIQUE,
    provision_request_hash bytea NOT NULL CHECK (octet_length(provision_request_hash) = 32),
    provision_input_hash bytea NOT NULL CHECK (octet_length(provision_input_hash) = 32),
    encrypted_credentials jsonb NOT NULL CHECK (jsonb_typeof(encrypted_credentials) = 'object'),
    actor_id text CHECK (octet_length(actor_id) BETWEEN 1 AND 255),
    expires_at timestamptz,
    validated boolean NOT NULL DEFAULT false,
    rejected boolean NOT NULL DEFAULT false,
    operation_key uuid,
    operation_started_at timestamptz,
    lease_id uuid,
    lease_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (environment_id, org_id),
    CHECK ((environment_id = '00000000-0000-0000-0000-000000000000'::uuid AND environment_generation = 0)
        OR (environment_id <> '00000000-0000-0000-0000-000000000000'::uuid AND environment_generation > 0)),
    CHECK ((operation_key IS NULL) = (operation_started_at IS NULL)),
    CHECK ((lease_id IS NULL) = (lease_until IS NULL)),
    CHECK ((actor_id IS NULL) = (expires_at IS NULL)),
    CHECK (NOT validated OR (actor_id IS NOT NULL AND NOT rejected)),
    CHECK (isfinite(created_at) AND isfinite(updated_at)
        AND (expires_at IS NULL OR isfinite(expires_at))
        AND (operation_started_at IS NULL OR isfinite(operation_started_at))
        AND (lease_until IS NULL OR isfinite(lease_until)))
);
ALTER TABLE hook_private.ting_publisher_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE hook_private.ting_publisher_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY environment_scope ON hook_private.ting_publisher_credentials
    USING (environment_id = hook_private.environment_id() AND hook_private.environment_is_available())
    WITH CHECK (environment_id = hook_private.environment_id() AND hook_private.environment_is_available());
CREATE TRIGGER fence_environment_write
    BEFORE INSERT OR UPDATE OR DELETE ON hook_private.ting_publisher_credentials
    FOR EACH STATEMENT EXECUTE FUNCTION hook_private.fence_environment_write();
REVOKE ALL ON hook_private.ting_publisher_credentials FROM PUBLIC;
COMMENT ON TABLE hook_private.ting_publisher_credentials IS
    'Encrypted dedicated publisher SLT/session with durable exchange keys and fenced leases. Never accepts an existing caller refresh family.';

CREATE OR REPLACE FUNCTION hook_control.clean_environment(target uuid) RETURNS bigint
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
    DELETE FROM hook_private.ting_publisher_credentials WHERE environment_id = target;
    -- Removing events also removes their Ting outbox rows through the foreign key.
    DELETE FROM hook.events WHERE environment_id = target;
    DELETE FROM hook.blocked_requests WHERE environment_id = target;
    DELETE FROM hook_private.ip_blocks WHERE environment_id = target;
    DELETE FROM hook.hooks WHERE environment_id = target;
    DELETE FROM hook_private.retired_endpoint_keys WHERE environment_id = target;
    DELETE FROM hook_private.delivery_sequences WHERE environment_id = target;
    DELETE FROM hook_private.delivery_cursors WHERE environment_id = target;
    DELETE FROM hook_private.management_idempotency WHERE environment_id = target;
    DELETE FROM hook_private.audit_log WHERE environment_id = target;
    DELETE FROM hook_private.contract_versions WHERE environment_id = target;
    DELETE FROM hook_private.telemetry_events WHERE environment_id = target;
    -- Endpoint routing tombstones must survive a clean.
    UPDATE hook_control.environments SET generation = generation + 1,
        last_activity_at = clock_timestamp() WHERE id = target RETURNING generation INTO new_generation;
    RETURN new_generation;
END
$$;
REVOKE ALL ON FUNCTION hook_control.clean_environment(uuid) FROM PUBLIC;
