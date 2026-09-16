-- Shared lifecycle state is independent of IAM user sessions and survives clean.
ALTER TABLE hook_control.environments
    ADD COLUMN honeycomb_revision bigint,
    ADD COLUMN honeycomb_generation bigint,
    ADD COLUMN honeycomb_key_version bigint,
    ADD COLUMN honeycomb_operation uuid,
    ADD COLUMN honeycomb_state text CHECK (honeycomb_state IN ('pending','ready','disabled','purged'));
CREATE TABLE hook_control.lifecycle_operations (
    environment_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    input_hash bytea NOT NULL,
    receipt jsonb NOT NULL,
    PRIMARY KEY (environment_id, operation_id)
);
REVOKE ALL ON hook_control.lifecycle_operations FROM PUBLIC;

CREATE OR REPLACE FUNCTION hook_private.environment_is_available() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT hook_private.environment_id() = '00000000-0000-0000-0000-000000000000'::uuid
        OR COALESCE(current_setting('hook.clean_environment', true) = hook_private.environment_id()::text, false)
        OR EXISTS (
            SELECT FROM hook_control.environments e
            WHERE e.id = hook_private.environment_id() AND e.deleted_at IS NULL
              AND (e.honeycomb_state IS NULL OR e.honeycomb_state = 'ready')
              AND e.generation::text = current_setting('hook.environment_generation', true)
        )
$$;

-- Every test write holds the same row lock as lifecycle changes. A request
-- authorized before a clean cannot recreate rows after cleanup commits.
CREATE FUNCTION hook_private.fence_environment_write() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE target uuid := hook_private.environment_id();
DECLARE live_generation bigint;
DECLARE available boolean;
BEGIN
    IF target = '00000000-0000-0000-0000-000000000000'::uuid
       OR COALESCE(current_setting('hook.clean_environment', true) = target::text, false) THEN
        RETURN NULL;
    END IF;
    SELECT generation, deleted_at IS NULL AND (honeycomb_state IS NULL OR honeycomb_state = 'ready') INTO live_generation, available FROM hook_control.environments WHERE id = target FOR UPDATE;
    IF live_generation::text IS DISTINCT FROM current_setting('hook.environment_generation', true) OR available IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'test environment changed' USING ERRCODE = '42501';
    END IF;
    RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION hook_private.fence_environment_write() FROM PUBLIC;
DO $fences$
DECLARE relation text;
BEGIN
    FOREACH relation IN ARRAY ARRAY[
        'hook.hooks', 'hook.events', 'hook.blocked_requests',
        'hook_private.retired_endpoint_keys', 'hook_private.delivery_sequences',
        'hook_private.delivery_cursors', 'hook_private.ip_blocks',
        'hook_private.management_idempotency', 'hook_private.audit_log',
        'hook_private.contract_versions', 'hook_private.telemetry_events'
    ] LOOP
        EXECUTE format('CREATE TRIGGER fence_environment_write BEFORE INSERT OR UPDATE OR DELETE ON %s FOR EACH STATEMENT EXECUTE FUNCTION hook_private.fence_environment_write()', relation);
    END LOOP;
END
$fences$;
CREATE TABLE hook_control.activity_reports (
    environment_id uuid PRIMARY KEY REFERENCES hook_control.environments(id),
    report_id uuid NOT NULL,
    generation bigint NOT NULL,
    key_version bigint NOT NULL
);
REVOKE ALL ON hook_control.activity_reports FROM PUBLIC;
