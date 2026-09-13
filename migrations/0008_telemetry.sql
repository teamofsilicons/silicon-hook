-- Hook-owned event store. No dependency on an external telemetry service.
CREATE TABLE hook_private.telemetry_events (
    environment_id uuid NOT NULL DEFAULT hook_private.environment_id(),
    event_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    source text NOT NULL CHECK (source IN ('backend','worker','cli','daemon','client','web')),
    step text NOT NULL,
    trace_id uuid NOT NULL,
    subject_hash text,
    exported_at timestamptz,
    data jsonb NOT NULL CHECK (jsonb_typeof(data) = 'object' AND octet_length(data::text) <= 8192),
    PRIMARY KEY(environment_id, event_id)
);
CREATE INDEX telemetry_retention ON hook_private.telemetry_events(environment_id, recorded_at);
CREATE INDEX telemetry_outbox ON hook_private.telemetry_events(environment_id, recorded_at) WHERE exported_at IS NULL;
CREATE INDEX telemetry_trace ON hook_private.telemetry_events(environment_id, trace_id, recorded_at);
ALTER TABLE hook_private.telemetry_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE hook_private.telemetry_events FORCE ROW LEVEL SECURITY;
CREATE POLICY telemetry_environment ON hook_private.telemetry_events
    USING (environment_id = hook_private.environment_id() AND hook_private.environment_is_available())
    WITH CHECK (environment_id = hook_private.environment_id() AND hook_private.environment_is_available());
REVOKE ALL ON hook_private.telemetry_events FROM PUBLIC;
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
    -- Keep routing tombstones during reset; old provider URLs must never reach
    -- a subsequently created hook, even if an endpoint generator collides.
    UPDATE hook_control.environments SET generation = generation + 1,
        last_activity_at = clock_timestamp() WHERE id = target RETURNING generation INTO new_generation;
    RETURN new_generation;
END
$$;
REVOKE ALL ON FUNCTION hook_control.clean_environment(uuid) FROM PUBLIC;
