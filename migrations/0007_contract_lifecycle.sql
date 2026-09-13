-- Operational contract lifecycle state, not telemetry. No request contents,
-- credentials, actors or addresses are collected. Sandboxes have separate rows.
CREATE TABLE hook_private.contract_versions (
    environment_id uuid NOT NULL DEFAULT hook_private.environment_id(),
    major text NOT NULL CHECK (major = 'v1'),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','deprecated','sunset')),
    deprecated_at timestamptz,
    last_requested_at timestamptz,
    request_count bigint NOT NULL DEFAULT 0,
    sunset_at timestamptz,
    PRIMARY KEY (environment_id, major)
);
ALTER TABLE hook_private.contract_versions ENABLE ROW LEVEL SECURITY;
CREATE POLICY contract_environment ON hook_private.contract_versions
    USING (environment_id = hook_private.environment_id())
    WITH CHECK (environment_id = hook_private.environment_id());

CREATE FUNCTION hook_private.contract_status(selected_major text, record_request boolean)
RETURNS TABLE (status text, deprecated_at timestamptz, last_requested_at timestamptz, request_count bigint, sunset_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE current_row hook_private.contract_versions%ROWTYPE;
BEGIN
    IF selected_major <> 'v1' OR NOT hook_private.environment_is_available() THEN RETURN; END IF;
    INSERT INTO hook_private.contract_versions (environment_id, major)
        VALUES (hook_private.environment_id(), selected_major) ON CONFLICT DO NOTHING;
    SELECT * INTO current_row FROM hook_private.contract_versions c
        WHERE c.environment_id = hook_private.environment_id() AND c.major = selected_major FOR UPDATE;
    IF current_row.status = 'deprecated' AND
        GREATEST(current_row.deprecated_at, current_row.last_requested_at) <= clock_timestamp() - INTERVAL '7 days' THEN
        current_row.status := 'sunset';
        current_row.sunset_at := clock_timestamp();
        UPDATE hook_private.contract_versions c SET status = 'sunset', sunset_at = current_row.sunset_at
            WHERE c.environment_id = current_row.environment_id AND c.major = selected_major;
    END IF;
    IF record_request AND current_row.status <> 'sunset' THEN
        UPDATE hook_private.contract_versions c SET last_requested_at = clock_timestamp(), request_count = c.request_count + 1
            WHERE c.environment_id = current_row.environment_id AND c.major = selected_major RETURNING * INTO current_row;
    END IF;
    RETURN QUERY SELECT current_row.status, current_row.deprecated_at, current_row.last_requested_at, current_row.request_count, current_row.sunset_at;
END $$;
REVOKE ALL ON FUNCTION hook_private.contract_status(text, boolean) FROM PUBLIC;

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
    -- Keep routing tombstones during reset; old provider URLs must never reach
    -- a subsequently created hook, even if an endpoint generator collides.
    UPDATE hook_control.environments SET generation = generation + 1,
        last_activity_at = clock_timestamp() WHERE id = target RETURNING generation INTO new_generation;
    RETURN new_generation;
END
$$;
REVOKE ALL ON FUNCTION hook_control.clean_environment(uuid) FROM PUBLIC;
