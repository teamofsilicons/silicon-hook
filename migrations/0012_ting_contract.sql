-- v2 delivers through Ting; v1 keeps its existing transport while deprecated.
-- Existing deprecation dates and sunset decisions must never be reset.
ALTER TABLE hook_private.contract_versions
    DROP CONSTRAINT contract_versions_major_check;
ALTER TABLE hook_private.contract_versions
    ADD CONSTRAINT contract_versions_major_check CHECK (major IN ('v1', 'v2'));

UPDATE hook_private.contract_versions
SET status = 'deprecated', deprecated_at = COALESCE(deprecated_at, clock_timestamp())
WHERE major = 'v1' AND status = 'active';

CREATE OR REPLACE FUNCTION hook_private.contract_status(selected_major text, record_request boolean)
RETURNS TABLE (status text, deprecated_at timestamptz, last_requested_at timestamptz, request_count bigint, sunset_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE current_row hook_private.contract_versions%ROWTYPE;
BEGIN
    IF selected_major NOT IN ('v1', 'v2') OR NOT hook_private.environment_is_available() THEN RETURN; END IF;
    INSERT INTO hook_private.contract_versions (environment_id, major, status, deprecated_at)
        VALUES (hook_private.environment_id(), selected_major,
                CASE WHEN selected_major = 'v1' THEN 'deprecated' ELSE 'active' END,
                CASE WHEN selected_major = 'v1' THEN clock_timestamp() ELSE NULL END)
        ON CONFLICT DO NOTHING;
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
