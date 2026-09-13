-- IAM remains the authority; these values only bind isolated Hook storage.
ALTER TABLE hook_control.environments
    ADD COLUMN iam_environment_id uuid UNIQUE,
    ADD COLUMN iam_version bigint,
    ADD COLUMN iam_cleaned_at timestamptz;

-- Sandboxes use the same hook capacity as production.
CREATE OR REPLACE FUNCTION hook_private.guard_test_hook() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE live_generation bigint;
BEGIN
    IF NEW.environment_id = '00000000-0000-0000-0000-000000000000'::uuid THEN RETURN NEW; END IF;
    SELECT generation INTO live_generation FROM hook_control.environments
        WHERE id = NEW.environment_id AND deleted_at IS NULL FOR UPDATE;
    IF live_generation IS NULL OR live_generation::text IS DISTINCT FROM current_setting('hook.environment_generation', true) THEN
        RAISE EXCEPTION 'test environment is inactive or reset' USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'INSERT' AND (SELECT iam_environment_id IS NULL FROM hook_control.environments WHERE id = NEW.environment_id)
        AND (SELECT count(*) FROM hook.hooks WHERE environment_id = NEW.environment_id) >= 10 THEN
        RAISE EXCEPTION 'legacy test environments are limited to ten hooks' USING ERRCODE = '23514', CONSTRAINT = 'test_environment_hook_limit';
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
