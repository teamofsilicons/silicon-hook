-- An unset maintenance override is NULL. Coalesce it so an unavailable test
-- generation returns false instead of NULL (and can close streams with 4001).
CREATE OR REPLACE FUNCTION hook_private.environment_is_available() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT hook_private.environment_id() = '00000000-0000-0000-0000-000000000000'::uuid
        OR COALESCE(
            current_setting('hook.clean_environment', true) = hook_private.environment_id()::text,
            false
        )
        OR EXISTS (
            SELECT FROM hook_control.environments e
            WHERE e.id = hook_private.environment_id() AND e.deleted_at IS NULL
              AND e.generation::text = current_setting('hook.environment_generation', true)
        )
$$;
