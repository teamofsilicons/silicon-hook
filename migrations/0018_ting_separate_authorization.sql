-- Login sessions are never converted into endpoint authority.
CREATE TABLE hook_private.ting_authorizations (
  environment_id uuid NOT NULL DEFAULT hook_private.environment_id(),
  generation bigint NOT NULL, app_id text NOT NULL, org_id text NOT NULL,
  actor_kind text NOT NULL CHECK(actor_kind IN ('carbon','silicon')), actor_id text NOT NULL,
  authorization_id uuid NOT NULL, expires_at timestamptz NOT NULL,
  start_key text NOT NULL, start_payload jsonb NOT NULL CHECK(jsonb_typeof(start_payload)='object'),
  UNIQUE(environment_id,generation,app_id,org_id,actor_kind,actor_id,start_key),
  completion_digest bytea CHECK(completion_digest IS NULL OR octet_length(completion_digest)=32),
  PRIMARY KEY(environment_id,generation,app_id,org_id,actor_kind,actor_id,authorization_id)
);
CREATE TABLE hook_private.ting_obo_credentials (
  environment_id uuid NOT NULL DEFAULT hook_private.environment_id(),
  generation bigint NOT NULL, app_id text NOT NULL, org_id text NOT NULL,
  actor_kind text NOT NULL CHECK(actor_kind IN ('carbon','silicon')), actor_id text NOT NULL,
  endpoint_id text NOT NULL CHECK(endpoint_id IN ('subscriptions.register','tings.send','sent.query','receivers.bootstrap')),
  grant_id uuid NOT NULL, sealed jsonb NOT NULL CHECK(jsonb_typeof(sealed)='object'),
  PRIMARY KEY(environment_id,generation,app_id,org_id,actor_kind,actor_id,endpoint_id)
);
ALTER TABLE hook_private.ting_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE hook_private.ting_authorizations FORCE ROW LEVEL SECURITY;
ALTER TABLE hook_private.ting_obo_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE hook_private.ting_obo_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY environment_scope ON hook_private.ting_authorizations
USING (environment_id=hook_private.environment_id() AND hook_private.environment_is_available())
WITH CHECK (environment_id=hook_private.environment_id() AND hook_private.environment_is_available());
CREATE POLICY environment_scope ON hook_private.ting_obo_credentials
USING (environment_id=hook_private.environment_id() AND hook_private.environment_is_available())
WITH CHECK (environment_id=hook_private.environment_id() AND hook_private.environment_is_available());
-- Grant writes need to exclude lifecycle changes, not each other. A shared
-- lifecycle fence avoids upgrading a shared outer delivery lock to exclusive
-- while another caller waits for the same account's advisory grant lock.
CREATE FUNCTION hook_private.fence_ting_authorization_write() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE target uuid := hook_private.environment_id();
DECLARE live_generation bigint;
DECLARE available boolean;
BEGIN
 IF target='00000000-0000-0000-0000-000000000000'::uuid
 OR COALESCE(current_setting('hook.clean_environment',true)=target::text,false) THEN RETURN NULL; END IF;
 SELECT generation,deleted_at IS NULL AND (honeycomb_state IS NULL OR honeycomb_state='ready')
 INTO live_generation,available FROM hook_control.environments WHERE id=target FOR SHARE;
 IF live_generation::text IS DISTINCT FROM current_setting('hook.environment_generation',true) OR available IS DISTINCT FROM true THEN
 RAISE EXCEPTION 'test environment changed' USING ERRCODE='42501'; END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION hook_private.fence_ting_authorization_write() FROM PUBLIC;
CREATE TRIGGER fence_environment_write BEFORE INSERT OR UPDATE OR DELETE ON hook_private.ting_authorizations
FOR EACH STATEMENT EXECUTE FUNCTION hook_private.fence_ting_authorization_write();
CREATE TRIGGER fence_environment_write BEFORE INSERT OR UPDATE OR DELETE ON hook_private.ting_obo_credentials
FOR EACH STATEMENT EXECUTE FUNCTION hook_private.fence_ting_authorization_write();
REVOKE ALL ON hook_private.ting_authorizations, hook_private.ting_obo_credentials FROM PUBLIC;
-- Keep the existing cleaner behavior, adding the new private state before generation advances.
DO $$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('hook_control.clean_environment(uuid)'::regprocedure) INTO definition;
 definition := replace(definition, 'DELETE FROM hook_private.ting_publisher_credentials WHERE environment_id = target;',
 'DELETE FROM hook_private.ting_authorizations WHERE environment_id = target;
 DELETE FROM hook_private.ting_obo_credentials WHERE environment_id = target;
 DELETE FROM hook_private.ting_publisher_credentials WHERE environment_id = target;');
 IF position('DELETE FROM hook_private.ting_obo_credentials' IN definition)=0 THEN
 RAISE EXCEPTION 'cleaner did not contain expected publisher cleanup'; END IF;
 EXECUTE definition;
END $$;
REVOKE ALL ON FUNCTION hook_control.clean_environment(uuid) FROM PUBLIC;

COMMENT ON COLUMN hook_private.ting_outbox.request_body IS
 'Exact UTF-8 operation bytes and stable producer key. Separately approved reusable IAM OBO authority is verified by Ting for every attempt.';
