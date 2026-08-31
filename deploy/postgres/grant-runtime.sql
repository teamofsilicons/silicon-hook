-- Apply after every migration as the schema owner. Invoke with:
--   psql "$HOOK_MIGRATOR_DATABASE_URL" \
--     --set=api_role=... --set=worker_role=... \
--     --file=deploy/postgres/grant-runtime.sql
\set ON_ERROR_STOP on

\if :{?api_role}
\else
  \echo 'api_role is required'
  \quit 3
\endif
\if :{?worker_role}
\else
  \echo 'worker_role is required'
  \quit 3
\endif

SELECT :'api_role' <> :'worker_role' AS roles_are_distinct \gset
\if :roles_are_distinct
\else
  \echo 'api_role and worker_role must be distinct'
  \quit 3
\endif

SELECT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = :'api_role')
    AS api_role_exists \gset
\if :api_role_exists
\else
  \echo 'api_role does not exist'
  \quit 3
\endif
SELECT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = :'worker_role')
    AS worker_role_exists \gset
\if :worker_role_exists
\else
  \echo 'worker_role does not exist'
  \quit 3
\endif

SELECT format(
    'GRANT CONNECT ON DATABASE %I TO %I, %I',
    current_database(),
    :'api_role',
    :'worker_role'
) \gexec

REVOKE ALL PRIVILEGES ON SCHEMA hook, hook_private
    FROM :"api_role", :"worker_role";
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA hook, hook_private
    FROM :"api_role", :"worker_role";
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA hook, hook_private
    FROM :"api_role", :"worker_role";
REVOKE ALL PRIVILEGES ON TABLE public._sqlx_migrations
    FROM :"api_role", :"worker_role";

GRANT USAGE ON SCHEMA hook, hook_private
    TO :"api_role", :"worker_role";
GRANT SELECT ON TABLE public._sqlx_migrations
    TO :"api_role", :"worker_role";

GRANT SELECT, INSERT, UPDATE ON TABLE hook.hooks TO :"api_role";
GRANT SELECT, INSERT ON TABLE hook.events TO :"api_role";
GRANT SELECT, INSERT
    ON TABLE hook_private.ingress_idempotency
    TO :"api_role";
GRANT SELECT, INSERT, DELETE
    ON TABLE hook_private.ingress_authenticated_requests
    TO :"api_role";
GRANT INSERT
    ON TABLE hook_private.iam_hook_registrations
    TO :"api_role";
GRANT SELECT, INSERT ON TABLE hook_private.dm_outbox TO :"api_role";
GRANT SELECT, INSERT, UPDATE, DELETE
    ON TABLE hook_private.management_idempotency
    TO :"api_role";
GRANT INSERT ON TABLE hook_private.audit_log TO :"api_role";

GRANT SELECT, DELETE ON TABLE hook.hooks, hook.events TO :"worker_role";
GRANT SELECT, UPDATE
    ON TABLE hook_private.event_retention_state
    TO :"worker_role";
GRANT SELECT, UPDATE, DELETE
    ON TABLE hook_private.dm_outbox
    TO :"worker_role";
GRANT SELECT, DELETE
    ON TABLE hook_private.management_idempotency
    TO :"worker_role";

-- Trigger functions are not application APIs, but explicit EXECUTE grants keep
-- runtime behavior independent of PostgreSQL's default PUBLIC function grant.
REVOKE ALL PRIVILEGES ON FUNCTION hook_private.reject_row_mutation() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION hook_private.protect_dm_outbox_payload() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION hook_private.track_event_retention_inserts() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION hook_private.track_event_retention_deletes() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hook_private.protect_dm_outbox_payload()
    TO :"worker_role";
GRANT EXECUTE ON FUNCTION hook_private.track_event_retention_inserts()
    TO :"api_role";
GRANT EXECUTE ON FUNCTION hook_private.track_event_retention_deletes()
    TO :"worker_role";
