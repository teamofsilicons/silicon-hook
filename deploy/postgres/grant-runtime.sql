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

-- API: management, ingress, history, and realtime delivery.
GRANT SELECT, INSERT, UPDATE ON TABLE hook.hooks TO :"api_role";
GRANT SELECT, INSERT ON TABLE hook.events TO :"api_role";
GRANT SELECT, INSERT ON TABLE hook.blocked_requests TO :"api_role";
GRANT SELECT, INSERT ON TABLE hook_private.retired_endpoint_keys TO :"api_role";
GRANT SELECT, INSERT, UPDATE ON TABLE hook_private.delivery_sequences TO :"api_role";
GRANT SELECT, INSERT, UPDATE ON TABLE hook_private.delivery_cursors TO :"api_role";
GRANT SELECT, INSERT, UPDATE ON TABLE hook_private.ip_blocks TO :"api_role";
GRANT SELECT, INSERT, UPDATE, DELETE
    ON TABLE hook_private.management_idempotency
    TO :"api_role";
GRANT INSERT ON TABLE hook_private.audit_log TO :"api_role";

-- Worker: retention maintenance only.
GRANT SELECT, DELETE ON TABLE hook.hooks, hook.events, hook.blocked_requests
    TO :"worker_role";
GRANT SELECT, DELETE ON TABLE hook_private.ip_blocks TO :"worker_role";
GRANT SELECT, DELETE ON TABLE hook_private.management_idempotency TO :"worker_role";

-- Trigger functions are not application APIs; keep them off PUBLIC.
REVOKE ALL PRIVILEGES ON FUNCTION hook_private.reject_row_mutation() FROM PUBLIC;
