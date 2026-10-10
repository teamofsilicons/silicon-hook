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

REVOKE ALL PRIVILEGES ON SCHEMA hook, hook_private, hook_control
    FROM :"api_role", :"worker_role";
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA hook, hook_private, hook_control
    FROM :"api_role", :"worker_role";
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA hook, hook_private, hook_control
    FROM :"api_role", :"worker_role";
REVOKE ALL PRIVILEGES ON TABLE public._sqlx_migrations
    FROM :"api_role", :"worker_role";
-- Table-level REVOKE above does not remove old column-level grants.
REVOKE ALL PRIVILEGES (
    id, environment_id, environment_generation, event_id, org_id, silicon_id,
    recipient_id, idempotency_key, request_body, created_at, expires_at,
    next_attempt_at, attempts, last_attempt_at, last_error_code, lease_id,
    lease_until, accepted_at, ting_id, silent, recipient_binding_id,
    observer_subscription_id
) ON TABLE hook_private.ting_outbox FROM :"api_role", :"worker_role";
REVOKE ALL PRIVILEGES (
    environment_id, environment_generation, org_id, id, provision_request_hash,
    provision_input_hash, encrypted_credentials, actor_id, expires_at, validated,
    rejected, operation_key, operation_started_at, lease_id, lease_until,
    created_at, updated_at
) ON TABLE hook_private.ting_publisher_credentials FROM :"api_role", :"worker_role";
REVOKE ALL PRIVILEGES (
    id, environment_id, org_id, silicon_id, recipient_id, created_at,
    encrypted_authority, authority_version
) ON TABLE hook_private.ting_recipient_bindings FROM :"api_role", :"worker_role";

-- Tables kept from Hook before 1.0 (publisher credentials, delegated Ting
-- grants, the earlier observer bindings, delivery cursors and hook_control)
-- hold data but are no longer used: no runtime role reads them.

GRANT USAGE ON SCHEMA hook, hook_private
    TO :"api_role", :"worker_role";
GRANT SELECT ON TABLE public._sqlx_migrations
    TO :"api_role", :"worker_role";

-- API: management, ingress, history, the Accounts webhook and Ting publication.
GRANT SELECT, INSERT, UPDATE ON TABLE hook.hooks TO :"api_role";
GRANT SELECT, INSERT ON TABLE hook.events TO :"api_role";
GRANT SELECT, INSERT ON TABLE hook.blocked_requests TO :"api_role";
GRANT SELECT, INSERT ON TABLE hook_private.retired_endpoint_keys TO :"api_role";
GRANT SELECT, INSERT, UPDATE ON TABLE hook_private.delivery_sequences TO :"api_role";
GRANT SELECT, INSERT, UPDATE ON TABLE hook_private.ip_blocks TO :"api_role";
GRANT SELECT, INSERT, UPDATE, DELETE
    ON TABLE hook_private.management_idempotency
    TO :"api_role";
GRANT INSERT ON TABLE hook_private.audit_log TO :"api_role";

-- Silicon Accounts identities, grants, allow-lists and webhook deduplication.
GRANT SELECT, INSERT, UPDATE ON TABLE hook_private.accounts,
    hook_private.account_ids TO :"api_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE hook_private.silicon_grants,
    hook_private.silicon_allowances TO :"api_role";
GRANT SELECT, INSERT ON TABLE hook_private.accounts_events TO :"api_role";
GRANT SELECT, INSERT, DELETE ON TABLE hook_private.observer_subscriptions TO :"api_role";

-- Ting publication runs in the API process. It may advance a send's progress
-- but never rewrite its prepared body, producer key or recipient. Event cleanup
-- cascades to outbox rows.
GRANT SELECT, INSERT ON TABLE hook_private.ting_outbox TO :"api_role";
GRANT UPDATE (
    next_attempt_at, attempts, last_attempt_at, last_error_code, lease_id,
    lease_until, accepted_at, ting_id, silent
) ON TABLE hook_private.ting_outbox TO :"api_role";

-- Worker: retention maintenance only.
GRANT SELECT, DELETE ON TABLE hook.hooks, hook.events, hook.blocked_requests
    TO :"worker_role";
GRANT SELECT, DELETE ON TABLE hook_private.ip_blocks TO :"worker_role";
GRANT SELECT, DELETE ON TABLE hook_private.management_idempotency TO :"worker_role";
GRANT SELECT, DELETE ON TABLE hook_private.accounts_events TO :"worker_role";

-- Trigger functions are not application APIs; keep them off PUBLIC.
REVOKE ALL PRIVILEGES ON FUNCTION hook_private.reject_row_mutation() FROM PUBLIC;

-- Row-level policy functions (every production row has the nil environment).
GRANT EXECUTE ON FUNCTION hook_private.environment_id(), hook_private.environment_is_available()
    TO :"api_role", :"worker_role";

GRANT INSERT ON hook_private.telemetry_events TO :"api_role", :"worker_role";
GRANT SELECT, DELETE ON hook_private.telemetry_events TO :"worker_role";
GRANT UPDATE (exported_at) ON hook_private.telemetry_events TO :"worker_role";
GRANT EXECUTE ON FUNCTION hook_private.contract_status(text, boolean) TO :"api_role", :"worker_role";

GRANT SELECT ON hook_private.accounts_uuid128_map TO :"api_role";
