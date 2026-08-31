-- Development-only login bootstrap used by Docker Compose. Production role
-- creation belongs to the platform's secret and identity provisioning system.
CREATE ROLE silicon_hook_api
    LOGIN PASSWORD 'silicon_hook_api'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;

CREATE ROLE silicon_hook_worker
    LOGIN PASSWORD 'silicon_hook_worker'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
