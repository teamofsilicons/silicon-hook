-- Deleting a sandbox must not make one of its public URLs allocatable again.
-- Keep only the reservation after permanent deletion, without a reference to
-- the removed environment or any of its credentials/data.
ALTER TABLE hook_control.endpoint_routes
    ALTER COLUMN environment_id DROP NOT NULL;
ALTER TABLE hook_control.endpoint_routes
    DROP CONSTRAINT endpoint_routes_environment_id_fkey;
ALTER TABLE hook_control.endpoint_routes
    ADD CONSTRAINT endpoint_routes_environment_id_fkey
    FOREIGN KEY (environment_id) REFERENCES hook_control.environments(id) ON DELETE SET NULL;
