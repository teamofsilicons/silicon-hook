-- Control-plane retries survive resets. Responses contain public metadata;
-- one-time credentials are protected with the environment's encryption AAD.
CREATE TABLE hook_control.mutation_results (
    environment_id uuid NOT NULL REFERENCES hook_control.environments(id) ON DELETE CASCADE,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    input_hash bytea NOT NULL CHECK (octet_length(input_hash) = 32),
    metadata jsonb NOT NULL,
    encrypted_credentials jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (environment_id, request_hash)
);
CREATE INDEX mutation_results_retention ON hook_control.mutation_results (created_at);
REVOKE ALL ON hook_control.mutation_results FROM PUBLIC;
