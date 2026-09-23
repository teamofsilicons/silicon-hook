-- Ting sends are committed with verified Hook events. This migration deliberately
-- leaves historical events alone: only explicitly enqueued new events are sent.
ALTER TABLE hook.events ADD CONSTRAINT events_ting_identity_unique
    UNIQUE (environment_id, org_id, silicon_id, id, expires_at);

CREATE TABLE hook_private.ting_outbox (
    id uuid PRIMARY KEY,
    environment_id uuid NOT NULL DEFAULT hook_private.environment_id(),
    environment_generation bigint NOT NULL DEFAULT (
        CASE WHEN hook_private.environment_id() = '00000000-0000-0000-0000-000000000000'::uuid
             THEN 0 ELSE current_setting('hook.environment_generation')::bigint END
    ),
    event_id uuid NOT NULL,
    org_id text NOT NULL,
    silicon_id text NOT NULL,
    recipient_id text NOT NULL,
    idempotency_key text NOT NULL,
    request_body bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    attempts bigint NOT NULL DEFAULT 0,
    last_attempt_at timestamptz,
    last_error_code text,
    lease_id uuid,
    lease_until timestamptz,
    accepted_at timestamptz,
    ting_id text,
    silent boolean,

    CONSTRAINT ting_outbox_event_fk FOREIGN KEY (environment_id, org_id, silicon_id, event_id, expires_at)
        REFERENCES hook.events (environment_id, org_id, silicon_id, id, expires_at) ON DELETE CASCADE,
    CONSTRAINT ting_outbox_event_recipient_unique UNIQUE (environment_id, event_id, recipient_id),
    CONSTRAINT ting_outbox_key_unique UNIQUE (environment_id, org_id, idempotency_key),
    CONSTRAINT ting_outbox_generation_valid CHECK (
        (environment_id = '00000000-0000-0000-0000-000000000000'::uuid AND environment_generation = 0)
        OR (environment_id <> '00000000-0000-0000-0000-000000000000'::uuid AND environment_generation > 0)
    ),
    CONSTRAINT ting_outbox_recipient_valid CHECK (
        octet_length(recipient_id) BETWEEN 1 AND 255 AND recipient_id ~ '^[!-~]+$'
    ),
    CONSTRAINT ting_outbox_key_valid CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 200 AND idempotency_key !~ '[[:cntrl:]]'
    ),
    CONSTRAINT ting_outbox_body_valid CHECK (octet_length(request_body) BETWEEN 1 AND 262144),
    CONSTRAINT ting_outbox_attempts_nonnegative CHECK (attempts >= 0),
    CONSTRAINT ting_outbox_error_safe CHECK (last_error_code IN (
        'authorization_unavailable', 'consent_required', 'recipient_not_registered',
        'transport_unavailable', 'rate_limited', 'ting_unavailable',
        'request_rejected', 'invalid_response', 'publisher_not_configured',
        'publisher_unavailable', 'publisher_unauthorized', 'ting_unauthorized',
        'type_not_registered', 'idempotency_conflict', 'environment_changed'
    )),
    CONSTRAINT ting_outbox_lease_complete CHECK (
        (lease_id IS NULL AND lease_until IS NULL)
        OR (lease_id IS NOT NULL AND lease_until IS NOT NULL)
    ),
    CONSTRAINT ting_outbox_acceptance_complete CHECK (
        (accepted_at IS NULL AND ting_id IS NULL AND silent IS NULL)
        OR (accepted_at IS NOT NULL AND ting_id IS NOT NULL AND silent IS NOT NULL
            AND lease_id IS NULL AND last_error_code IS NULL)
    ),
    CONSTRAINT ting_outbox_ting_id_valid CHECK (
        ting_id IS NULL OR (octet_length(ting_id) BETWEEN 1 AND 255 AND ting_id ~ '^[!-~]+$')
    ),
    CONSTRAINT ting_outbox_times_finite CHECK (
        isfinite(created_at) AND isfinite(expires_at) AND isfinite(next_attempt_at)
        AND (last_attempt_at IS NULL OR isfinite(last_attempt_at))
        AND (lease_until IS NULL OR isfinite(lease_until))
        AND (accepted_at IS NULL OR isfinite(accepted_at))
    )
);

CREATE INDEX ting_outbox_due ON hook_private.ting_outbox
    (environment_id, next_attempt_at, created_at, id) WHERE accepted_at IS NULL;
CREATE INDEX ting_outbox_by_silicon ON hook_private.ting_outbox
    (environment_id, org_id, silicon_id, created_at DESC, id DESC);

ALTER TABLE hook_private.ting_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE hook_private.ting_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY environment_scope ON hook_private.ting_outbox
    USING (environment_id = hook_private.environment_id() AND hook_private.environment_is_available())
    WITH CHECK (environment_id = hook_private.environment_id() AND hook_private.environment_is_available());
CREATE TRIGGER fence_environment_write
    BEFORE INSERT OR UPDATE OR DELETE ON hook_private.ting_outbox
    FOR EACH STATEMENT EXECUTE FUNCTION hook_private.fence_environment_write();
REVOKE ALL ON hook_private.ting_outbox FROM PUBLIC;

COMMENT ON TABLE hook_private.ting_outbox IS
    'Exact prepared Ting request bodies and durable send progress; never tokens, proofs or credentials. Removed with the original Hook event.';
COMMENT ON COLUMN hook_private.ting_outbox.request_body IS
    'Exact unsigned UTF-8 JSON bytes; mint a fresh request-bound IAM proof for each send attempt.';
COMMENT ON COLUMN hook_private.ting_outbox.accepted_at IS
    'Time Hook confirmed Ting acceptance, not recipient delivery, read acknowledgement or completed processing.';
