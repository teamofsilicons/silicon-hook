-- A Carbon's receiving interest does not authorize future disclosure by itself.
-- Keep only its current access token, encrypted at rest. The runtime owns all
-- refresh credentials and renews this authority by subscribing again.
ALTER TABLE hook_private.ting_recipient_bindings
    ADD COLUMN encrypted_authority jsonb,
    ADD COLUMN authority_version uuid,
    ADD CONSTRAINT ting_observer_authority_pair CHECK (
        (encrypted_authority IS NULL AND authority_version IS NULL)
        OR (encrypted_authority IS NOT NULL AND jsonb_typeof(encrypted_authority) = 'object' AND authority_version IS NOT NULL)
    );
COMMENT ON COLUMN hook_private.ting_recipient_bindings.encrypted_authority IS
    'Encrypted current Carbon access token only; never a refresh token. Live IAM actor, org, environment and target visibility checks precede every observer publication. NULL legacy rows require the runtime to subscribe again.';
COMMENT ON COLUMN hook_private.ting_recipient_bindings.authority_version IS
    'Opaque renewal fence; stale denied checks cannot delete a later renewed binding.';
COMMENT ON TABLE hook_private.ting_recipient_bindings IS
    'Carbon self-subscriptions with separately encrypted current authority. Live IAM visibility is required at bind, publication and hydration. Retained through key rotation/restore; clean deletes all bindings.';

ALTER TABLE hook_private.ting_outbox DROP CONSTRAINT ting_outbox_error_safe;
ALTER TABLE hook_private.ting_outbox ADD CONSTRAINT ting_outbox_error_safe CHECK (last_error_code IN (
    'authorization_unavailable', 'consent_required', 'recipient_not_registered',
    'transport_unavailable', 'rate_limited', 'ting_unavailable',
    'request_rejected', 'invalid_response', 'publisher_not_configured',
    'publisher_unavailable', 'publisher_unauthorized', 'ting_unauthorized',
    'type_not_registered', 'idempotency_conflict', 'environment_changed',
    'observer_authority_refresh_required', 'observer_authorization_unavailable'
));
