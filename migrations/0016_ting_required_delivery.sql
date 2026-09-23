-- A missing recipient opt-in is a precise, retryable pending condition.
-- Existing immutable send bodies and keys keep their original delivery policy.
ALTER TABLE hook_private.ting_outbox DROP CONSTRAINT ting_outbox_error_safe;
ALTER TABLE hook_private.ting_outbox ADD CONSTRAINT ting_outbox_error_safe CHECK (last_error_code IN (
    'authorization_unavailable', 'consent_required', 'recipient_not_registered',
    'required_delivery_not_enabled',
    'transport_unavailable', 'rate_limited', 'ting_unavailable',
    'request_rejected', 'invalid_response', 'publisher_not_configured',
    'publisher_unavailable', 'publisher_unauthorized', 'ting_unauthorized',
    'type_not_registered', 'idempotency_conflict', 'environment_changed',
    'observer_authority_refresh_required', 'observer_authorization_unavailable'
));
