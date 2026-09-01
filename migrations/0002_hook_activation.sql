-- Reversible hook activation, distinct from 45-day soft deletion.

ALTER TABLE hook.hooks
    ADD COLUMN disabled_at timestamptz;

COMMENT ON COLUMN hook.hooks.disabled_at IS
    'Latest reversible ingress-disable transition; NULL for active or deleted hooks.';

ALTER TABLE hook.hooks
    ADD CONSTRAINT hooks_disabled_at_valid CHECK (
        disabled_at IS NULL
        OR (isfinite(disabled_at) AND disabled_at >= created_at)
    ),
    ADD CONSTRAINT hooks_lifecycle_timestamps_mutually_exclusive CHECK (
        disabled_at IS NULL OR deleted_at IS NULL
    );

ALTER TABLE hook_private.audit_log
    DROP CONSTRAINT audit_log_action;

ALTER TABLE hook_private.audit_log
    ADD CONSTRAINT audit_log_action CHECK (
        action IN (
            'hook.created',
            'hook.disabled',
            'hook.enabled',
            'hook.deleted',
            'hook.restored',
            'hook.secret_rotated',
            'hook.iam_provisioned'
        )
    );
