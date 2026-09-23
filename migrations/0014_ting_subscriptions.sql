-- Explicit Carbon receiving interest. This stores no recipient credentials and
-- does not backfill notifications for events that predate a subscription.
CREATE TABLE hook_private.ting_recipient_bindings (
    id uuid PRIMARY KEY,
    environment_id uuid NOT NULL DEFAULT hook_private.environment_id(),
    org_id text NOT NULL,
    silicon_id text NOT NULL,
    recipient_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ting_bindings_scope_unique UNIQUE (environment_id, org_id, silicon_id, recipient_id),
    CONSTRAINT ting_bindings_outbox_identity_unique UNIQUE (environment_id, org_id, silicon_id, recipient_id, id),
    CONSTRAINT ting_bindings_org_valid CHECK (octet_length(org_id) BETWEEN 1 AND 255),
    CONSTRAINT ting_bindings_silicon_valid CHECK (octet_length(silicon_id) BETWEEN 1 AND 255),
    CONSTRAINT ting_bindings_recipient_valid CHECK (octet_length(recipient_id) BETWEEN 1 AND 255 AND recipient_id <> silicon_id),
    CONSTRAINT ting_bindings_created_finite CHECK (isfinite(created_at))
);
ALTER TABLE hook_private.ting_recipient_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE hook_private.ting_recipient_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY environment_scope ON hook_private.ting_recipient_bindings
    USING (environment_id = hook_private.environment_id() AND hook_private.environment_is_available())
    WITH CHECK (environment_id = hook_private.environment_id() AND hook_private.environment_is_available());
CREATE TRIGGER fence_environment_write
    BEFORE INSERT OR UPDATE OR DELETE ON hook_private.ting_recipient_bindings
    FOR EACH STATEMENT EXECUTE FUNCTION hook_private.fence_environment_write();
REVOKE ALL ON hook_private.ting_recipient_bindings FROM PUBLIC;
COMMENT ON TABLE hook_private.ting_recipient_bindings IS
    'Carbon self-subscriptions checked against current IAM visibility at bind and hydration. Retained through key rotation/restore, erased by clean. No credential storage or historical backfill.';

ALTER TABLE hook_private.ting_outbox ADD COLUMN recipient_binding_id uuid;
ALTER TABLE hook_private.ting_outbox ADD CONSTRAINT ting_outbox_binding_fk
    FOREIGN KEY (environment_id, org_id, silicon_id, recipient_id, recipient_binding_id)
    REFERENCES hook_private.ting_recipient_bindings (environment_id, org_id, silicon_id, recipient_id, id)
    ON DELETE CASCADE;
CREATE INDEX ting_outbox_by_binding ON hook_private.ting_outbox (recipient_binding_id)
    WHERE recipient_binding_id IS NOT NULL;
COMMENT ON COLUMN hook_private.ting_outbox.recipient_binding_id IS
    'Observer receiving interest; deleting it cancels pending sends, without affecting primary Silicon sends. Already accepted Ting references cannot be retracted.';

CREATE OR REPLACE FUNCTION hook_control.clean_environment(target uuid) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE new_generation bigint;
BEGIN
    IF target = '00000000-0000-0000-0000-000000000000'::uuid THEN
        RAISE EXCEPTION 'production cannot be cleaned' USING ERRCODE = '42501';
    END IF;
    PERFORM 1 FROM hook_control.environments WHERE id = target FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'environment missing' USING ERRCODE = 'P0002'; END IF;
    PERFORM set_config('hook.environment_id', target::text, true);
    PERFORM set_config('hook.clean_environment', target::text, true);
    DELETE FROM hook_private.ting_publisher_credentials WHERE environment_id = target;
    DELETE FROM hook_private.ting_recipient_bindings WHERE environment_id = target;
    -- Removing events also removes their Ting outbox rows through the foreign key.
    DELETE FROM hook.events WHERE environment_id = target;
    DELETE FROM hook.blocked_requests WHERE environment_id = target;
    DELETE FROM hook_private.ip_blocks WHERE environment_id = target;
    DELETE FROM hook.hooks WHERE environment_id = target;
    DELETE FROM hook_private.retired_endpoint_keys WHERE environment_id = target;
    DELETE FROM hook_private.delivery_sequences WHERE environment_id = target;
    DELETE FROM hook_private.delivery_cursors WHERE environment_id = target;
    DELETE FROM hook_private.management_idempotency WHERE environment_id = target;
    DELETE FROM hook_private.audit_log WHERE environment_id = target;
    DELETE FROM hook_private.contract_versions WHERE environment_id = target;
    DELETE FROM hook_private.telemetry_events WHERE environment_id = target;
    -- Endpoint routing tombstones must survive a clean.
    UPDATE hook_control.environments SET generation = generation + 1,
        last_activity_at = clock_timestamp() WHERE id = target RETURNING generation INTO new_generation;
    RETURN new_generation;
END
$$;
REVOKE ALL ON FUNCTION hook_control.clean_environment(uuid) FROM PUBLIC;
