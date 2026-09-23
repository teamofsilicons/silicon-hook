-- A lifecycle generation fences credentials and pools. Retained events keep
-- their original reference identity when keys rotate or a disabled plane resumes.
ALTER TABLE hook.events ADD COLUMN source_generation bigint;

-- The migration owner backfills all planes atomically, without changing their
-- immutable payloads. Existing queued references still contain this generation.
ALTER TABLE hook.events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE hook_private.ting_outbox NO FORCE ROW LEVEL SECURITY;
ALTER TABLE hook.events DISABLE TRIGGER events_are_immutable;
UPDATE hook.events AS event SET source_generation = CASE
    WHEN event.environment_id = '00000000-0000-0000-0000-000000000000'::uuid THEN 0
    ELSE COALESCE(
        (SELECT min(send.environment_generation) FROM hook_private.ting_outbox AS send
         WHERE send.environment_id = event.environment_id AND send.event_id = event.id),
        (SELECT environment.generation FROM hook_control.environments AS environment
         WHERE environment.id = event.environment_id),
        1
    ) END;
ALTER TABLE hook.events ENABLE TRIGGER events_are_immutable;
ALTER TABLE hook.events FORCE ROW LEVEL SECURITY;
ALTER TABLE hook_private.ting_outbox FORCE ROW LEVEL SECURITY;

ALTER TABLE hook.events ALTER COLUMN source_generation SET NOT NULL;
ALTER TABLE hook.events ALTER COLUMN source_generation SET DEFAULT (
    CASE WHEN hook_private.environment_id() = '00000000-0000-0000-0000-000000000000'::uuid
         THEN 0 ELSE current_setting('hook.environment_generation')::bigint END
);
ALTER TABLE hook.events ADD CONSTRAINT events_source_generation_valid CHECK (
    (environment_id = '00000000-0000-0000-0000-000000000000'::uuid AND source_generation = 0)
    OR (environment_id <> '00000000-0000-0000-0000-000000000000'::uuid AND source_generation > 0)
);
COMMENT ON COLUMN hook.events.source_generation IS
    'Immutable generation at event acceptance, used by compact Ting references even after retained-data key rotation or restore.';
COMMENT ON COLUMN hook_private.ting_outbox.environment_generation IS
    'Current authority generation for publication; pending retained rows may advance under the current ready environment fence without changing their exact request bytes or producer key.';
