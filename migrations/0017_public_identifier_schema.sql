-- IAM's cutover must pass its global collision preflight before this migration.
-- Only declared identity columns are rewritten. Signed/replay JSON, request
-- hashes, free text, ciphertext and private UUID keys are deliberately retained.
CREATE OR REPLACE FUNCTION pg_temp.schema_actor(value text) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
BEGIN
    IF value ~ '^si:[a-z0-9_-]{3,50}$' OR value ~ '^c:[a-z0-9_-]{3,30}$' THEN RETURN value; END IF;
    IF value ~ '^[a-z0-9_-]{3,50}:[a-z0-9_-]{3,50}$' THEN RETURN 'si:' || split_part(value, ':', 1); END IF;
    IF value ~ '^[a-z0-9_-]{3,30}$' THEN RETURN 'c:' || value; END IF;
    RAISE EXCEPTION 'unmapped public actor ID in schema cutover: %', value USING ERRCODE='22023';
END $$;
CREATE OR REPLACE FUNCTION pg_temp.schema_app(value text) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
BEGIN
    IF value ~ '^[a-z][a-z0-9_-]{0,79}$' THEN RETURN value; END IF;
    IF value ~ '^[a-z0-9_-]+>[a-z][a-z0-9_-]{0,79}$' THEN RETURN split_part(value, '>', 2); END IF;
    RAISE EXCEPTION 'unmapped application ID in schema cutover: %', value USING ERRCODE='22023';
END $$;

CREATE TEMP TABLE hook_schema_tables ON COMMIT DROP AS
SELECT c.oid,format('%I.%I',n.nspname,c.relname) AS relation,c.relforcerowsecurity AS forced
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname IN ('hook','hook_private','hook_control') AND c.relkind='r';
CREATE TEMP TABLE hook_schema_triggers ON COMMIT DROP AS
SELECT tables.relation,t.tgname,t.tgenabled
FROM pg_trigger t JOIN hook_schema_tables tables ON tables.oid=t.tgrelid
WHERE NOT t.tgisinternal;
CREATE TEMP TABLE hook_schema_fks ON COMMIT DROP AS
SELECT conrelid::regclass::text AS relation,conname,pg_get_constraintdef(oid) AS definition
FROM pg_constraint WHERE contype='f' AND conrelid IN(SELECT oid FROM hook_schema_tables);
DO $$ DECLARE r record; BEGIN
    FOR r IN SELECT * FROM hook_schema_tables ORDER BY relation LOOP
        EXECUTE format('LOCK TABLE %s IN ACCESS EXCLUSIVE MODE',r.relation);
        EXECUTE format('ALTER TABLE %s NO FORCE ROW LEVEL SECURITY',r.relation);
        EXECUTE format('ALTER TABLE %s DISABLE TRIGGER USER',r.relation);
    END LOOP;
    FOR r IN SELECT * FROM hook_schema_fks LOOP
        EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',r.relation,r.conname);
    END LOOP;
END $$;

DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM hook_private.ting_outbox WHERE accepted_at IS NULL AND expires_at>clock_timestamp()) THEN
        RAISE EXCEPTION 'drain Hook Ting outbox before the identifier cutover' USING ERRCODE='55000';
    END IF;
END $$;
CREATE TEMP TABLE hook_schema_mapping(environment_id uuid,old_id text,new_id text,
    PRIMARY KEY(environment_id,old_id),UNIQUE(environment_id,new_id)) ON COMMIT DROP;
DO $$ DECLARE r record; BEGIN
    FOR r IN SELECT c.table_schema,c.table_name,c.column_name
        FROM information_schema.columns c JOIN hook_schema_tables t ON t.relation=format('%I.%I',c.table_schema,c.table_name)
        WHERE c.data_type='text' AND c.column_name IN('silicon_id','actor_id','created_by_id','recipient_id','consumer_id')
    LOOP
        EXECUTE format('INSERT INTO hook_schema_mapping SELECT DISTINCT environment_id,%I,pg_temp.schema_actor(%I) FROM %I.%I WHERE %I IS NOT NULL ON CONFLICT(environment_id,old_id) DO NOTHING',r.column_name,r.column_name,r.table_schema,r.table_name,r.column_name);
    END LOOP;
    FOR r IN SELECT c.table_schema,c.table_name,c.column_name
        FROM information_schema.columns c JOIN hook_schema_tables t ON t.relation=format('%I.%I',c.table_schema,c.table_name)
        WHERE c.data_type='text' AND c.column_name IN('silicon_id','actor_id','created_by_id','recipient_id','consumer_id','target_id')
    LOOP
        EXECUTE format('UPDATE %I.%I row SET %I=m.new_id FROM hook_schema_mapping m WHERE row.environment_id=m.environment_id AND row.%I=m.old_id',r.table_schema,r.table_name,r.column_name,r.column_name);
    END LOOP;
END $$;
UPDATE hook_control.environments SET creator_id=pg_temp.schema_actor(creator_id)
WHERE creator_id<>'honeycomb';
-- Ingress routes use the new Silicon ID with the existing endpoint key. Update
-- the registered upstream URL at cutover; route tombstones are migrated as well.
-- Signing credentials are encrypted with the unchanged hook UUID as AAD.

DO $$ DECLARE r record; BEGIN
    FOR r IN SELECT * FROM hook_schema_fks LOOP
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',r.relation,r.conname,r.definition);
    END LOOP;
    FOR r IN SELECT * FROM hook_schema_tables LOOP
        IF r.forced THEN EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',r.relation); END IF;
    END LOOP;
    FOR r IN SELECT * FROM hook_schema_triggers LOOP
        EXECUTE format('ALTER TABLE %s %s TRIGGER %I',r.relation,
            CASE r.tgenabled WHEN 'D' THEN 'DISABLE' WHEN 'R' THEN 'ENABLE REPLICA'
                WHEN 'A' THEN 'ENABLE ALWAYS' ELSE 'ENABLE' END,r.tgname);
    END LOOP;
END $$;
