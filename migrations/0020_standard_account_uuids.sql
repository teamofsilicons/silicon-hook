-- Broaden only the identity checks introduced by0019. Other public IDs,
-- endpoint keys and opaque provider identifiers retain their original rules.
DO $upgrade$
DECLARE item record;
BEGIN
  FOR item IN
    SELECT c.conrelid::regclass AS relation, c.conname, pg_get_constraintdef(c.oid) AS definition
    FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace
    WHERE c.contype='c' AND n.nspname IN ('hook','hook_private')
      AND position('^[A-Za-z0-9]{1,64}$' in pg_get_constraintdef(c.oid)) > 0
  LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', item.relation, item.conname);
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s', item.relation, item.conname,
      replace(item.definition, '^[A-Za-z0-9]{1,64}$', '^([A-Za-z0-9]{1,64}|[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$'));
  END LOOP;
END;
$upgrade$;
