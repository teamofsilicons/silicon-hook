-- Cutover ledger also fences tokens bearing an identity retired by the backfill.
CREATE TABLE IF NOT EXISTS hook_private.accounts_uuid128_map (
 old_uuid text PRIMARY KEY, new_uuid text UNIQUE NOT NULL,
 kind text NOT NULL CHECK (kind IN ('carbon','silicon')),
 mapping_sha256 text NOT NULL,
 applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
