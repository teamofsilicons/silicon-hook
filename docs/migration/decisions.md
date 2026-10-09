# Hook: migration decisions

The Carbon asked for Hook (and seven other apps) to move from Silicon IAM and Honeycomb to Silicon Accounts and
Silicon Apps, and was asleep while the work ran ("dont ask any questions"). Every judgement call is recorded here for
review. The platform-wide decisions (D1–D9) are in the migration brief; this file records how Hook applies them and the
calls Hook needed on top.

## Stage 1: service

### Tests run against a provided PostgreSQL, not Docker
Docker is not available on the build machine, and every database test used testcontainers. Database tests now use
`HOOK_TEST_POSTGRES_URL` (an administrator URL); each test creates and drops its own database and runtime roles and
applies the real `deploy/postgres/grant-runtime.sql` with `psql` (`HOOK_TEST_PSQL` overrides the binary). Without the
variable the tests skip and say why. `HOOK_TEST_DATABASE_URL` is deliberately not reused: it named the production
host's shared sandbox database, which is being removed.

### Identity storage: new columns next to the old ones, never rewritten in place
Accounts uuids are kept in new text columns (`silicon_uuid`, `created_by_uuid`, `actor_uuid`) beside the IAM-era
columns, which keep their values. Rows created in the Accounts era store the account uuid in the legacy key columns
too (`silicon_id`, `created_by_id`, `actor_id`), so an IAM public id (`si:…`, `c:…`, always with a colon) can only ever
appear in a pre-migration row (uuids never contain a colon). That makes the operator's `link-identities` command exact,
idempotent and reversible: it only writes the new uuid columns of rows whose legacy column holds a mapped IAM id, and
re-running it with a corrected mapping simply overwrites them. The organization column is no longer read; new rows get
the constant `accounts` (a column default), and child rows copy their parent's value so the existing composite foreign
keys stay valid.

### Endpoint keys are globally unique and ingress routes by key
Migration 0019 refuses to run if any live or retired endpoint key is used by two Silicons (36^8 keys, so this should
never trigger; it is checked rather than assumed) and adds a unique index. Ingress finds the hook by its key, then
accepts the path segment if it is the hook's original key column (the IAM-era `si:` id for old hooks), the owning
Silicon's uuid, or any public id Hook has seen that Silicon use (every id observed in a token, lookup or
`account.id_changed` is recorded). A URL a provider already holds keeps working after the cutover and after renames,
and a reused id can never misroute because the key decides. Ingress never calls Accounts.

### Who can do what with a Silicon's hooks
| actor | access |
|---|---|
| the Silicon itself | everything |
| its custodian (a Carbon) | everything the Silicon can do, recorded as the custodian (never as the Silicon) |
| an account granted `manage` | create, update, enable/disable, delete/restore, rotate secret/endpoint, set a secret |
| an account granted `view` | list hooks, read events, blocked requests and publication status, observe deliveries (Carbons) |
| anyone else | refused (`403`), including the Silicon's siblings |

Only the Silicon and its custodian grant or revoke access and manage its allow-list; a grantee may remove its own
grant. "Connect Silicon Accounts updates" is limited to the Silicon and its custodian, because only they can set the
Silicon's Accounts webhook. Old org owner/admin powers map to the custodian; old "any Carbon in the org who can see the
Silicon" maps to explicit grants. There is no acceptance step for grants (decided after the survey).

### Silicons are not open to the world: an allow-list per Silicon
A grant to a Silicon from outside its circle (a Silicon with a different custodian) is refused unless that Silicon's
allow-list contains the owning Silicon or its custodian. The Silicon or its custodian manages the allow-list
(`/api/v3/silicons/{s}/allow-list`). Grants to Carbons need nothing (Carbons can be reached by anyone signed in).
This matches the allow-lists DM, Commit and MCPort use.

### Silicon listing comes from Hook's own account cache
Silicon Accounts has no "Silicons of this custodian" listing for apps, so `GET /api/v3/silicons` lists the Silicons Hook
knows to be looked after by the caller (from token sign-ins, lookups and custodian webhooks) plus those granted to the
caller. A Silicon Hook has never seen can still be opened by its id (Hook resolves it with Accounts on first use).
Custodian data used for an authorization decision is refreshed from Accounts when older than 5 minutes, and updated at
once by `silicon.custodian_changed`.
