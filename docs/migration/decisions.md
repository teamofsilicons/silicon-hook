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

### Which routes ask Silicon Accounts whether a token is still active
Every route verifies the access token locally (signature against the cached key set, audience `hook`, issuer
`ACCOUNTS_URL`, expiry) and refuses tokens issued before a sign-out Hook was told about. These routes also
introspect: creating a hook (it returns a secret), setting a secret, rotating a secret or an endpoint, deleting and
restoring a hook, granting and revoking access, changing an allow-list, connecting Silicon Accounts updates,
observing a Silicon and enrolling with Ting. An "active" answer is never reused, so a sign-out is seen at once on
these routes; an "inactive" answer is remembered for 30 minutes (a revoked token never comes back). Hook has no IP
block management route, so there is nothing to introspect there.

### Sign-outs, access removal and deletion
`membership.signed_out` with reason `app_revoked` means Hook itself ended one sign-in (a logout); it changes nothing
else. Any other sign-out, `membership.access_removed` and `account.deleted` refuse every token issued before the
event and end the account's observer subscriptions. If such an event arrives before the account ever used Hook, Hook
still records it (the account's kind stays unknown until Hook meets it), so earlier tokens never work. A deleted
account never comes back: its id and profile are dropped, its grants and allow-list entries go, and a deleted
Silicon's hooks are soft-deleted at once (ingress answers `410 account_deleted`; the usual 45-day purge removes them).
Events apply in any order: id and custodian changes only when newer, profile updates only with a higher version.

### Delivery through Ting
Per D4: enrolment uses a single-use User verification proof (receiving app `ting`, scope `tings.subscribe`) issued
from the caller's own Hook token; sends and receipts use App verification proofs (`tings.send`, `sent.query`) kept in
memory and renewed single-flight. Recipients are `{uuid, id}`. The event reference carries `silicon: {uuid, id}` (the
uuid the decisions asked for, in the same shape as every other response) and no longer carries the old tenant and
environment fields. With `HOOK_TING_URL` unset nothing is queued, `/readyz` and the startup log say delivery is off,
and the delivery routes answer `delivery_disabled`. Sends queued under the old sign-in that Ting never accepted cannot
be signed with Silicon Accounts proofs; migration 0019 parks them as `legacy_identity` (kept as a record until the
event expires, shown as `not_delivered_legacy`). The old Carbon receiving bindings are not carried over: Carbons
subscribe again, and Hook re-checks their access inside every event acceptance.

### API v3; v1 and v2 answer 410
Breaking changes need a new major (the repo's policy), so v3 replaces v2. Every `/api/v1/...` and `/api/v2/...`
management route answers `410 api_version_sunset` with a pointer to v3 rather than 404, so old clients get a clear
reason. Provider ingress under `/api/v1/silicon/...` and `/api/v2/silicon/...` keeps working.

### Versions
The crate versions are unchanged in this stage (`silicon-hook` 0.10.1); the release stage sets 1.0.0 for the service,
client and CLI together (hook.md). The OpenAPI document says 1.0.0 because it describes that release's API.

### Delivery sequence numbers
Sequences stay keyed by the hook's original owner column, so a linked IAM-era hook continues its old numbering while
hooks created later number from 1 under the uuid. Order across Ting was never implied; the number only identifies the
event within its stream.

### A new Silicon's custodian is looked up once
Access tokens do not name a Silicon's custodian, so the first time a Silicon signs in Hook looks it up once (within
the lookup budget). That keeps the custodian's list of Silicons complete; a failure only delays it.

### Allow-list changes are not retroactive
Removing an account from a Silicon's allow-list stops new grants and level changes from that account; grants that
already exist stay until the Silicon or its custodian revokes them.

### The mapping file accepts the shared header
The brief's mapping layout is `iam_principal_id,accounts_uuid`. Hook stored its principals by their public ids
(`si:cos`, `c:alice`), so that header is read as the public id; `iam_public_id,accounts_uuid` and
`iam_principal_id,iam_public_id,accounts_uuid` are accepted too. `identity_links.in_hook_data` records which ids
Hook's data references, so the report's "not in Hook data" and "unmatched" lists stay exact across runs. The
operator command and its messages say "IAM" because they exist only for this migration; nothing else does.

### "Connect Silicon Accounts updates" next steps
The response gives the exact `silicon-accounts` command (`webhook set` for the Silicon itself, `silicon webhook set`
for its custodian) and says how to store the `whsec_` secret through the API, without naming a CLI command the CLI
stage has not built yet.

### Telemetry operations
The server's allow-list of client telemetry operation names is unchanged; the CLI stage adds the names of its new
commands there (`src/telemetry/events.rs` and the OpenAPI `TelemetryEvent` schema).
