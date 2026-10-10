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

## Stage 2: client crate and CLI

### Versions: client and CLI 1.0.0
`silicon-hook-client` and `silicon-hook-cli` are 1.0.0 (hook.md: breaking). The service crate stays 0.10.1 until
the release stage sets the service version. `honeycomb.yaml` follows the CLI version only so the old packager's
version check stays consistent until the release stage replaces it with `apps.yaml`.

### Sign-in lives in the client crate (`silicon_hook_client::signin`)
UNDERSTANDING says the CLI has no feature the Rust package lacks, so the public-client sign-in (device flow,
short-lived token exchange, refresh, revoke) is in the client crate, built on `silicon-accounts-client` 0.4.0.
Two calls are sent directly because the published 0.4.0 lacks them: the public-client SLT exchange (the same form
POST that `exchange_slt_public_client` sends in the unpublished source) and the public-client revoke
(`revoke_public_client` accepts only Silicon Accounts' own client ids). Both are marked in the code to switch to the
crate once a release has them. The device wait loop is our own because `wait_for_device_tokens` polls with the
first-party client id.

### No proof-authenticated calls in Hook's client
The cross-app matrix has no app calling Hook on someone's behalf, and UNDERSTANDING says Hook exposes no OBO
endpoints, so the client has no `Authorization: Proof` support. Other apps call Hook as the Silicon with its own
Hook token (hook.md).

### Typed errors keep Hook's envelope
Hook's service answers `{error: {code, message, request_id, details}}` (it has no `hint` field yet). The client's
`ApiError` keeps all of them plus `hint` (read when present) and `retry_after`; sign-in failures are
`Error::SignIn` with a kind (`SltRefused(reason)`, `SessionEnded`, `Denied`, `Expired`, `NotEnabled`,
`Unavailable{maybe_processed}`, `Rejected`). The SLT refusal reason is read from Silicon Accounts' exact
`error_description` (already used, expired, another app, unknown, not an SLT, sign-in ended).

### Output stays JSON on stdout; errors get stable codes and exit codes
The CLI kept its existing style (results as JSON on stdout, next-step hints on stderr, `--json` silences hints).
Errors are now `{"error": {code, message, hint, status, request_id, exit_code}}` with `--json`, and exit codes follow
silicon-accounts (1 failure, 2 invalid input, 3 sign-in, 4 not found, 5 conflict, 6 rate limited, 130 interrupted).
`hook login status` without `--json` exits 1 when signed out, like `silicon-accounts login status`.

### Session file and legacy state
Sessions are written to `.silicon-hook/profiles.json` (0600, directory 0700, atomic write, `profiles.lock`); the
IAM-era `state.json` is never read for credentials and never changed. Its non-secret settings carry over once (a
non-default URL, the default Silicon, and the telemetry choice, so an opt-out survives the upgrade), and a profile
that had a session reports `previous_version_session` until it signs in again. Profiles (`--profile`) stay.
A `profiles.json` that cannot be parsed is reported (`state_unreadable`, `login status --json` still exits 0) and is
never overwritten, except by `hook login`, which moves it aside (kept for inspection) and starts a new one, so an
automated Silicon can always recover by signing in.

### A sign-in is bound to its services
A saved session records the Silicon Accounts URL and the Hook API URL it was made with. If either in effect differs
(flag, environment, `config set`), the CLI refuses to send the token (`signed_in_elsewhere`) instead of leaking it
to another service. `config set url|accounts-url` on a signed-in profile is refused with "sign out first".

### Refresh: single flight, and never present a possibly spent refresh token
Refresh happens under the state lock when less than 60 seconds remain; a process that waited for the lock re-reads
the file and uses the token another process just saved. Before sending a refresh the CLI saves a
`refresh_started_at` marker. If a later command finds the marker (the earlier one was killed mid-refresh), or a
refresh fails after the request may have reached Silicon Accounts (a timeout, an unreadable answer), the CLI does
not present that refresh token again: a spent token presented again ends the whole sign-in as theft
(`refresh_token_reuse`, which Hook's service turns into a sign-out of every Hook session of the account). It revokes
the token instead (ending only this sign-in, reason `app_revoked`, which Hook ignores), forgets the session and
reports `refresh_interrupted`. A refresh that fails before reaching Silicon Accounts (connection refused) keeps the
session.

### One retry after Hook refuses a token
If Hook answers 401 to a command (for example `session_ended` because another sign-in of the account ended), the CLI
refreshes once and retries the same request (mutations keep their idempotency key). `login status` does the same
before reporting `authenticated: false` with Hook's reason.

### `hook login` replaces a previous sign-in and signs it out
Signing in again in the same profile saves the new session first, then revokes the previous refresh token (best
effort, reason `app_revoked`), so old sign-ins are not left behind in the account's session list.

### The positional SLT, `--slt-file` and `hook iam --json` stay as compatibility forms
`hook login <SLT>` stays documented (UNDERSTANDING and the Silicon runtime use it). The pre-1.0 `--slt-file <path|->`
is accepted but hidden. `hook iam --json` is hidden and prints exactly `hook accounts --json` (brief: one minor
release); `hook docs iam` quietly shows the sign-in guide. No `HOOK_SLT` variable: the CLI never had one.

### Removed flags explain themselves
`--org`, `--test` and `--production` still parse (hidden) so that old scripts get a precise error (exit 2) naming
what replaced them, instead of clap's generic "unexpected argument". `SILICON_ORG` and `SILICON_HOOK_ORG` are
ignored silently because Silicon runtimes still export them.

### Which Silicon a command acts on
`--silicon` (a `si:` id or uuid), then `hook config set silicon`, then a signed-in Silicon's own uuid (uuid rather
than id, so a rename between commands cannot redirect them). A Carbon without one gets an error naming
`hook silicons`. A `c:` id is refused locally.

### Commands
New: `hook login` (device flow), `--slt-stdin`, `login status --offline`, `accounts`, `silicons`,
`access list|grant|revoke|leave`, `allow-list list|add|remove`, `connect-accounts [--secret-file]`,
`system delivery`, `config unset`, `config set accounts-url`. Removed: `iam` (hidden alias), `env`, `publisher`,
`connect-iam`, `receiving authorize|complete|authorization-status|disconnect-authorization|scope|bootstrap`,
`config set org`. `connect-accounts --secret-file -` creates or restores the hook and stores the `whsec_` secret in
one step; without it, the answer says `secret_stored_now: false` (the hook's generated placeholder secret is not
Silicon Accounts' one).

### Telemetry
Unchanged in spirit: one event per command, only while signed in, never refreshing a token for it, 500 ms at most,
off with `config set telemetry off` or `SILICON_HOOK_TELEMETRY=off`. The service's operation allow-list gained the
new command names.

### Docs bundled with the CLI
`hook docs` covers overview, signin, cli, client, receiving, signatures/api, delivery, contracts, configuration,
telemetry, deployment and releases; all were rewritten for Silicon Accounts and API v3 except `deployment` (service
stage) and `releases` (release stage). The IAM guide, the test-environment guides and the Ting-issues record are no
longer bundled or published on the docs site; the files stay in `docs/` for the release stage's history move. The
bundle check now also fails on leftover copies.
