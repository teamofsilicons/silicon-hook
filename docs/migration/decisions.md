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

## Stage 3: packaging, CI, deployment and documentation

### One version for the service, the client and the CLI
`silicon-hook` moves from 0.10.1 to 1.0.0 like the client and the CLI, so a release tag (`v1.0.0`) names all three
and the package manifest, which takes its version from `crates/cli/Cargo.toml`, cannot drift. The API stays v3
(introduced by the service stage).

### Packaging: one archive per target, checked where it was built
`packaging/apps.yaml.in` lists one target; `scripts/package-apps.sh` (a shell entry over `scripts/package_apps.py`,
Python 3.9+, standard library only) renders it, stages `apps.yaml` and `bin/hook[.exe]`, and runs
`silicon-apps validate`, `silicon-apps pack`, an exact-inventory check and a second validation of the archive and of
its extracted files. On top of the brief's three commands it also requires `hook --version` to print the manifest's
version and refuses a binary whose discovery commands write into the empty home (the CLI stage made that a
property). `silicon-apps` runs with an empty home of its own and `--server http://127.0.0.1:9`, so a sign-in saved on
the machine is never used and a packer that tried to reach a server would fail instead of calling one.

### Same runners and toolchains as before
The release workflow keeps the 0.x matrix: native Linux builds on ubuntu-24.04 and ubuntu-24.04-arm, Windows on
windows-2025 (aarch64 cross-compiled), macOS on macos-15 (x86_64 cross-compiled). Each build job checks its own
binary with `--check-only`; discovery is required where the runner executes the binary natively and best effort for
the two cross builds (Silicon Apps runs the commands at upload anyway). One packing job installs
silicon-apps-cli 0.2.0 once and packs all six archives with SHA256SUMS. The Linux binaries stay dynamically linked
against the runner's glibc: Silicon Apps' Linux workers are documented to run "a glibc compatible with Ubuntu 24.04
builds" (`silicon-apps/deploy/PRODUCTION.md`), and the packager refuses anything needing more than glibc 2.39.
Switching to static musl builds (as Waveform did) was not needed and would change a toolchain that shipped.

### The installer carries Silicon Accounts settings, and only to the API
The first 1.0 install reads `HOOK_APP_SECRET` and `HOOK_ACCOUNTS_WEBHOOK_SECRET` (and any other Silicon Accounts
setting) from an owner-only `accounts.env` on the host; the file may hold only Silicon Accounts keys and no quoted
values, and the values go into the API's settings only (the worker and the migrator never read them). Later
installs carry them over. The installer refuses before changing anything when either secret is missing. Settings
of the previous sign-in, the test environments and the lifecycle callbacks are removed from every process.
`HOOK_TING_BASE_URL` is removed and deliberately not translated into `HOOK_TING_URL`: production Ting does not
accept Silicon Accounts proofs yet, so delivery stays off until someone sets the new variable on purpose. Without
`--apply`, the installer previews the change by variable name, never by value.

### The shared test database is backed up, not migrated or dropped
`hook_test` (the test environments' database) is unused from 1.0 on. The installer backs it up (online and
quiesced) while its URL is still configured, never migrates it, and the daily backup keeps dumping it while it
exists. Dropping it is left to a later, explicit decision: no step of this migration deletes data.

### The browser gateway is retired with the old web
The Next.js web on Vercel replaces the SolidJS console and its Node gateway, so the host's Caddy proxies only the
API, the deployment workflow no longer builds the gateway image, and the host bootstrap stops (and disables) a
gateway it finds instead of starting one. The cutover keeps the stopped container and its session files for a week
for rollback, then deletes them (they hold encrypted tokens of the previous sign-in).

### The host bootstrap stays, switched to Silicon Accounts
`deploy/aws/install.py`/`prepare.py` are only used to rebuild the host, but they are the only record of how it was
built, so they were kept and switched: `accounts.json` instead of the previous credentials file, no test database,
no gateway, Caddy for the API only, and the API alone gets the Silicon Accounts secrets.

### The identity mapping is drafted by a script in the backend bundle
`draft-identity-mapping.py` (in `deploy/native/`, so it ships next to `install.py`) proposes the
`link-identities` file by looking every stored id up at Silicon Accounts by its current id with Hook's app
credentials. It is a separate operator script rather than a `hook-migrate` subcommand because the migrator
deliberately loads only its database URL and never holds the app secret. It only reads, stays under the lookup
budget, leaves out ids that are unknown, of the other kind, not active, or that would give one uuid to two ids,
and lists each Silicon's custodian so the reviewer can check it. Matching current ids is a proposal, never proof;
the runbook makes the review a step.

### History moves to docs/history, links pinned to the last pre-1.0 commit
The previous sign-in and test-environment guides, 0.x release notes, verification evidence, dated host records and
the root status files moved to `docs/history/` with an index. Links between moved records still work; links to
guides that have since changed point at `d621aba` on GitHub, so the records keep meaning what they meant.
`IAM_INTEGRATION.md` (a pointer to a guide that no longer applies) was deleted; `API_DOCS.md` stays (it points at the
current API guide). `scripts/ting_e2e/` was deleted rather than moved: it is code that drove the previous identity
service, the test environments and API v2 in Docker, it cannot run against 1.0, and git history keeps it.

### The docs site
It publishes neither `docs/history/` nor `docs/migration/`, drops the verification page from its navigation, and
uses its own favicon: the web kit's mark recipe (a white lucide "webhook" glyph on the brand-blue squircle)
instead of the copy of the previous identity service's mark it took from the old web, so it no longer depends on
`web/`. `docs/install.sh` (served at `/install.sh`) installs through Silicon Apps and tells you how to get
Silicon Apps when it is missing.

The Carbon asked for every app's frontend in the style of Accounts and Apps. The docs site is Hook's second
public surface, so it moved from its own green and Inter look to the family's: the semantic colour tokens in
light and dark, a Light / Dark / System switch (`theme.js`, the choice kept in `localStorage`, applied before the
first paint), BDO Grotesk for titles (self-hosted, SIL OFL licence beside the files) with the system face for
text, hairline borders, squircle corners where the browser draws them, and the Hook mark in the header. It stays a
static marked build: moving it to Next.js was not part of this request's web work (`web/`), and the site's CSP
(`'self'` only) already covers the new script and fonts. Headings are now slugged and listed from their plain
text (an apostrophe showed as `&#39;` in the page outline).

### No CSP change in this stage
The backend host serves only the API and provider ingress (no HTML), and the docs site calls nothing; the web's
Content Security Policy, including Silicon Accounts and profile-photo origins, comes with the Next.js web.

### CI
The documentation job is named for what it runs and also runs the packager and installer tests
(`scripts/test_*.py`). No extra packaging job runs on every push: the release workflow can be dispatched by hand
to rehearse a release, and the packager's behaviour is covered by unit tests with stand-in packers and binaries.

### Code comments
Doc comments that still spoke of tenant and organization scopes, or of the previous identity service where the code
no longer has anything to do with it, now describe the owner scopes the code checks. Column names (`org_id`,
`iam_public_id`), the audit action `hook.iam_connected` of old rows, the hidden `hook iam --json`, the old telemetry
operation names and the list of obsolete variables stay: they are data, compatibility or operator help.

## Stage 4: end to end against Silicon Accounts

### The dev stack and the e2e run are repository scripts, in Python like the packager
`scripts/dev-accounts.sh` (over `scripts/dev_accounts.py`) and `scripts/e2e-accounts.sh` (over the
`scripts/e2e_accounts/` package) use only the Python 3.9+ standard library, like `scripts/package_apps.py`, so
they run on this Mac's `/usr/bin/python3` and on CI images without installing anything. They are not CI jobs:
they need a running Silicon Accounts stack with its development helpers. The run takes the stack's description,
its identity helper (`mint.mts`) and runner, and a `silicon-accounts` CLI from environment variables
(`HOOK_DEV_STACK_FILE`, `HOOK_E2E_MINT`, `HOOK_E2E_TSX`, `HOOK_E2E_ACCOUNTS_CLI`) instead of hard-coded paths,
and refuses to start, naming the variable, when one is missing. The Silicon Accounts CLI is always given the
stack's URL and a scratch home, so it can never act on a production sign-in saved on the machine.

### Dev state lives in .mig/, keys and the webhook secret survive restarts
The brief puts pids and logs in `.mig/`; the script also keeps there, in `dev-accounts.env` (0600), the
encryption key, the cursor key and the webhook secret, so `restart` brings back the same Hook (stored hook
secrets stay readable, cursors stay valid, the webhook keeps verifying). The directory gets a `.gitignore` of
`*` when the script creates it. App secrets are read from the stack file each time and never copied. `stop`
keeps everything; `down` drops the database and its roles, forgets the keys and removes Hook's webhook from the
stack only when it points at this Hook (it was unset before the stage, and is unset again after every run).

### The webhook secret is generated first, then the URL is set, with every update
`generate-secret` works before a URL exists and the following `PUT` keeps that secret, so the script always
knows the secret Silicon Accounts signs with, whatever state the stack was in. The `PUT` sends `"events": null`
(every update); when the URL and secret are right but the picks are not, the script restores every update. A
signed `ping` must reach Hook before `start` reports success.

### Ting stand-in: the receiving app is a setting, and the test stack's `interface` app plays Ting
The shared stack has no `ting` app, and a proof can only be issued for an app that exists, so the issuer side
of scenario 6 needed a receiving app whose credentials the stand-in can use. Hook's receiving app was a
constant; it is now `HOOK_TING_APP_ID` (default `ting`, validated, never Hook's own id), which production also
benefits from if Ting registers under another id. The e2e run points it at the testkit's fake `interface` app,
the app the brief designates for proof tests; the stand-in (`scripts/ting_stub.py`) verifies every proof with
`interface`'s development credentials, as Ting will with its own. Adding a `ting` app to the shared stack was
ruled out: only Hook's own sign-in setup and webhook may change there. The stand-in refuses the first send proof
once on request (to prove Hook renews it), can deliver accepted sends on to a receiving host the way Ting's
daemon does, and journals proof digests, never tokens.

### A token from the second of a sign-out is settled by Silicon Accounts
Access tokens carry `iat` in whole seconds, sign-out events carry milliseconds. Comparing them directly refused
the new token of a Silicon that signed in again within the same second as a sign-out (3 of 4 attempts against
the stack after an STK rotation). Truncating the sign-out to its second would instead accept tokens issued just
before it. Hook now refuses earlier seconds and accepts later ones locally, and asks introspection only for a
token from the sign-out's own second; a confirmation is remembered for that token and that sign-out instant
only. This reuses an "active" answer for one narrow, permanent fact (the token postdates that sign-out); the
routes that introspect every time still never reuse one.

### Proof requests pause after a failure
With Ting's app missing (or Silicon Accounts down), every queued send asked for its own proof and logged a
warning, every 30 seconds per send. A failed request now pauses proof requests for that scope: 30 seconds,
doubling to 5 minutes while failures continue. Sends fail fast meanwhile, keep their 30-second retry, and stay
`pending` with `proof_unavailable`; the log gets one line per failed request, with the pause. Enrolment proofs
(per user request, never cached) are not paused.

### Silicon Accounts outages get their own error code
When Silicon Accounts does not answer (introspection, lookups, or the first signing-key fetch after a restart),
Hook answers `503 accounts_unavailable` saying what it needed Silicon Accounts for; `provider_unavailable` now
means the database only. The connection detail stays in the log because it can name private addresses. Reads
verified with cached keys, sign-in status and provider ingress keep working during an outage (scenario 9), and
the CLI keeps its sign-in.

### hook-api checks its webhook settings at startup, warning only
Setting an app webhook's URL keeps update picks made earlier, and Silicon Apps' recommended picks leave out
`custodian_change`. Rather than trust every operator path, hook-api reads `GET /v1/apps/hook/webhook` once at
startup and logs either that every event it acts on reaches its own `/webhook`, or each problem with its
consequence (missing update, no secret, paused, another URL). It never blocks startup and `/readyz` does not
depend on Silicon Accounts, so an outage cannot take Hook out of rotation. The cutover sets `"events": null`
explicitly through the API (the CLI cannot choose updates) and verifies it.

### Kept as they are
- The CLI exits 3 for `403` refusals such as `silicon_not_reachable`: "sign-in required or refused" is the
  silicon-accounts CLI's convention (`401 | 403 => EXIT_AUTH`), which Hook's CLI follows.
- An unsigned request to a Standard Webhooks hook is withheld as `payload_unavailable`, not
  `signature_missing`: the policy's payload needs `webhook-id` and `webhook-timestamp`, and the documented order
  evaluates the payload first. The run checks all three reasons.
- `/readyz` stays "ready" while Silicon Accounts is down (see above).
- Development logs are coloured; the dev script sets `NO_COLOR=1` so its log files are plain. Production logs
  are JSON and were never coloured.

### Test identities
Each run uses a fresh suffix: Carbons `hook-e2e-c1-<n>` and `hook-e2e-c2-<n>` (`@example.test`), Silicons
`si:hook-e2e-s1-<n>` and `si:hook-e2e-s3-<n>` (looked after by C1) and `si:hook-e2e-s2-<n>` (by C2). A run spends
about ten email codes over two addresses, under the per-address limit, and retries once after 40 seconds if the
shared per-network limit refuses one. The accounts stay on the shared stack except S3, which the run deletes.
