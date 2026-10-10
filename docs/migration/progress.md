# Hook: migration to Silicon Accounts and Silicon Apps — progress log

Branch `migrate/accounts-apps-20261010` (based on `origin/main` d621aba, Hook 0.10.1). Each stage appends a dated
section: what it did, commits, test commands and results, what is left, gotchas.

## 2026-10-10 — Stage 1: service

### Baseline (before any change)

Environment: `CARGO_TARGET_DIR=$PWD/target/mig CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=3`,
95 GB free, Docker unavailable (`DOCKER_HOST=tcp://127.0.0.1:1` makes testcontainers fail fast instead of hanging).

| command | result |
|---|---|
| `cargo test --workspace --locked --no-run` | builds (1m40s) |
| `cargo test --locked -p silicon-hook-client -p silicon-hook-cli` | pass: CLI 7 unit + 19 + 4 + 6; client 1 unit + 1 + 4 + 4 + 5 + 14 |
| `DOCKER_HOST=tcp://127.0.0.1:1 cargo test --locked -p silicon-hook --lib` | 139 passed, 14 failed — every failure is a testcontainers start (`api::routes::tests::*` 6, `delivery::credentials` 1, `iam::ting_grants` 1, `postgres::ting` 1, `infrastructure::ting::*` 3, `ting::receiver::*` 2) |
| `DOCKER_HOST=tcp://127.0.0.1:1 cargo test -p silicon-hook --test <t>` | all fail at container start: postgres_integration 21 (+1 ignored), ting_contract 4, ting_delivery 3, ting_generations 2, ting_publisher 6, ting_subscriptions 7, websocket_delivery 3 |
| `cargo fmt --all --check` | ok |
| `cargo clippy --workspace --locked --all-targets --all-features -- -D warnings` | ok |
| `python3 scripts/bundle-cli-docs.py --check` | ok |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | ok |
| `npx --yes @redocly/cli@2.49.0 lint openapi.yaml` | valid (10 problems explicitly ignored) |
| `cargo deny --locked check` | advisories, bans, licenses, sources ok |

True database baseline: `tests/postgres_integration.rs` was ported to a Docker-free harness
(`tests/support/postgres.rs`: `HOOK_TEST_POSTGRES_URL` names an administrator URL; every test gets its own `hook_t_*`
database and `hook_api_*`/`hook_worker_*` roles, the real grant manifest is applied with `psql`, everything is dropped
afterwards; without the variable the tests skip with the reason). On the unchanged code:
`HOOK_TEST_POSTGRES_URL=postgres://postgres@127.0.0.1:5460/postgres cargo test -p silicon-hook --test postgres_integration`
→ 21 passed, 1 ignored (the ignored one sends a real Space Station diagnostic and needs a table key).

### What the service stage did

- **Sign-in.** Every API route takes a Silicon Accounts access token issued to Hook (`aud` = `HOOK_APP_ID`, `iss` =
  `ACCOUNTS_URL`), verified locally against the cached JWKS (refetched on an unknown `kid`, at most once a second).
  Sensitive routes also introspect (see decisions). The vendored `silicon-iam-client`, every IAM route
  (`/auth/iam|login|refresh|logout`, `/iam/events`, `hooks/iam`), the publisher credentials and the `local:*` dev
  bearers are gone; `silicon-accounts-client = "0.4.0"` is the only identity dependency.
- **Ownership and access.** Hooks belong to a Silicon (keyed by its uuid). The Silicon and its custodian have full
  control; `view`/`manage` grants; allow-list for Silicons outside the circle; no sibling access. New routes:
  `GET /api/v3/silicons`, `/silicons/{s}/access[/{account}]`, `/silicons/{s}/allow-list[/{account}]`,
  `POST /silicons/{s}/hooks/accounts`.
- **Data.** Migration `0019_accounts_identity.sql` (additive only): uuid columns beside the old ones, global endpoint
  key uniqueness check, account cache (`hook_private.accounts`, `account_ids`), grants, allow-lists, observer
  subscriptions, webhook dedupe, `identity_links` with an inventory of every stored IAM id, unaccepted IAM-era Ting
  sends parked as `legacy_identity`, contract v3. `hook-migrate link-identities --file mapping.csv [--dry-run]`.
- **Accounts webhook** at `/webhook` and `/webhook/`: raw-body signature, 5-minute tolerance, dedupe on `event_id`,
  the six events applied in order-safe ways, unknown types 204, bad signature 401, bad body 400.
- **Ting adapter** per D4, off unless `HOOK_TING_URL` is set (no outbox rows, `delivery_disabled` answers, startup log,
  `/readyz` detail).
- **API v3** only; `/api/v1/*` and `/api/v2/*` management answer 410; ingress aliases under both prefixes keep working.
- **Removed with their features:** test environments and the Honeycomb lifecycle, the v1 WebSocket/relay/pull
  delivery, `testcontainers`/`tokio-tungstenite` dev-dependencies and axum's `ws` feature. Tables they created stay.
- **OpenAPI** rewritten for v3 (2,335 lines, redocly clean); `.env.example`, `docker-compose.yml`,
  `docs/deployment.md` (service configuration + 1.0 upgrade order) updated; CI gets a `postgres:16` service.

### Commits

| commit | subject |
|---|---|
| 03ad12f | Run PostgreSQL integration tests against a provided server instead of Docker |
| 0a7babb | Remove test environments, Honeycomb lifecycle and the v1 delivery transports |
| 1401f05 | Authenticate with Silicon Accounts and give every hook to its Silicon |
| 28590b6 | Refuse tokens revoked before Hook met the account, and test access over HTTP |
| 1e96247 | Test the upgrade path, link-identities and delivery through Ting |
| 7fff1c8 | Describe API v3 in the OpenAPI document |
| 3bd761a | Document Hook's Silicon Accounts configuration and the 1.0 upgrade |
| f5ff7ae | Run the PostgreSQL tests in CI against a service container |
| a4d9339 | Keep the docs site's links valid after the deployment guide rewrite |

### Tests (final run, 2026-10-10)

`export CARGO_TARGET_DIR=$PWD/target/mig CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=3
HOOK_TEST_POSTGRES_URL=postgres://postgres@127.0.0.1:5460/postgres`

| command | result |
|---|---|
| `cargo test --workspace --locked --all-targets --all-features` | all pass. Service: lib 137; `accounts_access` 5; `accounts_webhook` 5; `migration_upgrade` 1; `postgres_integration` 19 (+1 ignored, needs a Space Station key); `ting_delivery` 2. CLI 7 + 19 + 4 + 6, client 1 + 1 + 4 + 4 + 5 + 14 (same as baseline) |
| `cargo fmt --all --check` | ok |
| `cargo check --workspace --locked --all-targets --all-features` | ok |
| `cargo clippy --workspace --locked --all-targets --all-features -- -D warnings` | ok |
| `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --locked --no-deps --all-features` | ok |
| `npx --yes @redocly/cli@2.49.0 lint openapi.yaml` | valid, 0 warnings (1 documented ignore) |
| `cargo deny --locked check` | advisories, bans, licenses, sources ok |
| `python3 scripts/bundle-cli-docs.py --check` | ok |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | ok |
| `npm ci && npm run build && npm run check` in `docs-site` | 28 pages, 1,186 links ok |

Compared with the baseline: `postgres_integration` 21 → 19 because its two test-environment and Honeycomb lifecycle
tests went with those features; the rest were adapted (identity fixture, Accounts hook instead of the IAM hook, v3
contract lifecycle, additive 0019 columns). Of 153 baseline unit tests, 16 no longer exist: they covered the IAM
client, the WebSocket, publisher credentials, IAM-scoped Ting receivers, org ids and local auth, or were renamed to
Accounts-era equivalents (`application_failures_map_to_their_statuses`, `worker_does_not_load_api_credentials_or_crypto`,
the rewritten Ting client and outbox tests). The six Docker-only Ting/WebSocket suites were removed with their
features; `ting_delivery.rs` (new) covers the Accounts-era adapter.

New coverage: test JWKS and token refusals (`wrong aud`, `wrong iss`, expired, unknown `kid`, bad signature,
malformed; rotated keys picked up), signed webhooks (forged, stale, unsigned, not an event, ping, unknown type,
dedupe, all six events incl. `app_revoked` vs other sign-outs), the authz matrix for every route family, the
allow-list rule, introspection on sensitive routes, ingress aliases after a rename, `410 account_deleted`, migrations
on an empty database (schema contract) and on the 0018 upgrade path with an IAM-era fixture, `link-identities`
through the real binary (dry run, real, idempotent re-run, conflict, unlink, malformed file), Ting enabled (Proof
header, uuid recipients, observer copies, receipts) and disabled.

### End to end against the shared local Silicon Accounts stack

hook-api ran on 127.0.0.1:4201 (database `hook_e2e` on 5460 with real runtime roles and grants) with
`ACCOUNTS_URL=http://localhost:9590`, `ACCOUNTS_API_URL=http://127.0.0.1:9589` and hook's dev credentials; hook's
local-stack webhook was pointed at it for the run and removed afterwards (it was unset before). With a minted Carbon
and its Silicon (`si:hook-e2e-590574`), 19/19 checks passed: real Silicon and Carbon tokens accepted; a first-party
token refused with `token_wrong_audience`; hook creation with real introspection; the custodian found through a real
lookup and listed the Silicon's hooks and history; ingress by id and uuid; the stack's `ping` and
`account.id_changed` deliveries were acknowledged (204) and both the old and new id kept routing; after the Silicon
removed Hook's access (`membership.access_removed`) its old token got `session_ended` while the custodian kept
managing the hooks. Everything was stopped and dropped afterwards (script: scratchpad `hook-scripts/e2e.py`).

### Blocked on

- **Ting still signs in with IAM** (D4). The adapter sends Silicon Accounts proofs; production Ting will accept them
  only after it migrates. Until then keep `HOOK_TING_URL` unset in production (Hook keeps receiving and storing).

### Left for later stages

- CLI 1.0.0: device-flow / `--slt` login, `accounts --json` (hidden `iam --json` alias), Silicon selection by id/uuid
  instead of `--org`, commands for access and allow-lists, v3 routes, new telemetry operation names
  (`src/telemetry/events.rs` allow-list + OpenAPI `TelemetryEvent`).
- Client 1.0.0: v3 paths, bearer = Accounts token, `silicon: {uuid, id}` in hooks/events and the Ting `EventReference`
  (no org/environment fields), relay adapter.
- Web: Next.js + Arc UI BFF on the v3 API (polling live view).
- Packaging: `apps.yaml`, release workflow, remove Honeycomb files.
- Deploy installers still write IAM-era variables and the removed test database: `deploy/aws/install.py`,
  `deploy/aws/prepare.py`, `deploy/native/install.py`, `scripts/test_native_deployment.py`, `scripts/ting_e2e/*`.
  hook-api will refuse to start without `HOOK_APP_SECRET`.
- Docs: the `docs/` tree (except the new deployment sections), `API_DOCS.md`, `IAM_INTEGRATION.md`,
  `RELEASE_IAM5.md` still describe the old model.
- Cutover: set hook's production webhook (six events), `HOOK_APP_SECRET` and `HOOK_ACCOUNTS_WEBHOOK_SECRET`, produce
  and review the production mapping, run `link-identities` (dry run first).
- `docs/migration/understanding-proposal.md` is for the Carbon to apply to UNDERSTANDING.md.

### Gotchas

- sqlx 0.9 refuses dynamic SQL unless wrapped in `sqlx::AssertSqlSafe`.
- `psql -c` with several statements runs them in one transaction, which `DROP DATABASE` refuses: pass separate
  `--command`s. Migration 0017 must be applied with `psql -1` when replaying migrations by hand.
- The local Accounts CLI defaults to production when `--url` and `ACCOUNTS_URL` are absent; the e2e run used plain
  HTTP calls to 127.0.0.1:9589 instead.
- A per-worktree `info/exclude` is ignored (git reads the common dir); `.mig/.gitignore` holds `*`.

## 2026-10-10 — Stage 2: client crate and CLI

### What the CLI stage did

- **`silicon-hook-client` 1.0.0** speaks API v3 only (handshake advertises and pins `v3`). Bearer = a Silicon
  Accounts access token issued to Hook. Gone: Hook-mediated SLT login/refresh/logout, `with_organization`,
  test-key/test-app-secret selection, publisher provisioning, Ting authorization, scoped test receivers,
  `environments`, the crates.io `updater`, `connect_iam_hook`. New: `signin` (device flow with
  interval/`slow_down`/expiry, public-client SLT exchange with the exact refusal reason, refresh, revoke — built on
  `silicon-accounts-client` 0.4.0, two form POSTs sent directly because the published crate lacks them), `silicons`,
  `access`/`grant`/`revoke`/`leave`, `allow_list`/`allow`/`disallow`, `connect_accounts_hook`, `delivery_status`,
  `sign_in_information`, typed `Error::Api(ApiError{status, code, message, details, hint, request_id, retry_after})`
  and `Error::SignIn`. Models show accounts as `{uuid, id}`; the Ting `EventReference` carries
  `silicon: {uuid, id}` and refuses the old tenant/environment fields; the receiver matches `for` given as uuid, id
  or `{uuid, id}`. Examples rewritten.
- **`hook` 1.0.0**: `hook login` = Carbon device flow (`--json` progress lines, `--open`), `--slt-stdin`,
  `--slt`, positional `<SLT>` (and hidden `--slt-file`); `login status [--offline]` (always exit 0 with `--json`;
  exit 1 signed out without it); `logout` revokes at Silicon Accounts; `whoami`; `accounts --json` (offline, exit 0;
  hidden `iam --json` prints the same); new `silicons`, `access`, `allow-list`, `connect-accounts`,
  `system delivery`, `config set accounts-url`/`config unset`. Removed `--org`/`--test`/`--production` (hidden, fail
  with an explanation), `env`, `publisher`, `connect-iam`, Ting-approval and sandbox `receiving` subcommands.
  Sessions in `.silicon-hook/profiles.json` (0600, atomic, `profiles.lock`), refreshed once under the lock with an
  interrupted-refresh marker; IAM-era `state.json` untouched, settings carried over, `previous_version_session`
  reported. Structured errors with stable codes and exit codes 1–6/130.
- **Service**: telemetry operation allow-list (and the OpenAPI `TelemetryEvent` enum) gained the new command names;
  the request-event filter now skips `/api/v3/telemetry` (it named the retired v2 path).
- **Docs**: new `docs/accounts/README.md` (Sign in to Hook); rewritten overview, CLI, Rust client, receiving
  through Ting, API reference (v3), delivery, contracts, configuration, telemetry. `scripts/bundle-cli-docs.py`
  bundles exactly the `hook docs` topics and refuses leftovers; the docs site no longer publishes the IAM,
  test-environment and Ting-issue records (files kept for the history move) and its footer says API v3.

### Commits

| commit | subject |
|---|---|
| 26522d5 | Sign the client and the hook CLI in with Silicon Accounts (1.0.0) |
| 78d8d7a | Accept the 1.0 CLI's command names in client telemetry |
| 252ddcc | Say what connect-accounts stored, and give account refusals precise hints |
| cd0e18a | Document signing in with Silicon Accounts, the 1.0 CLI and client, and API v3 |
| e80065d | Record the client and CLI stage in the migration log and decisions |
| 3f23482 | Show how the access, allow-list, receiving, config and events commands are used |

### Tests (final run, 2026-10-10)

`export CARGO_TARGET_DIR=$PWD/target/mig CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=3
HOOK_TEST_POSTGRES_URL=postgres://postgres@127.0.0.1:5460/postgres`

| command | result |
|---|---|
| `cargo test --workspace --locked --all-targets --all-features` | all pass. Service unchanged (lib 137; accounts_access 5; accounts_webhook 5; migration_upgrade 1; postgres_integration 19 + 1 ignored; ting_delivery 2). CLI: unit 12, `commands` 6, `discovery` 5, `login` 15. Client: unit 1, `api` 6, `byos` 1, `signin` 8, `ting_delivery` 13 |
| `cargo fmt --all --check` | ok |
| `cargo clippy --workspace --locked --all-targets --all-features -- -D warnings` | ok |
| `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --locked --no-deps --all-features` | ok |
| `cargo deny --locked check` | advisories, bans, licenses, sources ok |
| `npx --yes @redocly/cli@2.49.0 lint openapi.yaml` | valid (1 documented ignore) |
| `python3 scripts/bundle-cli-docs.py --check` | ok |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | 4 ok (needed `honeycomb.yaml` at 1.0.0) |
| `npm run build && npm run check` in `docs-site` | 20 pages, 750 local links ok |
| `cargo package --list -p silicon-hook-client` / `-p silicon-hook-cli` | ok |
| `cargo publish --dry-run -p silicon-hook-client` | ok (nothing uploaded). The CLI's dry run needs client 1.0.0 on crates.io first |

What the new tests cover: client — v3 handshake refusing a v2 server before any token is sent, every path/verb/body
(hooks, history, access, allow-list, accounts hook, delivery), the error envelope (details, hint, request id,
Retry-After), URL rules; sign-in against a stub Silicon Accounts — device flow pending → slow_down (+5 s measured)
→ approved, denied, expired, deadline, transient 503 retried; SLT exchange with `client_id=hook` and no secret,
each refusal reason, `NotEnabled`, local refusal of non-SLTs (nothing sent); refresh rotation and ended sign-ins;
revoke form; unreachable Accounts = `Unavailable{maybe_processed: false}`; Ting callbacks and hydration with the new
reference (renamed Silicon still hydrates by uuid, pre-1.0 references refused, Carbon observers). CLI — argument
tree, help without retired words, retired commands rejected, target selection, session binding; state perms (0700 /
0600), atomic writes, the lock blocks a second holder, unreadable file handling, legacy import (opt-out kept,
tokens never read, `state.json` untouched); with the real binary against a stub Accounts + Hook: discovery in an
empty home and with no HOME at all, device flow with NDJSON lines, denied/expired, SLT never echoed or stored, each
refusal reason, refresh saved before use, five concurrent commands → exactly one refresh and no reuse, three
commands blocked by a held lock → zero refreshes until released then one, ended sign-in forgotten, interrupted
refresh revoked instead of presented, 401 → one refresh + retry, logout revokes, legacy state, unreadable state
recovered by login, `signed_in_elsewhere`, `--org` refused, telemetry on/off, every management command's request.

### End to end against the shared local Silicon Accounts stack

hook-api ran on 127.0.0.1:4201 (database `hook_cli_e2e` on 5460, runtime roles `hook_cli_api`/`hook_cli_worker`
with the real grant manifest; `ACCOUNTS_URL=http://localhost:9590`, `ACCOUNTS_API_URL=http://127.0.0.1:9589`,
hook's dev secret, Ting off). Scripts: scratchpad `hook-scripts/cli-service.sh start|stop`,
`cli-e2e-silicon.sh`, `cli-e2e-carbon.sh`, `cli-e2e-refresh.sh` (they never print STKs, SLTs or tokens). Identities:
Carbon `c:hook-cli-c1-99293` (uuid `dio`) and its Silicon `si:hook-cli-s1-99293` (uuid `PB7`).

- **Silicon**: `mint.mts slt --app hook` → `printf %s "$SLT" | hook login --slt-stdin` in a fresh `SILICON_HOME` →
  `authenticated: true, uuid PB7, kind silicon, verified: true` → `login status --json` verified by Hook →
  `hook create GitHub --unsigned` (201, `silicon {uuid PB7, id si:hook-cli-s1-99293}`, created_by the Silicon) →
  `hook create Stripe` (signed, generated secret returned once) → a provider POST to the GitHub URL answered
  `webhook.ok` → `hook list` (2 hooks) → `hook events --hook …` (`GitHub triggered at 02:43:06 10-10-2026 UTC`,
  body `{"action":"opened"}`) → `hook event <id>` → `hook publication <id>` (`state: delivery_disabled` with the
  explanation) → `hook rotate secret` → `hook connect-accounts` (`set_webhook: silicon-accounts webhook set
  http://127.0.0.1:4201/silicon/si:hook-cli-s1-99293/HG3RQINL`) → `hook access list` (`you: self`, custodian
  `c:hook-cli-c1-99293`) → `hook system delivery` (`enabled: false` + reason) → `hook logout` (`revoked: true`) →
  `login status --json` = `{"authenticated": false}` → `hook --json list` exit 3 `not_signed_in`.
- **Carbon (device flow)**: `hook login --json &` printed
  `{"event":"device_code","user_code":"9X2C-M58A","verification_uri":"http://localhost:9590/device",…,"interval":5}`
  → `mint.mts approve --email hook-cli-c1-99293@example.test --code 9X2C-M58A` (204) → the CLI finished
  (`kind carbon, uuid dio, method device, verified true`) → `hook silicons` (`PB7`, access `custodian`) →
  `hook --silicon si:hook-cli-s1-99293 list` (the Silicon's 3 hooks) and `events` → `create Linear` recorded
  `created_by {uuid dio, kind carbon}` (the custodian, not the Silicon) → granting an unknown `c:` id: exit 4
  `account_not_found` with Hook's message → `hook --json list` without `--silicon`: exit 2 "Which Silicon?" naming
  `hook silicons` → `hook logout` (`revoked: true`).
- **Refresh and sign-out at the real stack**: after `hook login <SLT>` (positional), the saved access token was set
  to expire in 10 s; `hook list` refreshed with `client_id=hook` (refresh and access token digests both changed,
  new expiry 1800 s, no marker left), `login status --json` verified; after `hook logout`, presenting its refresh
  token answered `invalid_grant … revoked at … (app_revoked)`.
- **Refusals at the real stack**: reusing an SLT → exit 3 `details.reason: already_used`; an SLT minted with
  `--app dm` → `wrong_app` ("issued for the app 'dm', not for 'hook'"); `slt_mistyped` → `unknown`; an SLT used
  three seconds after its two minutes → `expired` ("expired at 2026-10-10T02:59:08.315Z (they last 120 seconds)").
  Each hint says `silicon-accounts login --app hook -q | hook login --slt-stdin`.
- **Discovery in an empty `HOME`/`SILICON_HOME`** (`env -i HOME=$E SILICON_HOME=$E PATH=/usr/bin:/bin`):
  `hook --help` exit 0 (5,436 bytes); `hook accounts --json` exit 0 →
  `{"app_id":"hook","name":"Silicon Hook","version":"1.0.0","accounts_url":"https://accounts.teamofsilicons.com","api_url":"https://backend.hook.teamofsilicons.com","api_version":"v3","docs":…,"repository":…,"install":"silicon-apps install hook","sign_in":{…},"state_dir":"$E/.silicon-hook"}`;
  `hook login status --json` exit 0 → `{"authenticated": false}`; `hook iam --json` identical to
  `accounts --json`; no file created in the home.

### Blocked on

- Nothing new. The service stage's Ting note still applies (Ting must accept Silicon Accounts proofs before
  `HOOK_TING_URL` is set in production).

### Left for later stages

- Release stage: `apps.yaml` + `scripts/package-apps.sh` + release workflow (replace `honeycomb.yaml`,
  `scripts/package-cli.py`, `scripts/test_package_cli.py`; `honeycomb.yaml` was only bumped to 1.0.0);
  `docs/releases.md` and the tail of `docs/deployment.md` (CLI release artifacts) still describe Honeycomb;
  `docs/install.sh` (copied by the docs site) is the Honeycomb installer shim; root `README.md`, `API_DOCS.md`,
  `IAM_INTEGRATION.md`, `RELEASE_IAM5.md`, `docs/verification/*`, and the move of `docs/iam`, `docs/testing`,
  `docs/ting-integration-issues.md`, `docs/ting-implementation.md`, `docs/frontend-iam5-contexts.md` into
  `docs/history/` (the docs site already skips them and `history/`). The service crate version (0.10.1 → 1.0.0).
- Web stage: the web console must call API v3 with `silicon: {uuid, id}` shapes (see `docs/api/README.md`);
  `docs-site/build.mjs` copies `web/public/brand/mark.svg` as the favicon, keep or move that file.
- e2e stage: `scripts/dev-accounts.sh`; the CLI scripts above can be reused. The webhook scenarios (id change,
  access removed) were proven by the service stage, not re-run here.
- Silicon runtime (outside the migration): it runs `hook login <SLT>` and `hook iam --json`; both still work (the
  alias is hidden). It must mint the token with `silicon-accounts login --app hook -q`.

### Gotchas

- `std::env::set_var` is `unsafe` in Rust 2024 and the crates forbid unsafe code: unit tests that need another
  state directory call `Locked::open_in(dir)`; the binary's behaviour with environment variables is tested by
  spawning it.
- Integration tests spawn the real binary with `env_clear()` plus `PATH` (the device flow's label runs `hostname`)
  and `SILICON_HOOK_TELEMETRY=off`.
- `tokio::join!` is needed to start several `hook` processes at once; awaiting the futures in order runs them one
  after the other.
- The local stack's device flow interval is 5 s; approving with `mint.mts approve` right after the code is printed
  finishes the login within one interval.

## 2026-10-10 — Stage 3: packaging, CI, deployment configuration and documentation

### What the ship stage did

- **Silicon Apps packaging.** `packaging/apps.yaml.in` (one target per archive) and `scripts/package-apps.sh
  <version> <target> <binary>` (over `scripts/package_apps.py`, Python 3.9+, stdlib): native-format and processor
  check, glibc ceiling 2.39 for dynamic Linux builds, the three discovery commands plus `--version` in an empty
  `HOME`/`SILICON_HOME` (required with `PACKAGE_DISCOVERY=require`, skipped with a note where the binary cannot run,
  never silently), `silicon-apps validate` + `pack` with an empty home and no server, exact archive inventory, a
  second validation of the archive and of its extracted files, `dist/apps/hook-<v>-<target>.tar.gz` + `.sha256`.
  `--check-only` checks a binary without packing. `honeycomb.yaml`, `scripts/package-cli.py` and its tests are gone;
  `scripts/package-backend.py` reuses the new executable check. Service crate 0.10.1 → 1.0.0.
- **CI.** `release.yml` ("Silicon Apps release archives"): tag `v*` (must equal `crates/cli/Cargo.toml`) or manual;
  the same six targets and runners as 0.x; each build job checks its binary on its own runner; one packing job
  installs `silicon-apps-cli` 0.2.0 and uploads `hook-silicon-apps-release` (six archives, `.sha256` files,
  `SHA256SUMS`). `ci.yml`: the docs job is renamed and runs all `scripts/test_*.py`. `deployment-builds.yml` no longer
  builds the gateway image.
- **Deployment configuration (nothing deployed).** `deploy/native/install.py` takes Hook's Silicon Accounts
  settings from an owner-only `accounts.env` on the first 1.0 install (API only), refuses without
  `HOOK_APP_SECRET`/`HOOK_ACCOUNTS_WEBHOOK_SECRET`, drops the previous sign-in's, test environments' and lifecycle
  settings and `HOOK_TING_BASE_URL`, backs up but never migrates `hook_test`, previews changes by name.
  `deploy/aws/{install,prepare}.py` and `backup.sh` (host rebuild and daily backup) switched to `accounts.json`, no
  test database, no gateway; Caddy proxies only the API. `deploy/native/draft-identity-mapping.py` (shipped in the
  backend bundle) drafts the `link-identities` file from Silicon Accounts lookups. `docs/migration/cutover.md`: the
  production runbook (every production command marked *run at cutover*), verification, rollback, the old CLIs,
  Ting.
- **Documentation.** New root `README.md` and `docs/releases.md`; `docs/deployment.md` (where Hook runs, release
  artifacts), install sections (Linux today, macOS/Windows packages kept), contract wording; `docs/install.sh`
  installs through Silicon Apps; bundled CLI docs re-synced. Records of Hook before 1.0 moved to `docs/history/`
  (index, links pinned to `d621aba`); `IAM_INTEGRATION.md` and `scripts/ting_e2e/` deleted. The docs site publishes
  neither `docs/history/` nor `docs/migration/`, and now has the Silicon look (tokens, light/dark/system switch, BDO
  Grotesk titles, Hook mark) instead of its green/Inter one.
- **UNDERSTANDING proposal** extended: the Updates section for one archive per target, `app iam --json`, and the
  Carbon-owned `understanding/api.yaml` route inventory.

### Commits

| commit | subject |
|---|---|
| 5bc3554 | Package the hook CLI for Silicon Apps instead of Honeycomb |
| d4b81b5 | Build Silicon Apps archives in the release workflow and drop Honeycomb |
| d3d577e | Deploy Hook 1.0 with Silicon Accounts settings and write the cutover runbook |
| f7bf6be | Document Hook 1.0 releases, hosting and install with Silicon Apps; move history |
| 0235dd1 | Remove the end-to-end fixture of the previous sign-in and test environments |
| d7fa5a9 | Describe owner scopes in code comments instead of tenants and organizations |
| 380229f | Give the docs site the Silicon look, with light, dark and system modes |
| 973c7b5 | Record the ship stage in the migration log, decisions and proposal |
| a32bbee | Link the release guide from the docs index and simplify local setup in the README |

### Tests (final run, 2026-10-10, after d7fa5a9; docs site re-checked after 380229f)

`export CARGO_TARGET_DIR=$PWD/target/mig CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=3
HOOK_TEST_POSTGRES_URL=postgres://postgres@127.0.0.1:5460/postgres HOOK_TEST_PSQL=/opt/homebrew/opt/postgresql@16/bin/psql`
(script: `.mig/ship-tests.sh`, log `.mig/logs/ship-tests.log`)

| command | result |
|---|---|
| `cargo fmt --all --check` | ok |
| `cargo check --workspace --locked --all-targets --all-features` | ok |
| `cargo clippy --workspace --locked --all-targets --all-features -- -D warnings` | ok |
| `cargo test --workspace --locked --all-targets --all-features` | all pass, same counts as stage 2: service lib 137, accounts_access 5, accounts_webhook 5, migration_upgrade 1, postgres_integration 19 (+1 ignored: needs a Space Station key), ting_delivery 2; CLI unit 12, commands 6, discovery 5, login 15; client unit 1, api 6, byos 1, signin 8, ting_delivery 13 |
| `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --locked --no-deps --all-features` | ok |
| `cargo deny --locked check` | advisories, bans, licenses, sources ok |
| `npx --yes @redocly/cli@2.49.0 lint openapi.yaml` | valid |
| `python3 scripts/bundle-cli-docs.py --check` | ok |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | 25 ok (packager 17, native installer 5, mapping draft 3), under Python 3.14 and under macOS's `/usr/bin/python3` 3.9 |
| `npm run build && npm run check` in `docs-site` | 12 pages, 473 local links/assets ok |
| workflow YAML | parsed with Ruby's YAML and PyYAML (scratch venv); a structural check (jobs, `needs`, outputs, matrix keys, pinned `uses`) passed for all four files; actionlint is not installed |

### Packaging proof (this Mac)

- `cargo build --release --locked -p silicon-hook-cli` (1m07s) → `scripts/package-apps.sh 1.0.0 macos-aarch64
  target/mig/release/hook --discovery require` → `binary: … macos-aarch64 executable (Mach-O)`, `discovery: --help,
  accounts --json, login status --json and --version answered as Silicon Apps requires`, `packaged
  dist/apps/hook-1.0.0-macos-aarch64.tar.gz (2992069 bytes)`, sha256 `bd3d42de358d0de3805b2dc47017df04a89505e0cd8cec2c7f4f59558e40bcd7`
  (identical to a manual `silicon-apps pack` of the same files: the pack is deterministic).
- `silicon-apps validate` (0.2.0, empty `--home`, `--server http://127.0.0.1:9`): `"valid": true` on the staged
  directory and on the archive; nothing written to the home.
- From the extracted archive (`apps.yaml` + `bin/hook` only), `env -i HOME=$E SILICON_HOME=$E PATH=/usr/bin:/bin`:
  `hook --help` exit 0 (5,436 bytes), `hook accounts --json` exit 0 (709 bytes, `"app_id": "hook"`, version 1.0.0),
  `hook login status --json` exit 0 → `{"authenticated": false}`; 0 files in the home afterwards.
- The release workflow's packing loop, simulated with the real macOS binary and header fixtures for the other five
  targets (mode 0644, as downloaded artifacts are): six archives, `.sha256` files and `SHA256SUMS` that verify;
  discovery ran for macos-aarch64 from the 0644 copy and was skipped with a note for the targets this Mac cannot run.
- `scripts/package-backend.py` with fixture ARM64 binaries: the bundle now includes `draft-identity-mapping.py`,
  and `install.py`'s `verify()` accepts it.

### Mapping draft end to end (shared local stack + PostgreSQL 5460)

Scratch script `hook-ship/mapping-e2e.sh`: database `hook_ship_mapping` migrated with `hook-migrate`, a minted
Carbon and Silicon (`si:hook-ship-s1-02830` uuid `TSZ`, custodian `c:hook-ship-c1-02830` uuid `hzg`) plus two unknown
ids in the inventory → `draft-identity-mapping.py --accounts-url http://127.0.0.1:9589` with hook's dev secret:
`{"stored_ids": 4, "mapped": 2, "left_out": 2}`, both unknown ids `account_not_found`, the Silicon's custodian listed;
`hook-migrate link-identities --dry-run` → `rows_in_file 2, linked 2, unlinked 0, hooks_without_owner 0`; the real
run linked both (`source mapping:3bdab8d6…`). Database dropped afterwards (no `hook*` databases or roles left).

### Docs site look (screenshots in scratch `hook-ship/screens/`, not in git)

Home, Releases and API pages at 1440×900 and 390×844 in light and dark, the switch (Dark chosen, reload keeps it:
`data-theme="dark"`, `aria-pressed="true"`), search results and the 404 page: no console errors, BDO Grotesk 600
loaded, nothing scrolls sideways except code. Found and fixed: the page outline showed `Hook&#39;s` (double
escaping); headings are now slugged from plain text.

### Sweep

`git grep -n -i -E 'iam|honeycomb|org_id|organi[sz]ation|\borg\b|tenant'`, every remaining hit is intentional:

| where | why it stays |
|---|---|
| `web/` (356) | the old SolidJS console and gateway; the web stages replace and delete `web/` |
| `docs/history/` (317) | historical records, kept as written (brief) |
| `migrations/` (101) | applied migrations are checksummed by readiness and must never change |
| `docs/migration/` (70) | the migration's own records (decisions, progress, cutover, proposal) may name both |
| `understanding/` (34) | Carbon-owned contract and route inventory; changes proposed in `understanding-proposal.md` |
| `tests/`, `crates/*/tests`, `crates/cli/src/tests.rs`, `src/**` test fixtures | legacy-data fixtures (0018 upgrade, old Ting references) and assertions that retired words, flags and fields are refused or absent |
| `src/infrastructure/postgres/{schema_contract,events,idempotency,ting}.rs`, `deploy/postgres/grant-runtime.sql` | the legacy `org_id` / `iam_public_id` / `is_iam_default` columns: kept (no data deleted, no column renamed), new rows get the constant `accounts`, readiness checks the exact schema |
| `src/infrastructure/postgres/identity_links.rs`, `src/bin/hook_migrate.rs`, `deploy/native/draft-identity-mapping.py`, `tests/migration_upgrade.rs` | the operator's link-identities path exists only to link ids stored before 1.0 (decisions) |
| `src/infrastructure/postgres/types.rs` (`IamConnected` → `hook.iam_connected`) | audit action of rows written before 1.0 |
| `src/config.rs` (`OBSOLETE_VARIABLES`) | names each old variable to say what replaced it |
| `src/domain/request.rs` (`iam_test_key`) | header redaction: never store the old selector/test-key headers if a provider sends them |
| `crates/cli/src/{args,main,status}.rs`, `src/telemetry/events.rs`, `openapi.yaml` `TelemetryEvent` | the hidden `hook iam --json` alias (brief) and old CLIs' telemetry operation names |
| `crates/cli/src/store.rs`, `store/load.rs` | describe the pre-1.0 `state.json` the CLI leaves untouched |
| doc comments saying "IAM-era id" (`src/domain`, `src/api/dto.rs`, `src/application`, `postgres/hooks.rs`, `postgres/ting.rs`) | accurately describe legacy rows and parked sends |
| `deploy/native/install.py`, `deploy/aws/backup.sh`, `scripts/test_native_deployment.py` | remove `HOOK_IAM_*`/`HOOK_HONEYCOMB_*` settings and back up the old `iam.json` while it is on the host |
| `deploy/aws/standalone.yaml` | AWS IAM (the cloud's roles), a different product |
| `observability/spacestation/*` | Space Station's own organization (`tos`) for its table; not Hook's |

### Blocked on

- Nothing new. Ting must accept Silicon Accounts proofs before `HOOK_TING_URL` is set; the Silicon runtime must
  install from Silicon Apps and mint with `silicon-accounts login --app hook -q` (both in cutover.md).

### Left for later stages

- **Web stages**: replace `web/` (and the `frontend` job in `ci.yml`, which still builds the SolidJS console); the
  root README's "web console" sentence and `docs/deployment.md` describe the D7 target (Next.js on Vercel, BFF,
  `https://hook.teamofsilicons.com/auth/callback`) — keep them true and add the one-command local run; cutover step 7
  points at the web's `.env.example` for its server settings; the web's CSP (Silicon Accounts, profile photos).
- **e2e stage**: `scripts/dev-accounts.sh`; the stage 2 CLI scripts in scratch can be reused.
- **Fix stage (observation, not changed here)**: on Windows the CLI finds its home only through `SILICON_HOME` or
  `HOME` (no `USERPROFILE` fallback), as before 1.0; `login status --json` still answers (`reason: no_home`), but a
  Windows Carbon must set one to sign in. It matters once Silicon Apps validates Windows.
- **Operator (cutover.md)**: every production step.

### Gotchas

- `psql` is not on this Mac's PATH: `/opt/homebrew/opt/postgresql@16/bin/psql` (`HOOK_TEST_PSQL`, `HOOK_PSQL`).
- No PyYAML in either Python; Ruby's YAML or a scratch venv (`pip install pyyaml`) parses the workflows.
- Playwright for screenshots: the web kit's `node_modules/.pnpm/playwright@1.56.1/node_modules/playwright/index.mjs`.
- Downloaded workflow artifacts lose their mode bits; the packager runs discovery on an executable private copy.
- A relative binary path made the first discovery attempt fail inside the empty home and get mistaken for "cannot
  run here"; the packager now resolves the path and treats only Exec-format/Bad-CPU errors as "cannot run".
- `silicon-apps validate` accepts an archive as well as a directory.

## 2026-10-10 — Stage 4: end to end against Silicon Accounts

### What the e2e stage did

- **`scripts/dev-accounts.sh start|restart|status|stop|down`** (over `scripts/dev_accounts.py`): builds, creates
  and migrates `hook_e2e` on 5460 with roles `hook_e2e_api`/`hook_e2e_worker` and the real grant manifest,
  generates Hook's webhook secret at the stack and points the webhook at `http://127.0.0.1:4201/webhook` with
  every update, starts hook-api (4201) and hook-worker, and does not report success until a signed `ping` from
  the stack was acknowledged. `--ting-stub` adds the Ting stand-in on 4202 (`scripts/ting_stub.py`), which
  verifies every proof Hook presents with the receiving app's own credentials. Idempotent; keys and the webhook
  secret survive restarts in `.mig/dev-accounts.env` (0600); pids in `.mig/pids`; `down` leaves nothing behind.
- **`scripts/e2e-accounts.sh`** (over `scripts/e2e_accounts/`): every scenario of the stage, scripted, with real
  tokens, against the shared stack: 0 identities, 1 Carbon on the API (web code + PKCE exchange), 2 Silicon on
  the CLI, 3 device flow, 4 circle and sharing, 5 webhooks, 8 restart safety, 9 Silicon Accounts cut off (added),
  6 proofs (issuer side), 7 discovery from a packaged archive. It starts from `down`, ends with `down`, and
  writes `<state>/e2e-<n>/report.json`.
- **Bugs found and fixed** (each with a regression test, unit or integration, plus the e2e check):
  1. A token issued in the same second as a sign-out was refused: `iat` has whole seconds, sign-outs have
     milliseconds. Probe: after an STK rotation, the Silicon's new token was refused once the event landed in
     3 of 4 attempts (`rotated_at 04:12:20.041Z`, new token `iat` …540 → 401 `session_ended`; the one that
     crossed into the next second passed). Now settled by introspection for that second only (`30e499a`).
  2. Ting proof requests multiplied with the queue: with Ting's app missing at Silicon Accounts, 5 queued sends
     made 5 refused proof requests (`400 unknown_receiving_app`) and 5 warnings, repeating every 30 s per send.
     Now one request, then a pause of 30 s doubling to 5 min; the sends stay `pending` / `proof_unavailable`
     (`93270b4`).
  3. Silicon Accounts outages answered `503 provider_unavailable` "A required dependency is temporarily
     unavailable", also when a freshly started API had no signing keys yet. Now `503 accounts_unavailable`
     saying what Hook needed it for (`1c44471`).
  4. A production webhook set the obvious way could withhold `silicon.custodian_changed` (setting the URL keeps
     earlier picks; the recommended picks lack `custodian_change`). hook-api now checks its webhook settings at
     startup and says what is missing; the cutover sets `"events": null` and verifies it (`887d8cf`).
  5. The receiving app of Hook's Ting proofs was the constant `ting`, absent from the stack: now
     `HOOK_TING_APP_ID` (default `ting`) (`9727852`).

### Commits

| commit | subject |
|---|---|
| 9727852 | Name Ting's Silicon Accounts app in HOOK_TING_APP_ID instead of fixing it to ting |
| 30e499a | Accept a token signed in again in the second of a sign-out once Accounts confirms it |
| 8907f0a | Run Hook against a Silicon Accounts test stack and prove it end to end |
| 93270b4 | Pause Ting proof requests after a failure instead of asking once per queued send |
| 1c44471 | Say that Silicon Accounts did not answer instead of a generic dependency error |
| 3421fde | Prove Hook end to end while Silicon Accounts stops answering, and observer copies follow access |
| aaef145 | Close the Ting loop end to end: the Silicon's receiving host hydrates from Hook |
| 70624f7 | Check a denied device code end to end and describe the whole e2e run |
| 887d8cf | Check at startup that every account event Hook acts on reaches it |
| 1498516 | Record the end-to-end stage in the migration log, decisions and cutover runbook |

### Tests (final run, 2026-10-10, after 887d8cf)

`export CARGO_TARGET_DIR=$PWD/target/mig CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=3
HOOK_TEST_POSTGRES_URL=postgres://postgres@127.0.0.1:5460/postgres HOOK_TEST_PSQL=/opt/homebrew/opt/postgresql@16/bin/psql`

| command | result |
|---|---|
| `cargo fmt --all --check` | ok |
| `cargo clippy --workspace --locked --all-targets --all-features -- -D warnings` | ok |
| `cargo test --workspace --locked --all-targets --all-features --no-fail-fast` | all pass. Service: lib 142 (+5: Ting app id setting, proof pause schedule, 3 webhook-settings findings), accounts_access 6 (+1 Accounts outage), accounts_webhook 6 (+1 same-second sign-out), migration_upgrade 1, postgres_integration 19 (+1 ignored: needs a Space Station key), ting_delivery 3 (+1 proof pause). CLI 12 / 6 / 5 / 15, client 1 / 6 / 1 / 8 / 13 (unchanged) |
| `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --locked --no-deps --all-features` | ok |
| `cargo deny --locked check` | advisories, bans, licenses, sources ok |
| `npx --yes @redocly/cli@2.49.0 lint openapi.yaml` | valid (1 documented ignore) |
| `python3 scripts/bundle-cli-docs.py --check` | ok |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | 25 ok |
| `npm run build && npm run check` in `docs-site` | 12 pages, 474 local links/assets ok |
| `scripts/e2e-accounts.sh` (env in `.mig/e2e.env`) | **137 passed, 0 failed in 80 s** (run 55559; earlier passes: 27/2 → 30/1 → 105/1 → 115/0 → 121/0 → 135/0 → 137/0 as checks were added; the failures were the harness's own wrong expectations, fixed) |

### End-to-end run 55559 (real output, trimmed: every check, details kept where they carry evidence)

Hook 1.0 on 127.0.0.1:4201 (`hook_e2e` on 5460), the shared stack at `http://localhost:9590`, Hook's webhook
registered for the run and removed after it.

```text
   Compiling silicon-hook-cli v1.0.0 (/Users/codanium/Documents/silicon/.worktrees/hook-accounts-apps/crates/cli)
PASS [setup] scripts/dev-accounts.sh start: fresh database, webhook registered, signed ping delivered
## Scenario 0: test identities on the shared stack
   C1: c:hook-e2e-c1-55559 (uuid oVm)
   C2: c:hook-e2e-c2-55559 (uuid fSx)
   S1: si:hook-e2e-s1-55559 (uuid 1e5)
   S2: si:hook-e2e-s2-55559 (uuid Scg)
   S3: si:hook-e2e-s3-55559 (uuid DyO)
PASS [0] S1 and S3 are looked after by C1, S2 by C2
## Scenario 1: a Carbon signs in like the web does and manages its Silicon's hooks over the API
PASS [1] GET /api/v3/auth/accounts (public) names Hook's app id and the stack as the token issuer
PASS [1] code exchange with Hook's app secret returns C1's access and refresh tokens  ({"account":{"uuid":"oVm","id":"c:hook-e2e-c1-55559","kind":"carbon"},"expires_in":1800})
PASS [1] Hook accepts the token (JWKS, audience hook, issuer the stack)  ({"app_id":"hook","authenticated":true,"id":"c:hook-e2e-c1-55559","kind":"carbon","uuid":"oVm"})
PASS [1] create: the custodian makes a signed hook for its Silicon (201, secret returned once)
PASS [1] the hook is recorded as made by the custodian, never as the Silicon
PASS [1] a provider request signed with the hook's secret is accepted
PASS [1] unverifiable requests get the identical answer (no signature oracle)
PASS [1] list: the hook is in its Silicon's list
PASS [1] read: by the Silicon's uuid, without any secret material
PASS [1] the verified request is in the history with its exact body
PASS [1] they are withheld with exact reasons: payload_unavailable, signature_missing, signature_mismatch  (["payload_unavailable","signature_mismatch","signature_missing"])
PASS [1] update: description and time zone change
PASS [1] a second hook for the delete/restore cycle
PASS [1] delete: soft-deletes the hook
PASS [1] a deleted hook's URL answers 404
PASS [1] include_deleted shows it inside its 45-day recovery window
PASS [1] restore: the same URL works again
PASS [1] delete again
PASS [1] GET /silicons lists S1 for C1 with access `custodian`
PASS [1] API v2 management answers 410 api_version_sunset with a pointer to v3  ({"error":{"code":"api_version_sunset","message":"Hook API v1 and v2 are retired. Use /api/v3 with a Silicon Accounts access token issued to Hook (Auth…)
PASS [1] ingress under /api/v1/silicon/... and /api/v2/silicon/... still verifies and accepts  ({"/api/v1":200,"/api/v2":200})
## Scenario 2: a Silicon signs in to the hook CLI with a short-lived token and uses it
PASS [2] printf %s "$SLT" | hook login --slt-stdin (fresh SILICON_HOME)
PASS [2] hook login status --json: authenticated, confirmed by Hook
PASS [2] hook create LocalDemo --unsigned
PASS [2] a provider posts to it
PASS [2] hook events --hook <id> shows the request
PASS [2] hook update --patch, then hook show reflects it
PASS [2] hook rotate endpoint: the old URL is retired (410), the new one works
PASS [2] hook list shows the custodian's GitHub hook and the Silicon's own
PASS [2] hook connect-accounts prepares the hook and names the exact silicon-accounts command  ({"set_webhook":"silicon-accounts webhook set http://127.0.0.1:4201/silicon/si:hook-e2e-s1-55559/1K5X14GQ","secret_stored_now":false})
PASS [2] the Silicon signs in to the Silicon Accounts CLI (silicon-accounts login --silicon)
PASS [2] silicon-accounts webhook set <hook URL> prints a whsec_ secret once
PASS [2] hook connect-accounts --secret-file - stores it on the same hook
PASS [2] silicon-accounts webhook test queues a signed ping
PASS [2] the ping arrives at Hook and verifies with the x-accounts-signature policy
PASS [2] …and nothing from Silicon Accounts was withheld
PASS [2] hook logout revokes the sign-in at Silicon Accounts
PASS [2] Hook hears membership.signed_out (app_revoked) and keeps the Silicon's other sign-in working  ({"reason":"app_revoked","other_token_status":200})
PASS [2] hook login status --json after logout: {"authenticated": false}, exit 0
PASS [2] the Silicon runtime's positional form, hook login <SLT>, signs it in again
## Scenario 3: a Carbon signs in to the hook CLI with the device flow
   hook login --json printed: {"event": "device_code", "user_code": "JM4U-7R9P", "verification_uri": "http://localhost:9590/device"}; approved: {'approved': 'JM4U-7R9P', 'status': 204}
PASS [3] hook login (device flow) finishes after the Carbon approves the code
PASS [3] hook login status --json: the Carbon, confirmed by Hook
PASS [3] hook silicons lists S1 as looked after by this Carbon
PASS [3] a code the Carbon denies at Silicon Accounts: exit 3 access_denied, nothing saved  ({"deny":204,"exit":3,"error":"access_denied","files":[]})
PASS [3] hook --silicon <S1> events reads the Silicon's history
## Scenario 4: the custodian circle, sharing by id, and Silicons that are not open to the world
PASS [4] the custodian sees its Silicon's hooks
PASS [4] an unrelated Carbon is refused (403)
PASS [4] …and cannot read one of its events by id
PASS [4] a sibling Silicon (same custodian) is refused too
PASS [4] the custodian makes a hook for its other Silicon S3
PASS [4] C1 grants C2 `view` by its c: id (hook access grant)
PASS [4] C2 now lists the hooks
PASS [4] C2 now reads the event
PASS [4] `view` cannot create a hook (403)
PASS [4] after an upgrade to `manage` C2 creates one, recorded as C2
PASS [4] hook access list shows the custodian and C2's grant by current id
PASS [4] unsharing removes access at once
PASS [4] a grantee can leave on its own
PASS [4] granting S2 (another custodian's Silicon) is refused until S2 allows it
PASS [4] S2's custodian adds C1 to S2's allow-list
PASS [4] now the grant to S2 goes through
PASS [4] S2 reads S1's hooks with its own token
PASS [4] …but cannot create one with `view` (403)
## Scenario 5: Silicon Accounts webhook events: id change, profile, sign-outs, custodian change, deletion, access removal
PASS [5] Silicon Accounts' own (first-party) token is refused: token_wrong_audience  ({"error":{"code":"token_wrong_audience","message":"The access token was issued to a different app; expected audience hook. Send a token issued to Hook…)
PASS [5] the custodian changes S1's id (POST /v1/me/silicons/{uuid}/id, first-party token)  ({"status":200,"id":"si:hook-e2e-s1r-55559"})
PASS [5] Hook shows the new id in GET /silicons
PASS [5] the Silicon's hooks answer to the new id and show URLs with it
PASS [5] a URL a provider already holds (old id) keeps working, and so does the new one  ({"old_id_url":200,"new_id_url":200,"verified_events":5})
PASS [5] the Silicon's CLI session from before the rename keeps working (uuid-keyed)
PASS [5] the Silicon's own Accounts hook received silicon.id_changed, verified
PASS [5] the stack replays the id-change delivery (same event_id, fresh signature)
PASS [5] Hook acknowledges the replay and ignores it (logged duplicate, one dedupe row)  ({"log":"_id=01a12424-de77-7239-9759-d2380f9efedf event_type=account.id_changed duplicate=true request_id=01a12424-e303-7151-97c2-e27bf6e90a4e method=P…)
PASS [5] a delivery reusing that event_id with a sign-out payload changes nothing
PASS [5] a delivery signed with another secret is refused (401)
PASS [5] an unsigned delivery is refused (401)
PASS [5] a correctly signed but 10-minute-old delivery is refused (401)
PASS [5] none of them signed C1 out
PASS [5] the custodian renames S1's display name
PASS [5] Hook applies account.updated to its account cache
PASS [5] the custodian rotates S3's STK
PASS [5] membership.signed_out (stk_rotated) ends S3's earlier Hook tokens (401 session_ended)  ({"reason":"stk_rotated","status":401,"code":"session_ended"})
PASS [5] a Silicon that signs in again in the very second its STK was rotated is accepted after the sign-out lands; its earlier token is refused  ({"sign_out_at":"2026-10-10T04:49:22.215Z","new_token_same_second":true,"new":200,"old":401})
PASS [5] after S2 is renamed, S1's access list shows S2's grant under its new id  ({"Scg":"si:hook-e2e-s2r-55559"})
PASS [5] C1 offers S3 to C2
PASS [5] C2 accepts and becomes S3's custodian
PASS [5] after silicon.custodian_changed the new custodian manages S3's hooks and the old one is refused  ({"new_custodian":200,"old_custodian":403})
PASS [5] GET /silicons moves S3 from C1's list to C2's
PASS [5] S3's new custodian deletes S3's account
PASS [5] account.deleted: S3's hook URL answers 410 account_deleted at once  ({"error":{"code":"account_deleted","message":"The Silicon this endpoint belonged to was deleted; it accepts no more requests.","request_id":"01a12424-…)
PASS [5] …its hooks are soft-deleted (kept for the 45-day purge, not dropped)
PASS [5] the Silicon removes Hook's access (silicon-accounts apps remove hook)
PASS [5] after membership.access_removed its old access token is refused (401 session_ended)  ({"error":{"code":"session_ended","message":"This sign-in ended at 2026-10-10T04:49:25.741Z (signed out or Hook's access removed in Silicon Accounts). …)
PASS [5] its CLI says it is signed out (exit 0)
PASS [5] the custodian still manages the Silicon's hooks
PASS [5] signing in again right away works and the Silicon's hooks are all still there
## Scenario 8: restart safety: stateless sessions, kept keys, persistent webhook dedupe
PASS [8] scripts/dev-accounts.sh restart (same database, keys and webhook secret)
PASS [8] the Silicon's CLI session works without signing in again
PASS [8] the Carbon's access token is still accepted
PASS [8] the hook CLI refreshes at Silicon Accounts when its token is about to expire (both tokens rotate)  ({"exit":0,"access_rotated":true,"refresh_rotated":true,"expires_in":1800})
PASS [8] a duplicate of an event applied before the restart is still ignored  ({"delivery":204,"c1":200,"rows":"1"})
PASS [8] a hook secret stored before the restart still verifies, and the history is intact  ({"before":11,"after":12})
## Scenario 9: Silicon Accounts stops answering: local checks and ingress keep working, the rest says why
PASS [9] Hook restarted with Silicon Accounts reached through a relay on base+3
PASS [9] with Silicon Accounts reachable, the custodian reads the hooks (keys fetched)
PASS [9] cut off: reads verified locally keep working
PASS [9] cut off: hook login status still says signed in
PASS [9] cut off: creating a hook (which must confirm the sign-in) is refused as accounts_unavailable  ({"code":"accounts_unavailable","exit_code":1,"message":"Silicon Accounts did not answer, and this request needs it (to confirm that the sign-in is sti…)
PASS [9] …and the CLI keeps its sign-in
PASS [9] cut off: provider ingress never needs Silicon Accounts
PASS [9] Silicon Accounts back: the same command succeeds
## Scenario 6: Hook as a proof issuer: Ting stand-in on base+2 verifies every proof as the receiving app 'interface'
PASS [6] restart with the Ting stand-in (HOOK_TING_URL=base+2, HOOK_TING_APP_ID=the stand-in's app)
PASS [6] GET /delivery says delivery through Ting is on
PASS [6] hook receiving register: a User verification proof from the Silicon's own token, verified by the receiver
PASS [6] the custodian subscribes to copies: a User verification proof for the Carbon
PASS [6] a provider request is stored and queued for Ting
PASS [6] the first send carried a valid App verification proof (tings.send) issued by hook for the receiver
PASS [6] after the stand-in refused it once, Hook refreshed the proof (same proof, new token) and Ting accepted  ({"refused":{"call":"send","outcome":"invalid_proof","valid":true,"kind":"app_verification","issuing_app":"hook","receiving_app":"interface","scopes":[…)
PASS [6] the Silicon's send names it by uuid and asks for required delivery  ({"call":"send","outcome":"accepted","valid":true,"kind":"app_verification","issuing_app":"hook","receiving_app":"interface","scopes":["tings.send"],"f…)
PASS [6] the custodian's copy goes out as an ordinary send  ({"call":"send","outcome":"accepted","valid":true,"kind":"app_verification","issuing_app":"hook","receiving_app":"interface","scopes":["tings.send"],"f…)
PASS [6] hook publication: accepted by Ting, with the receipt read through an App verification proof (sent.query)  ({"state":"accepted_by_ting","receipt_proof":{"call":"receipt","outcome":"receipt","valid":true,"kind":"app_verification","issuing_app":"hook","receivi…)
PASS [6] the stand-in's journal holds digests, never a proof token
PASS [6] the Silicon's receiving host (client crate SDK) gets the reference, hydrates it from Hook with the Silicon's own token and answers 204  ({"callback_status":204,"hydrated":{"id":"01a12425-2b88-7892-9aba-5e79952f5d54","provider":"LocalDemo","silicon":{"id":"si:hook-e2e-s1r-55559","uuid":"…)
PASS [6] a Carbon granted `view` subscribes to copies (User verification proof for it)
PASS [6] an event goes to the Silicon (required), its custodian and the grantee (ordinary copies)  ({"1e5":"required","oVm":"ordinary","fSx":"ordinary"})
PASS [6] revoking the grant ends the grantee's copies at once  ({"subscription_status":403,"sent_to":{"1e5":"required","oVm":"ordinary"}})
PASS [6] after S1 moves to C2, the former custodian gets no more copies (C2 has not subscribed)  ({"sent_to":{"1e5":"required"}})
PASS [6] the new custodian subscribes and receives copies  ({"status":200,"sent_to":{"1e5":"required","fSx":"ordinary"}})
## Scenario 7: discovery commands from a packaged Silicon Apps archive, in an empty home
PASS [7] cargo build --release -p silicon-hook-cli
PASS [7] scripts/package-apps.sh 1.0.0 macos-aarch64 … --discovery require  (["packaged /Users/codanium/Documents/silicon/.worktrees/hook-accounts-apps/.mig/e2e-55559/dist/hook-1.0.0-macos-aarch64.tar.gz (2992547 bytes)","sha25…)
PASS [7] the archive holds exactly apps.yaml and bin/hook
PASS [7] apps.yaml names app hook, this version and only this target
PASS [7] hook --help: exit 0, non-empty
PASS [7] hook accounts --json: exit 0 with "app_id": "hook"  ({"app_id":"hook","name":"Silicon Hook","version":"1.0.0","accounts_url":"https://accounts.teamofsilicons.com","api_version":"v3"})
PASS [7] hook login status --json: exit 0, {"authenticated": false}  ({
PASS [7] the hidden `hook iam --json` (Silicon runtime alias) prints exactly `hook accounts --json`; help never shows it  ({"exit":0})
PASS [7] the discovery commands wrote nothing into the empty home
cleanup: {"stopped": ["hook-worker", "hook-api", "ting-stub"], "webhook": "removed", "database": "dropped hook_e2e and roles hook_e2e_api, hook_e2e_worker"}
137 passed, 0 failed in 80 s (report: .mig/e2e-55559/report.json)
```

Outside the run, two probes against the same stack (scratch scripts, not in git) found bugs 1 and 2 above and
confirmed the fixes live: the same-second probe (four STK rotations, each followed within half a second by a new
public-client token: three refused before the fix; the e2e check now reproduces it deterministically by
rotating at the top of a second, `new_token_same_second: true`), and the missing-Ting-app probe (a stack file
whose stand-in receiver is `ting`; before: `proof failures logged in 8 s: 5`, after: `1`, with all five sends
`('pending', 'proof_unavailable', 1)`). The outage probe through a relay became scenario 9.

### Blocked on

- **Ting** (unchanged): production Ting must accept Silicon Accounts proofs before `HOOK_TING_URL` is set. The
  issuer side is proven against a stand-in that verifies proofs as the stack's `interface` app (there is no
  `ting` app on the shared stack and only Hook's own setup may change there); if Ting's production app id is
  not `ting`, set `HOOK_TING_APP_ID`.
- Nothing in Silicon Accounts blocked this stage: every request it was given behaved as documented.

### Left for later stages

- **Web stages**: the Next.js web (the e2e run's scenario 1 already signs a Carbon in with the web's redirect
  URI `http://localhost:4200/auth/callback` and the code exchange the BFF will do); `scripts/dev-accounts.sh`
  gives the web a running API on 4201 with a working webhook. The `frontend` CI job still builds the old web.
- **Operator (cutover.md)**: every production step; step 4 now sets the webhook with `"events": null` and checks
  hook-api's startup line. Re-run `scripts/e2e-accounts.sh` before the cutover.
- **Windows home directory** (observation from stage 3, unchanged): the CLI needs `SILICON_HOME` or `HOME`.

### Gotchas

- `mint.mts` starts Node for every call (about a second); a fast path (direct HTTP: Silicon login, short-lived
  token, public-client exchange) is needed to issue a token within the same second as an event.
- The stack's `PUT /v1/apps/{app}/webhook` keeps update picks unless `events` is sent; `null` means every
  update. The Accounts CLI's `app webhook set` cannot choose updates and has no `get`.
- hook-api's development log format is coloured unless `NO_COLOR` is set (the dev script sets it).
- A freshly started hook-api has no signing keys until its first token; `hook login` does not call Hook, so the
  first call after a restart is the one that fetches them.
- Accounts CLI JSON: `webhook set` returns the secret as `webhook_secret`; the hook CLI's flag for a stored
  secret is `secret_stored_now`.
- The Ting stand-in and the receiving host are started by the harness; `down` stops the dev processes, and the
  harness stops its own relay and host in `finally` blocks (pids `accounts-relay`, `receiving-host`).

## 2026-10-10 — Codex continuation: backend review fixes

Fixed the self-UUID authorization fast path so Carbons cannot own hook namespaces.
Grant responses now report the actual granter kind and public ID. The sign-out
regression uses a genuinely earlier token and catches account-wide revocation on
`app_revoked`. Identity mapping now verifies each destination online before writes,
refusing wrong-kind, missing, and non-active accounts; cached kinds are checked
inside the transaction too. Runbook includes a pre-window endpoint-key collision
query; OpenAPI uses the actual provider ingress host and current command names.

Verified: real PostgreSQL access suite 7/7, webhook suite 6/6, populated legacy
upgrade/linking suite 1/1. `cargo clippy --locked -p silicon-hook --all-targets
--all-features -- -D warnings` and `cargo fmt --all` pass. Full live rerun and
Next frontend remain in progress. The inherited throwaway review probe is
preserved outside the worktree in `.migration/recovery/hook-inherited-review-probe.rs`;
its actionable assertions are now regression tests.


## 2026-10-10 — Next.js and Arc console verified

Replaced the Solid frontend/session gateway with the full Next.js16/React19 Arc
console: seven product sections, hook creation/signature editing and rotation,
bulk enable/disable, recovery, Accounts connection setup, history/blocked request
inspection and exports, delivery receipts and subscriptions, live viewing, named
sharing/allow-lists, theme and telemetry settings. Runtime-only app secrets and
sealed Accounts sessions back the BFF. Native Vercel and non-root standalone
Docker recipes replace the former gateway; CI uses locked pnpm and checks types,
lint, sessions and production build.

Verification on the isolated local Accounts9589/9590 and Hook4201 stack:

- API/CLI end-to-end:128 passed (`.mig/e2e-16749/report.json`).
- Web:44 unit tests, typecheck, zero-warning lint and standalone production build.
- Browser:25/25 complete suite, including hosted sign-in, real refresh rotation,
  cross-tab sign-out, keyboard and axe WCAG2.2AA in both themes and phone/desktop.
- Expanded product journey:2/2 with setup; signed and blocked provider requests,
  custodian CRUD/recovery, viewer403, grants and allow-list, observer subscribe/
  unsubscribe, bulk toggles, secret and endpoint rotation, Accounts hook setup.
- Populated screenshots:28 PNGs across seven pages, both themes and1440/390widths;
  representative desktop/phone views inspected and no horizontal overflow.
- Packaging/deployment Python checks and bundled CLI documentation check pass.

Evidence: `.mig/web-full-e2e.log`, `.mig/web-product-e2e.log`,
`.mig/web-unit.log`, `.mig/web-build.log`, `.mig/web-packaging-tests.log`,
`web/screens/`. Docker image build is still a CI/release gate because the local
Docker daemon does not respond. Production Ting acceptance and the coordinated
identity cutover remain release gates. No production deployment performed.

The user has additionally requested standard128-bit account UUIDs and migration
of existing account IDs across linked apps. That follow-up is being implemented
as a separate coherent change using one Accounts mapping export.
