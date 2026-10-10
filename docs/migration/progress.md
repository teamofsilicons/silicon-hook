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
| (next) | Link the release guide from the docs index and simplify local setup in the README |

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
