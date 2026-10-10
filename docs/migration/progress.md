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
