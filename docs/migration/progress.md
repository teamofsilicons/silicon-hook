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
