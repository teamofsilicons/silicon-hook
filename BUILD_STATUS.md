# Hook implementation and verification

The acceptance contract is `UNDERSTANDING.md`. The requested delivery includes
the backend, stateless Rust client, stateful CLI, local relay daemon, updates,
and separate API/client/CLI/IAM/testing guides. The SolidJS frontend is implemented;
`hook report` remains later work. Frontend coverage and its remaining IAM/hosting
checks are recorded in [web/VERIFICATION.md](web/VERIFICATION.md).

## Implementation

- [ ] Migrate all IAM access to the published `silicon-iam-client`; SLT login,
  refresh/revoke, current authorization, production and test webhook verification.
- [ ] Organization-owned test environments: isolated shared test storage, IAM
  binding, keys/retrieval/rotation, reset, recoverable deletion, inactivity cleanup.
- [ ] Apply environment isolation to every hook operation, ingress, history,
  blocked log, delivery cursor, WebSocket, idempotency key and retired endpoint.
- [ ] Preserve the full signing expression language, lifecycle and retention
  requirements; limit test environments to ten hooks.
- [ ] Stateless Rust client covering all public backend actions.
- [ ] Stateful CLI using only the client, profiles, short-lived-token login,
  `--test <id>`, comprehensive help and contextual guidance.
- [ ] Local relay at `hook.localhost`, per-identity destinations, heartbeat,
  reconnect/replay, downstream acknowledgment, request receipt echo.
- [ ] Default-on hourly update checks, post-command updates, opt-out; Rust
  dependency updates take effect at the next build.
- [ ] Complete segregated docs and current OpenAPI contract.

## Verification

- [ ] Required formatting, build, lint, existing tests, docs and contract gates.
- [x] Manually provision a real IAM test environment and a Hook test environment.
- [ ] Manually exercise every CLI command and every client operation, including
  invalid input and permissions, and record actual responses in `docs/verification/`.
- [ ] Manually exercise signatures, rotations, disabled/deleted endpoints,
  recovery, test isolation, limits, key rotation, cleanup, and retention edges.
- [ ] Manually exercise multiple relay identities, disconnections, unanswered
  heartbeat, downstream failures, duplicate deliveries and acknowledgment replay.
- [ ] Fix discovered defects and repeat the affected manual checks.

The final end-to-end stage is interactive manual testing, not a scripted test
scenario suite. Existing automated tests remain development regression checks.

## Initial evidence

The working tree already contains user changes in `UNDERSTANDING.md`,
`src/infrastructure/postgres/maintenance.rs`, and `tests/postgres_integration.rs`.
The backend exists; the client repository mentioned by its README is absent.
The published IAM client version resolved by `cargo search` is 1.2.1.
Production IAM credentials are in the owner's private local store, outside Git.

## Current implementation (2026-09-06)

The backend now uses published IAM client 1.2.1 and opaque SLT login, with
explicit test IAM configuration and no production fallback. Migrations 2–5 add
shared-test environment isolation, generation invalidation, lifecycle/reset,
ten-hook quota, retained endpoint routes and 24-hour lifecycle retry records.
The worker handles test retention and inactivity. Test traffic has its own
PostgreSQL notification listener. WebSocket replay has a 32-event window per
Silicon and periodically rechecks IAM authority.

The workspace now includes stateless `crates/client` and stateful `crates/cli`,
both targeting the next 0.2.0 release:
hook/history/delivery/environment operations, profiles, separate test sessions,
relay daemon, authenticated loopback request/receipt API and Cargo-aware hourly
updaters. SDK login now starts a caller-owned in-memory gateway, relay and token
refresh session. Guides are in `docs/` and bundled into CLI `docs`.

Manual boundary checks exposed and fixed future-sequence ACK acceptance,
nullable environment availability, administrator target-existence bypass and
the updater's handling of a crate whose only releases are yanked. Reset retry,
real concurrent quota enforcement, 32-event replay backpressure and SDK delivery
have since passed their focused checks. Full coverage is still in progress.

The resumed checks verified raw binary signatures, all four asymmetric
algorithms, and pagination of seventeen 1-MiB events without duplicates or
omissions. A deliberately lost successful refresh response exposed a CLI retry
risk; refresh now saves and reuses its mutation key, and recovery passed against
real IAM test tokens. CLI errors now point to the exact subcommand help.
Workspace tests (130 library, 13 PostgreSQL, 2 WebSocket), Clippy, Rustdoc,
OpenAPI lint and dependency policy checks passed after the substantive fixes.

Initial real manual checks have proven production and test SLT exchange,
environment creation, test Silicon hook creation, public test ingress,
local recipient delivery, and persisted ACK sequence 1. They also exposed and
fixed an invalid SLT prefix requirement and a daemon process-group lifetime bug.
This is not the full acceptance run; the checkboxes remain open until verified.

### Remaining integration and completion work

- Resolve application-token target Silicon existence/visibility and the IAM
  webhook redirection credential/step-up flow. User clarification about adding
  an IAM lookup remains pending. See docs/iam/README.md.
- Environment pagination, successful-request activity and control-plane
  readiness/grants are implemented; complete their manual boundary/concurrency checks.
- Tighten relay diagnostics, local receipt completeness, profile refresh and
  daemon cancellation/expiry behavior; verify all SDK updater paths.
- Run full build/lint/regression/OpenAPI/dependency/docs gates after changes.
- Complete the manual coverage recorded in docs/verification/README.md, fixing
  and retesting every observed defect.

## Understanding updates implemented (2026-09-09)

- Added CLI `iam --json`, `login status --json`, `webhook <url>` and `unhook`.
- `login <slt>` now works before a recipient is configured; the optional legacy
  `--webhook-url` flag remains supported. Missing destinations do not consume events.
- Added public IAM discovery and online identity-status API/client methods.
  Discovery selects the configured production/test app; it never returns secrets.
- Added SDK login without a recipient and session-level attach/replace/detach.
  Existing CLI recipient strings deserialize alongside new optional recipients.
- Added `SILICON_HOME` as the default CLI base directory and upgraded the official
  IAM client from 1.2.1 to 1.4.0. Updated API, client, CLI and testing guides.
- Checked the full workspace (131 backend unit, 13 PostgreSQL, 2 WebSocket,
  2 CLI parsing and 1 SDK relay integration tests), strict Clippy, Rustdoc,
  OpenAPI and dependency policy. CLI fixture checks exercised discovery/status
  for Carbon and Silicon, test-only detach/reattach, existing state, URL/home
  validation, and home relocation. These checks use local fixtures and do not
  claim a new real IAM deployment acceptance run.

An existing older daemon must be stopped before using the new optional-recipient
state, then started with the rebuilt CLI. The running local daemon and deployed
backend were not changed by this source implementation.
