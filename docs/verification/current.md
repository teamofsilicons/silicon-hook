# Understanding update verification

The September 16 changes are local: Honeycomb lifecycle participation, migration 9, final-send delivery fences, durable activity reporting and CLI release packaging. They have not been deployed, published to crates.io or packed into a six-platform release. See [the lifecycle contract](../testing/honeycomb.md) and [release build](../releases.md). The earlier verification below describes the September 13 release, including its superseded source installer.

Local validation: 162 workspace unit/integration and WebSocket tests pass (one opt-in live telemetry test remains ignored). Restricted-role PostgreSQL regressions cover failed-clean retry, concurrent identical operations, endpoint tombstones, stale writes and deliveries, key rotation, disable/restore/purge, service authentication and IAM shared readiness. Strict Clippy, dependency policy, packaging regressions and the 18-page documentation build/link check pass. Rustls is patched to 0.23.45. Client/CLI and the Honeycomb manifest are staged at 0.6.0; no release archive is claimed without all six native executables.


Verified locally on September 13, 2026. `UNDERSTANDING.md` was preserved as supplied.

## Automated checks

- Rust workspace: 161 tests passed, including PostgreSQL 16 integration tests and real WebSocket transport tests. The explicitly opt-in Space Station test is excluded from ordinary runs and was executed separately against the newly created Hook table.
- Strict Clippy, all target/type checks, formatting, and warning-free Rust documentation passed.
- Dependency policy: advisories, dependency bans, licenses, and source checks passed.
- Frontend: production build/type checks and all seven session/gateway tests passed.
- OpenAPI validated. Its three documented lint exceptions cover the two WebSocket 101 responses and the existing IAM receiver's trailing slash.
- Docs: 16 pages; all internal links, anchors and assets checked. Browser review verified the landing page layout and full-text search.
- CLI source distribution: its isolated workspace builds with locked dependencies. The installer embeds the source archive SHA-256 and passes shell syntax validation.

Coverage includes encrypted IAM selectors, repeat selection without creating duplicate storage, online revocation, sandbox cleaning, runtime database permissions, webhook signatures and retention, two independently authorized identities sharing one physical socket, per-identity ACKs, seven-day contract sunset, SDK prewarm/attach/detach/replay, CLI grammar, and browser session isolation and telemetry opt-out forwarding.

## September 13 live results

[Docs](https://docs.hook.teamofsilicons.com) are published through the `silicon-hook-docs` Vercel project. Authoritative and public DNS resolve `docs.hook` to Vercel, and the requested hostname serves the landing page, guide routes and installer over verified HTTPS. Some resolvers may temporarily retain an earlier negative DNS answer.

The new [siliconhook Space Station table](https://spacestation.teamofsilicons.com/o/tos/tables/siliconhook) received the synthetic verification event `01a09a8d-df78-7d51-bf35-bf65a8c188a4`. Its page also shows two earlier synthetic events recovered from the local spool, verifying retry delivery after the connection configuration was corrected. No customer webhook contents or IAM credentials were sent.

## September 13 production release

Published September 13, 2026. The dedicated AWS server runs the updated API, worker and persistent browser gateway. Both production and shared-test PostgreSQL databases have migrations 1–8 applied and the current runtime grants. Public liveness, readiness and contract discovery return HTTP 200. The worker has exported production backend and maintenance events to the dedicated Space Station table, with no container restarts during verification.

The frontend is live at [hook.teamofsilicons.com](https://hook.teamofsilicons.com). Client and CLI version 0.5.0 are published to crates.io. Existing installed CLI processes need an update/restart to load the release.

A pre-upgrade database/configuration backup is stored in the private release bucket. Previous API/worker and gateway images are retained on the host as `rollback-20260913`; image rollback does not reverse migrations.

The bug-report workflow is published with its Postmark server secret and the existing verified `iam@teamofsilicons.com` sender configured through `POSTMARK_FROM_EMAIL`. No real bug report or email was submitted during deployment checks. See [deployment instructions](../deployment.md).

A fresh hosted IAM login and organization selection passed after configuring Hook’s required read permissions. The scoped directory regression covers pagination and exclusion of invisible targets. Automated IAM, isolation, WebSocket and delivery checks passed. No customer webhook was sent during deployment verification.

The upstream IAM directory filter was corrected and deployed as `15e98aec5d261e27908650fa2ede2bf5cc428634`; the same scoped request changed from HTTP 500 to HTTP 200. The authorized production directory is currently empty, and nonexistent Silicon IDs remain rejected. Browser diagnostics now forward the selected organization for unscoped IAM sessions; this is covered by the gateway regression test.
