# Internal Ting delivery implementation

The requirements are `understanding/UNDERSTANDING.md`. Hook receives, verifies and stores external webhooks. Ting owns recipient transport. Implementation proceeds backend, Rust client, CLI, then website; the migration is not complete until send and receive are verified end to end.

## Completion evidence

- [x] Backend commits each accepted event and its outgoing Ting record atomically; rejected signatures publish nothing.
- [x] Publishing uses fresh proof-bound requests, independent durable publisher credentials, stable retry keys, bounded claims and restart recovery.
- [x] Production/test authority and generation fences apply to enqueue, publish and event hydration.
- [x] An authorized event lookup preserves full 1 MiB webhook payloads while Ting carries compact event references.
- [x] Delivery status distinguishes pending, Ting acceptance/silent acceptance, and recipient acceptance; transport acceptance never means work completed.
- [x] Hook's direct event WebSockets and delivery daemon are retired from the new contract.
- [x] Rust client uses the new backend and internal Ting receiving setup.
- [x] CLI uses the Rust client and no longer runs a Hook delivery relay or asks users to configure a second delivery service.
- [x] Website uses the new contract, internally acquires the required IAM sessions and refreshes event data from Hook.
- [x] Sandbox receiving uses the same app-secret-only setup without asking for another application's credentials.
- [x] Isolated integration tests cover successful send/receive, outage/restart, uncertain responses, duplicates, authorization, large payloads and test cleanup.
- [x] Real Ting/IAM end-to-end evidence correlates provider receipt, stored Hook event, Ting acceptance, recipient receipt and ACK state.
- [x] Formatting, Clippy, backend/client/CLI checks and website tests/build pass for the final source.

## Baseline

On 2026-09-22, `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test --lib` passed all 134 tests before implementation. Existing modified requirements and untracked deployment verification files are preserved.

See [Ting integration issues](ting-integration-issues.md) for current external constraints. These are not waived by mock verification.

## Backend progress, 2026-09-22

`cargo test --test ting_delivery` passes all three tests using PostgreSQL with the actual restricted API grants. These prove atomic rollback on an outbox failure, signature rejection without publication, an exact 1 MiB body hydrated through current access checks, and clean-generation isolation including production preservation.

The backend now passes 185 tests: 147 library, 19 PostgreSQL, 3 v2 contract, 3 delivery, 2 generation/retention, 3 publisher recovery, 5 Carbon subscriptions and 3 deprecated WebSocket compatibility tests. The external Space Station telemetry test remains intentionally ignored. `cargo clippy -p silicon-hook --all-targets -- -D warnings` passes. OpenAPI lint passes with no warnings, covering 85 paths and 99 unique operations.

The rebuilt native Hook API passed signed provider ingress, real IAM proof exchange, real Ting 0.1.2 publication, authenticated full-payload hydration and separate delivery/read ACK checks. The published Ting CLI/daemon also passed local HTTP forwarding: its durable delivery ACK was visible while the callback was held, and the read ACK appeared only after HTTP 204. The isolated fixture scripts and limitations are documented in `scripts/ting_e2e/README.md`.

The normal-plane fixture seeds the notification type and uses disposable IAM identities. Production deployment and real IAM testing-plane integration are not claimed by these tests. Test lifecycle, grants and generation fences are verified separately with restricted PostgreSQL roles.

## Rust client progress, 2026-09-22

The stateless client now negotiates only v2. Login returns tokens and the host owns refresh; the old Hook WebSocket, relay, local gateway and delivery cursor/ACK methods are removed. `delivery::Receiver` authenticates Ting callbacks, checks the original reference and uses current Hook authorization to hydrate each event. It does not acknowledge work on the host's behalf.

All 18 client tests and Clippy pass. The real native Ting/SDK test preserves an exact 300,098-byte provider request using a 696-byte compact callback. The SDK host durably writes the event and returns HTTP503, leaving Ting unread. After both native daemon and SDK host restart, Ting automatically retries the same record; the host finds one persisted duplicate and returns HTTP204. Hook then reports the destination read ACK. The fixture report records two requests, one new event and one duplicate.

The CLI migration follows this verified client; website changes follow the CLI checks.

## CLI progress, 2026-09-23

The 0.8 source builds successfully with the workspace binaries and actual SDK receiving example. All 17 CLI tests pass, including v2 event/publication inspection, internal receiving commands, refresh recovery and removal of legacy relay state. Login no longer creates a Hook delivery daemon or requires a receiving URL.

The real CLI fixture passes SLT-file login, current identity, recipient registration, webhook creation, signed provider ingress, native Ting-to-SDK delivery, exact event/history inspection, delivery/read receipt inspection, retired-command rejection and logout revocation. It also checks that login creates no Hook relay process or saved transport state. `cli-verification.json` correlates these steps with the event and Ting IDs. Website implementation follows this gate.

Review also found that retained Ting records can outlive Hook payloads. The client now has an explicit unavailable outcome so a host can durably report that event without treating it as work. All 20 client tests and Clippy pass. `unavailable-verification.json` proves that recording an unavailable original releases the real native delivery queue and permits the next valid event to arrive.

## Ting 0.1.3 regression gate, 2026-09-23

Carbon observer authority renewal is implemented and tested. Before publishing an observer copy, Hook checks the exact Carbon's current access; expired authority waits for the runtime to renew its subscription, and lost access removes its queued copies. Migration 15 requires existing observers to renew. Primary Silicon delivery remains independent.

All 233 workspace tests pass: 188 backend, 24 client and 21 CLI. Workspace Clippy, formatting, rustdoc, dependency checks and OpenAPI validation pass. The SDK and CLI now expose owner/admin provisioning and explicit recovery of the dedicated publisher, using a Hook-bound SLT and stable retry identity.

The real publisher CLI fixture also passes provisioning, replay through file/stdin, refusal to replace a healthy publisher, subsequent Ting publication and exact original-event hydration. It uses a separate disposable Hook backend/database and records credential-cleanup limits in the verification report.

All 22 website tests, TypeScript checking and the production build pass. Real IAM/Ting HTTP and Chrome flows verify paired sign-in/replacement, Carbon receiving, exact large-payload hydration, publication inspection, observation without read ACKs, responsive navigation and logout. Real-service send/receive and recovery evidence is collected in [the current verification record](verification/ting-e2e-2026-09-23.md).

The current backend, native receiver, SDK recovery, CLI and website paths also pass against the published Ting 0.1.3 server and daemon. Website receiving now requires its explicit production environment attestation; missing, malformed or testing context cannot activate a production session. The earlier 0.1.2 evidence remains preserved separately.

At the 0.1.3 gate, the full sandbox receiving flow remained incomplete because Ting lacked an authorized bootstrap from Hook's test selector. Late uncertain-login recovery and required delivery of muted internal events also lacked upstream contracts. See the 0.1.4 update below for their current status.

The late-login limitation was reproduced against the real 0.1.3 fixture: replay after 125 seconds returned `401 session_expired` while the original session remained authenticated. The test retained the initial response privately for its oracle and cleanup, then revoked that session; it did not induce an actual lost packet or production outage. At that check, upstream main `3be6ef37a8be561c774562b83b02a4d2769567f2` left the missing contracts unchanged.

## Ting 0.1.4 adoption, 2026-09-23

Ting 0.1.4 is now live. It adds test-only scoped receiver bootstrap, session-lifetime login recovery, correct refresh-replay expiry and recipient-authorized required delivery. The earlier missing-mechanism blockers are resolved upstream, and Hook has adopted the new paths below. Legacy login results already erased by old releases remain uncertain.

The current Rust workspace passes 254 tests: 196 backend, 29 client and 29 CLI, with one opt-in Space Station test ignored. Workspace Clippy, formatting, rustdoc, dependency checks and OpenAPI validation pass.

Existing Hook backend/native/SDK restart and website HTTP compatibility checks pass against the published 0.1.4 binaries. Login replay after 125.006 seconds returned the original response; replay after logout could not resurrect the session. These six reports are recorded separately under `ting_0_1_4` in the verification record.

- [x] Backend exposes context-bound scoped receiver creation/renewal through fresh IAM proofs without returning audience application secrets. Focused authorization, replay, transport and production-rejection checks pass.
- [x] Rust client and CLI expose the adopted backend contract with explicit retry identity and safe handling of short-lived capabilities. All 29 client and 29 CLI tests pass, with Clippy and formatting. Windows private-file ACL support is implemented but not runtime-verified; the cross-build lacks Windows SDK headers.
- [x] Website uses scoped testing inbox/watch APIs, validates actor/app/org/environment/generation, renews and reconnects within 30 seconds, and revokes on logout/context changes. All 36 tests and the production build pass; uncertain cleanup is retained when the original authority becomes unavailable.
- [x] Required delivery respects separate recipient opt-in, uses immutable `delivery: "required"` sends and distinguishes notification silence from automation delivery. Real refusal, unchanged 301-second scheduled retry, silent acceptance and native ACK checks pass.
- [x] Actual Hook sandbox and required-delivery flows pass end to end after backend, client, CLI and website adoption.
- [ ] Required production scope revisions finish their official approval and activation workflow; current public Honeycomb state still shows Ting effective revision 2 and Hook effective revision 1.

Hook's actual testing-plane worker now also passes Carbon and Silicon scoped delivery, exact 300,097-byte hydration and receiver renewal/reconnect. Scoped backend clean fencing and actual normal/scoped Chrome flows pass. The real 32-event catchup also passed across IAM throttling: 64 published copies, 32 unique forwarded events, same-ID renewal and no read ACKs. The fixture drives authenticated Honeycomb participant APIs; it does not run the full coordinator or establish production approval. See [Ting integration issues](ting-integration-issues.md) for current constraints and source evidence. Existing 0.1.3 E2E reports remain historical evidence for their tested paths.
