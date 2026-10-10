# Manual verification record

This record reports checks actually performed. Implementation remains in
progress; unchecked acceptance items in `BUILD_STATUS.md` are not claims of
successful end-to-end verification. Final testing is manual exploration of
real test environments, not an automated scenario suite.

## Fixture

- Dedicated PostgreSQL 16 container: `hook-manual-e2e-postgres-20260906`.
- Separate local databases: `hook_prod` and `hook_test`, separate API/worker roles.
- Local Hook backend: `http://127.0.0.1:18480`.
- Local event recipient: `http://127.0.0.1:18481/events`.
- Real IAM environment: `01a073a1-3c74-7f33-b455-e4ced6a47d2a`.
- Hook environment: `01a073bd-07b7-7d42-aafa-ba79c12275c4`.
- Fake test Carbon: `hook-proof`; test Silicon: `hook-proof:tos`.
- Private fixture secrets/responses live outside Git in
  `~/.silicon-hook/manual-e2e/`, with directory 0700 and files 0600.

## Checks completed so far

| Manual action | Actual result |
|---|---|
| Inspect production IAM app `tos>hook` | Verified app; receiver URL still pending review, not active |
| Create a new real IAM test environment | Success; root key saved privately |
| Sign up and sign in fake test Carbon | Success using test-only verification code |
| Import production app into IAM test world | Success; separate test app secret returned; webhook secret explicitly inherited |
| Create test Silicon with job role | Success, test credential saved privately |
| Migrate isolated Hook production/test databases | Success under migrator; runtime grants applied |
| Exchange real production IAM SLT in local Hook | Initially rejected by an incorrect prefix check; fixed to treat tokens as opaque, then succeeded |
| Create Hook test environment bound to real IAM test key and app | Success; empty sandbox and root key returned |

| Test Carbon SLT login | Success; separate test session saved |
| Start daemon and query it from a later command | Initially died with parent process group; fixed with independent group, then remained available |
| Create unsigned test hook | Success; hook UUID `01a073cb-96e0-7f02-a19b-b6205ff24fd1` |
| POST to public test endpoint | HTTP 200 webhook.ok, receipt `01a073cb-c713-7680-a515-b46129ae805b` |
| Local recipient receives event | HTTP 200, event ID matches receipt, sequence 1 |
| Query durable delivery cursor | acknowledged_through 1 after recipient receipt |

## Development regression checks

- `cargo test --workspace --all-targets --all-features`: 130 library,
  13 PostgreSQL integration and 2 WebSocket tests passed.
- `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --all-features`: passed.
- `npx --yes @redocly/cli@2.49.0 lint openapi.yaml`: passed, with the two
  documented WebSocket/trailing-slash contract exceptions.
- `cargo deny --locked check`: advisories, bans, licenses and sources passed;
  duplicate transitive dependency warnings remain informational.

## Recipient failure and ordered recovery

The recipient was deliberately changed to HTTP 500. Event sequence 2 was
receipted by Hook (`01a073cf-ade3-7aa2-b863-b963d30ae2cf`) and reached the local
receiver, but the durable cursor remained at 1. Sequence 3
(`01a073d0-68fb-7e02-bf00-759f3504a260`) was then accepted. Inspecting the receiver
showed only sequences 1 and 2, proving 3 had not bypassed the failed delivery.
After restoring HTTP 200, the cursor advanced to 3 in order.

## Outstanding manual coverage

Every CLI command and SDK operation; actor and organization permissions;
full signature DSL/algorithms/encodings; history boundaries and pagination;
retired/disabled/deleted endpoints; ten-hook quota and reset; root-key rotation
and recovery; test-vs-production isolation; relay concurrency, disconnects,
heartbeat timeout, recipient retries and ACK replay; IAM receiver authenticity;
retention and inactivity boundaries; updater behavior; correction/retest of all
failures. Do not interpret fixture setup as completion of this coverage.

## Additional manual checks

- Local API without a bearer: 401. An identity-scoped local list request returned
  the single sandbox hook with nested backend status 200. Its original JSON file
  initially lost whitespace through CLI reserialization; added the SDK's
  `LocalClient::request_bytes` path and repeated the comparison successfully.
- `env list --status all --limit 1` and `--test ... env current`: correct metadata.
- `config show`, `system version`, `system health`: correct context, version and ready.
- Hook update accepted Unicode provider name, description and Asia/Kolkata zone.
- Disable blocked public ingress with 404; enable restored the same hook.
- Endpoint rotation changed PEY29ZMB to II36E1KL; the retired URL returned 410
  endpoint_retired. Delete hid the replacement URL with 404; restore succeeded.
- Created default signed hook `01a073d6-f4d5-7371-8696-e1ef21cc9bb6` at AR8BQYI4.
  Its secret was v1. plus 32 alphanumeric characters. A manually calculated
  HMAC-SHA256 signature was accepted as event sequence 4. A missing signature
  got webhook.ok but appeared solely in the blocked log as payload_unavailable.
- `connect-iam` with the test Carbon's application token returned 403, confirming
  the documented first-party IAM webhook redirection integration gap. Its
  partially prepared IAM hook remains available for eventual reconciliation.

## Isolation, identities and size boundaries

- Environment key rotation raised generation to 2; the identical-key retry
  returned exactly the original metadata and replacement key. The previous
  root key returned 401. Public ingress and relay resumed at sequence 5.
- Logged in the real test Silicon as profile `manual-silicon`, using its own
  recipient at port 18482. Both recipient directories contained the same event
  IDs for sequences 1–6, and the Silicon had its own durable cursor.
- Secret rotation changed the signed hook's secret. A fresh request signed with
  the old secret appeared only in blocked history with signature_mismatch;
  signing with the new secret delivered sequence 6 to both recipients.
- A binary payload of 1 MiB + 1 byte returned 413. Exactly 1 MiB was accepted as
  sequence 7, and history base64 decoded to all original bytes with no text body.
- A foreign-organization Silicon target was denied, but initially mislabeled
  as provider_unavailable (503). Target validation has been separated from IAM
  response validation to return forbidden (403); awaiting the focused retest.
- History scope now includes environment UUID and generation; pending manual
  cross-environment and post-reset cursor rejection checks.

## Lifecycle and quota continuation

- Foreign-organization target retest now returns 403 forbidden.
- A test history cursor was rejected in production with 422 invalid_cursor.
  Environment deletion raised generation to 3, rejected its root key with 401
  and public ingress with 404. Restore raised generation to 4; the old-generation
  history cursor was rejected with 422 while retained data remained intact.
- Reusing the rotation idempotency key for deletion returned 409
  idempotency_conflict. Environment page limit 0 returned 422 invalid_limit.
- Eight concurrent CLI invocations were issued with seven quota slots remaining:
  seven succeeded and one returned hook_limit_reached. The resulting list had
  exactly ten hooks. The CLI originally held its state lock through all network
  mutations, serializing these calls; it now releases that lock after reading
  the immutable actor configuration (refresh/state-changing calls remain locked).
- This activity also exposed excessive IAM authorization polling on WebSockets,
  resulting in 429. Stopping relays allowed requests to recover. The backend
  now refreshes stream authority every 30 seconds and on verified IAM events
  broadcast through PostgreSQL; the reduced-rate relay retest is pending.

## IAM receiver, relay stability and retention

- Rebuilt the workspace and repeated Clippy with warnings denied, all existing
  regression tests (129 library, 13 PostgreSQL, 2 WebSocket), and Rustdoc with
  warnings denied. All passed after the stream authorization changes.
- Restarted the API and daemon with the reduced authorization frequency. Both
  test identities connected, refreshed credentials successfully, and showed no
  new relay retry diagnostics during the observed stability interval (77 seconds).
  The Silicon's durable cursor was 7, and both recipients retained seven events.
- A manually signed IAM test `session.logout.v1` envelope returned 204. Appending
  one space to the signed bytes returned 403. This proves receiver verification;
  a real revocation across two API replicas is still an outstanding check.
- A raw WebSocket client deliberately ignored all application pings. It received
  pings at approximately 30, 60 and 90 seconds and closed with application code
  4000, reason `heartbeat-timeout`, at 120.3 seconds.
- Creating another hook after soft-deleting Quota4 still returned 409
  `hook_limit_reached`; retained deleted hooks count against the test quota.
- Eighteen additional invalid signed-hook requests followed two existing
  failures. The next four requests returned 403 `ip_blocked`. The database
  recorded a block lasting 24 hours. Expiry/recovery remains to be checked.
- Retrieved the environment key as its production creator and compared it
  privately with the current stored key: identical. `env show`, test-context
  `config show`, and `config profiles` returned the expected metadata.
  `env current` without `--test` returned 422 `test_environment_required`.
- To exercise retention without waiting weeks, only the dedicated test database
  fixture timestamps were backdated: event sequence 1 and its first blocked log
  past 14 days, and the already deleted Quota4 hook past 45 days. Immutable-row
  triggers were disabled and restored inside that single fixture transaction.
  The running worker removed all three rows. The OVBG4DTM endpoint route remained
  reserved. No production data was altered.

## Delivery and reset boundary fixes

- A raw WebSocket ACK for sequence 9999 was initially accepted when only eight
  events existed. Fixed the cursor write to reject values above the latest
  allocated sequence. Restored only the deliberately poisoned fixture cursor.
  HTTP now returns 422 `invalid_through_sequence`; WebSocket returns recoverable
  `invalid_ack`, and a reconnect still reported cursor 7 and replayed event 8.
- Negative WebSocket resume positions now return recoverable `invalid_resume`.
- After advancing only the fixture IP block's deadline into the past, a correctly
  signed request was accepted as sequence 8 and reached the raw stream.
- Reconfiguring valid test IAM credentials advanced the environment to generation
  5. An identical-key retry returned exactly generation 5. Invalid app credentials
  returned 401 without installing that configuration.
- Reconfiguration exposed a SQL three-valued-logic bug: an unavailable generation
  returned NULL, causing stream close 1011. Migration 4 makes it return false.
  A later clean correctly closed the raw stream with 4001 `environment-changed`.
- Clean advanced the main fixture to generation 6 and removed events, blocked
  logs and delivery cursors. Created `Manual Boundary Provider` at MCAEVBG8
  (`01a073fc-35d4-7a81-8027-e97ea0623c14`). Retrying the old clean key returned
  generation 6 and preserved this newer hook. Old URLs II36E1KL, AR8BQYI4 and
  OVBG4DTM returned 404 and their reservations remained in the routing ledger.
- Eleven truly concurrent CLI creates competed for nine remaining quota slots:
  nine succeeded and two returned 409. A database read confirmed exactly ten hooks.
- An administrator's nonexistent target now returns 404; organization roles
  cannot substitute for IAM-confirmed existence/visibility. Carbon application
  access remains an integration gate until IAM supplies the needed lookup.

## CLI configuration and independent SDK exercise

- Attached the current root key to `manual-root-only` with a custom backend URL.
  The URL persisted. Root-only `env current` worked without an IAM session;
  normal hook listing returned 401 and `whoami` reported not signed in.
  Production/test organization and default-Silicon settings remained separate.
  Changing that profile's backend with stored credentials was rejected.
- All eleven bundled documentation topics and recursive command discovery ran
  successfully. Automatic CLI checking advanced its timestamp once; the next
  command within the hour did not change it. Opt-out preserved the timestamp.
- The interactive Rust example logged in using a real IAM test SLT and started
  its own gateway on port 18484. Health, version and cursor commands worked.
  Provider receipts reached the SDK recipient and advanced the shared Silicon
  cursor to 2. Explicit logout succeeded and the local service shut down.
- IAM logout also invalidated sibling application access tokens minted from
  the same underlying IAM authentication session. The IAM implementation
  explicitly revokes by source-session/application. Reauthenticated the CLI
  with a fresh SLT before continuing; no Hook credential fallback was added.
- The real SDK updater initially failed because crates.io reports
  `max_stable_version: null` for the existing, yanked 0.1.0 client. It now returns
  no eligible release; the independent Rust example's repeated check returned
  null successfully. The CLI crate is not yet published. New sources target
  0.2.0; an actual published-release installation remains unverified.
- A batch disable containing an unknown UUID returned 404 and left the known
  hook active. Disabling/enabling two valid IDs returned two results. Setting a
  description and explicitly clearing it with JSON null both worked.

## Backpressure with a failing SDK recipient

The SDK recipient at port 18482 returned 500 while forty new events were accepted
(sequences 3–42 in generation 6). Its durable cursor stayed at 2. The running SDK
reported HTTP-500 retries with delays 1, 2, 4, 8, 16 and then 30 seconds and kept
its connection alive for several minutes, beyond the heartbeat timeout.

A separate raw stream for the same identity received exactly sequences 3–34
(32 outstanding), followed only by heartbeats. Manually ACKing 3 released exactly
one more event, sequence 35. An ACK of 2 then returned cursor 3 without regression.
This raw observer shares the Silicon's cursor, as documented. After restoring
the SDK recipient to 200, SDK notices showed ordered delivery of all forty
events and a cursor query returned 42.

## Resumed live checks: raw bytes, asymmetric signatures and refresh recovery

- Reconciled the resumed fixture at delivery cursor 56. Old saved signing keys
  produced `signature_mismatch`; those HTTP-200 receipts were withheld, not
  counted as successful deliveries. Rotated the current boundary hook's secret
  through the CLI and saved the result privately. A 32-byte SHA256 signature
  sent as the raw request body was accepted as event
  `01a0762e-e64f-72a3-8110-f0cbda0d5f52`, sequence 57. The SDK recipient received
  it and its durable cursor advanced to 57.
- Independently generated provider keys and signatures using Python's
  cryptography library. Configured each algorithm through the CLI, then sent
  one Unicode-containing payload. Ed25519, ECDSA-SHA256 (P-256 DER), RSA-SHA1
  and RSA-SHA256 (2048-bit PKCS#1 v1.5) were delivered and acknowledged as
  sequences 58, 59, 60 and 61 respectively. The active boundary hook now uses
  RSA-SHA256; provider private keys remain outside Git with mode 0600.
- Found that CLI refresh created a new idempotency key on every invocation.
  Fixed it to persist the pending key before contacting Hook and clear it
  atomically with saving replacement tokens. An isolated local proxy forwarded
  a real refresh to Hook/IAM, observed upstream HTTP 200, and deliberately
  discarded its response. The CLI failed while retaining the pending key.
  Removed the fault and retried in a new CLI process: upstream returned 200
  with the identical key, the CLI listed all ten hooks, and the pending key
  cleared. Copied the recovered session back to the original manual fixture.
- Re-ran workspace tests, Clippy with warnings denied, Rustdoc with warnings
  denied, OpenAPI lint and dependency policy checks after the raw-signature and
  durable-refresh changes. All passed (130 library, 13 PostgreSQL integration,
  and 2 WebSocket tests).

## Large history pages and contextual CLI errors

Sent seventeen exact-1-MiB requests to the existing unsigned quota hook
`01a073fd-2412-7f60-b809-0db80bf8bb04`. All were receipted and delivered in order
as sequences 62–78; the SDK durable cursor reached 78. Requesting that hook's
history with limit 10000 returned seven items and a cursor because the
conservative history byte budget applied. Following each cursor manually
returned seven, then three items. The seventeen IDs were unique across pages;
the last page had no cursor. No accepted event was omitted.

History limit 10001 and a future ACK at 999999 both returned HTTP 422. CLI errors
now derive the exact command path from Clap's parsed subcommands, so these
failures suggested `hook events --help` and `hook deliveries ack --help`.
The change passed formatting, build, and workspace Clippy with warnings denied.

## 2026-09-09 login and delivery updates

Development verification for the revised understanding:

- Full workspace test run: 131 backend unit tests, 13 PostgreSQL integration,
  2 WebSocket integration, 2 CLI parsing tests and 1 SDK relay integration pass.
- SDK fixture: authentication sends only the SLT; gateway runs without a
  destination; HTTP 503 delivery remains pending; detach preserves the gateway;
  reattach delivers the same event and produces an upstream ACK. Invalid
  destinations fail locally. Discovery carries the selected test key; revoked
  status produces authenticated=false.
- Built CLI with temporary state and local mock backend/relay health: anonymous
  status, production/test IAM discovery, Silicon/Carbon identity status,
  test-only unhook/reattach, legacy recipient strings, invalid URL/home errors,
  SILICON_HOME and configured-home relocation pass. No actual daemon was stopped
  or started by this fixture check.
- Formatting, workspace check, strict Clippy, warning-free Rustdoc, OpenAPI lint
  and cargo-deny pass. Dependency-policy duplicate/unused-license notices are
  informational. The official IAM client is now 1.4.0.

This records development fixtures, not an additional real IAM acceptance run.
