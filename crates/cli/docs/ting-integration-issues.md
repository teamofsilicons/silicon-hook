# Ting integration issues

Checked on 2026-09-23: the live backend and published release are now **Ting 0.1.4**, with current source [`3fee4fc01e5b112fca42c9d7ca987ffdf40268e4`](https://github.com/teamofsilicons/silicon-ting/commit/3fee4fc01e5b112fca42c9d7ca987ffdf40268e4). This release adds the upstream mechanisms missing in 0.1.3. Historical reproductions below retain their original version and scope; they are not claims that the same bugs remain in 0.1.4.

| Earlier issue | Ting 0.1.4 status | Remaining Hook work or constraint |
| --- | --- | --- |
| Sandbox receiving from only Hook's test selector | Scoped receiver bootstrap implemented | Hook's backend, SDK, CLI and website are implemented. Real Carbon/Silicon bootstrap, delivery and normal/scoped browser verification pass. The capability lasts at most 30 seconds and only reads/watches an inbox. |
| Login recovery after two minutes | Fixed for retained operation results | Preserve uncertainty for legacy results already erased by older releases; these return `login_recovery_unresolved`. |
| Refresh replay expiry | Original refresh-attempt time is now persisted | Hook must still handle rejected/unavailable sessions normally. |
| Delivery suppressed by notification muting | Required delivery implemented with separate recipient opt-in | New Hook primary sends use required mode; real refusal, unchanged retry after opt-in, silent delivery and native ACK checks pass. An application cannot enable recipient opt-in through OBO registration or a receiver capability. |

Production rollout is also a separate gate. Fresh public Honeycomb reads show Ting revision 3/effective revision 2 and Hook revision 2/effective revision 1. The effective Ting catalog lacks `receivers.bootstrap`, and Hook's effective external scopes are empty. The [Ting configuration](https://backend.honeycomb.teamofsilicons.com/api/v1/apps/tos%3Eting) and [Hook configuration](https://backend.honeycomb.teamofsilicons.com/api/v1/apps/tos%3Ehook) need their official approval and activation workflow; published binaries alone do not grant that authority.

Upstream [Hook integration evidence](https://github.com/teamofsilicons/silicon-ting/blob/3fee4fc01e5b112fca42c9d7ca987ffdf40268e4/deploy/hook-integration.md) covers real isolated Carbon/Silicon bootstrap and required muted delivery. It explicitly excludes the complete Hook worker/browser adapter flow. Hook's worker and scoped receiver adapters now also pass real isolated Carbon/Silicon delivery. Website adoption passes 36 tests, its build and actual normal/scoped Chrome flows.

## Idle sandbox delivery exhausted IAM request capacity

**Hook integration defect fixed and verified against the real IAM/Ting fixture.**
The owned IAM testing plane allows 120 units/minute for the Hook application's
`/api/v1/application/testing-context` bucket. One selected Hook request consumed
four units. At a two-second worker interval, idle publisher context resolution
repeatedly consumed 60 units/minute before checking for due outbox work. The BFF
also repeated scope discovery during ordinary polling, leaving insufficient
capacity for renewal and event hydration. The real bucket reached 123/126 units
and returned rate-limit errors; this was not solely setup traffic or a Ting
receiver mismatch.

The backend fix now skips external context resolution when the database has no due send,
while retaining fresh lifecycle/actor proof for actual publication. The BFF
keeps scope validation at bootstrap and renewal, current Hook status/hydration
checks and Ting's capability fences, without redundant scope GETs before every
inbox read. A real 30.158-second idle check at the faster default one-second worker interval
consumed zero IAM application quota units, with no due work. Scoped rate-limit
backoff preserves the stream, receiver slot and emitted event IDs, waits for
Retry-After, renews the same receiver after expiry, then resumes reconciliation.
Regression tests cover 32 unique events, a queued renewal, silent polling after
recovery and logout cancellation. The real test published all 64 recipient copies
for 32 signed events, paused after 22 events on an actual IAM rate limit, and
completed all 32 on the same stream with no duplicates. The same receiver ID
renewed with a replacement token, and all 32 observed records stayed unread.
The IAM limit remains unchanged.
The diagnostic is recorded under `testing_rate_limit_diagnostic` in the
[versioned evidence](verification/ting-e2e-2026-09-23.json).

## Background publishing needs actor authority

Ting requires a new request-bound IAM OBO proof for each send. Hook's application secret alone cannot authorize a queued webhook after a user session expires. Sharing a caller's rotating refresh token between the caller and Hook's worker would create refresh races.

Implemented: a separate, encrypted, server-owned Hook publisher session, refreshed with durable operation keys. Its actor must have the required Ting external scopes and membership in the destination org. Revoked authority leaves sends pending with an actionable status, never bypassing IAM. Real IAM/Ting publication and backend refresh/recovery tests pass.

The real CLI provisioning test also passes file/stdin replay with the same mutation key, refuses replacement of a healthy publisher, and confirms that publisher can still deliver a new event. Its report is included in [the current E2E record](verification/ting-e2e-2026-09-23.md).

Evidence: [Ting app authentication](https://ting.teamofsilicons.com/docs/api.md#proof-bound-app-calls), IAM `OboExchangeRequest.subject_token`, and Hook's existing `/api/v1/auth/refresh` returning the rotated family to its caller.

## Hook credentials cannot bootstrap a Ting receiver alone

Ting `/v1/session` accepts a Ting-bound IAM SLT. A Hook application access token cannot mint that SLT: IAM requires a direct IAM session for single/batch SLT issuance (`direct_iam_login_required`). Ting 0.1.4 adds a separate scoped testing receiver, not a general OBO session exchange.

For ordinary production sessions and native destinations, the enclosing app/runtime must obtain Hook and Ting SLTs in one IAM batch login and perform receiving setup internally. The scoped testing inbox/watch path can instead use the new bootstrap below. Neither path requires exposing Ting setup to the end user.

Evidence: [Ting session contract](https://ting.teamofsilicons.com/docs/api.md#session-endpoints), IAM `src/features/applications/oauth.rs` `require_direct_login`, and the official IAM client's `auth().batch_short_lived_tokens`.

## Type registration requires operator permission

Creating `tos>hook.webhook.received` requires a Ting session with current Honeycomb permission to manage Hook. App send proofs cannot register types. The type must be provisioned in each applicable org/test context before publishing can succeed. Missing types must be reported rather than treated as successful delivery.

Evidence: [Ting type registration](https://ting.teamofsilicons.com/docs/api.md#ting-types).

## Hook and Ting use different organization identifiers

The real website fixture on 2026-09-23 reproduced a paired-login rejection for an otherwise valid identity: Hook uses the canonical organization handle (for example `tos`), while Ting's organization list returns a UUID in `id` and the canonical value in `handle`. Ting watch replies also normalize `org_id` to the UUID even when the subscription request used a handle.

The adapter must match authoritative organization records, retain Hook's canonical identifier for event validation and hydration, and use Ting's UUID for inbox/watch routing and frame checks. Comparing the two IDs directly rejects valid logins or ignores live updates. This is an integration mapping bug, not missing Ting data or a reason to relax organization authorization.

Fixed and verified with real IAM/Ting: paired login and replacement both succeed, a Carbon receives the exact 300,121-byte original through Ting's inbox watch, and observation leaves the notification unread. The gateway checks the IAM UUID as well as Ting's UUID/handle before selecting the transport context.

## Browser receiving must verify Ting's environment

Ting 0.1.3 adds an explicit environment to `/v1/me`. The website previously checked only the actor and treated its selector-free exchange as production. It now requires the live production attestation before activating a paired session or registering/opening a receiving watch. Missing, malformed or testing context is rejected, while any obtained credentials remain available for cleanup.

Website receiving therefore requires Ting 0.1.3 or its compatible attestation contract. Regression tests cover invalid context during both initial login and cached-session recovery, including revocation of rejected session pairs. Testing now uses the separate 0.1.4 scoped bootstrap below.

## A Hook test app secret cannot bootstrap a Ting browser session

**Upstream mechanism added in 0.1.4; Hook backend, SDK and CLI adopted.** `POST /v1/receivers/bootstrap` accepts a fresh request-bound IAM proof for `receivers.bootstrap`, using the audience testing headers issued for that exact request. Its signed body binds the Hook app, represented actor, canonical organization, environment UUID, generation and operation key. It requires an active recipient grant and approved scopes/consent, and rejects production proofs.

The returned secret capability lasts at most 30 seconds. It only reads/watches this app's inbox for that actor and testing generation through `/v1/receivers/{me,inbox,ws}`. It cannot send, acknowledge records, change preferences or attach a native destination. Keep it private, validate its complete context, and hydrate references under current Hook authorization.

An exact retry with a fresh proof returns the original capability and expiry. Renewal requires a new operation key and the original `receiver_id`; it replaces the old token. Reconnect the watch with the renewed capability and reconcile the scoped inbox. Revocation uses `DELETE /v1/receivers/session`, including after expiry or disablement. Clean, rotation and grant loss fail closed.

Hook now exposes authenticated testing scope discovery and bootstrap/renewal through `/api/v2/delivery/receiver`. It derives actor/app/organization from current authorization, verifies Ting's organization UUID through IAM, and requires the caller to pin the shared environment generation. Focused backend tests, all 29 SDK tests and all 29 CLI tests pass. Real Carbon and Silicon scoped receivers receive a signed 300,097-byte original through Hook publication, Ting watch/inbox and current-authority hydration; renewal invalidates the old capability and reconnect recovers the unread record. The CLI hands scoped capabilities to the enclosing runtime through a new private output file, with explicit retry identity and renewal. The website now owns private scoped renewal, inbox reconciliation and revocation; all 36 website tests and its build pass. Actual normal/scoped Chrome flows pass, including renewal, silent arrivals, unread observation and logout. General Ting test credentials must not be extracted or reused from a proof for an unrelated SLT login.

Evidence: [scoped receiver contract](https://ting.teamofsilicons.com/docs/api.md#scoped-testing-receiver-bootstrap), [receiver implementation](https://github.com/teamofsilicons/silicon-ting/blob/3fee4fc01e5b112fca42c9d7ca987ffdf40268e4/crates/ting-server/src/receiver.rs).

## Uncertain scoped receiver cleanup after authority loss

**Remaining recovery limitation, identified during Hook adapter review.** The BFF
persists the exact bootstrap or renewal operation before sending it. If its reply
is lost and the original Hook actor or test selector is then invalidated, replay
may no longer recover the receiver token needed for explicit revocation. The
browser retains `receiver_cleanup_pending` and the bounded private operation;
logout, replacement or forgetting that plane cannot claim completed cleanup.

This does not establish that a capability remains usable after clean or expiry.
Real clean tests invalidate known capabilities immediately. However, waiting
30 seconds from the client's attempt does not prove when an unknown request
committed. A generic `receiver_environment_changed` error can also mean a
selector mismatch, and public Hook environment metadata exposes a different
internal generation. Neither is sufficient evidence to discard uncertainty.

The normal path recovers the exact result and revokes it, including an expired
result. Completing cleanup after the original authority is lost needs an
operation recovery/cancellation contract or an authenticated attestation that
the original shared generation is irreversibly fenced. The current adapter has
neither. This edge was checked by source review and an in-memory lost-response
reproduction; it has not been reproduced as a real network outage plus clean.
No time-only pruning or production authorization bypass is implemented.

## A lost login response cannot be recovered after two minutes

**Fixed for retained results in Ting 0.1.4.** The encrypted exchange/result now lasts for the session lifetime; replay revalidates current authority and returns the original opaque credential. Logout and lifecycle fences prevent resurrection. Older releases may already have erased a result: `409 login_recovery_unresolved` preserves that uncertainty, and a new login does not cancel the older unknown operation. Retain Hook's durable uncertainty/cleanup handling for those cases.

Verified independently with the published 0.1.4 server: exact replay after 125.006 real seconds returned 200 and the identical original response. After session deletion, the same replay returned `401 session_expired` and the credential stayed revoked. The first response was retained privately for comparison and cleanup; no actual packet loss was injected. The sanitized report is under `ting_0_1_4.reports.login_recovery` in [the E2E evidence](verification/ting-e2e-2026-09-23.json).

Confirmed with isolated Ting 0.1.3 HTTP calls on 2026-09-23: an initial login returned 201 and immediate replay returned the identical response with 200. After 125 real seconds, the same operation key and body returned `401 session_expired`, while the original session still returned authenticated 200 from `/v1/me`. The test then deleted only that new session and verified its credential returned 401. The sanitized report is stored under `upstream_limitations` in [the E2E evidence](verification/ting-e2e-2026-09-23.json).

The first successful response was captured privately as an oracle and cleanup credential; this was not an actual lost-packet or production-outage test. The impact on a caller that lost that response follows from the observed replay failure and the source contract: `Auth::login` rejects an existing operation once `created + 120 < now()`, before returning its stored response. The caller cannot recover the opaque credential needed to revoke the still-live session. No operation-based recovery or cancellation endpoint is exposed.

The website must persist uncertainty before sending an exchange and retain it through process failure or malformed responses. A later rejection cannot prove the first attempt created no session. Unresolved cleanup is reported as `login_cleanup_pending`; credentials already recovered must be retained for revocation. Dropping the pending operation or presenting logout as complete would hide the unresolved session.

The 0.1.4 session-lifetime recovery contract resolves this for retained results. There is no claim that information already erased by an older release can be recovered or cancelled without its credential.

Historical evidence: 0.1.3 [`auth.rs`](https://github.com/teamofsilicons/silicon-ting/blob/115954f074a9dfd48e3f14b39a70ecaf8cc7a6c5/crates/ting-server/src/auth.rs#L658) applied the two-minute check before returning the stored response. The [0.1.4 recovery implementation](https://github.com/teamofsilicons/silicon-ting/blob/3253ea193c9fc244e6ef7e5fd818240ae0ad4782/crates/ting-server/src/auth.rs) removes that limit for retained results.

## Ting refresh replay can overstate the recovered access-token lifetime

**Fixed in Ting 0.1.4.** `refresh_started` is persisted with the operation key, and expiry uses that original time. A recovered rotated family is saved before another rotation; legacy pending operations without a timestamp recover conservatively. Upstream regression tests cover expired, unexpired and legacy recovery. The finding below describes 0.1.2/0.1.3.

Source-identified in Ting 0.1.2 and rechecked in 0.1.3, not reproduced in the real fixture: Ting persists its IAM refresh operation key but no original attempt timestamp. `Auth::live` records a replayed response's expiry as the current time plus `expires_in`. IAM's idempotent reply retains the original response, so recovery much later can assign a future local expiry to an already expired access token. The subsequent introspection can then fail instead of immediately renewing the recovered refresh family.

Hook's own publisher and CLI refresh recovery already retain their attempt time. The website must continue to surface unavailable/rejected Ting sessions rather than treating the delivery stream as healthy.

Evidence: Ting `crates/ting-server/src/auth.rs::live` and its `session.expires = now() + refreshed.expires_in` assignment; compare the same file's `Auth::login`, which retains `exchanged_at` across recovery.

## Large Hook events do not fit a Ting send

Hook accepts raw bodies up to 1 MiB plus headers. Ting limits the complete send JSON to 256 KiB. Copying every raw webhook into Ting would strand otherwise valid Hook events.

Implemented: Ting carries the Hook event identity, source, sequence and environment generation; authorized consumers fetch the original event from Hook. Hook's existing 14-day event retention bounds that fetch. An expired reference is reported explicitly, not processed with a missing payload. The real SDK/native test verifies exact retrieval of a payload above Ting's send limit.

Evidence: Hook `src/domain/request.rs::MAX_BODY_BYTES`, [Ting request limits](https://ting.teamofsilicons.com/docs/api.md#common-rules).

## Notification preferences can suppress required delivery

**Separate required-delivery mode added in 0.1.4 and adopted by Hook.** Ordinary muted events still stay silent. A recipient can explicitly enable required delivery for an existing active subscription through its own Ting session. The sender must then sign `delivery: "required"`; without the opt-in, Ting rejects a new required send with `403 required_delivery_not_enabled` rather than downgrading it.

Required events remain eligible for automatic delivery despite notification muting. Their `silent` field still describes notification visibility; it no longer implies absence of automation delivery when `delivery` is `required`. Current grant and required-delivery consent control every offer. Revocation clears the opt-in; re-enrollment or shared clean does not restore it. Recipient opt-out pauses pending required deliveries.

New Hook primary Silicon sends now use required mode; Carbon observers and already queued sends retain ordinary mode. Status exposes delivery policy separately from notification silence. Missing opt-in stays pending with `required_delivery_not_enabled`, with no downgrade or body/key rewrite. Migration `0016` permits that diagnostic in the outbox; the focused backend tests pass. A real owned fixture verified refusal without opt-in, the unchanged scheduled retry after 301.023 seconds once the recipient opted in, muted required acceptance and native delivery/read ACKs. Original recipient preferences were restored. The scoped receiver cannot modify the preference, and Hook never enables it through application authority. Existing retention, deduplication and destination ACK requirements still apply.

Evidence: [Ting notification preferences](https://ting.teamofsilicons.com/docs/api.md#notification-preferences).

## An unread delivery batch holds later events on that destination

Observed against the real Ting 0.1.2 fixture: a new destination immediately receives retained unread records. Ting keeps that batch active until its records receive read ACKs. A delivery ACK alone confirms receipt but does not let later records advance on the same destination. Ignoring an older record while waiting for a newer Hook event therefore stalls the receiver even though Hook's newer publication was accepted successfully.

The end-to-end harness now validates and consumes retained fixture records before checking its new event. Receiving integrations must process complete batches and reserve read ACKs for successful application acceptance; failed items can hold subsequent events on that destination. This is a Ting delivery constraint, not evidence of a lost Hook publication.

Evidence: Ting `crates/ting-server/src/store.rs::offer` checks outstanding `read=0` records bound to the receiver before selecting later records; the actual WebSocket exposed the retained Hook records and the newer publication appeared after their read ACKs.

## Native receiving must use its own OS service and callback contract

The published Linux ARM64 Ting 0.1.2 CLI/daemon requires glibc 2.39: running the pinned archive on Debian Bookworm fails with `GLIBC_2.39 not found`. The real native fixture uses Ubuntu 24.04. A separate `SILICON_HOME` isolates a CLI profile but does not isolate the daemon, whose Unix socket is fixed at `/var/tmp/silicon-ting/daemon.sock` and whose queue lives under the OS user's real home. The fixture therefore runs the unmodified published daemon in its own container without installing or replacing the host service.

The native HTTP callback also differs from its WebSocket input: it strips `for` and sends only `id`, `created_at`, `type`, `key`, `data`, and `metadata` inside each `tings` item. Hook consumers must bind the destination to their configured identity and hydrate each reference under current Hook authorization. Requiring the WebSocket-only `for` field would reject every real native callback.

Verified: the published daemon durably acknowledges the Ting delivery, sends a bearer-protected local batch, and leaves the record unread until that batch receives exactly HTTP 204. Hook's current publication status then reports the destination read ACK. Evidence: `scripts/ting_e2e/native.py` and the fixture's `native-verification.json`.

The later actual Rust SDK test also passed: a 300,098-byte provider request hydrated from a 696-byte native callback without changing its bytes. Its host synced acceptance to disk, returned HTTP 503, then restarted both the daemon and SDK host. Ting retried automatically with the same notification ID; the restarted host found one durable duplicate, returned HTTP 204, and Hook reported the read ACK. Evidence: `scripts/ting_e2e/sdk.py`, `crates/client/examples/ting_receiver_e2e.rs`, and the fixture's `sdk-verification.json`. The test proves the real SDK and native retry boundary; it does not prove an external application's processing logic.

## Test cleanup does not retract an already accepted Ting record

Hook can fence its outgoing queue by environment generation, but Ting's current notification contract does not itself enforce Hook's cleaning generation. A Ting record accepted before a clean may still exist after it.

Implemented: include the source generation and hydrate the event through Hook's current authenticated environment before handing its payload to a consumer. An invalid generation or deleted event fails closed. Restricted-role backend integration tests cover cleaning and generation fences. This does not add a cross-service cancellation guarantee to Ting.

## An unavailable original needs a terminal receiving result

Code review identified a liveness problem at the two retention boundaries: Ting can retain an unread notification after Hook's 14-day payload retention, and cleanup can remove it sooner. Retrying hydration forever would hold later records on that destination.

The client now offers `Receiver::resolve`, which returns an explicit `Unavailable` result only for a validated reference and Hook's structured `404 not_found` after current authorization. The host must durably record and report that result, deduplicate retries, and accept all other items before returning HTTP 204. Missing payloads never become completed work. Authentication, permission, network and protocol failures still reject the batch. The strict `hydrate` API remains available when the host wants all originals or an error.

Verified with the published native daemon: a queued reference whose original was removed returned an authenticated 404. The SDK host durably recorded it as unavailable; HTTP 204 then released the destination's queue, and the following valid event arrived with its original payload intact. `scripts/ting_e2e/unavailable.py` and `unavailable-verification.json` record the evidence.
