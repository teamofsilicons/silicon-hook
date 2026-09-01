# Silicon Hook engineering decisions

This file is the append-only decision log for the Silicon Hook backend. Material
architecture, security, data-model, API, and operational decisions are recorded
here before or alongside their implementation. A changed decision is marked as
superseded; its original record is not silently rewritten.

## D-001 — PostgreSQL is authoritative

**Status:** Accepted

PostgreSQL is the system of record for hooks, encrypted signing secrets,
received events, delivery state, idempotency records, and audit records. A
webhook acceptance response is never returned until the event and its pending
DM delivery are committed. Database constraints and transactions enforce
cross-process invariants.

Redis/Valkey is not required for the initial service. Coordination uses
PostgreSQL row leases so API and worker replicas can scale independently
without introducing a second durability boundary.

## D-002 — Modular monolith with separate processes

**Status:** Accepted

The backend is one Rust package with a library and three thin binaries:
`hook-api`, `hook-worker`, and `hook-migrate`. Domain, application,
infrastructure, HTTP, and worker concerns remain separate modules. API and
worker processes can scale and deploy independently while sharing one model and
migration history.

## D-003 — Rust safety and quality baseline

**Status:** Accepted

The service uses Rust 2024 on pinned stable Rust 1.98, rustfmt, strict Clippy
lints, `#![forbid(unsafe_code)]`, dependency policy checks, and a committed
lockfile. Recoverable production paths do not use `unwrap`, `expect`, `todo`,
or panic. Public modules and fallible behavior are documented.

## D-004 — HTTP and asynchronous runtime

**Status:** Accepted

Axum, Tokio, Tower, and SQLx provide the runtime. Reqwest with rustls is used
for IAM and DM. HTTP requests have correlation IDs, structured tracing,
timeouts, sensitive-header redaction, panic containment, body limits, and
graceful shutdown. Outbound clients use explicit connect/request timeouts,
bounded bodies, and no redirects.

## D-005 — Route layout preserves product and OpenAPI compatibility

**Status:** Accepted clarification

Management and internal endpoints live below `/api/v1`. The canonical public
webhook URL is the product-specified root route
`/silicon/{silicon_id}/{endpoint_key}` and is emitted in hook metadata. Because
the original OpenAPI server prefix implied `/api/v1/silicon/...`, the API also
accepts that route as a compatibility alias. An optional trailing slash is
accepted for both forms.

## D-006 — Endpoint keys route but never authenticate

**Status:** Accepted

Endpoint keys are exactly six uppercase hexadecimal characters generated from
cryptographically secure randomness. Uniqueness is enforced for each global
Silicon ID and collisions are retried. The five-character example in
`UNDERSTANDING.md` is treated as a typo. Possession of this 24-bit value never
grants authority.

## D-007 — Normative webhook signature format

**Status:** Accepted security clarification

Every ingress request uses HMAC-SHA-256 with a 32-byte random per-hook secret.
The signed bytes are the ASCII Unix timestamp, one ASCII period, then the exact
raw HTTP body. `X-Hook-Signature` is `v1=` followed by 64 lowercase hexadecimal
characters. Verification decodes strictly and compares in constant time.
`X-Hook-Timestamp` must be within 300 seconds of server time. This format is
documented and covered by test vectors.

## D-008 — Signing secrets are encrypted and one-time responses are bounded

**Status:** Accepted

Signing secrets are encrypted at rest using AES-256-GCM with a versioned runtime
keyring and hook identity as associated data. No plaintext or reusable digest is
logged or persisted. New and rotated secrets are returned only in the mutation
response. An identical idempotent retry by the same caller may replay that
response for ten minutes; after that, the caller must rotate the secret.

## D-009 — Secret rotation invalidates immediately

**Status:** Accepted

Secret rotation atomically replaces the encrypted secret and writes an audit
record. There is no old/new overlap window because none is specified and an
unbounded overlap weakens revocation. Senders must coordinate the cutover; a
future dual-secret feature requires an explicit contract change.

## D-010 — IAM is consulted online and failures are closed

**Status:** Accepted

Bearer access tokens, OBO proofs, and service tokens are verified online through
Silicon IAM so revocation and current organization membership take effect
immediately. Hook does not parse opaque tokens or derive authority from webhook
events. IAM timeout, malformed response, or unavailability never grants access;
management requests fail with `503` and invalid credentials with `401`.

The IAM HTTP adapter is isolated behind an application port because IAM's
authorization response is still evolving. A deterministic local adapter is
available only in development/test and production startup rejects it.

## D-011 — Authorization is actor- and resource-specific

**Status:** Accepted clarification

An authenticated Silicon can read and create hooks and read events only for
itself; it can delete/restore/rotate only its own hooks. A Carbon must have IAM
visibility of the target Silicon to read or create. Organization owners and
admins with the relevant IAM capability may manage hooks. OBO preserves the
represented actor's limits and records the calling application separately.

An OBO application may delete, restore, or rotate only hooks originally created
through that same application unless the represented actor is an organization
owner or has an explicit administrative override. This applies the product
rule that applications cannot delete resources they did not create.

## D-012 — IAM provisioning is authenticated and idempotent

**Status:** Accepted contract correction

Only the introspected `silicon-iam` service identity may call
`POST /api/v1/internal/iam/hooks`. Provisioning is unique per organization and
Silicon and creates the `Silicon IAM` hook once. The response includes the
one-time signing secret because IAM cannot sign its initial event without it.
Provisioning requires an idempotency key and allows the same ten-minute replay
window as other one-time-secret operations. A deliberately deleted default hook
is not silently recreated or restored.

## D-013 — Identifiers and timestamps

**Status:** Accepted

Internal public IDs use UUIDv7 for sortable, collision-resistant identifiers.
The external `org_id` and global `silicon_id` are immutable opaque handles and
are never parsed for authorization. Timestamps are stored as PostgreSQL
`timestamptz` and serialized as UTC RFC 3339.

## D-014 — Idempotency is scoped and content-bound

**Status:** Accepted clarification

Management idempotency is scoped by operation, effective actor, organization,
target, and key. Ingress idempotency is scoped by hook and key. Keys are 8–255
visible ASCII characters. A retry with the same canonical request digest returns
the original result; reuse with different content returns `409`. Management
records remain for 24 hours, while the replay of a one-time secret is limited to
ten minutes. Ingress keys live as long as their retained event record. D-040
adds a key-independent authenticated-request replay guard without changing
these caller-visible key semantics.

## D-015 — Event envelopes are immutable after acceptance

**Status:** Accepted

The exact validated envelope, routing identity, request digest, receive time,
and stable event ID are committed together. Delivery fields are the only mutable
part of an event record. `occurred_at` defaults to the receive time,
`schema_version` defaults to `1.0`, and missing trace IDs are assigned from the
request correlation ID.

## D-016 — Payload and input limits

**Status:** Accepted security clarification

Ingress accepts only `application/json` and at most 1 MiB of raw body. The
payload must be a JSON object. Event type, source, subject, schema version, trace
ID, service name, description, headers, cursors, and idempotency keys have
explicit length and character limits enforced before database work. Management
bodies use a smaller 64 KiB server limit where the router permits separate
limits.

## D-017 — Retention preserves both history and delivery durability

**Status:** Accepted clarification

API history exposes the newest 10,000 events per hook. Account-wide queries are
the newest requested events across those per-hook retained windows and have no
additional independent retention cap. Delivered rows older than each hook's
10,000-event window are purged asynchronously.

Pending and retrying deliveries are retained even if temporarily outside the
visible history window; an outage must never erase undelivered work. Delivered
and failed terminal receipts remain while their event is visible, then become
eligible for bounded asynchronous purge after that event leaves the 10,000-row
window. D-055 records this terminal-retention clarification.

## D-018 — Deleted hooks are soft-deleted for 45 days

**Status:** Accepted

Deletion immediately rejects new ingress but retains the hook, encrypted secret,
audit trail, and visible history for 45 days. Restore keeps the endpoint and
secret. A maintenance worker permanently purges expired deleted hooks and their
retained events. Already accepted events continue delivery after deletion.

## D-019 — Delivery is an at-least-once transactional outbox

**Status:** Accepted

The event row is also its durable delivery job. Workers claim due rows with
`FOR UPDATE SKIP LOCKED` and expiring leases. Only DM `202 Accepted` marks an
event delivered; this means durable acceptance by DM, not WebSocket receipt by
the Silicon. Every retry uses the same event ID and exact DM payload.

DM deduplicates identical `event_id` values before fan-out. Hook still
guarantees at-least-once transport attempts because a timeout can hide DM's
successful commit; the stable identity makes those retries safe at the current
DM boundary.

## D-020 — Bounded retries and durable dead letters

**Status:** Accepted operational clarification

Connection failures, timeouts, HTTP `408`, `425`, `429`, and `5xx` responses are
retried with capped exponential backoff and full jitter; a valid `Retry-After`
is honored within the configured cap. The default maximum is 20 attempts and
the maximum delay is 15 minutes. Other `4xx` responses are terminal. Exhausted
and terminal jobs remain in `failed` state for diagnosis throughout the
event's retained-history lifetime; D-055 bounds cleanup after history eviction.

## D-021 — DM receives its published minimal system event

**Status:** Accepted

Hook sends `event_id`, `org_id`, `silicon_id`, `type`, optional `trace_id`, and
`payload` to DM's `/api/v1/internal/hook-events` using the dedicated Hook service
token. Source, subject, occurrence time, schema version, hook ID, and receive
time remain in Hook history because DM's current `SystemEvent` omits them.

## D-022 — Keyset pagination is opaque and stable

**Status:** Accepted

Event history is ordered by `(received_at DESC, id DESC)` and paginated with an
opaque base64url cursor containing that exclusive boundary. Invalid or
mismatched-version cursors return a validation error. Offset pagination is not
used because concurrent ingress would make it unstable and increasingly costly.

## D-023 — Audit records are transactional and redacted

**Status:** Accepted

Create, delete, restore, rotate, and IAM-provision actions write an append-only
audit record in the same transaction as the state change. Records identify the
effective actor and OBO application but never contain signing secrets, bearer
tokens, proofs, full event payloads, or raw authorization headers.

## D-024 — Configuration fails safely

**Status:** Accepted

All configuration is typed and validated at startup. Production requires HTTPS
provider/public URLs, IAM application credentials, a DM service token, and a
valid encryption keyring. Local auth or insecure provider URLs are rejected in
production. Secrets use redacting wrapper types and never appear in debug
output.

## D-025 — Health, readiness, and observability are separate

**Status:** Accepted

`/healthz` reports process liveness without dependencies. `/readyz` checks
PostgreSQL and the validity of essential local configuration; it does not make
an IAM or DM request on every probe. `/api/v1/version` exposes service and
package version. Metrics and traces use bounded labels and never include Silicon
IDs, endpoint keys, payloads, or credentials as metric labels.

## D-026 — Schema ownership and deployment portability

**Status:** Accepted

Objects live in `hook` and `hook_private` PostgreSQL schemas. Runtime and
migration credentials are configured separately so production can grant DML and
DDL independently. The service is packaged as OCI containers and has no
cloud-specific runtime dependency until an infrastructure target is selected.

## D-027 — Contract artifacts evolve with implementation

**Status:** Accepted

`openapi.yaml` remains the machine-readable HTTP contract and `API_DOCS.md`
explains it. Security clarifications required to make the original behavior
implementable—signature canonicalization, canonical ingress URL, default-hook
secret return, idempotency, limits, error cases, and DM retry semantics—are
reflected in both artifacts and tested against the router. Product intent stays
in `UNDERSTANDING.md`; implementation choices stay in this decision log.

## D-028 — A separate outbox supersedes D-019's shared-row detail

**Status:** Accepted; supersedes only the sentence in D-019 that makes the
event row itself the delivery job

Accepted event history and DM delivery work are stored in separate tables but
created in one transaction. The outbox contains the complete immutable DM
request body and does not cascade when an old history row is evicted. This keeps
event envelopes immutable, permits an exact 10,000-row history window, and
preserves accepted work through an arbitrarily long DM outage. API delivery
state is projected by joining the outbox receipt to retained history.

All other D-019 semantics—leased claims, stable IDs and bodies, DM `202` as the
success boundary, and at-least-once delivery—remain in force.

## D-029 — Cursors carry an integrity tag

**Status:** Accepted; strengthens D-022

Cursor payloads are authenticated with HMAC-SHA-256 under a dedicated runtime
key, separate from data-encryption and webhook-signing keys. The tag binds the
cursor version, organization, Silicon, filters, timestamp, and ID boundary.
This prevents clients from forging alternate database boundaries or reusing a
cursor under different filters while retaining stateless keyset pagination.

## D-030 — Signing secrets have an explicit wire encoding

**Status:** Accepted clarification

One-time signing secrets use `whsec_` followed by the unpadded base64url
encoding of exactly 32 random bytes. The prefix prevents accidental confusion
with bearer tokens and the decoded 32 bytes, not the printable representation,
are the HMAC key. Parsers reject non-canonical encodings and incorrect lengths.

## D-031 — DM delivery repeats the event ID as an idempotency header

**Status:** Accepted compatibility extension

Every Hook-to-DM attempt sends `Idempotency-Key: <event_id>` as well as the
stable `event_id` in the documented JSON body. DM's current ingestion
deduplicates the body identity; the redundant HTTP identity makes the retry
contract explicit at both layers. Retries never generate a new value.

## D-032 — IAM default-hook metadata is deterministic

**Status:** Accepted implementation detail

IAM provisioning assigns the fixed display name `Silicon IAM` and description
`Default Silicon IAM event hook`. These values are server-owned rather than
caller-controlled because the internal request identifies only the organization
and Silicon, and deterministic metadata makes idempotent provisioning stable.

## D-033 — Repeated deletion is a successful no-op

**Status:** Accepted HTTP lifecycle clarification

Deleting a hook that is already soft-deleted returns the same successful
`204 No Content` result after authentication and resource-specific
authorization. This makes retries safe even though DELETE does not require an
idempotency key. Unknown hooks still return `404`, and restore remains the only
operation that reactivates a deleted endpoint.

## D-034 — Fixed lifecycle windows are enforced at startup and persistence

**Status:** Accepted hardening

The 24-hour management-idempotency lifetime, ten-minute one-time-secret replay
window, and 45-day deletion recovery period are product invariants rather than
tunable deployment behavior. Configuration accepts only those exact values,
and persistence/domain code independently enforces them. Worker batch size is
bounded to 1,000 both during configuration loading and at the store boundary.

## D-035 — IAM proofs bind to stable resource identifiers

**Status:** Accepted integration convention

IAM authorization actions use the `hook.*` vocabulary documented by the IAM
adapter. Collection creation/listing and event-history actions bind `resource`
to the target Silicon ID. Per-hook read, delete, restore, and secret-rotation
actions bind it to the hook UUID. Route strings are not used because deployment
prefixes are transport details, while these identifiers are stable across API
aliases and versions.

## D-036 — Secret-bearing HTTP responses are non-cacheable

**Status:** Accepted security hardening

Create, IAM-provision, and secret-rotation responses set
`Cache-Control: no-store` and `Pragma: no-cache`. The credential is still
available for the documented ten-minute idempotent replay, but browsers,
proxies, and shared HTTP caches must not retain the plaintext response.

## D-037 — Persisted timestamps use microsecond precision

**Status:** Accepted implementation invariant

Authoritative application timestamps and sender-provided `occurred_at` values
are normalized to UTC microsecond precision before they enter aggregates or
idempotent responses. PostgreSQL `timestamptz` stores microseconds, so this
prevents a first response from differing from its database-rehydrated replay
only because the process clock supplied additional nanoseconds.

## D-038 — The outbox owns exact serialized request bytes

**Status:** Accepted; strengthens D-028

Event acceptance serializes the minimal DM system-event representation once,
stores those bytes in a `bytea` outbox column, and every retry transmits those
same bytes. Workers parse the stored representation only to enforce invariants;
they do not reserialize it. This makes retry identity cover field order and byte
representation as well as the stable event ID.

## D-039 — Secret rotation and webhook acceptance are linearized

**Status:** Accepted concurrency invariant

Ingress carries the exact encrypted-secret generation that authenticated the
request into its transaction. Acceptance share-locks the hook and compares the
key ID, nonce, and ciphertext; secret rotation takes the conflicting row lock.
Whichever transaction obtains the lock first defines the order. An old-secret
request can commit before a rotation, but never after that rotation commits.

## D-040 — Signed-request replay is independent of the caller's key

**Status:** Accepted security hardening

The public HMAC remains the interoperable D-007 format. In addition to normal
`(hook, Idempotency-Key)` bindings, persistence stores a separate SHA-256 replay
guard for the exact authenticated `timestamp + "." + raw_body` representation
with a unique per-hook constraint. Replaying captured signed bytes under
another idempotency key returns the original event and durably aliases the new
key to it. That alias remains content-bound, so later reuse with a different
body returns `409`. A legitimate repeat with a fresh timestamp has a distinct
fingerprint.

## D-041 — Dependency outages are distinct from internal defects

**Status:** Accepted error-classification rule

Connection, TLS, pool exhaustion/closure, worker crashes, PostgreSQL connection
exceptions, resource exhaustion, administrative restart, and statement timeout
failures map to the redacted `503 provider_unavailable` response. Decode,
schema, invariant, and programming failures remain `500 internal_error` so
operational incidents do not conceal defects and defects are not advertised as
safe retries.

## D-042 — Application code derives canonical management digests

**Status:** Accepted application-boundary invariant

HTTP code supplies validated commands and idempotency keys, but cannot inject
the digest persisted for management idempotency. The application derives a
stable JSON digest from validated create/provision semantics; bodyless restore
and rotation commands use the SHA-256 digest of an empty representation.
Equivalent JSON whitespace and member order therefore replay, while a semantic
change conflicts.

## D-043 — IAM wire compatibility stays explicit and fail-closed

**Status:** Accepted integration hardening

Organization-scoped introspection and OBO verification forward `X-Org-ID`.
OBO verification uses a deterministic, domain-separated SHA-256 idempotency key
bound to the opaque proof, presented application, organization, action, and
resource, without exposing the proof. Private wire DTOs accept current IAM
constraint aliases and the anticipated enriched form only where names have
identical semantics; an internal principal `id` is never accepted as a public
actor ID. Management authorization requires public actor identity,
organization role, visibility/capabilities, audience, and exact proof bindings;
missing facts fail closed. The narrowly scoped provisioning path requires an
explicit `service` actor kind as well as
service ID `silicon-iam`, audience `silicon-hook`, and `hook.iam.provision`
scope. A `client_id` alone never turns an application or user token into a
service identity.

## D-044 — Release builds unwind through HTTP panic containment

**Status:** Accepted runtime-safety correction

Release builds retain Rust's unwind behavior so the HTTP catch-panic layer can
convert handler panics into redacted JSON `500` responses and preserve process
availability. Configuring `panic = "abort"` would make that documented boundary
ineffective and is therefore rejected.

## D-045 — Database text checks match public character semantics

**Status:** Accepted persistence-contract alignment

Human-readable names, descriptions, sources, and subjects use PostgreSQL
`char_length` limits matching the domain's Unicode-scalar validation rather
than byte-length limits. Optional source, subject, and trace values may be empty
where the HTTP contract permits them. ASCII identifiers and cryptographic byte
fields retain their stricter syntax and octet constraints.

## D-046 — Invisible targets are concealed before aggregate lookup

**Status:** Accepted authorization hardening

Per-hook management first evaluates IAM-derived visibility against the target
Silicon, before reading the hook row, and maps a non-visible target to `404`.
After lookup, destructive privilege and OBO creator-application ownership are
evaluated with the persisted hook facts. This prevents absent-versus-existing
hook IDs from becoming an oracle outside the actor's Silicon visibility while
retaining meaningful `403` responses inside an authorized scope.

## D-047 — Legacy unsigned IAM delivery is not accepted

**Status:** Accepted integration boundary

The current sibling IAM implementation still provisions a different legacy
Hook route/shape and emits webhook deliveries without a per-hook signing secret
or Hook's required signature headers. Hook does not add an unsigned bypass or
weaken public ingress to accommodate that client. IAM must adopt the internal
provisioning contract, retain the returned one-time secret securely, and sign
each delivery using D-007 before end-to-end new-Silicon delivery can work.

## D-048 — Plaintext key material stays in zeroizing ownership

**Status:** Accepted cryptographic hygiene

Decoded signing secrets and runtime keys are written directly into
`Zeroizing<[u8; 32]>` buffers. AES-GCM decryption authenticates in place into a
zeroizing fixed-size buffer, and clones preserve that wrapper. Ordinary stack
arrays are accepted only at explicit construction/test boundaries; adapter
decode and decrypt paths do not create unmanaged plaintext copies.

## D-049 — Input and normalized event schemas are distinct

**Status:** Accepted contract correction

Webhook input accepts an explicit JSON `null` for optional description and
event metadata in the same way as omission. The normalized retained event
never serializes null event metadata: source and subject are omitted when
absent, while occurrence time, schema version, and trace ID are always
defaulted. OpenAPI therefore composes request and response shapes from a small
required core instead of weakening the normalized response schema to match the
pre-normalization request.

## D-050 — Cross-layer bounds describe the same units and values

**Status:** Accepted persistence hardening; extends D-045

Database constraints mirror domain limits rather than merely accepting a
wider storage range. Schema versions and encryption-key IDs use their exact
50- and 64-byte domain bounds; the current AES-256-GCM secret ciphertext is
exactly 48 bytes; and human-readable failure reasons use a 2,000 Unicode-scalar
limit rather than a UTF-8 byte limit. This makes direct writes fail at the same
boundary as normal application writes and prevents persistence from admitting
values that cannot be rehydrated.

## D-051 — OpenAPI documents cross-cutting failure responses

**Status:** Accepted contract hardening

The request deadline and panic-containment layers apply to every HTTP route,
so every operation documents redacted `408` and `500` responses. Operations
also enumerate their actual path-validation, body-limit, media-type,
dependency, recovery, and secret-replay failures. Reusable error components
keep the status descriptions consistent while the stable JSON error envelope
remains identical across routes.

## D-052 — Recoverable hook collections have a fixed bound

**Status:** Accepted scalability boundary

Each Silicon may retain at most 1,000 hooks, counting both active hooks and
soft-deleted hooks still inside the 45-day recovery window. Creation takes a
tenant-scoped PostgreSQL advisory transaction lock before counting and
inserting, so concurrent creators cannot exceed the limit; exact idempotent
replays are evaluated first and remain available at the limit. The complete
hook-list response is consequently bounded without introducing pagination
that the product contract does not currently define. A full collection returns
`409 hook_limit_reached`; restoring an existing retained hook does not consume
a new slot. Both quota admission and deleted-inclusive listing apply the same
inclusive recovery cutoff at the operation's authoritative timestamp. Expired
soft-deleted rows therefore stop consuming slots and disappear from lists even
when the asynchronous physical-purge worker has not processed them yet.

## D-053 — Delivery concurrency and lease ownership are independent

**Status:** Accepted worker-scaling invariant

`HOOK_WORKER_BATCH_SIZE` bounds database work per pass, while
`HOOK_WORKER_DELIVERY_CONCURRENCY` independently bounds in-flight DM requests
per replica and defaults to 16. A pass claims at most the smaller value, so a
row never spends its lease waiting behind a local queue. Each lease is renewed
with PostgreSQL's clock before delivery and every one-third of its duration
through both the DM request and persistence of the result. Losing renewal
cancels local work; a possible timeout-after-DM-commit retry is safe because
the stable event ID is DM's deduplication identity.

## D-054 — Valid ingress cannot exceed the local DM send bound

**Status:** Accepted startup invariant

The DM request-size setting has a fixed minimum of 1,052,672 bytes: the 1 MiB
maximum accepted ingress representation plus a 4 KiB budget for the bounded
minimal delivery envelope and escaping. Startup rejects a smaller value. This
prevents one replica from accepting a contract-valid event that another local
configuration deterministically classifies as an unsendable terminal failure.

## D-055 — Terminal delivery receipts follow visible history

**Status:** Accepted retention correction; amends D-017 and D-020

Pending and retrying outbox work is never removed by retention maintenance.
Delivered and failed receipts remain available while the corresponding event
is inside Hook's retained history and are purged only after that event is
evicted. This preserves every undelivered event through arbitrarily long
outages, keeps terminal diagnostics aligned with the public 10,000-event
window, and prevents dead-letter metadata from growing without a bound.

## D-056 — Readiness proves the exact embedded schema contract

**Status:** Accepted deployment-safety invariant

`/readyz` and worker startup validate the complete embedded up-migration
version set, successful application state, byte-for-byte checksums, and the
presence of required Hook relations. A reachable but empty, stale, newer,
partially applied, checksum-divergent, or structurally damaged database is not
ready. Operators must run `hook-migrate` or deploy the binary whose embedded
contract exactly matches the database; this intentionally makes incompatible
rolling combinations fail closed.

## D-057 — Event pages have both item and serialized-size ceilings

**Status:** Accepted history-scaling invariant; extends D-022

The requested `limit` remains an item-count ceiling from 1 through 10,000, but
one response also has a conservative 16 MiB estimated serialized-size budget.
Persistence streams rows and stops before adding the first record that would
cross the budget, returning the last included record as the authenticated next
cursor; one record is always allowed and remains bounded by ingress limits.
Per-hook reads select their direct newest 10,000 without tenant-wide ranking.
Account-wide reads use a bounded lateral top-10,000 selection for each of the
Silicon's at-most-1,000 hooks, then merge only the requested candidates. Large
pages can therefore be consumed safely without allocating payload size times
item limit or applying a window rank to an unbounded physical event table.

## D-058 — IAM identity assertions must be explicit and consistent

**Status:** Accepted cross-service security contract; strengthens D-043

Hook never treats IAM's internal principal UUID as a public Carbon or Silicon
identifier, never infers service kind from `client_id`, and rejects duplicated
identity assertions unless all supplied values agree. Service provisioning
requires an explicit service kind, `silicon-iam` public identity, Hook audience,
and provisioning scope. The versioned positive wire fixtures and the required
sibling changes live under `contracts/iam/v1` and `IAM_INTEGRATION.md`; missing
facts remain an availability-class fail-closed result rather than reduced
authorization.

## D-059 — Retention discovery is queued, fair, and replay-safe

**Status:** Accepted retention-scaling and security invariant; extends D-017,
D-040, D-053, D-055, and D-057

Statement-level PostgreSQL triggers maintain one exact event count and due time
per hook in the same transaction as event insertion or deletion. Only hooks
above the visible 10,000-event window enter the partial-indexed due queue.
Maintenance claims a bounded set of due hooks with `SKIP LOCKED`, divides each
batch across them, finds the 10,000th-row boundary through the per-hook history
index, and rotates still-overfull hooks to the back. A hook remains due while
any excess row has passed its replay deadline; only a hook with no safe victim
sleeps until the earliest deadline among all remaining excess rows. A protected
newest-excess row therefore cannot hide an older purgeable backlog. Maintenance
never ranks or scans the complete event table to discover excess history.

History, expired-hook, terminal-outbox, and management-idempotency cleanup run
as independent short transactions. A worker drains them round-robin until
quiescent or until the configurable batch-round budget is exhausted; a failure
in one class does not roll back or suppress the others. Maintenance capacity is
independent from delivery: the defaults are 1,000 rows per task, 32 drain rounds,
and a five-second interval. Multiple replicas safely share work, and the worker
logs when a cycle exhausts its budget so operators can increase capacity before
physical backlog accumulates.

All eligibility cutoffs use PostgreSQL's clock. Event eviction additionally
requires the row to be strictly older than ten minutes. This covers the entire
remaining validity of a request originally accepted with the maximum 300-second
future timestamp skew, so cascading its key binding and authenticated-request
guard cannot make still-valid signed bytes replayable. The API continues to
expose exactly the newest 10,000 immediately; the replay floor may temporarily
retain additional physical rows. Pending and retrying outbox work remains
independent and durable, while terminal receipts become eligible only after
their event is actually evicted.

## D-060 — Configuration and database authority are process-owned

**Status:** Accepted least-privilege deployment boundary

The API, worker, and migrator load separate typed settings and reject only
missing or invalid values they own. Production gives the API its IAM and
cryptographic material, the worker its DM credential and delivery policy, and
the migrator the only schema-owner URL. API and worker use distinct non-owner
PostgreSQL roles whose executable grant manifest is revoked and rebuilt after
every migration. Readiness probes the exact table, schema, and trigger-function
privileges required by the running process, so an incomplete grant fails before
traffic or background consumption begins.

## D-061 — Readiness verifies declared structure, not arbitrary tamper evidence

**Status:** Accepted deployment-safety clarification; amends D-056

Readiness requires the exact embedded migration version set and checksums, then
checks every declared column's type/nullability, named and validated constraint,
valid/ready index, enabled trigger binding, selected default expression, and
process-specific grant. This catches missing, stale, partial, or accidentally
damaged deployments. It is intentionally not a cryptographic attestation of
every PostgreSQL catalog definition after migration; schema-owner access remains
a trusted deployment boundary and is never granted to runtime roles.

## D-062 — PostgreSQL clocks distributed ingress and worker coordination

**Status:** Accepted clock-consistency invariant

Active endpoint resolution samples `clock_timestamp()` in the same statement;
that value validates the signature window and becomes the event receive time.
Event rows also receive a database-default replay-protection deadline ten
minutes after insertion. Replica operating-system skew therefore cannot make a
new guard immediately evictable. Outbox claims, lease extensions, completion
timestamps, retry availability, and maintenance cutoffs likewise derive from
PostgreSQL; retry commands carry durations rather than process-clock deadlines.
Injected application time remains useful for deterministic management lifecycle
tests but does not coordinate multi-replica leases or ingress replay safety.

## D-063 — IAM default provisioning has a lifetime registration

**Status:** Accepted lifecycle correction; strengthens D-012

Provisioning IAM's default connection atomically inserts an immutable private
`(org_id, silicon_id)` registration before creating the recoverable hook. The
registration deliberately has no foreign key to that hook and survives its
45-day permanent purge. Exact idempotent replays are resolved before the insert;
different keys or later calls return `409 iam_hook_already_exists`. Failed hook
creation rolls the registration back, while deliberate deletion can never be
silently reversed by provisioning after cleanup.

## D-064 — Durable acceptance measures the exact normalized DM body

**Status:** Accepted end-to-end size invariant; supersedes D-054's envelope
budget assumption

A raw ingress body remains limited to 1 MiB, but that limit is not proof that
its parsed representation is equally small: compact JSON numbers can expand
during canonical serialization. After signature and domain validation, the API
constructs the published minimal DM event exactly once and rejects it with
`413 payload_too_large` if those bytes exceed 1,052,672. This occurs before any
event, idempotency binding, authenticated-request guard, or outbox row is
committed.

The bounded byte value is passed into the acceptance transaction and stored
verbatim; persistence never reconstructs it. The same centralized limit is the
minimum accepted by worker configuration, while the database constraint has
additional defensive capacity. Therefore every event acknowledged with `202`
fits immutable outbox storage and every valid local worker send policy, and all
retries remain byte-identical.

## D-065 — Published request bounds are fixed deployment invariants

**Status:** Accepted contract-consistency rule; strengthens D-007 and D-016

The 1 MiB raw ingress limit, 64 KiB management-body limit, and 300-second
signature tolerance are exact public contract values. Configuration may state
those values for explicit deployment manifests but cannot lower or raise them.
Operational tuning remains available for concurrency, timeouts, pools, and
worker capacity; it may not cause one healthy replica to reject a request that
another replica and the published OpenAPI contract accept.

## D-066 — Domain validation excludes PostgreSQL's unrepresentable NUL

**Status:** Accepted persistence-boundary hardening

PostgreSQL `text` and `jsonb` cannot represent `U+0000`. Hook names and
descriptions reject it, and event normalization iteratively checks every nested
JSON string and object member name before any transaction starts. Such input is
a deterministic client validation failure rather than a PostgreSQL error or
redacted `500`. The iterative walk avoids adding a second recursion-risk surface
beyond the bounded JSON parser.

## D-067 — Authenticated management responses are never shared-cacheable

**Status:** Accepted confidentiality boundary; extends D-036

Every management and internal-IAM response, including middleware and error
responses, carries `Cache-Control: private, no-store`, legacy
`Pragma: no-cache`, and `Vary` across every supported credential and
organization header. This protects hook metadata and event payloads as well as
one-time secrets; route-specific secret headers remain defense in depth.

## D-068 — Production database TLS mode is singular and secure

**Status:** Accepted configuration hardening; extends D-024

Production PostgreSQL URLs must contain exactly one effective `sslmode` or
driver-compatible `ssl-mode` parameter, and its value must be `require`,
`verify-ca`, or `verify-full`. Duplicate keys or mixed aliases are rejected even
when one secure value is present, preventing parser precedence from silently
downgrading the connection after startup validation.

## D-069 — Recovery visibility expires independently of physical cleanup

**Status:** Accepted lifecycle consistency; extends D-018 and D-052

The inclusive 45-day recovery deadline controls direct hook reads,
deleted-inclusive lists, quota admission, and per-hook or account-wide event
history. At the first instant after that deadline, metadata and history are no
longer visible even if the bounded worker has not yet hard-deleted the row.
Restore alone reports the explicit expired-recovery outcome while the tombstone
still exists; asynchronous purge remains storage reclamation, not product-time
enforcement.

## D-070 — Dependency policy treats Hook as unpublished private software

**Status:** Accepted supply-chain policy

The Hook crate is explicitly unpublished and does not claim a fabricated SPDX
license identifier. Dependency license enforcement ignores only unpublished
workspace crates while continuing to require an allowlisted SPDX expression for
every third-party dependency. `CDLA-Permissive-2.0` is allowed for the WebPKI
root-certificate data used by the Rustls HTTPS stack; advisories, yanked crates,
wildcard requirements, and unknown dependency sources remain enforced.

## D-071 — A Silicon base endpoint is an identity namespace

**Status:** Accepted interpretation of the authenticated-base-endpoint requirement

Successful IAM authentication establishes the deterministic namespace
`https://hook.teamofsilicons.com/{silicon_id}/` for the Silicon identity. The
namespace is not a persisted hook, an ingress credential, or an addressable
management operation, and authentication remains free of resource-creation side
effects. Usable webhook endpoints continue to be created explicitly and use
the signed canonical route `/silicon/{silicon_id}/{endpoint_key}`. This preserves
multiple independently managed endpoints per Silicon without inventing an
unsigned catch-all ingress route.

## D-072 — Reversible activation is independent of deletion

**Status:** Accepted lifecycle extension

A retained hook has one of three exclusive states: `active`, `disabled`, or
`deleted`. Disabling preserves its endpoint, encrypted secret, metadata,
history, and quota position but makes ingress resolve as not found. Enabling a
disabled hook restores the same endpoint and secret. Secret rotation remains
available while disabled. Deletion and its 45-day recovery window remain a
separate lifecycle; a deleted hook must be restored rather than enabled, and
restore always produces an active hook.

Single-hook and collection PATCH operations express the desired `enabled`
state, so they need no `Idempotency-Key` and repeated requests are successful
no-ops. The collection accepts 1–1,000 unique Hook IDs, locks and validates the
complete set, and commits all transitions atomically. Missing, deleted,
cross-Silicon, or unauthorized members cannot produce partial changes. Only
actual transitions write `hook.enabled` or `hook.disabled` audit records, and
batch results preserve request order.

## D-073 — Hook activation has a dedicated IAM action

**Status:** Accepted least-privilege authorization extension

Enable and disable operations use action and administrator capability
`hook.hooks.enabled.update`; they do not reuse delete authority. Single-hook OBO
proofs bind the Hook UUID, while batch proofs bind the target Silicon ID and
Hook authorizes every selected aggregate. The represented actor's normal
visibility and role constraints still apply. An OBO application can mutate only
hooks created through that application unless the represented actor is an
organization owner or has `hook.administrative_override`.

## D-074 — Acknowledgment has durable Hook and DM stages

**Status:** Accepted cross-service ownership clarification; extends D-019

Hook's ingress `202 Accepted` with a stable `event_id` acknowledges that the
event and its delivery work committed durably in Hook. DM's later `202 Accepted`
acknowledges durable handoff from Hook to DM and is the point recorded as
`delivered` by Hook. Neither response claims that a connected client received
the event.

DM owns WebSocket representation authorization, the 30-second JSON ping/pong
heartbeat, the two-minute `4000 heartbeat-timeout` close, per-actor sequencing,
client acknowledgments, reconnect resumption, and replay of unacknowledged
events. Heartbeats are transient and have no acknowledgment or event sequence.
Hook neither exposes a WebSocket route nor stores client acknowledgment state.

## D-075 — The normalized DM payload has its own exact limit

**Status:** Accepted compatibility correction; amends D-064

DM independently limits the canonical JSON representation of the nested event
`payload` to exactly 1 MiB (1,048,576 bytes). Hook therefore serializes and
checks that value before constructing and checking the complete minimal DM
request against the existing 1,052,672-byte bound. Either normalized overflow
returns `413 payload_too_large` before event, idempotency, replay-guard, or
outbox persistence. This closes the compact-number expansion gap in which Hook
could previously acknowledge an event whose complete request fit locally but
whose nested payload DM would reject terminally.

## D-076 — Revised product prose does not silently retire integration contracts

**Status:** Accepted compatibility interpretation

The revised understanding replaces explanatory OBO and IAM paragraphs with
WebSocket and acknowledgment requirements but does not explicitly deprecate
their published API contracts. Hook therefore retains OBO Access authorization,
the service-authenticated default IAM Hook provisioning operation, and signed
IAM event delivery. Removing any of them would be an explicit versioned
cross-service breaking change rather than an inference from omitted prose.

## D-077 — The DM 0.2 contract conflicts with Hook's delivery contract

**Status:** Release blocked pending an explicit cross-service product decision

Hook's current product understanding still requires every accepted webhook
event to be delivered to Silicon DM and then conveyed to the target Silicon.
The reviewed Silicon DM `0.2.0` contract on `main` explicitly retires
`POST /api/v1/internal/hook-events`, its `SystemEvent` type, and the corresponding
WebSocket frame. Deploying the two contracts together would make every Hook
delivery terminate at DM with `404`; client acknowledgment and replay could
never occur.

Hook does not silently discard its own explicit requirement or reinterpret a
DM `404` as successful delivery. Its durable outbox and existing DM contract
remain implemented so accepted events are not lost locally. A combined release
is blocked until product ownership chooses and versions one of two compatible
directions: restore durable Hook-event ingestion and replay in DM, or revise
Hook's understanding and assign a different durable delivery destination.
This decision records the incompatibility; it does not authorize changes in the
separate DM repository.
