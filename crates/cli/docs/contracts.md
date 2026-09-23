# Contract lifecycle and compatibility

## Integrate safely

1. Call unversioned `GET /api/version` with the majors your consumer implements, for example `Silicon-Hook-Supported-API-Versions: v2,v1` after migrating delivery to Ting. Existing v1-only consumers must continue advertising `v1`.
2. Require `service: silicon-hook` and a shared `selected_api_version`.
3. Pin every versioned call to its negotiated route major, for example `Silicon-Hook-API-Version: v2` on `/api/v2/...`.
4. Handle additive JSON fields. Deduplicate by Hook event ID and reuse mutation keys when retrying. Ting arrival order is not guaranteed; `delivery_sequence` records original Hook receipt order.
5. Read `GET /api/contracts` for lifecycle status and migration guidance. The official client's existing negotiation must only advertise majors its delivery implementation supports.

The highest shared, nonsunset major wins. The backend implements v2 and deprecated v1, in that preference order. Unsupported majors return `406 api_version_unsupported`; route/header disagreement returns `400 api_version_mismatch`. A sunset major returns `410 api_version_sunset`. Failed test selection never changes the request to production.

## Compatibility matrix

| Consumer | Backend API | Direct Hook WebSocket | Hook shared relay | Testing |
| --- | --- | --- | --- | --- |
| Ting-aware HTTP consumer | v2 | unavailable (410) | unavailable (410) | Current app-secret/root-key selection and IAM actor authority; isolated Ting publication |
| Rust client / CLI 0.8 source | v2 | removed | removed | Scoped inbox/watch bootstrap through Hook; native destinations still use the enclosing runtime's own matching Ting session |
| Browser gateway 0.8 source | v2 | observes Ting's inbox instead | removed | Scoped testing inbox/watch through Hook with private renewal and cleanup |
| Client/CLI through 0.4 (legacy) | deprecated v1 | protocol 1 | unavailable | legacy Hook root-key selection |
| Client/CLI 0.6/0.7 (legacy transport) | deprecated v1 | protocol 1 | relay protocol 1 | Honeycomb installation and shared lifecycle; IAM app-secret selection |
| Earlier browser gateway (legacy transport) | deprecated v1 | protocol 1 | daemon owns its own connection | app-secret selector and separate encrypted sessions |
| Existing generic HTTP consumer | deprecated v1 | optional | optional | `X-Hook-Test-App-Secret` plus actor bearer |

The 0.8 client, CLI and browser gateway source use v2; this does not claim publication, installation or deployment. The browser internally exchanges paired Hook/Ting sessions, watches the inbox and hydrates originals without acknowledging application work. Production receiving requires an explicit `/v1/me` production attestation; missing or mismatched context is rejected. Testing uses Ting 0.1.4's scoped receiver through Hook, with private renewal and no general Ting session. [Recovery and rollout constraints](ting-integration-issues.md) still apply. Existing v1 direct WebSocket, polling, ACK cursor and relay behavior remains available until that environment's v1 contract sunsets. The legacy local receiver envelope adds a top-level `metadata` object while preserving `type` and `data`; consumers must accept additive fields.

## V2 delivery contract

Verified provider ingress commits the canonical event and its Ting outbox entries atomically. Hook retains the raw request for 14 days. Ting receives a compact reference under `<Hook app_id>.webhook.received`, including the event ID, Silicon, sequence and original event environment generation. It does not receive captured provider bodies, headers or signing secrets. Each uncertain send retries the same persisted bytes and producer key with a fresh IAM proof.

The shared v1/v2 backend endpoints are:

- `POST /delivery/publisher`: a Carbon owner/admin provisions a dedicated Silicon publisher through a fresh Hook SLT; `replace_rejected` explicitly recovers a rejected session.
- `POST /delivery/recipient`: register the authenticated actor's Ting grant using an empty request body.
- `GET /silicons/{silicon_id}/events/{event_id}`: hydrate the retained event with current IAM read permission. Paired environment query fields validate its original reference.
- `GET /silicons/{silicon_id}/events/{event_id}/publication`: inspect pending, Ting-accepted or silently accepted publication for the primary Silicon, plus best-effort destination receipts.

V2 also provides `GET`, `POST`, `DELETE /silicons/{silicon_id}/delivery/subscription`: a Carbon manages their own future-event receiving interest after live read authorization. This does not backfill history or grant permanent access. GET and POST return the current subscription; DELETE returns `204` after removing it.

V2 `GET /delivery/receiver` returns the current authenticated testing scope;
`POST` accepts its pinned `environment_id`, shared `generation`, an optional
original `receiver_id`, and a required `Idempotency-Key`. Hook derives the
actor/app/org, obtains a fresh request-bound proof, and returns only a scoped
Ting capability with its original expiry. Production is rejected. Replaying an
operation never extends authority; renewal uses a new key and the original ID.

Every method on v2 `/ws`, `/relay/ws`, `/silicons/{silicon_id}/deliveries`, and its `/pull`, `/ack` and `/cursor` subpaths returns `410 delivery_transport_replaced`. A Ting-aware consumer must use the Ting transport and authorized event hydration. It must not reinterpret the compact reference as the v1 full Event payload or advance the v1 cumulative cursor from unordered Ting arrivals.

Ting acceptance, durable daemon receipt and destination acceptance are distinct. A read ACK or `read: true` is not proof that the recipient completed its work. New primary Silicon sends request required delivery and stay pending without the recipient's separate opt-in. Carbon observer and existing queued sends retain ordinary policy. Publication exposes `delivery` separately from nullable notification `silent`; required muted acceptance is `accepted_by_ting`, while ordinary muted acceptance is `accepted_silently`. Receipt mode must match the original immutable request. No retry changes policy or enables consent.

Current runtime generation fences control which environment may act. The immutable notification records the event's original generation, which can survive key rotation or restore. Cleaning deletes canonical events and their outbox rows, so old references cannot hydrate cleaned data. See the [endpoint contract](api/README.md#ting-delivery-v2) for schemas and error behavior.

## Version policy

Breaking HTTP route/field/permission semantics require a new API major and a compatibility adapter while the prior major remains supported. Ting replaces the Hook delivery transport in v2; common management, authentication and history operations retain their existing wire shapes. Additive management endpoints may also be served in v1 without replacing its transport. Legacy direct and multiplexed WebSocket protocols retain independently explicit version 1 ready frames. Client and CLI package versions follow semantic versioning; internal implementation versions are not API majors.

Consumer regression tests cover published wire shapes, SLT-only production login, sandbox selection, local delivery, heartbeat, replay, acknowledgment and legacy negotiation. Backend Ting tests also cover atomic enqueue, tenant isolation, immutable retries, publisher refresh, acceptance states and event hydration. Run `cargo test --workspace --all-targets` and OpenAPI validation before releasing a contract change; passing backend tests alone does not certify migrated client or recipient behavior.

## Deprecation and automatic sunset

The Ting contract migration marks v1 `deprecated`, preserving existing deprecation timestamps and sunset decisions; v2 starts `active`. Operators can also change lifecycle state explicitly. A deprecated version sunsets only after **seven complete days with zero requests**, measured from the later of deprecation and last activity. An active version never sunsets just because it is quiet. New admitted requests restart the idle window. Live authorized v1 WebSocket sessions count as activity during authority revalidation, so a long-lived consumer is not retired underneath its connection.

State survives restarts in PostgreSQL. Each environment has separate lifecycle counters; no request content, credential, address or actor is collected. This is functional contract governance and does not use Space Station. Test requests never keep a production version alive.

`GET /api/contracts` lists each major's `status`, deprecation/sunset Unix timestamps, `delivery_transport` (`ting` for v2, `hook` for v1), and supported WebSocket/relay protocol arrays (empty for v2, `[1]` for v1). It does not expose request counters. The versioned catalog is subject to admission for its own major.

The worker evaluates retirement periodically; request admission and catalog reads also evaluate it atomically. A request arriving after the idle deadline is rejected and cannot revive the retired version. Deprecated responses include a `Deprecation` timestamp and a link to this policy. A fixed future sunset date is not advertised while activity can extend the window.

## Operator commands

Build `hook-contract` from the backend workspace. It uses the privileged migration database configuration:

```sh
hook-contract status v1
hook-contract status v2
hook-contract deprecate v1
hook-contract activate v2
# Scope an operation to one sandbox using HOOK_TEST_DATABASE_URL:
hook-contract status v1 <sandbox-uuid>
```

`deprecate` is idempotent while already deprecated. `activate` explicitly restores service after an operator has resolved compatibility concerns. Neither action is an end-user or root-key HTTP endpoint. Validate migration readiness and runtime grants before deployment; see [deployment](deployment.md).
