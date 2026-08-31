# Silicon Hook API documentation

This document explains every operation in the Silicon Hook OpenAPI contract. The machine-readable contract is in [`openapi.yaml`](./openapi.yaml).

## API conventions

### Base URL

Management and internal operations use:

```text
https://hook.teamofsilicons.com/api/v1
```

Public webhook delivery uses the endpoint URL returned by Hook:

```text
https://hook.teamofsilicons.com/silicon/{silicon_id}/{endpoint_key}
```

Hook gives each Silicon multiple inbound webhook endpoints. It authenticates and persists incoming events, retains recent history, and forwards durable system events to Silicon DM.

### Authentication

- **Bearer authentication:** IAM access token for Silicon, Carbon, or administrator operations.
- **OBO Access:** An application supplies both `X-App-ID` and a short-lived `X-IAM-OBO-Access-Proof` to act for an authorized actor.
- **Service authentication:** IAM service token for internal IAM provisioning.

OBO proofs bind to the action and a stable resource identifier. Hook uses the
target Silicon ID for collection create/list and event-history actions, and the
hook UUID for per-hook read, delete, restore, and secret-rotation actions.
- **Public ingress:** Individual webhook URLs are publicly reachable but require request signatures.
- **Organization context:** Management requests require `X-Org-ID`.

Webhook endpoint keys help route requests but are not credentials. Authenticity comes from HMAC signatures and replay protection.

Hook verifies opaque credentials online with IAM and fails closed if IAM cannot make a current decision. `X-Org-ID`, Silicon ID suffixes, job roles, and trust metadata are never treated as proof of authority.

Every management and internal-IAM response, including errors, carries
`Cache-Control: private, no-store`, legacy `Pragma: no-cache`, and a `Vary`
value covering every supported authorization and organization header. Shared
caches must never retain hook metadata, event payloads, or one-time secrets.

### Idempotency

Mutation and ingress idempotency keys contain 8–255 visible ASCII characters. Repeating a key in the same operation scope with the same request returns the original result. Reusing it with different content returns `409 idempotency_conflict`.

One-time-secret responses can be replayed for ten minutes only by the same caller, route, target, request digest, and idempotency key. The idempotency record remains for 24 hours; after the secret replay window, callers rotate the secret instead of retrieving it.

### Errors

Errors use one stable envelope and include the request correlation ID:

```json
{
  "error": {
    "code": "validation_failed",
    "message": "The request contains invalid data.",
    "request_id": "0198..."
  }
}
```

Authentication failures return `401`, authorization failures return `403`, invisible resources return `404`, request deadlines return `408`, conflicting idempotency or state returns `409`, expired recovery or one-time-secret replay returns `410`, oversized bodies return `413`, unsupported request media return `415`, invalid input returns `422`, internal invariant failures return a redacted `500`, and dependency outages return `503`.

Opaque identifiers and idempotency keys use visible ASCII and are bounded by
the machine contract. Event `source` and `subject` values may contain Unicode
but cannot contain control characters. Hook names, descriptions, and every
string or member name nested in a JSON payload reject `U+0000`, which
PostgreSQL text and `jsonb` cannot represent.

## Hook management

### `GET /silicons/{silicon_id}/hooks`

Lists webhook connections belonging to a Silicon.

- **Authentication:** Bearer or OBO Access.
- **Query:** Optional `include_deleted`.
- **Returns:** Visible hooks.

The Silicon can list its hooks. Carbons may list hooks only for Silicons IAM says they can view. Owners and authorized administrators can manage organization Silicons.

A Silicon can retain at most 1,000 hooks, including soft-deleted hooks still
inside their 45-day recovery period. This keeps the complete, non-paginated
hook list bounded. Creation returns `409 hook_limit_reached` until an existing
hook ages out of recovery; callers can restore a deleted hook immediately.

### `POST /silicons/{silicon_id}/hooks`

Creates a webhook connection.

- **Authentication:** Bearer or OBO Access.
- **Input:** Service name and optional description.
- **Required header:** `Idempotency-Key`.
- **Returns:** Hook metadata and a one-time signing secret.

The endpoint URL contains the Silicon ID and an uppercase six-character hexadecimal routing key. The signing secret has the form `whsec_<base64url>` and must be displayed only once and stored securely by the sender.

### `GET /silicons/{silicon_id}/hooks/{hook_id}`

Returns one hook and its status.

- **Authentication:** Bearer or OBO Access.
- **Returns:** Hook metadata, endpoint URL, creator, and timestamps.

The signing secret is never returned after creation.
An expired soft-deleted hook returns `404` even if asynchronous physical purge
has not processed its row yet.

### `DELETE /silicons/{silicon_id}/hooks/{hook_id}`

Disables a webhook connection.

- **Authentication:** Bearer or OBO Access.
- **Returns:** `204 No Content`.

The URL immediately stops accepting events. The deleted hook remains recoverable for 45 days, along with its retained event history.

### `POST /silicons/{silicon_id}/hooks/{hook_id}/restore`

Restores a deleted hook during its recovery period.

- **Authentication:** Bearer or OBO Access.
- **Required header:** `Idempotency-Key`.
- **Returns:** Active hook.

Restoration retains the same endpoint and secret.

### `POST /silicons/{silicon_id}/hooks/{hook_id}/secret/rotate`

Rotates the webhook signing secret.

- **Authentication:** Bearer or OBO Access.
- **Required header:** `Idempotency-Key`.
- **Returns:** New one-time signing secret.

The old secret is invalid immediately. Rotation is transactional and audited.

## Events and logs

### `GET /silicons/{silicon_id}/events`

Lists retained events across one or all of a Silicon's hooks.

- **Authentication:** Bearer or OBO Access.
- **Filters:** Hook ID and event type.
- **Pagination:** Cursor and item limit, with a maximum requested page size of 10,000.
- **Returns:** Event envelopes and delivery state.

Hook exposes the latest 10,000 events per endpoint. Account-wide results are drawn from those per-hook retained windows and have no second storage cap; one response still contains at most 10,000 items. A response also has a conservative 16 MiB serialized-size budget, so a page can contain fewer items than requested and return a continuation cursor. A single event is always returned even when it alone reaches the budget. Payload visibility follows the same Silicon-access rules as hook management, and a hook whose 45-day recovery window has expired contributes no history even if physical cleanup is delayed.

Physical eviction is driven by a transactional per-hook counter and fair due queue rather than a scan or rank of the complete event table. The worker drains independently bounded history, terminal-delivery, idempotency, and deleted-hook batches. Rows outside the visible 10,000 are held for a strict ten-minute minimum before eviction so an accepted request with the maximum allowed future timestamp skew cannot become replayable after its guards cascade.

Each event contains a stable ID, type, occurrence time, schema version, trace ID, payload, receive time, and delivery attempts. `source` and `subject` are present only when the sender supplied them.

## Public webhook ingress

### `POST https://hook.teamofsilicons.com/silicon/{silicon_id}/{endpoint_key}`

Receives an event from an external or internal service.

- **Authentication:** HMAC request signature.
- **Required headers:** `X-Hook-Signature`, `X-Hook-Timestamp`, and `Idempotency-Key`.
- **Input:** Event type, payload, and optional source, subject, occurrence time, version, and trace ID.
- **Returns:** `202 Accepted`, stable `event_id`, and accepted status.

Hook accepts raw JSON bodies up to 1 MiB. It resolves the endpoint, rejects deleted hooks, checks that the timestamp is within the replay window, verifies the signature over the timestamp and exact raw request body, and deduplicates the idempotency key. It also replay-deduplicates an identical authenticated timestamp and exact body for the same hook even when the sender changes `Idempotency-Key`, returning the original stable `event_id`. The `/api/v1/silicon/{silicon_id}/{endpoint_key}` route and optional trailing slashes are compatibility aliases; generated endpoint URLs always use the canonical root route.

Before persistence, Hook normalizes the event, constructs the exact minimal DM request once, and requires that representation to be at most 1,052,672 bytes. This second bound matters because compact JSON numbers can occupy more bytes after parsing and canonical serialization. An oversized raw or normalized representation returns `413 payload_too_large`; no event, idempotency binding, replay guard, or outbox work is committed.

After validation, Hook persists the event before responding. It then delivers the event to DM asynchronously. A DM outage must not cause the accepted webhook event to disappear.

### Signature version 1

1. Decode the characters after the `whsec_` secret prefix as unpadded base64url. The result must be exactly 32 bytes.
2. Serialize the JSON once and preserve those exact bytes for transmission.
3. Set `X-Hook-Timestamp` to the current Unix timestamp in decimal seconds.
4. Compute HMAC-SHA-256 over `timestamp + "." + raw_body` using the decoded secret bytes.
5. Send `X-Hook-Signature: v1=<64 lowercase hexadecimal characters>`.

Hook rejects non-canonical encodings, signatures that do not compare in constant time, and timestamps more than 300 seconds in the past or future. The freshness comparison and accepted receive time use PostgreSQL's clock sampled with endpoint resolution, so API replica clock skew cannot weaken replay protection. Whitespace and JSON key ordering matter because the exact transmitted bytes are signed.

Test vector using the literal UTF-8 HMAC key `test-secret` to make independent implementations easy to verify:

```text
timestamp: 1700000000
body: {"type":"example.created","payload":{"ok":true}}
signed bytes: 1700000000.{"type":"example.created","payload":{"ok":true}}
signature: v1=68f7b62fdf8b22413cfa8815fd6fdf3818cbf87ec1faffa352ca50796c38e5b5
```

## IAM provisioning

### `POST /internal/iam/hooks`

Creates the default IAM hook for a newly created Silicon.

- **Authentication:** IAM service token; only the Silicon IAM service identity may call it.
- **Required header:** `Idempotency-Key`.
- **Input:** `org_id` and global `silicon_id`.
- **Returns:** Default hook named `Silicon IAM` and its one-time signing secret.

The operation is unique per organization and Silicon. IAM stores the returned endpoint and signing secret securely, then sends `iam.silicon.initialized` with the Silicon profile and current organization snapshot after activation. Only an introspected `silicon-iam` service token with the Hook audience may call this route. A deliberately deleted default hook is not recreated silently.
An immutable private registration survives permanent hook cleanup, so that
one-time provisioning invariant holds for the lifetime of the organization and
Silicon identity rather than only during the 45-day recovery window.

## Delivery to Silicon DM

The worker submits the published minimal system-event body to `POST /api/v1/internal/hook-events` with Hook's dedicated IAM service token and `Idempotency-Key` set to the stable event ID. Event acceptance and durable delivery work commit atomically; only DM `202 Accepted` marks delivery as delivered. The immutable outbox stores the already-bounded bytes constructed during ingress, and every worker configuration must accept at least that common bound.

Retries reuse the stable event ID and exact body. Retryable failures use capped exponential backoff with full jitter and honor bounded `Retry-After`; the default maximum is 20 attempts and 15 minutes. Terminal or exhausted deliveries remain visible as `failed` for diagnosis while their event is retained. Pending and retrying work survives history eviction; delivered and failed receipts are removed only after their event leaves retained history. Hook provides at-least-once delivery. DM deduplicates the stable event ID so a timeout-after-commit retry does not fan out the same accepted event twice.

## Complete flows

### External event

```text
Sender constructs event envelope
  -> signs timestamp + raw body
  -> POSTs to the Silicon endpoint
  -> Hook verifies and persists
  -> Hook returns stable event ID
  -> Hook queues delivery to DM
  -> Silicon receives a system event over WebSocket
```

### New Silicon

```text
IAM creates Silicon identity
  -> IAM calls internal Hook provisioning
  -> Hook creates the default Silicon IAM endpoint
  -> IAM stores the endpoint
  -> IAM emits iam.silicon.initialized
```

## Deliberately deferred operations

- There is no event-detail endpoint by event ID.
- There is no explicit event replay or redelivery operation.
- Hook rename and description-update operations are missing.
- Per-hook rate limits, IP restrictions, and allowlists are not represented.
- There is no public permanent-purge operation; the worker purges deleted hooks after 45 days.
- There is no public dead-letter replay operation yet; failed state remains visible while its event is retained and is then purged with the terminal receipt.
