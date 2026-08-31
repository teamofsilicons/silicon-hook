# Silicon Hook API documentation

This document explains every operation in the Silicon Hook OpenAPI contract. The machine-readable contract is in [`openapi.yaml`](./openapi.yaml).

## API conventions

### Base URL

```text
https://hook.teamofsilicons.com/api/v1
```

Hook gives each Silicon multiple inbound webhook endpoints. It authenticates and persists incoming events, retains recent history, and forwards durable system events to Silicon DM.

### Authentication

- **Bearer authentication:** IAM access token for Silicon, Carbon, or administrator operations.
- **OBO Access:** An application may act for an authorized actor.
- **Service authentication:** IAM service token for internal IAM provisioning.
- **Public ingress:** Individual webhook URLs are publicly reachable but require request signatures.
- **Organization context:** Management requests require `X-Org-ID`.

Webhook endpoint keys help route requests but are not credentials. Authenticity comes from HMAC signatures and replay protection.

## Hook management

### `GET /silicons/{silicon_id}/hooks`

Lists webhook connections belonging to a Silicon.

- **Authentication:** Bearer or OBO Access.
- **Query:** Optional `include_deleted`.
- **Returns:** Visible hooks.

The Silicon can list its hooks. Carbons may list hooks only for Silicons IAM says they can view. Owners and authorized administrators can manage organization Silicons.

### `POST /silicons/{silicon_id}/hooks`

Creates a webhook connection.

- **Authentication:** Bearer or OBO Access.
- **Input:** Service name and optional description.
- **Required header:** `Idempotency-Key`.
- **Returns:** Hook metadata and a one-time signing secret.

The endpoint URL contains the Silicon ID and a six-character routing key. The signing secret must be displayed only once and stored securely by the sender.

### `GET /silicons/{silicon_id}/hooks/{hook_id}`

Returns one hook and its status.

- **Authentication:** Bearer or OBO Access.
- **Returns:** Hook metadata, endpoint URL, creator, and timestamps.

The signing secret is never returned after creation.

### `DELETE /silicons/{silicon_id}/hooks/{hook_id}`

Disables a webhook connection.

- **Authentication:** Bearer or OBO Access.
- **Returns:** `204 No Content`.

The URL immediately stops accepting events. The deleted hook remains recoverable for 45 days, along with its retained event history.

### `POST /silicons/{silicon_id}/hooks/{hook_id}/restore`

Restores a deleted hook during its recovery period.

- **Authentication:** Bearer or OBO Access.
- **Returns:** Active hook.

The contract currently retains the same endpoint and secret. Whether restoration should force secret rotation is a security decision.

### `POST /silicons/{silicon_id}/hooks/{hook_id}/secret/rotate`

Rotates the webhook signing secret.

- **Authentication:** Bearer or OBO Access.
- **Returns:** New one-time signing secret.

The old secret should have either immediate invalidation or a clearly bounded overlap period. Rotation must be audited.

## Events and logs

### `GET /silicons/{silicon_id}/events`

Lists retained events across one or all of a Silicon's hooks.

- **Authentication:** Bearer or OBO Access.
- **Filters:** Hook ID and event type.
- **Pagination:** Cursor and limit, with a maximum request size of 10,000.
- **Returns:** Event envelopes and delivery state.

Hook retains the latest 10,000 events per endpoint. Account-wide results must define whether retention also has a separate total limit. Payload visibility follows the same Silicon-access rules as hook management.

Each event contains a stable ID, type, source, subject, occurrence time, schema version, trace ID, payload, receive time, and delivery attempts.

## Public webhook ingress

### `POST /silicon/{silicon_id}/{endpoint_key}`

Receives an event from an external or internal service.

- **Authentication:** HMAC request signature.
- **Required headers:** `X-Hook-Signature`, `X-Hook-Timestamp`, and `Idempotency-Key`.
- **Input:** Event type, payload, and optional source, subject, occurrence time, version, and trace ID.
- **Returns:** `202 Accepted`, stable `event_id`, and accepted status.

Hook resolves the endpoint, rejects deleted hooks, checks that the timestamp is within the replay window, verifies the signature over the timestamp and raw request body, and deduplicates the idempotency key.

After validation, Hook persists the event before responding. It then delivers the event to DM asynchronously. A DM outage must not cause the accepted webhook event to disappear.

## IAM provisioning

### `POST /internal/iam/hooks`

Creates the default IAM hook for a newly created Silicon.

- **Authentication:** IAM service token; only the Silicon IAM service identity may call it.
- **Input:** `org_id` and `silicon_id`.
- **Returns:** Default hook named `Silicon IAM`.

The operation must be idempotent for the same Silicon. IAM stores the returned endpoint and sends `iam.silicon.initialized` with the Silicon profile and current organization snapshot after activation.

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

## Contract gaps

- Retry intervals, maximum attempts, and dead-letter behavior for DM delivery are not defined.
- There is no event-detail endpoint by event ID.
- There is no explicit event replay or redelivery operation.
- Event payload-size limits and accepted content types are undefined.
- Secret overlap behavior during rotation is undefined.
- Hook rename and description-update operations are missing.
- Per-hook rate limits, IP restrictions, and allowlists are not represented.
- Account-wide versus per-hook retention limits need clarification.
- Deleted-hook permanent purge and recovery deadlines are not exposed.
- Signature algorithms and canonical signing instructions need a normative section with test vectors.
- The six-character endpoint key must remain a routing identifier, never the authentication boundary.
