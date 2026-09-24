# Silicon Hook API documentation

This document explains the Silicon Hook backend API contract. The machine-readable contract is in [`openapi.yaml`](../../openapi.yaml). The product requirements are in [`UNDERSTANDING.md`](../../understanding/UNDERSTANDING.md).

## API conventions

### Base URL

Management, history, and delivery operations use:

```text
https://backend.hook.teamofsilicons.com/api/v2
```

An authenticated Silicon owns the namespace `https://hook.teamofsilicons.com/{silicon_id}/`. Each hook it creates receives a public endpoint inside that namespace:

```text
https://hook.teamofsilicons.com/silicon/{silicon_id}/{endpoint_key}
```

The endpoint key is eight uppercase alphanumeric characters. It routes a request to a hook and is never a credential; authenticity comes from the hook's signature policy.

### API version

Every route belongs to an API major. Before anything else a client sends the unversioned handshake:

```http
GET /api/version
Silicon-Hook-Supported-API-Versions: v2,v1
```

Hook answers with the highest shared, nonsunset major in the body (`service`, `selected_api_version`, `supported_api_versions`, `build`, `commit`) and in `Silicon-Hook-API-Version`, and varies the response on the advertised list. With no shared major it answers `406 api_version_unsupported`. A v2 client pins every versioned call with `Silicon-Hook-API-Version: v2`; a pin that disagrees with the route is refused with `400 api_version_mismatch`. Advertise only majors the client actually implements. An existing client that implements only the legacy transport must continue advertising `v1` until migrated.

Unprefixed operation paths below are relative to `/api/v2`, except in the explicitly marked legacy sections. Hook management, authentication, history and testing operations also remain available under `/api/v1`. Publisher provisioning, recipient grants, event hydration and publication status are available in both majors; Carbon receiving interests require v2. The migration marks v1 deprecated; it continues serving its existing delivery protocol until the [seven idle day sunset policy](../contracts.md) retires it. Backend support does not imply that installed clients, the CLI or website have migrated.

### Authentication

- **Bearer authentication:** the only credential. A Silicon presents the access token Silicon IAM issued it; a Carbon presents the Hook Application token obtained through [sign-in](#sign-in) or an IAM access token of their own. Hook exposes no OBO endpoints.
- **Provider ingress:** Endpoint URLs are publicly reachable; each hook's signature policy decides what is delivered.
- **IAM ingress:** `POST /iam/events` is authenticated by IAM's webhook signature, not a bearer.
- **Organization context:** Management requests require `X-Org-ID`.

Hook verifies every bearer online with Silicon IAM through the official `silicon-iam-client` crate and IAM's organization directory, and fails closed if IAM cannot make a current decision. Every management response, including errors, carries `Cache-Control: private, no-store`.

Hooks are for Silicons. A Silicon manages only its own hooks. A Carbon sees the hooks, logs, and streams of every Silicon IAM confirms they can view; organization owners and administrators see and may mutate every Silicon's hooks. Deleting, restoring, enabling, updating, rotating, and connecting the IAM hook require the Silicon itself, an owner, or an administrator.

### Idempotency

Create, restore, secret rotation, endpoint rotation, and the IAM hook connection require an `Idempotency-Key` of 8–255 visible ASCII characters. Repeating a key in the same operation scope with the same request returns the original result; reusing it with different content returns `409 idempotency_conflict`. Secret-bearing responses can be replayed for ten minutes; afterwards, rotate instead. Update and activation express a desired state and need no key.

### Errors

Errors use one stable envelope and include the request correlation ID:

```json
{
  "error": {
    "code": "invalid_signature",
    "message": "The request contains invalid data.",
    "request_id": "0198...",
    "details": "unknown function md5 at byte 0"
  }
}
```

Authentication failures return `401`, authorization failures and blocked addresses return `403`, invisible resources return `404`, request deadlines return `408`, conflicts return `409`, expired recovery, expired one-time-secret replay, and retired endpoints return `410`, oversized requests return `413`, unsupported request media return `415`, invalid input returns `422` (with `details` where a safe explanation exists), internal invariant failures return a redacted `500`, and dependency outages return `503`.

## Hook management

### `GET /silicons/{silicon_id}/hooks`

Lists a Silicon's hooks. Each item includes the hook `name`, its `endpoint_url`, and `last_received_at`, the time the provider last reached out with a verified request, plus `last_blocked_at` and the full signature policy without secret material. `include_deleted=true` adds hooks still inside their 45-day recovery window. A Silicon can retain at most 1,000 hooks including recoverable deleted ones.

### `POST /silicons/{silicon_id}/hooks`

Creates a hook.

- **Required header:** `Idempotency-Key`.
- **Input:** `name` (the provider name included in received events), optional `description`, optional IANA `time_zone` (default `UTC`), and an optional `signature` policy.
- **Returns:** `201` with the hook, its `endpoint_url`, its `endpoint_key`, and `signing_secret`.

Omitting `signature` produces the Standard Webhooks policy with a generated secret of the form `v1.` followed by 32 alphanumeric characters. Give that secret to the provider. When the provider issues its own secret, supply it in `signature.secret` and describe its scheme; the response echoes the supplied secret once. Asymmetric algorithms take `public_key` instead and return `signing_secret: null`.

### Bring your own secret (BYOS)

Use `signature.secret` on creation or PATCH an existing hook at any time. The
secret is stored verbatim and encrypted at rest; `secret_encoding` determines
how it becomes verification key bytes. Changing only the secret preserves the
URL, algorithm, payload, signature locator, and enabled/required settings.

```json
{"signature":{"secret":"your-provider-secret","secret_encoding":"utf8"}}
```

To configure the verification scheme in the same request, include the other
`signature` members. You can create first with a generated secret, then set the
provider's secret once registration completes. Verification uses the new secret
immediately; the old secret stops working. PATCH/read/list responses contain no
secret. The creation response returns the supplied or generated secret once.

Omitting `secret` keeps the current secret on PATCH and generates one on POST
for symmetric algorithms. Secrets must contain 1–4096 UTF-8 bytes without control
characters and decode to a nonempty key using the selected encoding. Invalid
secrets, incompatible encoding changes, or a secret supplied with an asymmetric
algorithm return `422`. Asymmetric algorithms use `public_key` instead.
Generated/rotated secrets respect the configured encoding: text encodings use
`v1.` plus 32 random alphanumerics; hex/base64/base64url encode those key bytes.

### `GET /silicons/{silicon_id}/hooks/{hook_id}`

Returns one hook. The signing secret is never returned after creation. An expired soft-deleted hook returns `404`.

### `PATCH /silicons/{silicon_id}/hooks/{hook_id}`

Changes any subset of `name`, `description` (`null` clears it), `time_zone`, `enabled`, and `signature`. Signature members merge onto the current policy, so a single member such as `{"signature": {"required": false}}` turns verification off while keeping the rest. `"public_key": null` clears the key. Supplying `secret` replaces the stored secret. Requiring signatures for a symmetric algorithm needs a stored or supplied secret; otherwise the request fails with `422 invalid_signature` and an explanation.

`enabled` alone uses the `hook.hooks.enabled.update` action; any other member uses `hook.hooks.update`. Requesting the current activation state is a successful no-op.

### `PATCH /silicons/{silicon_id}/hooks`

Enables or disables 1–1,000 unique hooks atomically. An unknown, deleted, cross-Silicon, or unauthorized member makes the whole request fail with no partial change.

### `DELETE /silicons/{silicon_id}/hooks/{hook_id}`

Soft-deletes a hook. Its endpoint stops accepting requests immediately. The hook, its secret, and its logs remain recoverable for 45 days; repeating the delete is a successful `204`.

### `POST /silicons/{silicon_id}/hooks/{hook_id}/restore`

Restores a deleted hook within its recovery window with the same endpoint and secret. Requires `Idempotency-Key`.

### `POST /silicons/{silicon_id}/hooks/{hook_id}/secret/rotate`

Issues a new generated secret and returns it once. The previous secret stops verifying immediately. Not applicable to asymmetric policies. Requires `Idempotency-Key`.

### `POST /silicons/{silicon_id}/hooks/{hook_id}/endpoint/rotate`

Replaces the endpoint key with a fresh eight-character key that has never been used for this Silicon, and permanently retires the previous key: it is never reissued for the Silicon, and requests to it receive `410 endpoint_retired` for as long as the Silicon exists. Returns the hook with its new `endpoint_url`. Requires `Idempotency-Key`.

## Signature policy

A policy has six parts:

| Member | Meaning | Default |
| --- | --- | --- |
| `required` | Withhold requests that do not verify | `true` |
| `algorithm` | `HMAC-SHA1`, `HMAC-SHA256`, `HMAC-SHA384`, `HMAC-SHA512`, `SHA1`, `SHA256`, `SHA384`, `SHA512`, `Ed25519`, `ECDSA-SHA256`, `RSA-SHA1`, `RSA-SHA256` | `HMAC-SHA256` |
| `payload` | Expression producing the bytes the provider signed | `concat(request.headers["webhook-id"], ".", request.headers["webhook-timestamp"], ".", request.raw_body)` |
| `signature` | Expression locating the presented signature | `request.headers["webhook-signature"]` |
| `signature_encoding` | `hex`, `base64`, `base64url`, or `raw` | `base64` |
| `secret_encoding` | How the stored secret text becomes key bytes: `utf8`, `ascii`, `hex`, `base64`, `base64url`, `raw` | `utf8` |

Plain `SHA*` algorithms digest the payload without a key, so the payload must include `secret` itself, for example `concat(secret, request.raw_body)`. Asymmetric algorithms verify with `public_key` (PEM `SubjectPublicKeyInfo`, PEM `RSA PUBLIC KEY`, or raw hex/base64 key bytes; RSA moduli must be at least 2048 bits) and hold no secret.

The presented signature value is split on whitespace and commas, and a short `label=` prefix is stripped from each token, so `sha256=<hex>`, `t=<ts>,v1=<hex>`, and `v1,<base64> v1,<base64>` all verify. Symmetric comparisons run in constant time.

With `signature_encoding: raw`, the expression instead supplies one exact byte
sequence. It is never decoded as text, trimmed, split or stripped of labels;
for example, `signature: request.raw_body_bytes` can read a binary signature.

### Signature expressions

Blocks:

```text
request.raw_body            body as UTF-8 text        request.raw_body_bytes   exact bytes
request.body.<json path>    parsed JSON member        request.form.<key>       form field
request.multipart.<key>     multipart part            request.method           uppercase token
request.url  request.scheme  request.authority  request.host  request.hostname  request.port  request.path
request.query_string        raw query                 request.query.<key>      decoded value
request.headers.<name>      case-insensitive          request.cookies.<key>    cookie value
hook.id  hook.url           receiving hook            secret                   decoded key bytes
key.public                  DER SubjectPublicKeyInfo
```

Functions: `concat(...)`, `join(separator: "" | "." | ":" | "," | ";" | "\n" | " ", ...)`, `sort(list, order: asc | desc)`, `sort_keys(object, order: asc | desc)`, `utf8`, `ascii`, `url_encode`, `url_decode`, `percent_encode`, `percent_decode`, `canonicalize_url`, `canonicalize_query`, `json_encode`, `form_encode`, `sha1`, `sha256`, `sha384`, `sha512`, `hex`, `hex_decode`, `base64`, `base64_decode`, `base64url`, `base64url_decode`, `lowercase`, `uppercase`, `trim`.

Bracket syntax addresses names with hyphens or JSON members: `request.headers["x-hub-signature-256"]`, `request.body.items[0].id`. A missing header evaluates to null and makes the payload unavailable, so a partial payload is never signed. Expressions are limited to 4 KiB, 32 nesting levels, and 512 nodes.

Examples:

```text
GitHub:  payload request.raw_body
         signature request.headers["x-hub-signature-256"]    hex
Stripe:  payload concat(request.headers["stripe-timestamp"], ".", request.raw_body)
         signature request.headers["stripe-signature"]       hex
Shopify: payload request.raw_body
         signature request.headers["x-shopify-hmac-sha256"]  base64
```

## Ingress

### `ANY https://hook.teamofsilicons.com/silicon/{silicon_id}/{endpoint_key}`

Receives a provider request. `POST` is the common case, but every method is captured because some providers verify endpoints with `GET`. The `/api/v2/silicon/...` and legacy `/api/v1/silicon/...` routes and an optional trailing slash are aliases.

Processing order:

1. Resolve the endpoint. Unknown, disabled, and deleted endpoints return `404`; a retired key returns `410 endpoint_retired`.
2. Check the client address against the hook's block list. A blocked address receives `403 ip_blocked` (with `Retry-After` for a temporary block) and nothing it sent is stored.
3. Capture the exact method, URL, headers (at most 128 fields, 64 KiB), and body (at most 1 MiB). Multipart bodies are parsed for expressions.
4. If the policy requires signatures, verify. A verified request and its Ting publication rows commit in one database transaction; it also retains a sequence for history and v1 compatibility. An unverified request goes to the blocked log and counts against the address, with no Ting publication.
5. Respond `200 {"status":"webhook.ok","receipt_id":"..."}`. The response is identical for verified and withheld requests so it cannot be used as a signature oracle.

Behind a load balancer the deployment sets `HOOK_TRUSTED_PROXY_HOPS` so the blocked address is the real sender rather than the balancer.

### Safety

Twenty unverified requests from one address to one endpoint block that address from the endpoint for one day. Counting restarts after each block. Blocks are per endpoint, so a misconfigured provider cannot lock a Silicon out of its other hooks.

## History

### `GET /silicons/{silicon_id}/events` and `GET /silicons/{silicon_id}/hooks/{hook_id}/events`

Return the last `n` verified requests (`limit` 1–10,000, default 100) newest first, account-wide or for one hook. Each record contains the stable `id`, `hook_id`, `provider`, the `delivery_sequence`, `received_at`, and the captured `request` with its method, URL, headers, `content_type`, `body` (text) or `body_base64`, and `remote_ip`. A 16 MiB page budget may shorten a page; follow `next_cursor`. Logs are kept for 14 days.

### `GET /silicons/{silicon_id}/blocked-requests` and `GET /silicons/{silicon_id}/hooks/{hook_id}/blocked-requests`

Return withheld requests in the same shape with a `reason_code` (for example `signature_mismatch`, `signature_missing`, `payload_unavailable`) and a short `reason_detail`. Kept for 14 days.

Cursors are authenticated and bound to the organization, Silicon, collection, and filter; a cursor from the events list is rejected on the blocked list.

## Ting delivery (v2)

Hook keeps the exact provider request and signature verification result. Ting carries a compact reference, so a provider body up to Hook's 1 MiB limit does not need to fit inside Ting's 256 KiB send limit. Every queued send persists its complete bytes and producer key. Background retries reuse both and obtain a fresh, request-bound IAM proof for every attempt, including retries after an uncertain response. A temporary IAM or Ting outage leaves committed events pending until their 14-day retention expires.

The event payload carried by Ting is:

```json
{
  "type": "new_event",
  "data": {
    "sender": "stripe",
    "metadata": {
      "id": "0198c21a-6330-7000-8000-000000000001",
      "org_id": "tos",
      "silicon_id": "si:cos",
      "hook_id": "0198c21a-6330-7000-8000-000000000002",
      "delivery_sequence": 42,
      "received_at": "2026-09-22T10:00:00Z",
      "summary": "stripe triggered at 10:00:00 22-09-2026 UTC",
      "environment_id": "00000000-0000-0000-0000-000000000000",
      "environment_generation": 0
    }
  }
}
```

The registered Ting type is `<Hook app_id>.webhook.received`; the outer Ting send names the organization, recipient and stable producer key. The payload above contains no captured provider body, headers or endpoint secret. Use `metadata.id` for deduplication. `delivery_sequence` records Hook receipt order; Ting can arrive out of order and does not advance the legacy cumulative ACK cursor.

`environment_generation` in this reference records the original event's generation. Runtime generation fences authorize current work separately. Key rotation or restore must not rewrite already prepared notification bytes; a clean deletes the canonical event and invalidates its reference. Current IAM authority is always required to hydrate it.

### `POST /delivery/publisher`

An organization owner or administrator acting as a **Carbon** provisions a dedicated Silicon session used exclusively by Hook's backend publisher. Require `Authorization`, `X-Org-ID`, `Idempotency-Key` and `Content-Type: application/json`.

```json
{"slt":"<new Hook application SLT for the publisher Silicon>","replace_rejected":false}
```

`slt` is required. `replace_rejected` is optional and defaults to `false`. Supply a fresh Hook application SLT for a Silicon authorized in the selected organization; do not supply a caller's access or refresh token. Hook encrypts and exclusively owns the resulting family, serializes refreshes, and persists mutation keys before IAM calls. Retry the same request with the same idempotency key when its outcome is uncertain. The response is `200` with only `org_id`, `actor_id` and access-token `expires_at`; tokens are never returned.

`replace_rejected: true` explicitly recovers a rejected bootstrap or publisher family. Hook durably revokes the old family, when present, before exchanging the replacement SLT; it does not replace a usable publisher on an arbitrary retry. State conflicts return `409 publisher_already_configured` or `409 publisher_busy`, invalid input returns `422 invalid_publisher_slt`, rejected authority returns `403`, and dependency failures return `503`. A missing publisher does not reject verified provider ingress: publication remains pending with `publisher_not_configured`.

### `POST /delivery/recipient`

Registers the authenticated actor's Ting grant to the configured Hook application. Require `Authorization` and `X-Org-ID`; send an **empty body**, not `{}`. A fresh IAM proof represents the caller. The `200` response contains `id`, `app_id`, `for`, `active` and `required_delivery`. Registration does not enable required delivery; that separate choice belongs to the recipient through its own Ting session. The caller cannot choose another recipient or a remote URL. Nonempty bodies return `400 unexpected_body`; authority failures return `401` or `403`, rate limits return `429` with `Retry-After`, and dependency failures return `503`.

### `GET`, `POST /delivery/receiver` (v2, testing only)

GET returns the selected actor's current `app_id`, `for`, `kind`, Ting organization
UUID `org_id`, Hook handle `hook_org_id`, and `environment: {kind, id, generation}`.
This is the shared Honeycomb generation, separate from Hook's credential and
original-event generations. The enclosing runtime pins this scope before POST.

POST requires `Idempotency-Key` and JSON containing `environment_id`, `generation`
and an optional existing `receiver_id` for renewal. Hook derives the represented
actor and app from current authorization and sends a fresh request-bound IAM
proof. An active recipient grant is required; bootstrap does not create one.
The `200` response contains the scope plus `receiver_id`, private `receiver_token`
and RFC3339 `expires_at`, with `Cache-Control: no-store`.

Keep the original scope, body and key for an uncertain retry. Exact replay retains
its original expiry, including an expired historical result. Renew with a new
operation key and the same receiver ID. Capabilities last at most 30 seconds and
only read/watch that app's scoped Ting inbox; they cannot send, ACK, enroll a
native destination or change preferences. The enclosing runtime keeps them
private, validates scope, renews/reconnects and revokes them through Ting. Clean
and lost authority invalidate them; a changed pinned generation returns
`409 receiver_environment_changed`. Production is rejected.

### `GET`, `POST`, `DELETE /silicons/{silicon_id}/delivery/subscription`

A Carbon with current permission to read that Silicon's events can inspect or enable their own receiving interest through v2. An authenticated Carbon can remove their own interest after losing target visibility. Require `Authorization` and `X-Org-ID`; POST and DELETE take no body and no recipient selector. POST first registers the Carbon's Ting grant, then records the interest for **future** verified events and encrypts the current access token; it does not backfill history. Silicon recipients already receive their own events and do not use this Carbon-only operation.

GET and POST return `200`:

```json
{
  "receiving": true,
  "subscription": {
    "id": "0198c21a-6330-7000-8000-000000000003",
    "org_id": "tos",
    "silicon_id": "si:cos",
    "recipient_id": "c:alice",
    "created_at": "2026-09-22T10:00:00Z"
  }
}
```

GET returns `{"receiving":false,"subscription":null}` when no interest exists. DELETE returns `204` with no body, including when already absent or no longer visible. POST retains the same binding ID while renewing its encrypted current access authority; DELETE is idempotent. A Silicon allows at most 100 Carbon observers; exceeding the limit returns `409 receiving_subscription_limit`. Non-Carbon callers receive `403`; GET and POST for invisible Silicons receive `404`. An expired caller token returns `401 unauthenticated`, so the runtime must refresh its own Hook session before retrying POST. Temporary IAM, Ting or encrypted-storage failures return `503 provider_unavailable` and leave the caller able to retry.

The enclosing runtime must repeat POST after every Hook token refresh and when resuming receiving. Publication rechecks the exact Carbon's current identity and Silicon visibility through IAM before sending event metadata to Ting. Missing/expired authority keeps queued copies pending with `observer_authority_refresh_required`; unavailable checks retry with `observer_authorization_unavailable`. Revoked target visibility removes the binding and its queued copies. These diagnostics are internal observer queue state; the event publication endpoint below describes only the primary Silicon send. Removing an interest cannot retract a notification already accepted by Ting. Hook retains no Carbon refresh credentials, returns no encrypted authority in subscription responses, and raw-event hydration still requires current IAM permission.

### `GET /silicons/{silicon_id}/events/{event_id}`

Hydrates one retained event using the caller's current IAM read authority. Returns `200` with the same full Event object used by history: `id`, `org_id`, `silicon_id`, `hook_id`, `provider`, `delivery_sequence`, `received_at`, `summary` and captured `request`. The summary identifies the provider and receipt time with an IANA timezone. The compact Ting reference is not a bearer credential.

When hydrating a reference, pass its `environment_id` and `environment_generation` as paired query parameters. Both may be omitted for ordinary authorized lookup; supplying only one, or a negative generation, returns `422 environment_id_and_generation_required_together`. The generation must match the original event, not the current runtime generation: retained events remain hydratable after key rotation or restore. Foreign, invisible, expired or cleaned events return `404`. Use the selected test environment's current credentials for test references; failed selection never falls back to production.

### `GET /silicons/{silicon_id}/events/{event_id}/publication`

Returns the event's publication status for its **primary Silicon recipient** after current read authorization. There is no recipient selector. The response fields are `event_id`, `recipient_id`, `state`, `attempts`, `ting_id`, `last_error_code`, `accepted_at`, `next_attempt_at`, `expires_at`, `delivery`, `silent`, `recipient_receipt` and `recipient_status_error`. `delivery` is `ordinary` or `required`; `silent` is null before verified acceptance and otherwise records notification visibility.

| State | Meaning |
| --- | --- |
| `pending` | No verified Ting acceptance yet; inspect the bounded `last_error_code`. |
| `accepted_by_ting` | Ting confirmed durable acceptance; recipient processing is not established. |
| `accepted_silently` | Ting accepted an ordinary event under a silent preference, without automatic delivery. |

New primary Silicon sends use `required` policy; without separate recipient opt-in, they remain pending with `required_delivery_not_enabled`. Required muted acceptance is `accepted_by_ting` with `silent: true`, and remains eligible for automatic delivery. Carbon copies and existing queued sends retain ordinary policy. Retries never change the persisted body or key.

If available, `recipient_receipt` contains `id`, `read`, `silent`, `delivery`, `deliveries` and `more_destinations`. Each destination has `webhook_id`, `delivery_acked` (Ting's daemon durably received it) and `read_acked` (the local destination accepted it). `read` can also indicate a Carbon viewed the notification. This is the first destination page; `more_destinations: true` means the list is incomplete. These ACKs do not mean the recipient completed its work.

Receipt lookup is best effort. `recipient_receipt` is null before acceptance or when the live lookup fails; `recipient_status_error` is null, `publisher_unavailable` or `recipient_status_unavailable`. A successful status request can still return `200` with one of those diagnostics and the durable Hook publication state.

### Retired v2 transport operations

Every method on `/api/v2/ws`, `/api/v2/relay/ws`, `/api/v2/silicons/{silicon_id}/deliveries`, and its `/pull`, `/ack` and `/cursor` subpaths returns `410 delivery_transport_replaced`. There is no v2 Hook WebSocket, polling delivery queue or cumulative delivery ACK. History reads remain available.

## Legacy delivery (deprecated v1)

The following operations and wire shapes apply only to `/api/v1`, while its contract remains nonsunset. They describe the compatibility transport; v2 uses Ting as documented above.

Every verified request is one position in its Silicon's ordered delivery stream. Each consumer (the authenticated actor) has an acknowledged cursor per Silicon, so a Silicon's own acknowledgments and a Carbon viewer's are independent.

### `GET /api/v1/ws?silicon_id=...`

WebSocket delivery. Authenticate the upgrade request like a management call (`Authorization` plus `X-Org-ID`) and repeat `silicon_id` for every stream. Frames are JSON text.

Server frames:

```json
{"type":"ready","protocol_version":1,"connection_id":"...","silicon_ids":["si:cos"],
 "acknowledged_through":{"si:cos":41},"heartbeat_interval_seconds":30,"heartbeat_timeout_seconds":120}
{"type":"ping","ping_id":"..."}
{"type":"new_event","data":{"sender":"stripe","metadata":{...Event...}}}
{"type":"ack_recorded","silicon_id":"si:cos","acknowledged_through":42}
{"type":"error","code":"invalid_frame","message":"...","recoverable":true}
```

Client frames:

```json
{"type":"pong","ping_id":"..."}
{"type":"ack","silicon_id":"si:cos","through_sequence":42}
{"type":"resume","silicon_id":"si:cos","after_sequence":40}
```

Hook event deliveries contain exactly `type` and `data` at the top level.
`data.sender` is the provider name recorded at receipt; `data.metadata` is the
complete Event object, including `silicon_id`, `delivery_sequence`,
receive timestamp and the captured request. The same shape is used by the
client/CLI recipient POST and for replayed events. Read ACK positions from
`data.metadata.delivery_sequence`. Heartbeat, ready, ACK and error control
frames retain their documented shapes; REST history and polling continue to
return Event objects in `items`.

After `ready` the server sends every event after the acknowledged cursor, then live events as they arrive. The server sends `ping` every 30 seconds; the client answers with a `pong` carrying the same `ping_id`. If no valid pong arrives for two minutes the server closes with code `4000` and reason `heartbeat-timeout`. Pings and pongs are never stored, never acknowledged, and never consume sequences. `resume` replays from a client-held position without changing the cursor.

### `GET /api/v1/silicons/{silicon_id}/deliveries`

Polling alternative. Without `after_sequence` it returns the unacknowledged backlog, oldest first, with the consumer's `cursor` and the Silicon's `latest_sequence`.

### `POST /api/v1/silicons/{silicon_id}/deliveries/ack`

Acknowledges everything through `through_sequence`. Cursors never move backwards.
The value must be between zero and the stream's latest allocated sequence;
acknowledging a future event returns 422 without changing the cursor. The same
validation applies to WebSocket ACKs, which return a recoverable `invalid_ack`.

### `GET /api/v1/silicons/{silicon_id}/deliveries/cursor`

Reads the consumer's acknowledged position.

## Sign-in

Both Carbons and Silicons sign in with a short-lived token issued by IAM for
`hook`. Tokens are opaque. Do not infer their validity from a prefix.
There is no password, OTP, redirect or callback endpoint in Hook.

### `POST /auth/login`

JSON `{"slt":"<short-lived IAM token>"}` with `Idempotency-Key`. Returns
`access_token`, `refresh_token`, `token_type`, `expires_in`, `scopes`, `actor`
and `org_id`. IAM consumes the SLT; retry with the same idempotency key after an
uncertain result. Login starts no receiver; the enclosing application handles
internal Ting receiving separately.

### `POST /auth/refresh`

JSON `{"refresh_token":"<refresh token>"}` with `Idempotency-Key`. Returns a new
token pair. Save both atomically. Reuse the same mutation key when retrying an
uncertain refresh. Never refresh the same family concurrently from two stores.

### `POST /auth/logout`

Empty body and `Idempotency-Key`. Supply the refresh token as the bearer to
revoke the entire refresh-token family, as the CLI does. Supplying an access
token revokes that token according to IAM's revocation contract. Returns 204.

All these operations accept `X-Hook-Test-Key` to select the matching IAM test
world. A production SLT cannot authenticate a test session.

## Silicon IAM

### `POST /silicons/{silicon_id}/hooks/iam`

IAM must authorize the caller to configure the Silicon’s webhook; see [IAM authority](../iam/README.md#per-silicon-authority). The implemented orchestration connects IAM events to the Silicon. Hook finds or creates the Silicon's `Silicon IAM` hook (restoring a deleted one; there is exactly one per Silicon), registers the hook's endpoint URL as the Silicon's IAM webhook using the caller's own bearer, and stores the signing secret IAM issues. The hook's policy is IAM's own convention: HMAC-SHA-256 over `X-Silicon-IAM-Timestamp.body`, keyed with the secret's UTF-8 bytes and presented as `v1=<hex>` in `X-Silicon-IAM-Signature`. Returns the hook plus `iam_webhook.secret_version`. Requires `Idempotency-Key`; a retry with the same key reconciles a partial failure. IAM's own refusals surface as `403`, `404`, or `409 iam_rejected`.

### `POST /webhook/` (origin-relative; legacy alias `/api/v1/iam/events`)

Receives Hook's own Application webhook from IAM. Deliveries are verified with the crate's exact-byte verifier over the configured `whs_` keyring before anything is read; unverifiable deliveries receive `403`, verified ones `204`. See the [IAM integration guide](../iam/README.md).

## Complete flows

### Provider event

```text
Provider POSTs to the endpoint URL
  -> Hook routes the key and checks the address
  -> Hook captures the exact request and verifies the signature policy
  -> verified: event and Ting outbox commit together in the 14-day retained log
     withheld: appended to the blocked log and counted against the address
  -> Hook answers 200 webhook.ok
  -> publisher obtains a fresh IAM proof and sends the compact reference to Ting
  -> uncertain acceptance retries the same bytes/key with a new proof
  -> Ting delivers according to recipient preferences and records separate receipt ACKs
  -> recipient hydrates the original event through Hook using current IAM authority
```

### New Silicon

```text
Silicon authenticates with IAM and calls POST /silicons/{silicon_id}/hooks/iam
  -> Hook creates the Silicon IAM hook with IAM's signing convention
  -> Hook registers the endpoint as the Silicon's IAM webhook with the Silicon's bearer
  -> IAM issues the signing secret; Hook stores it as the hook's signing secret
  -> IAM signs every Silicon event to that endpoint; verified events enter the Ting outbox
```

## Deliberately deferred operations

- No public operation to create a fresh Ting send for an individual historical event; v1 retains its legacy `resume` behavior.
- No timestamp-tolerance option in signature policies; a signed timestamp is authenticated but is not checked for freshness by Hook. Providers requiring replay prevention should deduplicate by provider event ID and enforce timestamp freshness at the recipient.
- No public permanent-purge operation; the worker purges deleted hooks after 45 days and logs after 14 days.
- No unblock operation for addresses; temporary blocks expire after one day and inactive blocks are forgotten after 30 days.

## Testing environments

Use `X-Hook-Test-App-Secret` for app-selected environments, or the legacy `X-Hook-Test-Key: <32-alphanumeric-root-key>`, on ordinary versioned calls. These selectors are mutually exclusive.
The same bearer authorization, permissions and request shapes then apply
inside that environment. See the [complete testing API guide](../testing/api.md)
for legacy configuration. Honeycomb now coordinates shared environment lifecycle; see [the participant contract](../testing/honeycomb.md).
Public test ingress uses `/test/silicon/{silicon_id}/{endpoint_key}` and carries
no test key. Its endpoint ledger determines the environment.

## Legacy v1 WebSocket flow control

At most 32 events per subscribed Silicon are outstanding on a connection.
Acknowledging an event releases capacity for the next retained event. Read
frames continuously even when processing a slow recipient. Use independent
streams when different Silicons need independent processing budgets. A
consumer that reads without ACK eventually reaches the window limit; HTTP
history remains available for inspection without acknowledging delivery.

Environment reset, root-key rotation, deletion or IAM reconfiguration changes
the environment generation. Existing sessions close with `4001
environment-changed`; reconnect using the current key/configuration. Live IAM
authorization is rechecked every 30 seconds and after verified IAM webhook
notifications, which fan out to replicas over PostgreSQL.
Loss of authority closes with `4003 authorization-changed`.

## Login discovery and status

`GET /api/v2/auth/iam` (also available in v1) needs no bearer. It returns `app_id`, `iam_url`,
`testing`, and `login_method: "short_lived_token"`; `app_id` is null when only
local development auth is configured. It never exposes secrets. Attach
`x-hook-test-key` for the test application's configuration; an invalid or
unconfigured environment cannot fall back to the production application.

`GET /api/v2/auth/status` (also available in v1) requires a bearer and `x-org-id`, plus the test selector
in a test environment. Hook checks the actor and current membership online
through the official IAM client. Success returns `authenticated: true`,
`actor: {"type": "carbon" | "silicon", "id": "..."}`, and `org_id`.
Invalid/revoked credentials return 401; permission and provider failures retain
their normal error responses. Both discovery and status use `Cache-Control: no-store`.

For the legacy v1 transport, local relay destinations are configured after SLT exchange through the client
or CLI and never appear in the backend login request. `webhook` and `unhook`
change local delivery configuration; neither changes a provider hook URL.
