# Silicon Hook API documentation

This document explains every operation in the Silicon Hook OpenAPI contract. The machine-readable contract is in [`openapi.yaml`](./openapi.yaml). The product behavior it implements is [`UNDERSTANDING.md`](./UNDERSTANDING.md).

## API conventions

### Base URL

Management, history, and delivery operations use:

```text
https://hook.teamofsilicons.com/api/v1
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
Silicon-Hook-Supported-API-Versions: v1
```

Hook answers with the highest major both sides support, in the body (`service`, `selected_api_version`, `supported_api_versions`, `build`, `commit`) and in `Silicon-Hook-API-Version`, and varies the response on the advertised list. With no shared major it answers `406 api_version_unsupported`. A client then pins the major on every request with `Silicon-Hook-API-Version: v1`; a pin that disagrees with the route is refused with `400 api_version_mismatch`. The official Rust client, `silicon-hook-client`, performs this handshake on connect.

### Authentication

- **Bearer authentication:** the only credential. A Silicon presents the access token Silicon IAM issued it; a Carbon presents the Hook Application token obtained through [sign-in](#sign-in) or an IAM access token of their own. Hook exposes no OBO endpoints.
- **Provider ingress:** Endpoint URLs are publicly reachable; each hook's signature policy decides what is delivered.
- **IAM ingress:** `POST /iam/events` is authenticated by IAM's webhook signature, not a bearer.
- **Organization context:** Management requests require `X-Org-ID`.

Hook verifies every bearer online with Silicon IAM through the official `silicon-iam` crate and IAM's organization directory, and fails closed if IAM cannot make a current decision. Every management response, including errors, carries `Cache-Control: private, no-store`.

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
- **Input:** `name` (the provider name used in every summary), optional `description`, optional IANA `time_zone` (default `UTC`), and an optional `signature` policy.
- **Returns:** `201` with the hook, its `endpoint_url`, its `endpoint_key`, and `signing_secret`.

Omitting `signature` produces the Standard Webhooks policy with a generated secret of the form `v1.` followed by 32 alphanumeric characters. Give that secret to the provider. When the provider issues its own secret, supply it in `signature.secret` and describe its scheme; the response echoes the supplied secret once. Asymmetric algorithms take `public_key` instead and return `signing_secret: null`.

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

Plain `SHA*` algorithms digest the payload without a key, so the payload must include `secret` itself, for example `sha256(concat(secret, request.raw_body))`. Asymmetric algorithms verify with `public_key` (PEM `SubjectPublicKeyInfo`, PEM `RSA PUBLIC KEY`, or raw hex/base64 key bytes; RSA moduli must be at least 2048 bits) and hold no secret.

The presented signature value is split on whitespace and commas, and a short `label=` prefix is stripped from each token, so `sha256=<hex>`, `t=<ts>,v1=<hex>`, and `v1,<base64> v1,<base64>` all verify. Symmetric comparisons run in constant time.

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

Receives a provider request. `POST` is the common case, but every method is captured because some providers verify endpoints with `GET`. The `/api/v1/silicon/...` route and an optional trailing slash are aliases.

Processing order:

1. Resolve the endpoint. Unknown, disabled, and deleted endpoints return `404`; a retired key returns `410 endpoint_retired`.
2. Check the client address against the hook's block list. A blocked address receives `403 ip_blocked` (with `Retry-After` for a temporary block) and nothing it sent is stored.
3. Capture the exact method, URL, headers (at most 128 fields, 64 KiB), and body (at most 1 MiB). Multipart bodies are parsed for expressions.
4. If the policy requires signatures, verify. A verified request joins the log and the Silicon's delivery stream; an unverified request goes to the blocked log and counts against the address.
5. Respond `200 {"status":"webhook.ok","receipt_id":"..."}`. The response is identical for verified and withheld requests so it cannot be used as a signature oracle.

Behind a load balancer the deployment sets `HOOK_TRUSTED_PROXY_HOPS` so the blocked address is the real sender rather than the balancer.

### Safety

Twenty unverified requests from one address to one endpoint block that address from the endpoint for one day. Counting restarts after each block. Blocks are per endpoint, so a misconfigured provider cannot lock a Silicon out of its other hooks.

## History

### `GET /silicons/{silicon_id}/events` and `GET /silicons/{silicon_id}/hooks/{hook_id}/events`

Return the last `n` verified requests (`limit` 1–10,000, default 100) newest first, account-wide or for one hook. Each record contains the stable `id`, `hook_id`, `provider`, the `summary` line, the `delivery_sequence`, `received_at`, and the captured `request` with its method, URL, headers, `content_type`, `body` (text) or `body_base64`, and `remote_ip`. A 16 MiB page budget may shorten a page; follow `next_cursor`. Logs are kept for 14 days.

### `GET /silicons/{silicon_id}/blocked-requests` and `GET /silicons/{silicon_id}/hooks/{hook_id}/blocked-requests`

Return withheld requests in the same shape with a `reason_code` (for example `signature_mismatch`, `signature_missing`, `payload_unavailable`) and a short `reason_detail`. Kept for 14 days.

Cursors are authenticated and bound to the organization, Silicon, collection, and filter; a cursor from the events list is rejected on the blocked list.

## Deliveries

Every verified request is one position in its Silicon's ordered delivery stream. Each consumer (the authenticated actor) has an acknowledged cursor per Silicon, so a Silicon's own acknowledgments and a Carbon viewer's are independent.

### `GET /api/v1/ws?silicon_id=...`

WebSocket delivery. Authenticate the upgrade request like a management call (`Authorization` plus `X-Org-ID`) and repeat `silicon_id` for every stream. Frames are JSON text.

Server frames:

```json
{"type":"ready","protocol_version":1,"connection_id":"...","silicon_ids":["cos:tos"],
 "acknowledged_through":{"cos:tos":41},"heartbeat_interval_seconds":30,"heartbeat_timeout_seconds":120}
{"type":"ping","ping_id":"..."}
{"type":"event","silicon_id":"cos:tos","delivery_sequence":42,"event":{...Event...}}
{"type":"ack_recorded","silicon_id":"cos:tos","acknowledged_through":42}
{"type":"error","code":"invalid_frame","message":"...","recoverable":true}
```

Client frames:

```json
{"type":"pong","ping_id":"..."}
{"type":"ack","silicon_id":"cos:tos","through_sequence":42}
{"type":"resume","silicon_id":"cos:tos","after_sequence":40}
```

After `ready` the server sends every event after the acknowledged cursor, then live events as they arrive. The server sends `ping` every 30 seconds; the client answers with a `pong` carrying the same `ping_id`. If no valid pong arrives for two minutes the server closes with code `4000` and reason `heartbeat-timeout`. Pings and pongs are never stored, never acknowledged, and never consume sequences. `resume` replays from a client-held position without changing the cursor.

### `GET /silicons/{silicon_id}/deliveries`

Polling alternative. Without `after_sequence` it returns the unacknowledged backlog, oldest first, with the consumer's `cursor` and the Silicon's `latest_sequence`.

### `POST /silicons/{silicon_id}/deliveries/ack`

Acknowledges everything through `through_sequence`. Cursors never move backwards.

### `GET /silicons/{silicon_id}/deliveries/cursor`

Reads the consumer's acknowledged position.

## Sign-in

Carbons sign in through Silicon IAM's authorization-code flow with PKCE, which Hook runs with the official `silicon-iam` crate. These routes need no bearer.

### `POST /auth/login`

Optional body `{"org_id": "..."}`. Returns `authorization_url`, where the browser must be sent, and `continuation`, an encrypted, Hook-bound value that expires in ten minutes. Persist the continuation before redirecting.

### `POST /auth/callback`

Body `{"continuation": "...", "callback_url": "..."}` where `callback_url` is the exact URL the browser returned to, query string included. Returns `access_token`, `refresh_token`, `token_type`, `expires_in`, `scopes`, `actor`, and `org_id`. A denial returns `403 login_denied` with the OAuth error code in `details`.

### `POST /auth/refresh`

Body `{"refresh_token": "..."}`. Returns a new token pair; the old refresh token is consumed. Never refresh the same token family concurrently.

### `POST /auth/logout`

Bearer Hook Application token. Ends the IAM session behind it and returns `204`.

## Silicon IAM

### `POST /silicons/{silicon_id}/hooks/iam`

Connects IAM events to the Silicon. Hook finds or creates the Silicon's `Silicon IAM` hook (restoring a deleted one; there is exactly one per Silicon), registers the hook's endpoint URL as the Silicon's IAM webhook using the caller's own bearer, and stores the `swhs_` secret IAM issues. The hook's policy is IAM's own convention: HMAC-SHA-256 over `X-Silicon-IAM-Timestamp.body`, keyed with the secret's UTF-8 bytes and presented as `v1=<hex>` in `X-Silicon-IAM-Signature`. Returns the hook plus `iam_webhook.secret_version`. Requires `Idempotency-Key`; a retry with the same key reconciles a partial failure. IAM's own refusals surface as `403`, `404`, or `409 iam_rejected`.

### `POST /iam/events`

Receives Hook's own Application webhook from IAM. Deliveries are verified with the crate's exact-byte verifier over the configured `whs_` keyring before anything is read; unverifiable deliveries receive `403`, verified ones `204`. See [`IAM_INTEGRATION.md`](./IAM_INTEGRATION.md).

## Complete flows

### Provider event

```text
Provider POSTs to the endpoint URL
  -> Hook routes the key and checks the address
  -> Hook captures the exact request and verifies the signature policy
  -> Hook answers 200 webhook.ok
  -> verified: appended to the 14-day log and the Silicon's delivery stream
     withheld: appended to the blocked log and counted against the address
  -> connected sessions receive {"type":"event",...} and acknowledge
  -> unacknowledged events replay on the next connection
```

### New Silicon

```text
Silicon authenticates with IAM and calls POST /silicons/{silicon_id}/hooks/iam
  -> Hook creates the Silicon IAM hook with IAM's signing convention
  -> Hook registers the endpoint as the Silicon's IAM webhook with the Silicon's bearer
  -> IAM issues the swhs_ secret; Hook stores it as the hook's signing secret
  -> IAM signs every Silicon event to that endpoint; verified events flow to the stream
```

## Deliberately deferred operations

- No event-detail endpoint by event ID.
- No explicit replay of an individual event beyond `resume`.
- No timestamp-tolerance option in signature policies; providers that need one are covered by their signed timestamp header and Hook's 14-day log.
- No public permanent-purge operation; the worker purges deleted hooks after 45 days and logs after 14 days.
- No unblock operation for addresses; temporary blocks expire after one day and inactive blocks are forgotten after 30 days.
