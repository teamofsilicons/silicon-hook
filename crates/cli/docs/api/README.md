# Silicon Hook API documentation

This document explains the Silicon Hook API contract (v3). The machine-readable
contract is [`openapi.yaml`](../../openapi.yaml).

## API conventions

### Base URL

Management, history and delivery operations use:

```text
https://api.hook.teamofsilicons.com/api/v3
```

Each hook a Silicon creates has a public endpoint:

```text
https://api.hook.teamofsilicons.com/silicon/{silicon}/{endpoint_key}
```

`{silicon}` is the Silicon's current id (`si:scout`) or its Silicon Accounts
uuid. The endpoint key is eight uppercase letters and digits, unique across Hook;
it routes the request and is never a credential: the hook's signature policy
decides what is accepted. A URL a provider already holds keeps working after the
Silicon changes its id: the uuid, the current id and every earlier id route to
the same hook, and the key decides which one.

### API version

Before anything else a client sends the unversioned handshake:

```http
GET /api/version
Silicon-Hook-Supported-API-Versions: v3
```

Hook answers with the highest shared major in the body (`service`,
`selected_api_version`, `supported_api_versions`, `build`, `commit`) and in
`Silicon-Hook-API-Version`. With no shared major it answers
`406 api_version_unsupported`. A client pins every versioned call with
`Silicon-Hook-API-Version: v3`; a pin that disagrees with the route is refused with
`400 api_version_mismatch`. API v1 and v2 are retired: every `/api/v1/...` and
`/api/v2/...` management route answers `410 api_version_sunset`. Provider ingress
under `/api/v1/silicon/...` and `/api/v2/silicon/...` keeps working.
[Contracts](../contracts.md) describes the lifecycle policy.

Unprefixed paths below are relative to `/api/v3`.

### Authentication

- **Bearer.** Every management, history and delivery route takes
  `Authorization: Bearer <access token>`: a Silicon Accounts access token issued
  to Hook (an EdDSA JWT, audience `hook`, issuer the Silicon Accounts URL Hook
  trusts). [Sign in to Hook](../accounts/README.md) shows how Carbons and
  Silicons get one. Hook verifies it locally against Silicon Accounts' key set and
  refuses tokens issued before a sign-out Hook was told about. Routes that reveal
  a secret or change who has access also ask Silicon Accounts whether the token
  is still active.
- **Discovery.** `GET /auth/accounts` is public and returns Hook's `app_id`, the
  Silicon Accounts URL, the token's audience, issuer and key set URL, how to sign
  in, and whether delivery through Ting is on. `GET /auth/status` returns who the
  token belongs to: `{authenticated, app_id, uuid, id, kind}`.
- **Provider ingress** is public; each hook's signature policy decides what is
  accepted.
- **Hook's Silicon Accounts webhook** (`POST /webhook`, origin-relative) is
  authenticated by the Silicon Accounts signature.

Token refusals are `401` with a precise code: `token_expired`,
`token_wrong_audience`, `token_wrong_issuer`, `token_bad_signature`,
`token_malformed`, `token_unknown_key` and the other `token_*` codes of Silicon
Accounts' verifier, `session_ended` (signed out, or Hook's access removed) and
`account_deleted`. Every management
response carries `Cache-Control: private, no-store`. Hook exposes no endpoints for
other apps to act on someone's behalf.

### Who can do what

Hooks belong to a Silicon, keyed by its uuid.

| Caller | Can |
| --- | --- |
| The Silicon | everything with its hooks |
| Its custodian (the Carbon who looks after it) | everything, recorded as the custodian, never as the Silicon |
| An account granted `manage` | read; create, update, enable/disable, delete/restore, rotate, set secrets |
| An account granted `view` | read hooks, history, blocked requests and delivery status; subscribe to copies (Carbons) |
| Anyone else, including the Silicon's siblings | nothing (`403`) |

Granting, revoking and the allow-list belong to the Silicon and its custodian; a
grantee can leave. "Connect Silicon Accounts updates" belongs to the Silicon and
its custodian, because only they can set its Silicon Accounts webhook.

### Idempotency

Create, restore, secret rotation, endpoint rotation and the Silicon Accounts
updates hook require an `Idempotency-Key` of 8 to 255 visible ASCII characters.
Repeating a key with the same request returns the original result; reusing it
with different content returns `409 idempotency_conflict`. Secret-bearing answers
can be replayed for ten minutes; afterwards, rotate instead. Update and
activation express a desired state and need no key.

### Errors

Errors use one envelope with the request correlation id:

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

Authentication failures return `401`, authorization failures and blocked
addresses `403`, invisible resources `404`, request deadlines `408`, conflicts
`409` (including `delivery_disabled`), retired versions, expired recovery and
retired endpoints `410`, oversized requests `413`, unsupported media `415`,
invalid input `422` (with `details` where a safe explanation exists), redacted
internal failures `500`, and dependency outages `503` (`accounts_unavailable` when
Silicon Accounts did not answer a check the request needs, `proof_unavailable`
for a proof for Ting, `provider_unavailable` for the database).

## Silicons and access

### `GET /silicons`

The Silicons the caller can open: itself (a Silicon), the Silicons it looks after
(a custodian) and the ones granted to it. Each item has `silicon: {uuid, id}`,
`access` (`self`, `custodian`, `manage`, `view`) and the custodian's uuid.

### `GET /silicons/{silicon}/access`

Who has access: `silicon`, `you: {account, access}`, `custodian` and `grants`
(`account`, `level`, `granted_by`, `created_at`, `updated_at`).

### `PUT /silicons/{silicon}/access/{account}`

Grants `{"level": "view" | "manage"}` to a Carbon or Silicon named by its `c:` or
`si:` id or uuid (resolved with Silicon Accounts, stored by uuid, shown by current
id), or changes its level. Refusals: `account_not_found`, `already_has_access`
(the Silicon itself or its custodian), `silicon_not_reachable` (a Silicon looked
after by a different custodian that has not allowed the granting side).

### `DELETE /silicons/{silicon}/access/{account}`

Revokes a grant. `{account}` = `me` removes the caller's own grant.

### `GET`, `PUT`, `DELETE /silicons/{silicon}/allow-list[/{account}]`

The accounts a Silicon accepts grants from although their custodian is not its
custodian. Allowing a Carbon also covers the Silicons it looks after. Removing an
account stops new grants from it; grants that exist stay until revoked.

### `POST /silicons/{silicon}/hooks/accounts`

Creates (or restores) the hook that receives the Silicon's own Silicon Accounts
events, with the Silicon Accounts signature policy
(`concat(request.headers["x-accounts-timestamp"], ".", request.raw_body)`,
signature `request.headers["x-accounts-signature"]`, HMAC-SHA256, hex). The answer
is `{hook, next_steps}`: `set_webhook` is the exact `silicon-accounts` command for
the caller (`silicon-accounts webhook set <url>` for the Silicon,
`silicon-accounts silicon webhook set <si:id> <url>` for its custodian), and
`store_secret` says how to store the `whsec_` secret that command prints
(`PATCH /silicons/{silicon}/hooks/{hook_id}` with `{"signature": {"secret": ...}}`).
Until it is stored, deliveries are withheld as unverified. Requires
`Idempotency-Key`.

## Hook management

### `GET /silicons/{silicon}/hooks`

Lists a Silicon's hooks. Each item has `id`, `silicon: {uuid, id}`, `name`,
`endpoint_url`, `endpoint_key`, `status`, the signature policy without secret
material, `created_by: {uuid, kind, id}`, `last_received_at` (the last verified
request), `last_blocked_at` and lifecycle timestamps. `include_deleted=true` adds
hooks inside their 45-day recovery window. A Silicon can keep at most 1,000 hooks
including recoverable deleted ones.

### `POST /silicons/{silicon}/hooks`

Creates a hook.

- **Required header:** `Idempotency-Key`.
- **Input:** `name` (the provider name in received events), optional
  `description`, optional IANA `time_zone` (default `UTC`), optional `signature`.
- **Returns:** `201` with the hook and `signing_secret` (once).

Omitting `signature` produces the Standard Webhooks policy with a generated
secret (`v1.` followed by 32 letters and digits). Give that secret to the
provider. When the provider issues its own secret, supply it in
`signature.secret` and describe its scheme. Asymmetric algorithms take
`public_key` instead and return `signing_secret: null`.

### Bring your own secret (BYOS)

Use `signature.secret` on creation, or PATCH an existing hook at any time. The
secret is stored verbatim and encrypted at rest; `secret_encoding` decides how it
becomes key bytes. Changing only the secret keeps the URL, algorithm, payload,
signature locator and enabled/required settings.

```json
{"signature": {"secret": "your-provider-secret", "secret_encoding": "utf8"}}
```

Verification uses the new secret immediately; the old one stops working. PATCH,
read and list answers contain no secret. Omitting `secret` keeps the current
secret on PATCH and generates one on POST for symmetric algorithms. Secrets hold
1 to 4096 UTF-8 bytes without control characters and must decode to a non-empty
key in the selected encoding; otherwise `422`.

### `GET /silicons/{silicon}/hooks/{hook_id}`

Returns one hook. The signing secret is never returned after creation.

### `PATCH /silicons/{silicon}/hooks/{hook_id}`

Changes any subset of `name`, `description` (`null` clears it), `time_zone`,
`enabled` and `signature`. Signature members merge onto the current policy, so
`{"signature": {"required": false}}` turns verification off and keeps the rest.
`"public_key": null` clears the key; `secret` replaces the stored secret.
Requiring signatures for a symmetric algorithm needs a stored or supplied secret.

### `PATCH /silicons/{silicon}/hooks`

Enables or disables 1 to 1,000 unique hooks atomically
(`{"hook_ids": [...], "enabled": false}`). An unknown, deleted, foreign or
unauthorized member fails the whole request with no partial change.

### `DELETE /silicons/{silicon}/hooks/{hook_id}`

Soft-deletes a hook. Its endpoint stops accepting requests at once; the hook, its
secret and its logs stay recoverable for 45 days. Repeating the delete is `204`.
When a Silicon's account is deleted in Silicon Accounts, all its hooks are deleted
at once and their endpoints answer `410 account_deleted`.

### `POST /silicons/{silicon}/hooks/{hook_id}/restore`

Restores a deleted hook within its recovery window with the same endpoint and
secret. Requires `Idempotency-Key`.

### `POST /silicons/{silicon}/hooks/{hook_id}/secret/rotate`

Issues a new generated secret and returns it once; the previous one stops
verifying at once. Not for asymmetric policies. Requires `Idempotency-Key`.

### `POST /silicons/{silicon}/hooks/{hook_id}/endpoint/rotate`

Replaces the endpoint key with a fresh key never used before, and retires the
previous one for good: requests to it answer `410 endpoint_retired`. Returns the
hook with its new `endpoint_url`. Requires `Idempotency-Key`.

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

Plain `SHA*` algorithms digest the payload without a key, so the payload must
include `secret` itself, for example `concat(secret, request.raw_body)`.
Asymmetric algorithms verify with `public_key` (PEM `SubjectPublicKeyInfo`, PEM
`RSA PUBLIC KEY`, or raw hex/base64 key bytes; RSA moduli of at least 2048 bits)
and hold no secret.

The presented signature value is split on whitespace and commas, and a short
`label=` prefix is stripped from each token, so `sha256=<hex>`, `t=<ts>,v1=<hex>`
and `v1,<base64> v1,<base64>` all verify. Symmetric comparisons run in constant
time. With `signature_encoding: raw`, the expression supplies one exact byte
sequence that is never decoded, trimmed, split or stripped; for example
`signature: request.raw_body_bytes` reads a binary signature.

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

Functions: `concat(...)`, `join(separator: "" | "." | ":" | "," | ";" | "\n" | " ", ...)`,
`sort(list, order: asc | desc)`, `sort_keys(object, order: asc | desc)`, `utf8`,
`ascii`, `url_encode`, `url_decode`, `percent_encode`, `percent_decode`,
`canonicalize_url`, `canonicalize_query`, `json_encode`, `form_encode`, `sha1`,
`sha256`, `sha384`, `sha512`, `hex`, `hex_decode`, `base64`, `base64_decode`,
`base64url`, `base64url_decode`, `lowercase`, `uppercase`, `trim`.

Bracket syntax addresses names with hyphens or JSON members:
`request.headers["x-hub-signature-256"]`, `request.body.items[0].id`. A missing
header evaluates to null and makes the payload unavailable, so a partial payload
is never signed. Expressions are limited to 4 KiB, 32 nesting levels and 512
nodes.

Examples:

```text
GitHub:           payload request.raw_body
                  signature request.headers["x-hub-signature-256"]    hex
Stripe:           payload concat(request.headers["stripe-timestamp"], ".", request.raw_body)
                  signature request.headers["stripe-signature"]       hex
Shopify:          payload request.raw_body
                  signature request.headers["x-shopify-hmac-sha256"]  base64
Silicon Accounts: payload concat(request.headers["x-accounts-timestamp"], ".", request.raw_body)
                  signature request.headers["x-accounts-signature"]   hex (secret: the whsec_ text, utf8)
```

## Ingress

### `ANY https://api.hook.teamofsilicons.com/silicon/{silicon}/{endpoint_key}`

Receives a provider request. `POST` is the common case, but every method is
captured because some providers verify endpoints with `GET`. An optional trailing
slash and the `/api/v1/silicon/...` and `/api/v2/silicon/...` forms are aliases.
Ingress never calls Silicon Accounts.

Processing order:

1. Find the hook by its key, then check the path's Silicon segment: the owning
   Silicon's uuid, current id or an earlier id. Unknown, disabled and deleted
   endpoints answer `404`; a retired key `410 endpoint_retired`; a deleted
   account's hooks `410 account_deleted`.
2. Check the client address against the hook's block list. A blocked address
   receives `403 ip_blocked` (with `Retry-After`) and nothing it sent is stored.
3. Capture the exact method, URL, headers (at most 128 fields, 64 KiB) and body
   (at most 1 MiB). Multipart bodies are parsed for expressions.
4. If the policy requires signatures, verify. A verified request is stored, and,
   when delivery through Ting is on, its Ting send commits in the same
   transaction. An unverified request goes to the blocked log and counts against
   the address.
5. Answer `200 {"status": "webhook.ok", "receipt_id": "..."}`, identical for
   verified and withheld requests so the answer cannot be used as a signature
   oracle.

Behind a load balancer the deployment sets `HOOK_TRUSTED_PROXY_HOPS` so the
blocked address is the real sender.

### Safety

Twenty unverified requests from one address to one endpoint block that address
from the endpoint for one day. Counting restarts after each block. Blocks are per
endpoint, so a misconfigured provider cannot lock a Silicon out of its other
hooks.

## History

### `GET /silicons/{silicon}/events` and `GET /silicons/{silicon}/hooks/{hook_id}/events`

Return the last `n` verified requests (`limit` 1 to 10,000, default 100), newest
first, for the whole Silicon or one hook. Each record has `id`,
`silicon: {uuid, id}`, `hook_id`, `provider`, `delivery_sequence`, `summary`,
`received_at` and the captured `request` (`method`, `url`, `path`,
`query_string`, `headers`, `content_type`, `body` or `body_base64`,
`remote_ip`). A 16 MiB page budget may shorten a page; follow `next_cursor`.
Kept 14 days.

### `GET /silicons/{silicon}/blocked-requests` and `GET /silicons/{silicon}/hooks/{hook_id}/blocked-requests`

Withheld requests in the same shape, with `reason_code` (for example
`signature_mismatch`, `signature_missing`, `payload_unavailable`) and
`reason_detail`. Kept 14 days.

Cursors are authenticated and bound to the Silicon, the collection and the
filter; an events cursor is refused on the blocked list.

### `GET /silicons/{silicon}/events/{event_id}`

One retained event (the same object as history), for hydrating a Ting reference
or any authorized lookup. Expired or foreign events answer `404`.

## Delivery through Ting

Delivery is optional. When the operator sets `HOOK_TING_URL`, every verified
request is queued for its Silicon (and for Carbons who subscribed) and sent to
Ting as a compact reference; Hook retries until Ting confirms it stored the send,
reusing the same bytes and key. Hook signs its calls to Ting with Silicon
Accounts proofs: an App verification proof (scopes `tings.send`, `sent.query`)
for sends and receipts, and a User verification proof made from the caller's own
token (scope `tings.subscribe`) for enrolment.

When `HOOK_TING_URL` is unset, Hook still receives, verifies and stores every
event, queues nothing, and says so: `/readyz` reports it, `GET /delivery` answers
`{"enabled": false, "reason": ...}`, the routes below that need Ting answer
`409 delivery_disabled`, and publication status is `delivery_disabled`.

The reference Ting carries:

```json
{
  "type": "new_event",
  "data": {
    "sender": "stripe",
    "metadata": {
      "id": "0198c21a-6330-7000-8000-000000000001",
      "silicon": {"uuid": "Sx1", "id": "si:scout"},
      "hook_id": "0198c21a-6330-7000-8000-000000000002",
      "delivery_sequence": 42,
      "received_at": "2026-09-22T10:00:00Z",
      "summary": "stripe triggered at 10:00:00 22-09-2026 UTC"
    }
  }
}
```

The Ting type is `hook.webhook.received`; the send names the recipient as
`{uuid, id}` and the producer key `hook:{event id}:{sha256(recipient uuid)}`. No
provider body, header or secret travels through Ting. Use `metadata.id` to
deduplicate and `metadata.silicon.uuid` to hydrate. See
[Receiving through Ting](../client/relay.md).

### `GET /delivery`

Whether this Hook delivers through Ting.

### `POST /delivery/recipient`

Enrols the caller with Ting (empty body). Returns `recipient: {uuid, id}`,
`ting_subscription_id` and `required_delivery` (automation delivery the recipient
opts into in its own app).

### `GET`, `POST`, `DELETE /silicons/{silicon}/delivery/subscription`

A Carbon with `view` (or more) on the Silicon, or its custodian, inspects, starts
or stops copies of the Silicon's future events (no backfill; at most 100
observers per Silicon, `409 observer_limit_reached` beyond). POST enrols the
Carbon with Ting first. Hook re-checks the Carbon's access before every send, and
removes the subscription when access ends. DELETE works even after access ended.
Answers: `{"receiving": bool, "subscription": {id, silicon_uuid, recipient_uuid, created_at} | null}`.

### `GET /silicons/{silicon}/events/{event_id}/publication`

Where the event's send to its Silicon stands: `state` is `delivery_disabled`,
`not_queued` (received while delivery was off, or before the Silicon was linked
to Silicon Accounts), `pending`, `accepted_by_ting`, `accepted_silently`
(ordinary delivery while notifications are muted) or `not_delivered_legacy`
(queued before Hook 1.0 and never accepted). Queued sends also report
`recipient`, `delivery` (`ordinary` | `required`), `silent`, `attempts`,
`ting_id`, `last_error_code`, `accepted_at`, `next_attempt_at`, `expires_at`, and,
when available, Ting's `recipient_receipt` (`read`, per-destination
`delivery_acked` and `read_acked`). None of these mean the Silicon finished its
work.

## Hook's Silicon Accounts webhook

### `POST /webhook` (also `/webhook/`, origin-relative)

Silicon Accounts tells Hook about account changes. Hook verifies
`X-Accounts-Signature` over `{X-Accounts-Timestamp}.{raw body}` before parsing,
refuses deliveries older than five minutes (`401`), ignores a repeated
`event_id`, and acts on: `account.id_changed` (the new id is shown and routes
too), `account.updated`, `silicon.custodian_changed` (access moves to the new
custodian), `membership.signed_out` (except `app_revoked`, tokens issued before
it are refused), `membership.access_removed` and `account.deleted` (the account's
tokens stop working; a deleted Silicon's hooks are deleted). Other types are
acknowledged with `204`. A token's issue time has whole seconds, so a token from
the very second of a sign-out (a Silicon signing in again right after its STK
was rotated) is accepted only if Silicon Accounts confirms it is still active.

## Complete flows

### Provider event

```text
Provider POSTs to the endpoint URL
  -> Hook finds the hook by key and checks the address
  -> Hook captures the exact request and verifies the signature policy
  -> verified: stored for 14 days (and, with Ting on, queued in the same transaction)
     withheld: appended to the blocked log and counted against the address
  -> Hook answers 200 webhook.ok
  -> with Ting on: Hook sends the compact reference with an App verification proof
  -> the Silicon's app hydrates the event from Hook with the Silicon's own token
```

### A Silicon's own Silicon Accounts events

```text
The Silicon (or its custodian) calls POST /silicons/{silicon}/hooks/accounts
  -> Hook creates the "Silicon Accounts" hook and returns its URL and the command
  -> silicon-accounts webhook set <url> points the Silicon's webhook at it and prints whsec_
  -> PATCH the hook with that secret
  -> Silicon Accounts signs every event about the Silicon; Hook verifies and stores it
```

## Deliberately deferred operations

- No public operation to send a historical event through Ting again.
- No timestamp-tolerance option in signature policies; a signed timestamp is
  authenticated but not checked for freshness. Recipients that need replay
  protection deduplicate by provider event id.
- No public permanent purge; the worker purges deleted hooks after 45 days and
  logs after 14 days.
- No unblock operation for addresses; blocks expire after one day.
