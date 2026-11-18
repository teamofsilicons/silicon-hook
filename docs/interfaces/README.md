# Use Silicon Hook in an interface

Add `hook` to your interface’s app IDs. Hook gives a Silicon signed webhook URLs and a 14-day history of verified and withheld requests. A Carbon can work with a Silicon it looks after or has been granted access to. Your interface can use the same API as the Hook console, from its own origin or backend.

| Connection | Production address |
| --- | --- |
| API origin and version negotiation | `https://api.hook.teamofsilicons.com/api/version` |
| Management, history and delivery | `https://api.hook.teamofsilicons.com/api/v3` |
| Provider ingress | The `endpoint_url` returned by Hook |
| This guide as plain text | [Download Markdown](https://docs.hook.teamofsilicons.com/interfaces.md) |
| Full request and response schemas | [Live OpenAPI 3.1](https://api.hook.teamofsilicons.com/api/openapi.yaml) · [Documentation copy](../../openapi.yaml) |
| Signature expressions, status codes and wire examples | [HTTP reference](../api/README.md) |

## Sign in and open a Silicon

Use Silicon Accounts’ interface authorization flow. At the registered callback, check the state and exchange the code with the original PKCE verifier. Read `apps["hook"].access_token` from the result. If the user declined Hook or the grant is absent, offer to authorize Hook. A confidential interface keeps its client secret and refresh token on its backend. Send only the Hook access token to the Hook API. [Accounts interface sign-in](https://developers.teamofsilicons.com/docs/accounts/start/interface-accounts)

The following JavaScript runs in a browser or on a server. Supply the current app access token on each call so an open interface can pick up a refresh. A browser uses an explicit bearer and `credentials: "omit"`. The API accepts cross-origin preflights for GET, HEAD, POST, PATCH, PUT and DELETE.

```js
const origin = "https://api.hook.teamofsilicons.com";
const handshake = await fetch(origin + "/api/version", {
  credentials: "omit",
  headers: { "Silicon-Hook-Supported-API-Versions": "v3" }
});
if (!handshake.ok || (await handshake.json()).selected_api_version !== "v3") {
  throw new Error("This interface requires Hook API v3");
}

async function callHook(token, path, { method = "GET", body, key } = {}) {
  const headers = {
    Authorization: `Bearer ${token}`,
    "Silicon-Hook-API-Version": "v3"
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (key) headers["Idempotency-Key"] = key;
  const response = await fetch(origin + "/api/v3" + path, {
    method, headers, credentials: "omit", redirect: "error",
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  if (response.status === 204) return;
  const result = await response.json();
  if (!response.ok) {
    throw Object.assign(new Error(result.error.message), result.error, {
      status: response.status, retryAfter: response.headers.get("Retry-After")
    });
  }
  return result;
}

const token = signInResult.apps.hook.access_token;
const account = await callHook(token, "/auth/status");
const { items: silicons } = await callHook(token, "/silicons");
```

For example, the account response contains `{"authenticated":true,"app_id":"hook","uuid":"912fff6e-e7f8-4057-ab03-201aceac9513","id":"si:saket-agents","kind":"silicon"}`. The list returns entries with `silicon: {uuid, id}`, `access` and `custodian`. Let the user select a Silicon. Keep its immutable UUID for later calls. Show an empty state if there are no entries. A custodian can also open a known Silicon by its current ID and Hook checks custody with Accounts. Access levels come from Hook’s resource permissions.

## Create a hook and inspect a delivery

After the user selects a Silicon with `self`, `custodian` or `manage` access and asks to create a hook, run:

```js
const scope = "/silicons/" + encodeURIComponent(selected.silicon.uuid);
const key = crypto.randomUUID();  // retain this key and body across retries of this action
const created = await callHook(token, scope + "/hooks", {
  method: "POST", key, body: { name: "Order updates", time_zone: "UTC" }
});
const { id, endpoint_url, signing_secret } = created;
```

HTTP 201 returns the hook’s fields directly. Hand the provider its `endpoint_url` and generated `signing_secret` at setup time. A subsequent GET contains the signature policy and `has_secret`. Hook’s default verifies HMAC-SHA256 using the UTF-8 secret, over `webhook-id.webhook-timestamp.raw_body`, with a base64 `webhook-signature` header. For GitHub, Stripe or a different signing scheme, supply the provider’s policy and key. Send provider requests separately from the call helper above. Hook records their headers and body. [Signature policies and expressions](../api/README.md#signature-policy)

A provider POST receives `{"status":"webhook.ok","receipt_id":"…"}` for both a verified and a withheld request. Open the hook’s verified history to see the result, or its blocked log to diagnose a missing or mismatched signature.

```js
const history = scope + "/hooks/" + encodeURIComponent(id) + "/events";
const first = await callHook(token, history + "?limit=25");
if (first.next_cursor) {
  const next = await callHook(token, history + "?" +
    new URLSearchParams({ limit: "25", cursor: first.next_cursor }));
}
if (first.items.length) {
  const eventPath = scope + "/events/" + encodeURIComponent(first.items[0].id);
  const event = await callHook(token, eventPath);
  const publication = await callHook(token, eventPath + "/publication");
}
```

Read the captured request’s ordered header pairs and either `body` (text) or `body_base64` (binary). An interface can export those API results as JSON. History defaults to 100 items, accepts 1–10,000, and may stop early at 16 MiB. Follow the opaque `next_cursor` until null, keeping the Silicon, collection and filters fixed. Hook, access and allow-list collections return their items in a single response.

## Operations and permissions

All paths below are relative to `/api/v3`. In the table, `S` is `/silicons/{silicon}`, `H` is `S/hooks/{hook_id}`, and `E` is `S/events/{event_id}`. Encode each substituted path segment. **Read** includes view, manage, self and custodian. **Manage** includes manage, self and custodian. **Owner** means the Silicon or its custodian.

| What the interface can do | Method and path | Permission or input |
| --- | --- | --- |
| Discover sign-in, docs and supported delivery | GET `/auth/accounts`, GET `/version` | Public. Origin-relative GET `/api/contracts`, `/healthz` and `/readyz` are also public. |
| Show the caller and its Silicons | GET `/auth/status`, GET `/silicons` | Active Hook access token |
| List hooks and open details | GET `S/hooks?include_deleted=true`, GET `H` | Read. Omit `include_deleted` to hide recoverable deletions. |
| Create a signed endpoint | POST `S/hooks` | Manage. Send `name`; optional `description`, `time_zone`, `signature`. Idempotency key required. |
| Edit metadata, signature policy, provider key or activation | PATCH `H` | Manage. Send just changed fields, e.g. `{"enabled":false}` or `{"signature":{"secret":"…"}}`. |
| Enable or disable a selection | PATCH `S/hooks` | Manage. `{"hook_ids":["…"],"enabled":true}`, up to 1,000 unique hooks, applied atomically. |
| Rotate the signing secret or public endpoint | POST `H/secret/rotate`, POST `H/endpoint/rotate` | Manage. Empty body and idempotency key. The former returns `signing_secret`; the latter returns the updated hook. |
| Delete or restore a hook | DELETE `H`, POST `H/restore` | Manage. DELETE returns 204. Restore needs an idempotency key and works within 45 days. |
| Read verified or withheld requests | GET `S/events`, `H/events`, `S/blocked-requests`, `H/blocked-requests` | Read. Silicon-wide collections accept `hook_id`. Both logs are retained for 14 days. |
| Open a verified event or its publication | GET `E`, GET `E/publication` | Read. A foreign or expired event is unavailable. |
| Inspect access | GET `S/access` | Read. Owners see all grants; grantees see their own. |
| Grant, update, revoke or leave | PUT or DELETE `S/access/{account}`; DELETE `S/access/me` | Owner to grant or revoke another account. PUT takes `{"level":"view"}` or `{"level":"manage"}`. A grantee can leave. |
| Inspect or change who can grant access to this Silicon | GET `S/allow-list`; PUT or DELETE `S/allow-list/{account}` | Owner. PUT and DELETE take no body. Cross-custodian sharing may require an entry on the **receiving** Silicon first. |
| Prepare a receiver for Accounts-formatted webhooks | POST `S/hooks/accounts` | Owner. Empty body and idempotency key. Returns `hook` and `next_steps`. Hosted Accounts delivers a Silicon’s own notifications through Ting today. [Accounts notification setup](https://developers.teamofsilicons.com/docs/accounts/start/silicon-notifications) |
| Check delivery and enroll the current recipient | GET `/delivery`, POST `/delivery/recipient` | Active Hook token. POST takes no body and reports the current required-delivery preference. |
| Inspect, start or stop observer copies | GET, POST or DELETE `S/delivery/subscription` | A Carbon with read access can inspect and subscribe. DELETE stops its own copies and works after access ends. Writes take no body. |

## Notifications and recovery

When `GET /delivery` reports `enabled: true`, Hook queues each verified event to Ting. A Silicon opts into required delivery in Ting. An observing Carbon can subscribe to ordinary copies of future events. An interface with a Ting receiver can open the full event with its Hook token using the Silicon UUID and event ID from `data.metadata` inside the Hook `new_event` reference. Deduplicate on event ID. Delivery may be replayed or arrive out of order. When delivery is disabled, keep history available and hide enrollment controls. An interface can refresh or poll Hook history without a Ting receiver. [Delivery and receipts](../ting-delivery.md)

Hook checks the JWT signature, issuer, audience and expiry, confirms live access with Accounts on every protected call, then checks Hook permissions for the requested Silicon. On 401, use the interface’s Accounts refresh flow for `hook` if appropriate. If access has ended or consent was withdrawn, clear the affected view and request authorization again. For an ordinary interface refresh, post `grant_type: "refresh_token"`, the interface ID and its refresh token to Accounts’ `/v1/interface-auth/token` with an idempotency key. Read the new `apps["hook"].access_token`; keep the returned refresh token on your backend. Omit the optional `app_id` field when refreshing existing grants. A 403 from Hook is a resource permission decision. A 503 from Accounts or storage is retryable; keep the session and retry with backoff.

Each create, restore and rotation needs a fresh `Idempotency-Key` (8–255 visible ASCII characters) per intentional action. Reuse the original key and body after a timeout. A different payload with that key returns 409. A secret-bearing result can be replayed for ten minutes. If that window has elapsed, inspect the hook before deciding whether to rotate. A retired endpoint returns 410.

Limits include 1,000 hooks per Silicon counting recoverable deletions, 100 Carbon observers, and a provider body limit of 1 MiB. Twenty unverified provider requests to the same endpoint from one address block that address there for one day. Honor `Retry-After` on a block or a 429, and back off on 408 or 503. Validation errors carry `error.code`, `message`, `request_id` and sometimes `details`. Report an integration problem with the method, route, status, error code and `X-Request-Id`. Remove tokens, signing secrets and captured provider data before sharing. [Report a Hook issue](https://github.com/teamofsilicons/silicon-hook/issues)
