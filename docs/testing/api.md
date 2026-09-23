# Test over HTTP

## Select and inspect

First call unversioned `GET /api/version` with `Silicon-Hook-Supported-API-Versions: v2`, without a bearer or test selector. Require `service: silicon-hook` and `selected_api_version: v2`, then pin versioned requests with `Silicon-Hook-API-Version: v2`.

Send the test application's secret in `X-Hook-Test-App-Secret`. Hook fixes the app ID to its configured application and validates this secret with IAM. Never send an IAM root key or put a secret in the URL.

```http
GET /api/v2/testing-session
Silicon-Hook-API-Version: v2
X-Hook-Test-App-Secret: <test-app-secret>
```

The response contains `id`, `org_id`, `name`, `description`, `generation` and lifecycle timestamps. No token, app secret or administrative key is returned. Honeycomb prepares its empty storage before selection; IAM confirms shared readiness.

## Authenticate and act

```http
POST /api/v2/auth/login
Silicon-Hook-API-Version: v2
Content-Type: application/json
Idempotency-Key: a-unique-logical-login-key
X-Hook-Test-App-Secret: <test-app-secret>

{"slt":"<IAM-test-SLT-or-existing-test-identity-ID>"}
```

Use the returned bearer token, `X-Org-Id` and the same selector for subsequent ordinary API v2 requests. Actor permissions are checked through IAM. Refresh and logout must carry the same selector. Sandbox credentials cannot cross into production or another sandbox.

Duplicate selector headers, simultaneous root/application selectors, malformed secrets, revoked secrets and unavailable environments are rejected. App selectors cannot authorize root-administration endpoints, unversioned discovery or public ingress.

## Scoped inbox and watch

Ting 0.1.4 supports internal sandbox observation using the selected Hook app secret and signed-in actor. Register that actor through `POST /api/v2/delivery/recipient` with an empty body; a Carbon observing a visible Silicon uses its [receiving subscription](../api/README.md#get-post-delete-siliconssiliconiddeliverysubscription).

Read `GET /api/v2/delivery/receiver`, then persist its scope and a stable operation key. POST to the same endpoint with `Idempotency-Key` and JSON containing `environment_id` from `scope.environment.id` and `generation` from `scope.environment.generation`. The private response includes `receiver_id`, `receiver_token` and `expires_at`. Retry uncertain requests with the original scope, body and key. Renew explicitly with a new key and the same `receiver_id`; exact replay retains the original expiry, even if expired. Both scope lookup and issuance can return `429` with `Retry-After`.

The enclosing app uses the capability with Ting's `/v1/receivers/inbox` and `/v1/receivers/ws?protocol=v1`, renews/reconnects within its at-most-30-second lifetime, and revokes through `DELETE /v1/receivers/session`. This capability cannot ACK, attach a native destination or enable required delivery. Hook separately authorizes every original event lookup using its original reference generation. See the [receiver contract](../api/README.md#get-post-deliveryreceiver-v2-testing-only) and [testing client guide](client.md).

## Legacy WebSocket

Deprecated `/api/v1/ws` and `/api/v1/relay/ws` retain their existing protocols until that environment's v1 sunset. API v2 uses Ting instead. See [legacy delivery](../api/README.md#legacy-delivery-deprecated-v1).

## Legacy administrative API

The existing `/api/v1/testing-environments` collection and `/api/v1/testing-environment` root-key routes remain compatible with previous clients. They use `X-Hook-Test-Key`, require their documented production-owner/root permissions, and cannot accept an app selector. Use the new `/testing-session` route for ordinary app-selected testing.

Honeycomb-managed environments reject legacy root/owner lifecycle mutations. Use [the protected participant contract](honeycomb.md) for service operations.
