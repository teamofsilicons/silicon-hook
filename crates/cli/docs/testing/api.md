# Test over HTTP

## Select and inspect

Send the test application's secret in `X-Hook-Test-App-Secret`. Hook fixes the app ID to its configured application and validates this secret with IAM. Never send an IAM root key or put a secret in the URL.

```http
GET /api/v1/testing-session
X-Hook-Test-App-Secret: <test-app-secret>
```

The response contains `id`, `org_id`, `name`, `description`, `generation` and lifecycle timestamps. No token, app secret or administrative key is returned. Honeycomb prepares its empty storage before selection; IAM confirms shared readiness.

## Authenticate and act

```http
POST /api/v1/auth/login
Content-Type: application/json
Idempotency-Key: a-unique-logical-login-key
X-Hook-Test-App-Secret: <test-app-secret>

{"slt":"<IAM-test-SLT-or-existing-test-identity-ID>"}
```

Use the returned bearer token, `X-Org-Id` and the same selector for subsequent ordinary API v1 requests. Actor permissions are checked through IAM. Refresh and logout must carry the same selector. Sandbox credentials cannot cross into production or another sandbox.

Duplicate selector headers, simultaneous root/application selectors, malformed secrets, revoked secrets and unavailable environments are rejected. App selectors cannot authorize root-administration endpoints or public ingress. `/api/version` remains the unversioned compatibility handshake; clients pin `Silicon-Hook-API-Version: v1` afterward.

## WebSocket

The existing `/api/v1/ws` route accepts the selector in its upgrade headers. For system daemons, `/api/v1/relay/ws` starts one empty prewarmed transport; each `subscribe` frame includes a separate token, org, Silicon IDs and optional `app_secret`. Credentials appear only inside TLS-protected frame bodies. See [relay protocol](../client/relay.md).

## Legacy administrative API

The existing `/api/v1/testing-environments` collection and `/api/v1/testing-environment` root-key routes remain compatible with previous clients. They use `X-Hook-Test-Key`, require their documented production-owner/root permissions, and cannot accept an app selector. Use the new `/testing-session` route for ordinary app-selected testing.

Honeycomb-managed environments reject legacy root/owner lifecycle mutations. Use [the protected participant contract](honeycomb.md) for service operations.
