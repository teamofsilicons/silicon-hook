# Testing through HTTP

All paths below start at the Hook backend origin. JSON requests use
Content-Type: application/json. Mutations require an 8–255 visible-ASCII
Idempotency-Key. Secret responses use Cache-Control: no-store.

## Production control plane

Authenticate with the production bearer and X-Org-Id. Do not attach a Hook test
key to these routes: they administer environments owned by the production org.

| Method/path | Input | Result |
|---|---|---|
| POST `/api/v1/testing-environments` | Creation JSON below | Metadata, `key`, `max_hooks: 10` |
| GET `/api/v1/testing-environments?status=active` | `active`, `deleted`, or `all` | `items` metadata array |
| GET `/api/v1/testing-environments/{id}` | UUID path | Metadata |
| GET `/api/v1/testing-environments/{id}/key` | UUID path | Metadata and current root key |
| POST `/api/v1/testing-environments/{id}/key/rotate` | Empty body | Metadata and replacement key |
| DELETE `/api/v1/testing-environments/{id}` | Empty body | Soft-deleted metadata |
| POST `/api/v1/testing-environments/{id}/restore` | Empty body | Recovered metadata |

Creation JSON:

```json
{
  "name": "provider integration",
  "description": "Local test of signature and retry behavior",
  "iam_test_key": "<IAM testing key>",
  "iam": {
    "app_id": "tos>hook",
    "app_secret": "<test-only app secret>",
    "webhook_secret": "<test application signing secret>",
    "webhook_secret_version": 1
  }
}
```

`iam` is optional during initial creation. `name` is nonblank, at most 200
characters; description is optional and at most 2000 characters. Unknown fields
are rejected. The IAM root key is validated against IAM before creation.

## Root operations

These use `X-Hook-Test-Key` and need no actor bearer. They work before the test
application configuration is installed.

| Method/path | Input | Result |
|---|---|---|
| GET `/api/v1/testing-environment` | Current root key | Current metadata |
| POST `/api/v1/testing-environment/clean` | Empty body | Metadata after complete Hook data reset |
| PUT `/api/v1/testing-environment/iam` | The `iam` object above | Metadata after test configuration is installed |

## Ordinary sandbox actions

Use the same `/api/v1/auth/login`, `/silicons/.../hooks`, history, delivery and
WebSocket routes as production, adding the Hook root key. Login uses a test
IAM SLT. After login, add its test access token and test organization too.

An unknown/rotated/deleted key is rejected. Missing application credentials
return `test_iam_application_not_configured`. Root-only actions without the
header return `test_environment_required`. Cross-organization environment IDs
are hidden as not found; known in-org keys still require creator/admin rights
to retrieve or rotate.

Send provider traffic directly to the `endpoint_url` returned by hook creation.
Do not attach either root key to public ingress. Retired keys never reactivate.

Environment lists use keyset pagination: `limit` is 1–1000 (default 100),
ordered by descending UUID. Pass the last returned ID as `after` for the next
page and stop when a page contains fewer than `limit` items.
