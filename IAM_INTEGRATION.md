# Silicon Hook ↔ Silicon IAM integration contract

**Contract version:** `silicon-hook-iam/v1`

**Status:** Hook implemented; the sibling IAM service requires the changes in
the compatibility section before production end-to-end operation is possible.

This document is the authoritative cross-service boundary for Silicon Hook.
Opaque credentials are always checked online. Missing, stale, contradictory,
or malformed authorization facts deny access; Hook never derives authority
from an internal UUID, a public ID, a job-role string, or a tag name.

## 1. Management authorization

### Bearer introspection

Hook sends the caller's opaque token to:

```http
POST /api/v1/auth/tokens/introspect
Authorization: Basic base64(silicon-hook:<application-secret>)
Content-Type: application/x-www-form-urlencoded
X-Org-ID: <public organization handle>

token=<percent-encoded opaque token>
```

An active response for a Carbon or Silicon must provide this authorization
snapshot:

```json
{
  "active": true,
  "actor": {
    "principal_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91c2",
    "type": "carbon",
    "public_id": "alice"
  },
  "org_id": "acme",
  "membership_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91c5",
  "organization_role": "admin",
  "capabilities": ["hook.hooks.delete"],
  "visible_silicon_ids": ["support:acme"],
  "audience": "silicon-hook",
  "expires_at": 1788172800
}
```

The following fields have authorization meaning and are required for a usable
management decision:

| Field | Required meaning |
| --- | --- |
| `active` | `true` only after current credential, principal, session, app, membership, and authorization-epoch checks |
| `actor.type` | `carbon` or `silicon`; application/service actors cannot use management routes directly |
| `actor.public_id` | Current immutable public Carbon or global Silicon ID; an internal principal UUID is not a substitute |
| `org_id` | Public organization handle, exactly equal to `X-Org-ID` |
| `organization_role` | Current `owner`, `admin`, or `member` organization tier |
| `capabilities` | Current Hook action grants; unknown values grant nothing |
| `visible_silicon_ids` | Complete current set of global Silicon IDs visible to a Carbon; a Silicon is independently limited to its own public ID |
| `audience` | Contains exactly the receiving application audience `silicon-hook` |

`principal_id`, `membership_id`, and `expires_at` are recommended audit and
freshness fields, but they do not independently grant authority. An inactive
response is exactly `{"active":false}`. IAM must not return a partially active
snapshot when membership or directory resolution fails.

Hook action names are:

- `hook.hooks.list`
- `hook.hooks.read`
- `hook.hooks.create`
- `hook.hooks.delete`
- `hook.hooks.restore`
- `hook.hooks.secret.rotate`
- `hook.events.read`
- `hook.administrative_override`

For an organization owner, the role supplies the owner authority described by
Hook policy. An administrator needs the action-specific capability. A normal
Carbon receives visibility but no administrative authority. Job roles, tags,
and internal membership IDs never map directly to Hook capabilities.

### OBO proof verification

Hook sends:

```http
POST /api/v1/obo-access/verify
Authorization: Basic base64(silicon-hook:<application-secret>)
Content-Type: application/json
Idempotency-Key: <stable domain-separated digest of proof and bindings>
X-Org-ID: <public organization handle>

{
  "access_proof": "obo_<43 base64url characters>",
  "audience": "silicon-hook",
  "action": "hook.hooks.delete",
  "resource": "<bound Silicon ID or Hook UUID>"
}
```

The success response must repeat the exact proof bindings and include the same
authorization snapshot used for bearer introspection:

```json
{
  "valid": true,
  "proof_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91d1",
  "issuer_app_id": "silicon-console",
  "audience": "silicon-hook",
  "actor": {
    "principal_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91c2",
    "type": "carbon",
    "public_id": "alice"
  },
  "org_id": "acme",
  "membership_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91c5",
  "organization_role": "admin",
  "capabilities": ["hook.hooks.delete"],
  "visible_silicon_ids": ["support:acme"],
  "action": "hook.hooks.delete",
  "resource": "018eb4ce-e57a-7d2c-8f9f-a35928ef91e1",
  "expires_at": "2026-08-31T12:01:00Z",
  "consumed_at": "2026-08-31T12:00:01Z"
}
```

IAM consumes the proof atomically and returns `409` on a different replay. The
same `Idempotency-Key` and identical request may replay the original successful
verification response. Hook additionally verifies issuer application, audience,
organization, action, resource, and a near-term expiry before applying its own
resource policy. Collection operations bind `resource` to the global Silicon
ID; per-hook operations bind it to the Hook UUID.

## 2. IAM service authentication

IAM provisioning uses an online-introspected `svt_` service token. Its active
introspection response must bind all three values:

```json
{
  "active": true,
  "actor_type": "service",
  "client_id": "silicon-iam",
  "audience": "silicon-hook",
  "scope": "hook.iam.provision"
}
```

The service identifier is not authority by itself: Hook also requires the
audience and scope. This credential cannot call management routes as a user.

## 3. Default IAM Hook provisioning

IAM sends the public organization handle and global Silicon ID:

```http
POST /api/v1/internal/iam/hooks
Authorization: Bearer svt_<43 base64url characters>
Content-Type: application/json
Idempotency-Key: <stable key for this IAM silicon-hook record>

{"org_id":"acme","silicon_id":"support:acme"}
```

`Idempotency-Key` is an HTTP header, not a JSON member. Hook owns the default
name and description. A successful response is the normal Hook object plus the
one-time `signing_secret`; IAM needs only `id`, `endpoint_url`, and
`signing_secret`:

```json
{
  "id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91e1",
  "endpoint_url": "https://hook.teamofsilicons.com/silicon/support:acme/A1B2C3",
  "signing_secret": "whsec_<43 base64url characters>"
}
```

IAM must validate the expected HTTPS origin and exact Silicon path, then store
the URL and signing secret as separately authenticated-encrypted fields. The
secret is never placed in the URL, logged, or returned from IAM's status API.
IAM retries the identical request with the same idempotency key during Hook's
ten-minute secret-response replay window; after that, an indeterminate lost
secret requires an explicit recovery workflow rather than unsigned delivery.

## 4. IAM event delivery

IAM posts to the returned `endpoint_url`. Every attempt includes:

```http
Content-Type: application/json
Idempotency-Key: <IAM outbox event UUID>
X-Hook-Timestamp: <canonical Unix seconds>
X-Hook-Signature: v1=<64 lowercase hexadecimal HMAC bytes>
```

The signature is HMAC-SHA-256 using the provisioned `signing_secret` over the
exact bytes:

```text
{X-Hook-Timestamp}.{exact raw request body bytes}
```

IAM serializes the Hook ingress body once and reuses those exact bytes for all
retries under the same idempotency key. It maps its domain event into Hook's
public envelope rather than sending IAM's application-webhook envelope:

```json
{
  "type": "iam.silicon.initialized",
  "source": "silicon-iam",
  "subject": "support:acme",
  "occurred_at": "2026-08-31T12:00:00Z",
  "schema_version": "1",
  "trace_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91f1",
  "payload": {
    "iam_event_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91f1",
    "aggregate": {"type": "silicon", "id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91c8", "version": 1},
    "data": {}
  }
}
```

The IAM outbox UUID remains in `payload.iam_event_id` for cross-service
correlation; Hook assigns its own retained event UUID. IAM may generate a new
timestamp/signature for a retry, but the body and idempotency key remain exact.

## 5. Compatibility audit of the sibling IAM implementation

As audited on 2026-08-31, no safe Hook-only composition covers all required
principals and transports:

- IAM's Rust router implements `/api/v1/oauth/introspect`, but not the documented
  `/api/v1/auth/tokens/introspect`. OAuth introspection returns internal UUIDs
  and scopes only; it does not return public actor identity, role, Hook
  capabilities, or Silicon visibility.
- Existing userinfo/directory endpoints can enrich some Carbon OAuth tokens,
  but cannot safely identify a Silicon bearer, cannot verify an OBO proof, and
  do not produce one atomic authorization snapshot. Internal UUIDs cannot be
  treated as public IDs, and missing visibility cannot be inferred.
- IAM's Rust router now implements OBO exchange/verify, but verification
  serializes the represented actor's internal principal UUID and omits the
  organization role, Hook capabilities, and Silicon visibility required by
  the target application's resource decision. The current OpenAPI result also
  lacks those authorization facts.
- IAM's Hook client currently posts a legacy body to `/api/v1/hooks`, puts the
  idempotency key in JSON, expects a `url` member, and does not retain Hook's
  signing secret. Its Silicon delivery path sends a bearer token and different
  header/body/signature conventions, so Hook correctly rejects it.

The smallest secure IAM change is to implement the two documented online
verification routes with the authorization snapshots above, then update only
IAM's Hook provider/worker and persistence to use sections 3 and 4. Hook must
not add an unsigned compatibility route or accept a service bearer as public
webhook authenticity.
