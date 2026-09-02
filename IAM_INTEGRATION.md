# Silicon Hook ↔ Silicon IAM integration contract

**Contract version:** `silicon-hook-iam/v2`

**Status:** Hook implemented; the sibling IAM service requires the changes in
the compatibility section before production end-to-end operation is possible.

This document is the authoritative cross-service boundary for Silicon Hook.
Opaque credentials are always checked online. Missing, stale, contradictory,
or malformed authorization facts deny access; Hook never derives authority
from an internal UUID, a public ID, a job-role string, or a tag name. The
client-facing IAM documentation lives at
<https://backend.iam.teamofsilicons.com/docs/client/>.

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
  "capabilities": ["hook.hooks.delete", "hook.hooks.enabled.update"],
  "visible_silicon_ids": ["support:acme"],
  "audience": "silicon-hook",
  "expires_at": 1788172800
}
```

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

An inactive response is exactly `{"active":false}`.

Hook action names are:

- `hook.hooks.list`
- `hook.hooks.read`
- `hook.hooks.create`
- `hook.hooks.update`
- `hook.hooks.enabled.update`
- `hook.hooks.delete`
- `hook.hooks.restore`
- `hook.hooks.secret.rotate`
- `hook.hooks.endpoint.rotate`
- `hook.events.read` (history, blocked log, delivery pulls, acknowledgments, and the WebSocket stream)
- `hook.administrative_override`

For an organization owner, the role supplies the owner authority described by
Hook policy. An administrator needs the action-specific capability. A normal
Carbon receives visibility but no administrative authority.

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
  "action": "hook.hooks.enabled.update",
  "resource": "<bound Silicon ID or Hook UUID>"
}
```

The success response must repeat the exact proof bindings and include the same
authorization snapshot used for bearer introspection, plus `issuer_app_id`,
`action`, `resource`, and a near-term `expires_at`. Collection, history, and
delivery operations bind `resource` to the global Silicon ID; per-hook
operations bind it to the Hook UUID. A WebSocket upgrade authorized by an OBO
proof therefore subscribes to exactly one Silicon.

An OBO application may mutate only hooks created through that same
application unless the represented actor is an organization owner or has
`hook.administrative_override`.

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

## 3. Default IAM Hook provisioning

IAM sends the public organization handle and global Silicon ID:

```http
POST /api/v1/internal/iam/hooks
Authorization: Bearer svt_<43 base64url characters>
Content-Type: application/json
Idempotency-Key: <stable key for this IAM silicon-hook record>

{"org_id":"acme","silicon_id":"support:acme"}
```

Hook owns the default name and description and configures the hook to verify
IAM's own signing convention. A successful response is the normal Hook object
plus the one-time `signing_secret`; IAM needs `id`, `endpoint_url`, and
`signing_secret`:

```json
{
  "id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91e1",
  "endpoint_url": "https://hook.teamofsilicons.com/silicon/support:acme/A1B2C3",
  "signing_secret": "v1.<32 alphanumeric characters>"
}
```

IAM must validate the expected HTTPS origin and exact Silicon path, then store
the URL and signing secret as separately authenticated-encrypted fields. IAM
retries the identical request with the same idempotency key during Hook's
ten-minute secret-response replay window; after that, a lost secret requires
an explicit recovery workflow. Provisioning is unique per organization and
Silicon for the lifetime of that identity, even after a deleted default hook
is purged.

## 4. IAM event delivery

IAM posts to the returned `endpoint_url` with its existing application-webhook
convention:

```http
Content-Type: application/json
X-Silicon-IAM-Event-ID: <IAM outbox event UUID>
X-Silicon-IAM-Timestamp: <Unix seconds at signing>
X-Silicon-IAM-Key-Version: <signing-secret version>
X-Silicon-IAM-Signature: <lowercase hex HMAC-SHA-256>
```

The signature is HMAC-SHA-256 with the provisioned `signing_secret` (its UTF-8
bytes) over the exact bytes `{X-Silicon-IAM-Timestamp}.{raw body}`. The
default hook's policy is:

```text
algorithm           HMAC-SHA256
payload             concat(request.headers["x-silicon-iam-timestamp"], ".", request.raw_body)
signature           request.headers["x-silicon-iam-signature"]
signature_encoding  hex
secret_encoding     utf8
```

Hook does not interpret IAM's envelope. Every verified delivery reaches the
Silicon as a raw captured request with the summary line
`Silicon IAM triggered at HH:MM:SS DD-MM-YYYY UTC`, which is how a Silicon
learns about logouts, removals from the organization, and other changes.

## 5. Compatibility audit of the sibling IAM implementation

As audited on 2026-09-02:

- IAM's router implements `/api/v1/oauth/introspect`, but not the documented
  `/api/v1/auth/tokens/introspect`. Its introspection returns internal UUIDs
  and scopes only; it does not return public actor identity, role, Hook
  capabilities, or Silicon visibility.
- IAM's `/api/v1/obo-access/verify` now binds a proof to the downstream
  request's method, registered path, and body digest, rejects `X-Org-ID` and
  `Idempotency-Key`, and returns `actor`, `org_id`, `endpoint`, and `metadata`
  but not the organization role, Hook capabilities, or Silicon visibility.
  Hook's adapter still sends the audience/action/resource form and will be
  aligned to the request-binding form once IAM returns the authorization
  snapshot that the resource decision requires.
- IAM's Hook client posts a legacy body to `/api/v1/hooks`, puts the
  idempotency key in JSON, and expects a `url` member.

The smallest secure IAM change is to implement the online verification routes
with the authorization snapshots above, then update IAM's Hook provider to
sections 3 and 4. IAM's outbound signing convention already matches the
default hook policy, so no delivery-side change is needed.
