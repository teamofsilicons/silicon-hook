# Silicon IAM integration

Hook uses the official published `silicon-iam-client` for all IAM HTTP calls and
webhook verification. The resolved version is pinned in Cargo.lock. The Hook
backend disables IAM's automatic dependency updater; deployments are built and
validated from their lockfile.

## Configuration and application

The canonical application ID is `tos>hook`. Configure these server-side values:

| Setting | Purpose |
|---|---|
| `HOOK_IAM_BASE_URL` | IAM backend origin |
| `HOOK_IAM_APP_ID` | Canonical `organization>application` ID |
| `HOOK_IAM_APP_SECRET` | Backend-only application credential |
| `HOOK_IAM_WEBHOOK_SECRET` | Secret for Hook's own IAM webhook receiver |
| `HOOK_IAM_WEBHOOK_SECRET_VERSION` | Active signing-secret version |

The planned production receiver is
`https://backend.hook.teamofsilicons.com/webhook/`. Register and activate it in
IAM. A pending webhook URL is not an active subscription. Production app and
webhook secrets are stored outside this repository in the owner's private
configuration; never put them in the CLI distribution or Rust client.

## Login and current authorization

IAM performs Carbon/Silicon authentication and issues an application SLT. Hook
exchanges it through `oauth().login` using its own application credentials. The
backend returns the issued access/refresh pair to the client. Both client and
CLI require a local recipient, but that URL stays entirely local.

Application access tokens use IAM's live OAuth authorization snapshot. Hook
checks the intended application, actor, organization, disclosed organization
role and production/test plane before creating its authorization context.
Native IAM credentials use the official SDK's directory interfaces. Every
management call rechecks IAM; authorization is not inferred from stale local
JWT decoding. WebSocket sessions refresh authority every 30 seconds and after verified IAM
webhooks. PostgreSQL notifications invalidate retained authorization across
replicas; a missed notification is covered by the periodic refresh. Temporary
IAM failures close streams with 1013 iam-unavailable, rather than granting
authority from a failed refresh.

An IAM failure denies management actions; it does not silently fall back to a
local identity. Development-only local authorization requires explicit
non-production configuration and cannot be enabled in production.

## Per-Silicon authority: integration gate

The current published application-token authorization snapshot discloses the
actor's organization role, but does not provide an application-authorized
lookup for a Carbon's target Silicon visibility. This is a tracked integration
gap: Carbon access and authoritative target-Silicon existence must
be resolved before this implementation is considered complete. Do not treat
an organization suffix alone as proof that a Silicon exists. Hook requires an
authoritative visibility result for every Carbon, including owners and admins;
it denies target access when IAM cannot supply that result.

The first-party Silicon webhook configuration API also needs its documented
credential/step-up authority. An application token alone must not be assumed
to have permission to redirect a Silicon's IAM webhook. The `connect-iam` flow
must pass the final manual IAM integration checks before release.

## Webhook verification

Hook's application receiver accepts `/webhook/` and `/webhook`; the old
`/api/v1/iam/events` path remains an alias. Verification uses the exact received
bytes and the configured SDK keyring. Never parse and reserialize before
checking the signature. Bad signatures are rejected.

A testing envelope's `test.testing_key` is only a routing hint. Hook finds its
linked Hook environment, selects that environment's application secret/keyring,
then authenticates the original bytes. The test envelope must match the IAM
environment configured for that verifier. Production verification rejects test
envelopes. A valid webhook acknowledges with 204; current authorization still
comes from online IAM checks.

## Test application bootstrap

Create a real IAM testing environment first, then create/import `tos>hook`
inside it. Import returns a test-only application secret. Use that secret when
configuring the Hook test environment. If IAM explicitly reports that the
webhook secret is inherited, use the matching inherited signing secret/version;
do not substitute the production app credential.

Every IAM request from a Hook test context includes the configured IAM testing
key. No Hook test operation can use production IAM as a fallback. The Hook
root key and IAM root key are distinct and must not be confused. See the
[testing guide](../testing/README.md) for the complete bootstrap order.
