# Silicon IAM integration

Hook uses the official published `silicon-iam-client` for all IAM HTTP calls and
webhook verification. The resolved version is pinned in Cargo.lock. The Hook
backend disables IAM's automatic dependency updater; deployments are built and
validated from their lockfile.

## Configuration and application

The canonical application ID is `hook`. Configure these server-side values:

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

## Per-Silicon authority

Hook's application registration declares `self.identity.read`, `self.profile.read`, `self.organizations.read`, `self.membership.read`, `self.silicon_access.read`, and the reviewed `directory.silicons.read` permission. Users consent to the selected organizations during IAM login. Existing sessions need to sign in again after permission changes.

For Carbon application tokens, Hook pages through the SDK's scoped directory requesting only `id,org`. IAM returns active, visible memberships and enforces application consent. Hook validates each organization and exact target ID; missing targets, malformed projections, repeated cursors and unavailable IAM responses fail closed. This projection works with IAM's scoped responses without requiring unrelated Silicon profile fields. Native IAM credentials retain their direct Silicon lookup.

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

Create a Honeycomb shared test environment and import `hook`. Pass the returned test application secret to `hook env use --app-secret-file ./hook-test-app-secret`, or the SDK's `with_test_app_secret`. Hook validates the selector online with IAM 1.8, resolves the environment identity, and selects the isolated storage prepared by Honeycomb. Selection does not log in an actor.

Sign in with an IAM test SLT or an existing test Carbon/Silicon public ID. Production never accepts this ID shortcut. Normal usage does not require either root key or a manual Hook/IAM pairing. Root administration APIs remain available for existing installations; use [the testing guide](../testing/README.md) for the normal flow.

Imported IAM application webhooks retain their configured verification key; Hook additionally validates the signed testing-envelope key against the selected environment digest. The test selector is encrypted at rest and revalidated before data-plane operations. Invalid, deleted, revoked, foreign-app or unavailable selectors fail closed.
