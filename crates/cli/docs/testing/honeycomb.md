# Operate Hook as a Honeycomb lifecycle participant

Honeycomb creates and manages shared test environments. Hook prepares and cleans its own data; IAM continues to own test identities, authentication, webhook signatures and shared readiness. Configure this integration once at deployment. Users select a test `app_secret` without supplying any service credential.

## Configure the service boundary

Apply migration 9 to both Hook databases and reapply `deploy/postgres/grant-runtime.sql`. Configure the API with:

- `HOOK_TEST_DATABASE_URL`: the separate shared-test database.
- `HOOK_IAM_APP_ID`: Hook's application ID (`tos>hook` for the hosted service).
- `HOOK_HONEYCOMB_SERVICE_TOKEN`: a dedicated secret of at least 32 visible ASCII characters, provisioned by deployment secret management.
- `HOOK_HONEYCOMB_URL`: trusted coordinator origin for activity reports; defaults to `https://backend.honeycomb.teamofsilicons.com`. HTTPS is required outside loopback development.

Register the same credential in Honeycomb's deployment secret store. Its `HONEYCOMB_LIFECYCLE_PARTICIPANTS` entry binds Hook's application ID, HTTPS backend URL and token environment-variable name. Catalog metadata and user input never select the destination. Do not reuse an app secret, user token or environment key as service authority.

## Apply and inspect an operation

Honeycomb sends `PUT /internal/honeycomb/organizations/{org_id}/testing-environments/{environment_id}/operations/{operation_id}` with `Authorization: Bearer <service-token>`. The route bypasses test-session middleware so it remains available during disable, cleanup or IAM outages.

The JSON body contains `operation_id`, `environment_id`, `org_id`, `app_id`, `environment_revision`, `generation`, `key_version`, `action`, `testing_key` and optionally `snapshot`, `reason`, `retired_apps`. IDs and path bindings must match, versions must be positive and the environment key must be 32 alphanumeric characters. Unknown fields and unsupported actions are rejected. Hook accepts `create`, `prepare`, `import`, `rotate-key`, `clean`, `disable`, `restore`, `purge` and `retire-applications`.

A receipt contains `state` (`pending`, `completed`, or `failed`) and the exact operation/environment/application IDs, revision, generation, key version and retirement selection. No credentials or input snapshot are returned. `GET` at the same protected URL returns the durable receipt. Repeat a failed or interrupted `PUT` with the identical ID and body; changing that payload returns `idempotency_conflict`. Older revisions, regressing generations, conflicting key versions, and overlapping operations fail closed.

Pending state commits before cleanup. Completion commits only after all cleanup succeeds. A failed cleanup rolls back its data changes, retains a failed receipt and keeps test access blocked until the same operation succeeds. Timeouts can therefore leave a pending operation; retry it or inspect its receipt.

## Data and delivery isolation

Each operation advances Hook's local session generation. Database writes and WebSocket event sends hold lifecycle locks, including at the final shared-socket send boundary. Cleanup waits for already-admitted sends and writes, then rejects stale requests, ACKs, buffered deliveries and retries. Production data and other environments use different database scopes.

Clean erases endpoints, encrypted signing secrets, received and blocked events, delivery queues/cursors, request idempotency, audit history, contract counters and local diagnostic records. The shared binding and lifecycle receipts remain. Minimal retired endpoint reservations prevent an old URL from ever reaching a new hook. Restore re-enables access only after IAM confirms shared readiness and does not recover cleaned records. Purge removes credentials and descriptive metadata; a minimal permanently-disabled identity tombstone, operation receipts and URL reservations prevent resurrection.

An app selector cannot create storage ahead of Honeycomb preparation when the participant is configured. Every selection validates IAM's current context, and managed contexts recheck it while holding the lifecycle lock. Legacy owner/root mutation methods reject Honeycomb-managed environments.

## Activity and retention

Successful sandbox requests queue server-side activity for Honeycomb's `POST /api/v1/environments/{id}/apps/{app}/activity`. The API retries queued reports every 30 seconds using the encrypted environment credential and matching shared generation/key version. Report IDs survive failures. Clean and lifecycle changes discard reports for superseded state. Hook does not independently retire or purge environments; its worker only maintains record TTLs.
