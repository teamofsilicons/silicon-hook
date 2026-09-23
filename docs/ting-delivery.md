# Internal delivery through Ting

Hook receives, verifies and retains provider webhooks. Ting carries the event to the receiving application. The enclosing app handles login, consent and receiving setup; end users do not separately configure Hook or Ting.

API v2 uses Ting for delivery. Hook's management and history APIs remain available. V2 does not provide Hook event WebSockets, a relay daemon, or the old delivery cursor/ACK API. V1 remains deprecated during its existing seven-idle-day sunset policy so old clients can migrate.

## Service setup

Use Ting 0.1.4 or a compatible server. Configure `HOOK_TING_BASE_URL`, optionally `HOOK_TING_TIMEOUT_SECONDS` (1–15 seconds) and `HOOK_TING_POLL_MILLISECONDS` (100–30000 ms). Apply migrations and `deploy/postgres/grant-runtime.sql` before starting the API. The API process publishes committed events in the background; the maintenance worker does not receive publisher credentials.

In IAM, Hook needs the Ting external scopes for `subscriptions.register`, `tings.send` and `sent.query`, plus `receivers.bootstrap` for scoped sandbox observation, with the required review and consent. Provision the `tos>hook.webhook.received` Ting type with the authorized operator account. Type registration is a separate operator prerequisite; a missing type is not successful delivery. Local support does not activate pending Honeycomb scope revisions.

An organization owner or admin acting as a Carbon provisions a **separate server-owned Silicon session** using `POST /api/v2/delivery/publisher`, the ordinary Hook bearer and `X-Org-Id` headers, an `Idempotency-Key`, and JSON `{"slt":"<new Hook SLT>"}`. This SLT must be issued specifically for the publisher. Do not pass an interactive client's access/refresh pair. Retry an uncertain setup with the same key and SLT.

The equivalent internal CLI command is `hook --org tos --idempotency-key publisher-setup-001 publisher provision --slt-file ./publisher-slt`, under the admin's management profile. `--slt-file -` reads stdin; `--replace-rejected` explicitly requests recovery. The stateless SDK exposes `provision_publisher` and `replace_rejected_publisher` with the same mutation contract. Only non-secret publisher metadata is returned.

The backend encrypts that session, renews its own refresh family and persists IAM operation keys before external mutations. A revoked publisher leaves webhook events pending. To replace a rejected publisher, submit a fresh dedicated SLT and key with `"replace_rejected":true`; recovery first revokes the old family and can resume after a restart. Usable publishers cannot be accidentally replaced by an ordinary setup retry.

## Receiving application

Obtain Hook and Ting login SLTs through the enclosing runtime's direct IAM session/batch login. A Hook-only SLT cannot create a Ting receiver session. Register the signed-in actor's permission for Hook with `POST /api/v2/delivery/recipient` (Hook bearer, selected org, empty body); the backend obtains a request-bound IAM proof and validates Ting's returned recipient identity.

Attach the actor's destination through Ting's shared receiving service. Hook does not store the local receiving URL. Keep Hook and Ting sessions in the same production/test context. Test proof calls use Ting's test credentials returned by IAM, never Hook's app secret in place of Ting's.

New primary Silicon events use Ting's required automation mode. After the recipient explicitly chooses to enable automated events, the enclosing app uses that recipient's own Ting session to set `PUT /v1/orgs/{org}/subscriptions/{id}/required-delivery` with `{"enabled":true}`. Keep the service details internal to the app. Ordinary registration, Hook's publisher and a scoped test capability cannot make this choice. Without it, Hook keeps the event pending with `required_delivery_not_enabled`; it never silently downgrades the send. Grant revocation or sandbox clean requires a fresh explicit opt-in.

Notification muting still controls attention. A required send can be `silent: true` and still reach an authorized destination. Carbon observer copies use ordinary delivery, and their inbox queries include silent records. Previously queued primary sends retain their original bytes and ordinary policy, including previously muted events; the cutover does not rewrite or replay them under a different policy.

A Carbon can subscribe to future events from a currently visible Silicon with `POST /api/v2/silicons/{silicon_id}/delivery/subscription`, using an empty body. Hook registers that Carbon's Ting grant before saving the receiving interest and encrypting the caller's current access token. GET and POST require current read permission. DELETE returns `204` and cancels the caller's queued observer notifications even after that Carbon loses access to the Silicon. An interest never grants permanent access or backfills event history.

Before each observer send, Hook uses that exact Carbon token to check current IAM identity, organization, environment and Silicon visibility. The separate backend publisher session only authorizes the Ting operation. Lost target visibility removes the binding and its queued observer copies; the primary Silicon copy is unaffected. Expired or rejected Carbon tokens leave copies pending with `observer_authority_refresh_required`; temporarily unavailable checks retry with `observer_authorization_unavailable`.

The enclosing runtime must repeat POST subscription after it refreshes the Hook access token, and when resuming receiving. An existing binding retains its ID and queued events while its encrypted authority is replaced. Hook never stores or refreshes the Carbon's refresh token. Migration `0015` leaves older bindings without authority; their runtime must renew them before publication resumes. Already accepted Ting references cannot be retracted and still require current Hook authorization to hydrate.

## Event and acknowledgment flow

1. Hook verifies the provider signature, then atomically stores the original request and exact outgoing Ting request bytes. The provider receives success only after commit.
2. Hook retries a pending publication with its stable event/recipient key and a fresh request-bound IAM proof each time. An uncertain network result cannot generate a second producer identity.
3. Ting receives a compact `new_event` envelope containing the provider name and a reference: event ID, organization, Silicon, hook ID, original sequence/time, a summary with the provider and receipt time in an IANA timezone, environment ID and original event generation. Raw provider bodies and captured headers remain in Hook.
4. The receiving app fetches `GET /api/v2/silicons/{silicon_id}/events/{event_id}?environment_id={id}&environment_generation={generation}` with its current Hook authorization. Use both reference selectors, including the nil UUID and generation zero in production. The reference keeps its original generation across key rotation and restore; current runtime credentials still authorize the lookup. Cleaning deletes canonical events, so a cleaned reference cannot hydrate. Failed permission checks and expired or missing events must not become application work.
5. The receiver durably accepts and deduplicates the original event before completing Ting's local batch acknowledgment. Transport can replay and reorder events. Use the Hook event ID to deduplicate work and the original sequence for ordering when needed.

Hook retains original events for 14 days, even if Ting retains its reference longer. Do not process a reference with a missing payload.

`GET /api/v2/silicons/{silicon_id}/events/{event_id}/publication` reports `pending`, `accepted_by_ting` or `accepted_silently`, plus `delivery` (`ordinary` or `required`), notification `silent` (`null` until accepted), and a live Ting receipt when available. `accepted_silently` applies only to ordinary muted sends. Required muted sends report `accepted_by_ting`; that still does not prove recipient acceptance. `recipient_receipt.read` means a destination accepted it or a Carbon viewed it; it never means the Silicon completed its work. Per-destination delivery/read ACKs are separate, and `more_destinations` means the returned list is incomplete. A failed receipt lookup preserves the known publication state and reports that downstream status is unavailable.

See [Ting integration issues](ting-integration-issues.md) for notification muting, receiver authentication and lifecycle limitations. See [implementation evidence](ting-implementation.md) for the current verification state.
