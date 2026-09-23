# Receiving through Ting

The enclosing application owns the internal Ting login, daemon or transport,
destination, callback listener, and session refresh. Hook's Rust client starts
none of these. Users continue through the application's normal login and setup.

The host needs separate Hook and Ting sessions from the same authorized IAM
actor and organization. A Hook application token cannot bootstrap a Ting
session. Acquire the required application sessions through the host's IAM
login flow; never reuse Hook's test app secret as Ting's credential.

## Setup

After Hook login, call `register_recipient()` to grant the authenticated actor
receipt of this application's notifications. A Carbon interested in a visible
Silicon calls `subscribe(silicon)`; that operation grants the current recipient
and records interest in future events. No older events are backfilled.
Silicons receive their own primary events without an observer subscription.

The host registers its internal receiving destination with Ting and retains the
destination ID and a high-entropy bearer secret. The receiving URL stays in Ting's
local configuration. Use `delivery_context()` to obtain the trusted Hook
application, actor, organization, and environment; never take that context from
an incoming callback.

```rust,no_run
use silicon_hook_client::{Client, Secret, delivery::Receiver};

# async fn example(client: &Client) -> silicon_hook_client::Result<()> {
let context = client.delivery_context().await?;
let receiver = Receiver::new(context, "destination-id",
    Secret::new("a-host-generated-bearer-secret-at-least-32-characters"))?;
// Retain this immutable receiver alongside the host's destination configuration.
# let _ = receiver;
# Ok(()) }
```

## Callback acceptance

Ting sends `{"tings":[...]}`. Each Hook notification has the registered
`<hook-app-id>.webhook.received` type and a compact `new_event` envelope inside
`data`. The reference identifies the original event and its source environment.
Provider headers and raw body remain in Hook.

For each callback, the host:

1. Requires exactly one `Authorization` and `Ting-Webhook-Id` header and gives
   their values and the unmodified body to `Receiver::decode`.
2. Calls `Receiver::resolve(&client, &notifications)` with a current Hook token
   and the same selected environment. All references are checked before fetching
   any payload. Hook checks current IAM visibility on each lookup.
3. Durably accepts and deduplicates available events, keyed by Ting ID and the
   Hook event identity. Records and reports each `Unavailable` result separately;
   it is not completed application work. A durable application queue is
   sufficient for available events if that queue owns later processing retries.
4. Returns exactly HTTP 204 only after the complete batch is accepted.

```rust,no_run
# async fn decode_and_hydrate(
#     receiver: &silicon_hook_client::delivery::Receiver,
#     client: &silicon_hook_client::Client,
#     authorization: &str,
#     webhook_id: &str,
#     body: &[u8],
# ) -> silicon_hook_client::Result<()> {
let notifications = receiver.decode(authorization, webhook_id, body)?;
let outcomes = receiver.resolve(client, &notifications).await?;
// Persist/deduplicate every Event or Unavailable result before responding 204.
# let _ = outcomes;
# Ok(()) }
```

The SDK does not mark a fetched event as accepted, keep deduplication state, or
acknowledge Ting. Only Hook's structured `404 not_found`, after reference
validation and current authorization, produces an `Unavailable` result. Hook
retains payloads for 14 days; Ting can retain the reference longer. Saving this
terminal result lets later deliveries continue without inventing missing work.
The strict `hydrate` method instead fails on any missing original. Invalid,
unauthorized, transient and protocol failures still reject the batch. Do not
acknowledge a valid subset. A shared callback host must route
notifications for other applications separately; this receiver rejects
unhandled types. Batches are limited to 100 items and 2 MiB.

The hydrated `Event` preserves the original provider request. Binary payloads
use `request.body_base64`. `summary`, the source event ID, and the recorded
`delivery_sequence` remain available; sequence is useful metadata and does not
imply that Ting delivers in order.

## Lifecycle and delivery status

Token refresh is explicit and owned by the host. Replace both credentials
atomically and use the refreshed immutable `Client` for subsequent hydration.
Environment rotation or restore preserves retained events and their original
source generation. Clean destroys the old events, so queued references from
before a clean cannot hydrate in the new world.

`publication(silicon, event_id)` separates pending publication, acceptance by
Ting, and any available recipient receipt. Silent acceptance can occur when
Ting has muted notifications; it does not prove the destination received one.
Likewise a destination's HTTP 204 confirms its acceptance boundary, not that
later application processing finished.

`unsubscribe(silicon)` removes only the current Carbon's receiving interest and
queued observer sends. It preserves the primary Silicon's sends. An in-flight
notification already accepted by Ting may still arrive and must pass current
authorization during hydration.
