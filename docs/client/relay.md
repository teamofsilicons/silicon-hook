# Receiving through Ting

When the Hook server delivers through Ting, every verified provider request
reaches its Silicon (and Carbons who subscribed) as a compact reference. The app
that hosts the Silicon owns its Ting destination, the callback listener, durable
acceptance and token refresh; Hook's Rust client starts none of these. The
Silicon and its custodian never set anything up by hand.

Delivery through Ting is optional on the server. When the operator has not
configured it, Hook still receives, verifies and stores every event, queues
nothing, and says so: `client.delivery_status()` returns `enabled: false`,
`register_recipient` and `subscribe` answer `delivery_disabled`, and
`publication` reports `state: delivery_disabled`. Read events with
`client.events(..)` instead.

## Setup

1. Sign the receiving account in to Hook (see [Sign in](README.md#sign-in)) and
   keep its tokens.
2. `client.register_recipient()` enrols the account with Ting. Hook proves the
   account's agreement to Ting with a Silicon Accounts User verification proof
   made from the account's own Hook token; nothing else is needed.
3. A Carbon with access to a Silicon may call `client.subscribe(silicon)` to
   receive copies of its future events (no backfill). A Silicon receives its own
   events without subscribing.
4. Register the receiving destination with Ting and keep its destination id and
   a high-entropy bearer secret (32 characters or more). The receiving URL stays
   in Ting's configuration.
5. Build the receiver from the trusted context, never from a callback:

```rust,no_run
use silicon_hook_client::{Client, Secret, delivery::Receiver};

# async fn example(client: &Client) -> silicon_hook_client::Result<()> {
let context = client.delivery_context().await?; // Hook's app id + the account's uuid and id
let receiver = Receiver::new(
    context,
    "destination-id",
    Secret::new("a-host-generated-bearer-secret-at-least-32-characters"),
)?;
# let _ = receiver;
# Ok(()) }
```

## Callback acceptance

Ting sends `{"tings": [...]}`. Each Hook notification has the type
`hook.webhook.received`, the producer key `hook:{event id}:{sha256(recipient uuid)}`,
and inside `data` the envelope `{"type": "new_event", "data": {"sender", "metadata"}}`
where `metadata` is the reference:

```json
{
  "id": "0198c21a-6330-7000-8000-000000000001",
  "silicon": {"uuid": "Sx1", "id": "si:scout"},
  "hook_id": "0198c21a-6330-7000-8000-000000000002",
  "delivery_sequence": 42,
  "received_at": "2026-09-22T10:00:00Z",
  "summary": "stripe triggered at 10:00:00 22-09-2026 UTC"
}
```

`silicon.uuid` is permanent; fetch with it. `silicon.id` is the id the Silicon had
when the event arrived (display only). Provider headers and bodies stay in Hook.
A record's `for`, when Ting includes it, may name the recipient by uuid, by id or
as `{uuid, id}`; it must be the receiver's account.

For each callback, the host:

1. Requires exactly one `Authorization` and one `Ting-Webhook-Id` header and gives
   their values and the unmodified body to `Receiver::decode`.
2. Calls `Receiver::resolve(&client, &notifications)` with a current Hook token.
   Every reference is checked before any event is fetched, and Hook checks the
   account's access on each lookup.
3. Durably accepts and deduplicates the available events, keyed by Ting id and
   event id, and records each `Unavailable` result separately (it is not
   completed work).
4. Answers HTTP 204 only after the whole batch is accepted.

```rust,no_run
# async fn decode_and_resolve(
#     receiver: &silicon_hook_client::delivery::Receiver,
#     client: &silicon_hook_client::Client,
#     authorization: &str,
#     webhook_id: &str,
#     body: &[u8],
# ) -> silicon_hook_client::Result<()> {
let notifications = receiver.decode(authorization, webhook_id, body)?;
let outcomes = receiver.resolve(client, &notifications).await?;
// Persist and deduplicate every Event or Unavailable outcome, then answer 204.
# let _ = outcomes;
# Ok(()) }
```

The SDK never marks a fetched event as accepted, keeps no deduplication state and
never acknowledges Ting. Only Hook's `404 not_found` after validation becomes
`Unavailable` (Hook keeps events 14 days; Ting may keep the reference longer).
`hydrate` is the strict variant that fails on any missing event. Invalid,
unauthorized, transient and protocol failures reject the whole batch: never
acknowledge a valid subset. References that carry fields this version does not
know (for example those queued before Hook 1.0) are rejected. A shared callback
host routes other apps' notifications itself; this receiver rejects other types.
Batches hold at most 100 items and 2 MiB.

The hydrated `Event` is the original provider request. Binary bodies use
`request.body_base64`. `delivery_sequence` identifies the event within its hook's
stream; Ting does not promise order.

## Tokens and delivery status

Refreshing tokens is the host's job: refresh one at a time, store the new pair,
and build the next `Client` with the new access token.

`publication(silicon, event_id)` separates `pending`, `accepted_by_ting` and
`accepted_silently` (ordinary delivery while notifications are muted), and shows
Ting's receipt when available. `not_queued` means the event arrived while
delivery was off; `not_delivered_legacy` marks sends queued before Hook 1.0 that
Ting never accepted. A destination's 204 confirms its acceptance, not that the
application finished its work.

`unsubscribe(silicon)` stops only the current Carbon's copies; the Silicon's own
deliveries continue. A notification already accepted by Ting may still arrive,
and hydrating it checks access again.
