# Relay and local API

A relay connects a single Silicon stream using one IAM identity and sends its
events to that identity's configured local recipient. Run several `Relay`
instances for independent Silicons or recipients. A Carbon can subscribe to
several Silicons it may access. Distinct identities have distinct backend
cursors. Two relays using the same identity and Silicon share a cursor.

## Embedded relay

`Client::login` starts and owns these tasks automatically in a `RelaySession`,
including the loopback gateway and token refresh. Keep that session alive.
Use `Client::login_without_webhook` to authenticate first, then
`session.webhook(url)` to enable delivery. `session.unhook()` detaches delivery
while keeping authentication and the gateway alive.
The lower-level example below is for applications that already supervise their
own authentication and server lifetimes (the CLI uses this approach).

```rust,no_run
use silicon_hook_client::{Client, Recipient, Relay};
use tokio::sync::watch;
# async fn example(client: Client) -> silicon_hook_client::Result<()> {
let (credentials, current) = watch::channel(client);
let (stop, shutdown) = watch::channel(false);
let relay = Relay {
    silicon_id: "cos:tos".into(),
    recipient: Recipient::new("http://127.0.0.1:9000/events")?,
};
// Another task retains `credentials`, refreshes tokens, and calls send_replace.
// To shut down, call stop.send(true). Dropping the senders also stops the relay.
relay.run(current, shutdown, None).await?;
# drop((credentials, stop)); Ok(()) }
```

Every recipient POST has exactly two top-level fields: `type` and `data`.
`type` is `new_event`. `data` contains `sender` (the hook's provider name at
receipt) and `metadata` (the complete retained event). For example:

```json
{
  "type": "new_event",
  "data": {
    "sender": "stripe",
    "metadata": {
      "id": "00000000-0000-4000-8000-000000000001",
      "org_id": "tos",
      "silicon_id": "cos:tos",
      "hook_id": "00000000-0000-4000-8000-000000000002",
      "provider": "stripe",
      "summary": "stripe triggered at 12:00:00 11-09-2026 UTC",
      "delivery_sequence": 42,
      "received_at": "2026-09-11T12:00:00Z",
      "request": {
        "method": "POST",
        "url": "https://hook.teamofsilicons.com/silicon/cos:tos/ABCDEFGH/",
        "path": "/silicon/cos:tos/ABCDEFGH/",
        "query_string": "",
        "headers": [["content-type", "application/json"]],
        "content_type": "application/json",
        "body": "{\"example\":true}",
        "body_base64": null,
        "remote_ip": "203.0.113.1"
      }
    }
  }
}
```

This is also the WebSocket event delivery shape, including replays. Event ID,
Silicon ID, sequence, summary, timestamp and original request are all nested
under `data.metadata`; none are extra top-level fields. Non-UTF-8 request bytes
remain available in `data.metadata.request.body_base64`.
Headers `silicon-hook-event-id` and `silicon-hook-delivery-sequence` make
HTTP deduplication convenient. Consumers of the previous `type: event` shape
must switch to `type: new_event` and read event details from `data.metadata`.

A 2xx status acknowledges receipt. Redirects are not followed; 3xx, 4xx, 5xx,
connection failures and the 20-second timeout all retry, with exponential delays
up to 30 seconds. Responses do not need a special JSON body. Only after a
successful response does the relay send upstream ACK. Deduplicate by event ID:
a connection can fail after the recipient commits but before Hook receives ACK.

Each Silicon is processed sequentially. The WebSocket reader runs alongside
delivery and continues answering pings during recipient retries. The backend
limits each stream to 32 outstanding events; the relay has a bounded queue.
Reconnect starts at the backend's persisted cursor. No separate local event
spool is required, and stopping the relay does not lose pending deliveries.
The backend's 14-day retention remains the maximum recovery horizon.

Credential updates cancel old work and reconnect. Environment key rotation,
reset or reconfiguration closes old sessions, so supply the current test key.
A reset also clears delivery positions and retained events.

## Local request API

The CLI daemon listens on `127.0.0.1:18479`, named
`http://hook.localhost:18479`. `local::LocalClient` explicitly resolves that
name to loopback. Programs using another HTTP client may use 127.0.0.1 directly
or provide its equivalent resolver setting.

Every `/request` call requires a local bearer token selecting one saved
profile/environment. Obtain it with `hook [context] daemon token`. This token
is separate from the IAM access token. The daemon injects the selected IAM
bearer, organization and Hook test key; callers cannot override them. Requests
with an Origin header are rejected, and Host must name the loopback service.

POST `/request` with:

```json
{
  "method": "GET",
  "path": "/api/v1/silicons/cos:tos/hooks",
  "query": [],
  "headers": [],
  "body_base64": ""
}
```

Allowed methods are GET, POST, PUT, PATCH and DELETE. Paths must be literal
public Hook API routes, `/api/version` or `/readyz`; encoded/traversal paths are
rejected. Only Content-Type, Accept and Idempotency-Key can be set by the
caller. Query entries are name/value pairs. Body bytes use standard base64.
The local request limit is 2 MiB including the JSON envelope.

The response acknowledges receipt with `received: true`, echoes the exact input
JSON bytes as `request.body_base64`, the query string and original headers as
`headers_base64` name/base64-value pairs, and includes the backend `response.status`,
response headers and base64 body. This receipt confirms the local request was
received; inspect the nested backend status to determine whether the action
succeeded. On transport failure the nested response contains an error; retry a
mutation using the same Idempotency-Key. Echoes are returned only to the caller
and are not posted back to the provider or stored as Hook events.

`local::serve_local` offers the same interface for embedded applications. Supply
a watch channel of `LocalIdentity` values, a random control secret and a stop
channel. The separate control secret authenticates `/health` and
`POST /control/stop`. No network destination beyond loopback can be bound by
this server API.
