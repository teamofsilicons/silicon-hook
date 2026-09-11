# Stateless Rust client

The package is `silicon-hook-client`; the Rust import is `silicon_hook_client`.
For this source workspace use a path dependency on `crates/client`. Consumers
of a published release use its matching crates.io version. The SDK does not
persist authentication, environment keys or recipient configuration. Your
program owns those values. A login session refreshes tokens in memory and owns
its relay tasks; your program controls its lifetime and shutdown.

Version 0.3.0 uses the `new_event` delivery envelope with `data.sender` and
`data.metadata`. Upgrade the client/CLI and backend together; consumers of
0.2.x must update their event matching and field access to the new format.

## Sign in

Obtain an IAM short-lived token for `tos>hook` through IAM's existing
Carbon/Silicon login. Do not ask the user for their password or OTP in Hook.

```rust,no_run
use silicon_hook_client::{Client, Mutation};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let base = Client::new("https://backend.hook.teamofsilicons.com")?;
let iam = base.iam().await?;
println!("IAM application: {:?}", iam.app_id);
let slt = std::env::var("HOOK_SLT")?;
let login = Mutation::new();
let session = base.login_without_webhook(&slt, &login).await?;
session.webhook("http://127.0.0.1:9000/events")?;
let client = session.client();
let hooks = client.list_hooks("cos:tos", false).await?;
println!("{} hooks", hooks.items.len());
// Keep session alive while your application serves events.
session.shutdown().await?;
# Ok(()) }
```

`Recipient` validates HTTPS or local HTTP and rejects embedded credentials and
fragments. Configure it after login with `session.webhook(url)`, or pass it to
`Client::login` for the combined flow. It is never serialized to the backend. Login
starts the local request gateway, WebSocket relay and automatic token refresh.
It reserves the local port before consuming the SLT. `LoginOptions` and
`login_with_options` select Carbon streams, a different local port, or a relay
notice channel. A Silicon defaults to its own stream; a Carbon with no selected
streams still has a local request gateway. The default port is 18479; choose a
different port if a CLI daemon already owns it. Nothing is persisted.
`Client::new` accepts a pathless HTTPS origin or HTTP on loopback. Redirects
are disabled so credentials cannot follow a redirect to another service.

Tokens have redacted Debug output and zeroize their owned strings when dropped.
Use `Secret::expose()` only where plaintext is required. Serialization is
explicitly allowed because applications need to save credentials securely.
Avoid logging serialized token, hook-creation or environment-key responses.

The returned `RelaySession` automatically refreshes before token expiry; call
`session.client()` again to get the latest immutable client. Its `local_client()`
forwards identity-bound requests, `local_token()` supplies the local bearer,
`health()` queries its gateway, and `wait()` reports terminal relay failures.
`shutdown()` stops local work without revoking IAM; dropping it cancels its tasks.
To revoke, use its current refresh token with `logout`, then shut down.

Hosts that already manage a persistent relay, such as the CLI, use
`authenticate(slt, mutation)` and manage refresh themselves. The compatibility
`exchange_slt` method accepts a recipient but also only sends the SLT.
For this lower-level flow, refresh before `expires_in` elapses. Create one `Mutation`, pass it to
`refresh`, and retain it for retries. Replace the complete old token pair
atomically. To sign out the whole session family, construct a client with the
refresh token as bearer and call `logout(&mutation)`.

`session.webhook(url)` replaces the current destination; `session.unhook()`
detaches delivery while retaining authentication, token refresh and the local
gateway. Relay work is cancelled when the background task next runs; an in-flight
request may already have reached the old recipient. Unacknowledged events replay
when a destination is configured again. `session.recipient()` reads the local
setting. All of this state stays in memory. `LoginOptions::default()` starts
without a recipient; `LoginOptions::new(recipient)` starts with one.

`client.iam()` returns public configuration from the selected production/test
backend before login. `client.login_status()` verifies the current bearer and
organization membership online, returning an actor with `authenticated: true`.
Absent credentials or a 401 produce `authenticated: false`; outages and other
errors propagate. Select the organization with `with_organization` if the token
exchange did not bind one.

## Client selection and versioning

`with_token`, `with_organization`, `with_test_key` and `with_auto_update` return
clones with immutable configuration. They do not modify earlier clients. API
requests first negotiate `/api/version`, verify `service = silicon-hook` and
API v1, then pin requests with `silicon-hook-api-version: v1`.

A test client carries both a Hook test root key and a token minted in the linked
IAM test world. See [testing with Rust](../testing/client.md). Never attach a
production token to a test client as a fallback after a failed test login.

## Operations

| Area | Methods |
|---|---|
| Authentication | `login`, `login_without_webhook`, `login_with_options`, `authenticate`, `exchange_slt`, `login_status`, `refresh`, `logout` |
| Discovery | `iam`, `negotiate`, `version`, `health` |
| Hooks | `list_hooks`, `get_hook`, `create_hook`, `update_hook`, `delete_hook`, `restore_hook` |
| Activation | `set_enabled` with one or more hook UUIDs |
| Credentials | `rotate_endpoint`, `rotate_secret` |
| History | `events`, `blocked_requests` |
| Delivery | `deliveries`, `acknowledge`, `delivery_cursor`, `stream` |
| IAM | `connect_iam_hook` |
| Test administration | `create_environment`, `list_environments`, `environment`, `environment_key`, `rotate_environment_key`, `delete_environment`, `restore_environment`, `list_environments_page` |
| Test root operations | `current_environment`, `clean_environment`, `configure_test_iam` |
| Local service | `RelaySession`, `Relay::run`, `local::serve_local`, `local::LocalClient` |
| Updates | `updater::check`, `update_dependency`, `install_cli`, `find_manifest` |

All wire models are under `models`. `CreateHook::default()` plus a nonempty
name enables default HMAC-SHA256 verification. A `Signature` override changes
only fields supplied. `UpdateHook.description` and `Signature.public_key`
distinguish omission (`None`) from explicit clearing (`Some(None)`).

```rust,no_run
# async fn example(client: silicon_hook_client::Client) -> silicon_hook_client::Result<()> {
use silicon_hook_client::{Mutation, models::{CreateHook, UpdateHook}};
let mutation = Mutation::new();
let created = client.create_hook("cos:tos", &CreateHook {
    name: "GitHub".into(), ..Default::default()
}, &mutation).await?;
client.update_hook("cos:tos", created.hook.id, &UpdateHook {
    description: Some(None), ..Default::default()
}, &Mutation::new()).await?;
# Ok(()) }
```

## Failures, retries and limits

`Error::Api` includes HTTP status, stable code, message, request ID and optional
Retry-After. Transport errors mean the outcome of a mutation may be unknown.
Reuse its `Mutation` for a retry; do not generate a new key. Server error bodies
are decoded as structured Hook errors and are not dumped wholesale.

HTTP and WebSocket connection timeouts are 30 seconds. Stream writes time out
after 5 seconds, and 125 seconds without any server traffic causes reconnect in
the relay. WebSocket frames/messages are bounded at 4 MiB. Response buffering stops at 64 MiB; history is
already paginated within a backend byte budget. A request may ask for 1–10000
history records, but a byte-limited page can contain fewer: continue with
`next_cursor`. Delivery pulls allow up to 1000 events per call. Reading history
or pulling deliveries does not ACK them.

Delivery is at least once. Only ACK after successfully processing all earlier
retained events for that Silicon. ACK is cumulative per identity/Silicon, so
multiple consumers using the same identity share a cursor. Use separate IAM
identities when every consumer needs an independent copy.

## Streams and relay

`stream(&[silicon_ids])` yields Ready, Ping, NewEvent, AckRecorded and Error frames.
`ServerFrame::NewEvent { data }` carries the hook name in `data.sender` and the
complete event in `data.metadata`. On the wire it has exactly `type: new_event`
and `data` at the top level. Use the metadata's `silicon_id` and
`delivery_sequence` when acknowledging.
`Stream::next` immediately answers application and protocol pings. Keep calling
it while doing recipient work. `Stream::acknowledge` and `resume` send the
corresponding frames. Closing a stream never acknowledges pending events.

Use [the relay module](relay.md) for ordered local HTTP delivery with reconnect
and retry when your host manages its own lifecycle. Its credentials come through an in-memory watch channel. Your
program can refresh and replace them without restarting the application.

The interactive `crates/client/examples/relay_login.rs` example exercises login
and a live SDK relay. Run `cargo run -p silicon-hook-client --example relay_login`
with its documented environment variables; enter one command at a time.

## Updates

Automatic client checks are on by default and at most hourly in one process,
after an API request completes. The client checks crates.io and, when running
inside a consuming Cargo project, can advance the dependency's lockfile within
its manifest constraint. It skips Hook's own source workspace. Linked library
code changes only after a new build/restart; an update cannot replace compiled
code in a running process. Short-lived programs can use the explicit async
updater functions and await them before exiting.

Disable with `client.with_auto_update(false)` or
`SILICON_HOOK_CLIENT_AUTO_UPDATE=false`. Authentication remains stateless;
update timestamps for the SDK are in memory. The CLI handles its own persistent
hourly check and disables per-client background checks.

## Bring your own secret (BYOS)

Version 0.4.0 adds `Client::set_secret`. Creation and updates also accept
`Signature::secret` to configure the verification policy and secret together.

```rust,no_run
# async fn example(client: &silicon_hook_client::Client) -> silicon_hook_client::Result<()> {
use silicon_hook_client::{Mutation, Secret, models::{CreateHook, Signature}};
let created = client.create_hook("cos:tos", &CreateHook {
    name: "Provider".into(),
    signature: Some(Signature {
        secret: Some(Secret::new("provider-secret")),
        secret_encoding: Some("utf8".into()),
        ..Signature::default()
    }),
    ..CreateHook::default()
}, &Mutation::default()).await?;
client.set_secret("cos:tos", created.hook.id,
    Secret::new("replacement-secret"), None, &Mutation::default()).await?;
# Ok(()) }
```

`None` retains the current secret encoding; pass `Some("hex".into())` (or another
supported encoding) to change it. The previous secret stops verifying immediately.
Replacement preserves the URL, other policy fields and activation state and
returns no secret. You may create with a generated secret first, then set your
own after provider registration. A client selected with `with_test_key` applies
the same operations in the isolated testing environment. `Secret` redacts Debug
output; do not log serialized requests, which necessarily contain the secret.
