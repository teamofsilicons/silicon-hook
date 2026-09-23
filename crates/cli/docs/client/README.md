# Stateless Rust client

The package is `silicon-hook-client`; the Rust import is `silicon_hook_client`.
In this workspace use a path dependency on `crates/client`. Consumers of a
published release use its matching crates.io version.

This client uses Hook API v2 for management and authenticated event lookup.
The enclosing application handles IAM login, token storage and refresh, and
internal Ting receiving. Hook and Ting remain internal services; the user
does not need separate setup for either one. The SDK stores no credentials,
starts no listener or daemon, and owns no delivery connection.

## Sign in

The host obtains an IAM short-lived token for the selected Hook application
through its existing Carbon/Silicon login. Hook does not collect passwords or OTPs.

```rust,no_run
use silicon_hook_client::{Client, Mutation};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let base = Client::new("https://backend.hook.teamofsilicons.com")?;
let slt = std::env::var("HOOK_SLT")?;
let login = Mutation::new();
let tokens = base.login(&slt, &login).await?;
let client = base.with_token(tokens.access_token.expose())
    .with_organization("tos");
let hooks = client.list_hooks("cos:tos", false).await?;
println!("{} hooks", hooks.items.len());
# Ok(()) }
```

`login(slt, mutation)` and `authenticate(slt, mutation)` return the same `Tokens`
model. Neither changes the original client or configures receiving. Keep the
access and refresh tokens together in the host's secure session storage.
Before `expires_in` elapses, call `refresh(refresh_token, mutation)` explicitly
and atomically replace the complete pair. Keep one mutation key for retries of
the same exchange or refresh; an uncertain response may have consumed or rotated
the credential already.

To revoke the session family, call `logout(&mutation)` on a client whose bearer
is the current refresh token. Dropping a client has no remote side effects.

Tokens redact Debug output and zeroize their owned strings when dropped.
`Secret::expose()` gives plaintext only where needed. Serialization is explicit
because hosts may need to save credentials securely; never log serialized token,
hook-secret, or environment-key responses.

`iam()` discovers public application configuration before login.
`login_status()` checks the current bearer and selected organization online.
Absent credentials or a 401 return `authenticated: false`; outages and other
errors remain errors. If the token exchange did not bind an organization, the
host selects one with `with_organization`.

## Version and environment selection

`with_token`, `with_organization`, `with_test_key`, and `with_test_app_secret`
return immutable configurations. API calls first negotiate `/api/version`,
advertise only `v2`, verify `service = silicon-hook` and the selected major,
then use `/api/v2/` with `silicon-hook-api-version: v2`. A v1-only backend is
rejected before sending an SLT or a management mutation.

`Client::new` accepts a pathless HTTPS origin or HTTP on loopback (`localhost`,
`*.localhost`, or a loopback IP). Redirects are disabled. Authenticated requests
and test selectors stay on the configured Hook origin.

A test client uses a Hook test key or the linked IAM application's test secret,
plus an actor token from that test world. Changing to an application secret or
leaving testing clears the previous actor and organization. See
[testing with Rust](../testing/client.md). A failed test login must not fall
back to a production credential.

## Operations

| Area | Methods |
|---|---|
| Authentication | `login`, `authenticate`, `login_status`, `refresh`, `logout` |
| Discovery | `iam`, `negotiate`, `version`, `health` |
| Hooks | `list_hooks`, `get_hook`, `create_hook`, `update_hook`, `delete_hook`, `restore_hook` |
| Activation | `set_enabled` |
| Credentials | `rotate_endpoint`, `rotate_secret`, `set_secret` |
| History and lookup | `events`, `blocked_requests`, `event` |
| Internal receiving | `delivery_context`, `register_recipient`, `receiving_subscription`, `subscribe`, `unsubscribe`, `resolve_notification`, `hydrate_notification` |
| Scoped sandbox observation | `receiver_scope`, `bootstrap_receiver`, `renew_receiver` |
| Delivery status | `publication` |
| Internal publisher administration | `provision_publisher`, `replace_rejected_publisher` |
| IAM | `connect_iam_hook` |
| Test administration | `create_environment`, `list_environments`, `list_environments_page`, `environment`, `environment_key`, `rotate_environment_key`, `delete_environment`, `restore_environment` |
| Selected testing | `selected_environment`, `current_environment`, `clean_environment`, `configure_test_iam` |
| Release discovery | Explicit read-only `updater::check` |

Wire models live under `models`; receiving types live under `delivery`.
`CreateHook::default()` with a nonempty name enables default HMAC-SHA256
verification. A `Signature` override changes only supplied fields.
`UpdateHook.description` and `Signature.public_key` distinguish omission
(`None`) from explicit clearing (`Some(None)`).

```rust,no_run
# async fn example(client: &silicon_hook_client::Client) -> silicon_hook_client::Result<()> {
use silicon_hook_client::{Mutation, models::{CreateHook, UpdateHook}};
let created = client.create_hook("cos:tos", &CreateHook {
    name: "GitHub".into(), ..Default::default()
}, &Mutation::new()).await?;
client.update_hook("cos:tos", created.hook.id, &UpdateHook {
    description: Some(None), ..Default::default()
}, &Mutation::new()).await?;
# Ok(()) }
```

## Internal receiving

An organization owner/admin Carbon configures the backend's dedicated Silicon
publisher using `provision_publisher(&Secret, &Mutation)`. The SLT must be newly issued
for that server-owned Hook session, not an interactive session's refresh token.
The returned `PublisherMetadata` contains only organization, actor and expiry.
Reuse the same SLT and mutation for an uncertain provisioning result. To recover
a publisher whose session was rejected, explicitly call
`replace_rejected_publisher(slt, mutation)` with a fresh dedicated SLT and a new
operation key. This does not replace a currently usable publisher. See
[service setup](../ting-delivery.md) for scopes and notification-type provisioning.

The host configures its shared Ting session and destination internally, then
uses `delivery::Receiver` to validate the callback and hydrate compact event
references. See [receiving through Ting](relay.md) for the acceptance boundary.
There is no Hook WebSocket, local gateway, daemon, webhook destination setting,
cumulative cursor, or Hook ACK API in this client.

For sandbox inbox/watch observation, `receiver_scope` verifies the current
actor/app/organization/environment. Persist that scope and a caller-owned
`Mutation` before `bootstrap_receiver`. Retry them unchanged after uncertainty;
renew the original receiver ID using `renew_receiver` with a new mutation.
`ReceiverCapability` redacts its secret in Debug and retains the original expiry
on replay, even if expired. Check expiry before using it. The host owns the
scoped Ting inbox/watch transport and renewal; this capability cannot attach a
native destination, enable required delivery or ACK events. See
[sandbox receiving](../testing/client.md).

Silicons receive their own events after recipient setup. An authorized Carbon
uses `subscribe(silicon)` to request future events for a visible Silicon.
`unsubscribe` cancels that Carbon's queued sends without affecting the primary
Silicon. Already accepted Ting notifications cannot be retracted. The backend
checks current IAM visibility when hydrating every original webhook.

New primary Silicon sends use required automation delivery. Registration reports
the separate `required_delivery` opt-in, while publication and receipt expose
`DeliveryMode`. A silent required event can still reach a destination. The
enclosing app handles the recipient's explicit opt-in through its own Ting
session; the Hook client never enables it through application authority.

## Failures, retries and limits

`Error::Api` includes HTTP status, stable code, message, request ID, and optional
Retry-After. A transport error may leave a mutation's outcome unknown; reuse its
`Mutation` when retrying. Error bodies are decoded rather than dumped wholesale.
Requests time out after 30 seconds. Response buffering stops at 64 MiB, and
history is paginated within a backend byte budget. A 1–10000 item request may
return fewer records; continue with `next_cursor`.

Reading history or hydrating a notification does not acknowledge delivery.
Ting is at least once: the host must durably accept and deduplicate every item
in a callback batch before returning exactly HTTP 204. Acceptance by Ting,
delivery to a destination, and application processing are separate states.
`Receiver::resolve` returns an explicit unavailable result for a validated
reference whose original returns Hook's authenticated `404 not_found`. Persist
and report that result without treating it as work, so retained old notifications
do not block newer events. Authority and service failures remain retryable errors.

The one-shot `management_login` example lists hooks and revokes its temporary
session. Run `cargo run -p silicon-hook-client --example management_login` with
the environment variables documented in its source.

## Bring your own secret

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
}, &Mutation::new()).await?;
client.set_secret("cos:tos", created.hook.id,
    Secret::new("replacement-secret"), None, &Mutation::new()).await?;
# Ok(()) }
```

`None` retains the secret encoding. Pass an encoding such as `Some("hex".into())`
to change it. The previous secret stops verifying immediately. Replacement
preserves the URL, other policy fields, and activation state and returns no
secret. The same operations work in the selected testing environment.

## Updates

The Rust client is a normal dependency. It never runs Cargo, modifies a
lockfile, or schedules runtime updates. Update through the consuming project's
dependency workflow. `with_auto_update` remains a compatibility no-op;
Honeycomb owns CLI installation and updates.
