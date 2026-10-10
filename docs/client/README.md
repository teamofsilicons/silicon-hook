# Rust client

The package is `silicon-hook-client` (import `silicon_hook_client`). It is
stateless: it stores no credentials, starts no listener or daemon, and never
updates itself. The host keeps its tokens and decides when to call. The `hook`
CLI is built on this crate only.

```toml
[dependencies]
silicon-hook-client = "1"
```

Three parts:

| Module | For |
| --- | --- |
| [`signin`](#sign-in) | Getting a Silicon Accounts access token issued to Hook, as Hook's public client (no secret) |
| [`Client`](#call-hook) | Hook API v3 with that token: a Silicon's hooks, history, access, delivery status |
| [`delivery`](relay.md) | Checking Ting callbacks and fetching the events they point to |

## Sign in

Hook accepts Silicon Accounts access tokens whose audience is `hook`. Hook's own
tools get them as a public client:

```rust,no_run
use silicon_hook_client::signin::SignIn;

# async fn demo() -> silicon_hook_client::Result<()> {
let sign_in = SignIn::production()?; // or SignIn::new("http://localhost:9590")? locally

// A Silicon: a short-lived token from `silicon-accounts login --app hook -q`.
let tokens = sign_in.exchange_slt("slt_...").await?;

// A Carbon: the device flow.
let device = sign_in.start_device(Some("my tool on build-box"), None).await?;
println!("open {} and enter {}", device.verification_uri, device.user_code);
let tokens = sign_in.wait_for_device(&device, |_progress| {}).await?;

let account = tokens.account.as_ref().expect("token responses carry the account");
println!("signed in as {} ({}), a {}", account.id, account.uuid, account.kind.as_str());
# Ok(()) }
```

`wait_for_device` honours the server's interval, adds five seconds on each
`slow_down`, retries transient failures (reported through the callback) and gives
up when the code expires (10 minutes). `Tokens` holds a 30-minute
`access_token`, a rotating `refresh_token`, `expires_in`, `refresh_expires_at`,
`scope` and the `account` (`uuid`, `kind`, `id`, `display_name`, `pfp_url`, and a
Silicon's `custodian`).

Keep the pair together. Before the access token expires, call
`sign_in.refresh(refresh_token)`: it spends the refresh token you send and
returns a new pair. Silicon Accounts ends the whole sign-in if a spent refresh
token is presented again, so refresh one at a time per sign-in and store the new
pair before using it. `sign_in.revoke(refresh_token)` signs out.

Failures are `Error::SignIn` with a `kind` you can act on:

| `SignInErrorKind` | Meaning |
| --- | --- |
| `SltRefused(SltRefusal)` | The short-lived token was refused: `AlreadyUsed`, `Expired`, `WrongApp`, `Unknown`, `NotAnSlt`, `Ended`. Mint a fresh one. |
| `SessionEnded` | The refresh token no longer works: sign in again. |
| `Denied`, `Expired` | The device sign-in was denied, or its code expired. |
| `NotEnabled` | Hook's sign-in setup at that Silicon Accounts does not allow this sign-in. |
| `Unavailable { maybe_processed }` | Silicon Accounts could not be reached or failed. `maybe_processed` says whether the request may have been handled (a refresh token may then be spent). |
| `Rejected` | Any other refusal; `code`, `message` and `hint` say what. |

Servers that hold their own Silicon Accounts app secret use
`silicon-accounts-client`'s `AppClient` instead; any route works as long as the
token's audience is `hook`.

## Call Hook

```rust,no_run
use silicon_hook_client::{Client, Mutation, models::{CreateHook, UpdateHook}};

# async fn demo(access_token: &str) -> silicon_hook_client::Result<()> {
let hook = Client::production()?.with_token(access_token);
let created = hook
    .create_hook("si:scout", &CreateHook { name: "GitHub".into(), ..Default::default() }, &Mutation::new())
    .await?;
println!("give GitHub {}", created.hook.endpoint_url);
hook.update_hook("si:scout", created.hook.id, &UpdateHook {
    description: Some(None), // explicit null clears it
    ..Default::default()
}, &Mutation::new()).await?;
# Ok(()) }
```

`Client::new` takes a pathless HTTPS origin, or plain HTTP on this machine
(`localhost`, `*.localhost`, a loopback address). Redirects are off. Before the
first call the client checks `/api/version`: the server must be `silicon-hook`
serving API `v3`, and every request then pins `Silicon-Hook-API-Version: v3`.

`with_token` and `with_telemetry` return new, immutable clients. Every `silicon`
argument accepts the Silicon's current `si:` id or its uuid; responses show
accounts as `{uuid, id}` (and `kind` for `created_by`, grants and the like).

| Area | Methods |
| --- | --- |
| Sign-in and status | `sign_in_information` (public), `login_status`, `negotiate`, `version`, `health`, `contracts` |
| Silicons and access | `silicons`, `access`, `grant`, `revoke`, `leave`, `allow_list`, `allow`, `disallow` |
| Hooks | `list_hooks`, `get_hook`, `create_hook`, `update_hook`, `set_secret`, `delete_hook`, `restore_hook`, `set_enabled`, `rotate_endpoint`, `rotate_secret` |
| Silicon Accounts updates | `connect_accounts_hook` |
| History | `events`, `blocked_requests`, `event` |
| Delivery through Ting | `delivery_status`, `register_recipient`, `receiving_subscription`, `subscribe`, `unsubscribe`, `publication`, `delivery_context`, `resolve_notification`, `hydrate_notification` |
| Diagnostics | `emit_telemetry` (opt-out with `with_telemetry(false)` or `SILICON_HOOK_TELEMETRY=off`) |

Mutations take a `Mutation`: one idempotency key per logical change. Reuse the
same `Mutation` when retrying after an uncertain result, and Hook answers with
the first result instead of applying the change twice.

`login_status` returns `authenticated: false` without a token or when Hook
refuses the token (401), with Hook's `reason` and `message`; outages stay errors.

## Errors

`Error::Api` keeps Hook's error envelope: `status`, the stable `code`, `message`,
`details`, `hint`, `request_id` and `retry_after`. `error.code()`,
`error.status()`, `error.hint()`, `error.is_code("…")` and
`error.is_unauthenticated()` work across kinds. Other kinds: `Invalid` (nothing
was sent), `Transport` (Hook unreachable), `Protocol` (not Hook API v3, or an
unexpected answer), `Json`, and `SignIn`.

Secrets (`Secret`) never appear in `Debug` output and are wiped when dropped;
`expose()` returns the plaintext where it must leave the program. Creation and
rotation responses carry signing secrets once; store them privately and never log
serialized responses.

## Who can call what

The Silicon and its custodian can do everything with the Silicon's hooks.
`manage` grants create and change hooks; `view` grants read hooks, history and
delivery status. Granting, revoking and the allow-list belong to the Silicon and
its custodian. A custodian acts as itself, never as the Silicon. See
[Sign in to Hook](../accounts/README.md#who-can-do-what).

## Examples

- `examples/management_login.rs`: a Silicon signs in with a short-lived token,
  lists its hooks and signs out.
- `examples/ting_receiver_e2e.rs`: a fixture host that receives Ting callbacks,
  hydrates them and accepts them durably.
