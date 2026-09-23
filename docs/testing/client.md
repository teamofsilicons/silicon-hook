# Test with the Rust client

```rust,no_run
use silicon_hook_client::{Client, Mutation};
# async fn example(app_secret: &str, test_slt_or_id: &str) -> Result<(), Box<dyn std::error::Error>> {
let production = Client::new("https://backend.hook.teamofsilicons.com")?;
let sandbox = production.with_test_app_secret(app_secret)?;
let environment = sandbox.selected_environment().await?;
let sandbox = sandbox.with_organization(&environment.org_id);
let tokens = sandbox.login(test_slt_or_id, &Mutation::new()).await?;
let client = sandbox.with_token(tokens.access_token.expose());
let context = client.delivery_context().await?;
assert_eq!(context.environment_id, environment.id);
# Ok(()) }
```

`with_test_app_secret` makes an immutable selector and clears any old actor token/organization. It does not persist anything. `selected_environment` validates with IAM through Hook and returns public sandbox metadata. Set the organization and authenticate inside that sandbox.

Retain the production client separately. `without_test_environment` clears both selector and actor credentials, so it cannot accidentally reuse a test token in production. The host stores and refreshes tokens explicitly; the SDK starts no session task or listener.

The enclosing app selects matching test IAM, Hook and Ting contexts and handles Ting login/destination setup internally. Its shared Ting transport calls the stateless [receiving adapter](../client/relay.md). Bind the adapter to the selected environment UUID and resolve every original reference using current Hook authorization. Key rotation preserves retained event references; cleaning removes their payloads. Durably record an unavailable outcome for a validated reference whose lookup returns `404 not_found`, and report it separately from accepted work before acknowledging the complete batch. Never fall back to production or invent a missing payload. Other authorization, transport and protocol failures reject the batch.

For an inbox/watch observer, Ting 0.1.4 permits setup using only Hook's selected
test app secret and actor session:

```rust,no_run
# use silicon_hook_client::{Client, Mutation};
# async fn observe(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
client.register_recipient().await?;
let scope = client.receiver_scope().await?;
let operation = Mutation::new();
// Persist scope and operation.key() privately before sending.
let capability = client.bootstrap_receiver(&scope, &operation).await?;
// The host keeps the token private and checks expires_at before watching.
let renewal = Mutation::new();
let next = client.renew_receiver(&scope, &capability.receiver_id, &renewal).await?;
assert_eq!(next.receiver_id, capability.receiver_id);
# Ok(()) }
```

The scope's generation is Honeycomb's shared generation, not Hook's credential
generation or the original event reference's generation. An uncertain operation
must retry with the same scope/key/body. Exact replay does not extend expiry.
Do not silently select a newer generation after clean or rotation.

The host reads `/v1/receivers/inbox` and watches `/v1/receivers/ws?protocol=v1`
with the capability, renews before its at-most-30-second expiry, reconnects and
reconciles the inbox. It revokes through `DELETE /v1/receivers/session`, including
after expiry. These routes never ACK or provide general Ting authority. Native
destinations still require the enclosing runtime's own matching Ting session;
required automation requires a separate explicit recipient opt-in.
