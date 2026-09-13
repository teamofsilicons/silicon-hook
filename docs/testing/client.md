# Test with the Rust client

```rust,no_run
use silicon_hook_client::{Client, Mutation, Recipient};
# async fn example(app_secret: &str, test_slt_or_id: &str) -> Result<(), Box<dyn std::error::Error>> {
let production = Client::new("https://backend.hook.teamofsilicons.com")?;
let sandbox = production.with_test_app_secret(app_secret)?;
let environment = sandbox.selected_environment().await?;
let sandbox = sandbox.with_organization(&environment.org_id);
let session = sandbox.login(test_slt_or_id,
    &Recipient::new("http://127.0.0.1:9000/test-events")?, &Mutation::new()).await?;
// Keep this caller-owned session alive for delivery and token refresh.
session.shutdown().await?;
# Ok(()) }
```

`with_test_app_secret` makes an immutable selector and clears any old actor token/organization. It does not persist anything. `selected_environment` validates with IAM through Hook and returns public sandbox metadata. Set the organization and authenticate inside that sandbox.

Retain the production client separately. `without_test_environment` clears both selector and actor credentials, so it cannot accidentally reuse a test token in production. A host already managing tokens can call `authenticate`, `with_token` and `with_organization` directly instead of starting a session.

For several identities, use `RelayRegistration` and `run_shared_relay` with a watch channel. It multiplexes their independent credentials over one connection and remains prewarmed with an empty registration list. The CLI owns a system daemon; SDK sessions are caller-owned and in-memory. Avoid running SDK-owned listeners alongside an already running CLI daemon on the same default port; use the daemon's local API when sharing system delivery.
