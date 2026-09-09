# Testing through the Rust client

Start with a production client authenticated in the environment-owning org:

```rust,no_run
use silicon_hook_client::{Client, Mutation, Recipient, Secret, models::CreateEnvironment};
# async fn example(production: Client) -> Result<(), Box<dyn std::error::Error>> {
let created = production.create_environment(&CreateEnvironment {
    name: "provider test".into(),
    description: None,
    iam_test_key: Secret::new(std::env::var("IAM_TEST_KEY")?),
    iam: None,
}, &Mutation::new()).await?;
let test = Client::new(production.base_url().as_str())?
    .with_test_key(created.key.expose())?;
// Install test application credentials with test.configure_test_iam(...).
let recipient = Recipient::new("http://127.0.0.1:9000/events")?;
let session = test.login(&std::env::var("IAM_TEST_SLT")?, &recipient, &Mutation::new()).await?;
let actor = session.client();
let hooks = actor.list_hooks("cos:tos", false).await?;
println!("{} test hooks", hooks.items.len());
session.shutdown().await?;
# Ok(()) }
```

Keep the environment ID/key separately from tokens. `without_test_environment`
removes the test selector only; it does not magically turn a test actor into a
production identity. Prefer retaining separate production and test clients.

Root methods `current_environment`, `clean_environment` and `configure_test_iam`
require the test selector. Environment creation/list/key rotation/deletion and
restoration use the production client. After key rotation rebuild test clients
with the replacement key. `Relay` credential watch channels can accept that
new immutable client and reconnect to the new generation.

For a reset, retain one `Mutation` until the result is certain. Reuse it if the
network disconnects; a fresh key represents a fresh reset and can erase newly
created data. Cleaning Hook leaves the linked IAM environment and identities
intact. All production hooks remain outside the selected test database.
