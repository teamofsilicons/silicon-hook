//! One-shot management example. Supply HOOK_SLT, optionally HOOK_URL,
//! HOOK_TEST_KEY, HOOK_ORG, and HOOK_SILICON. No receiving tasks are started.

use silicon_hook_client::{Client, Mutation};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut base = Client::new(
        &std::env::var("HOOK_URL")
            .unwrap_or_else(|_| "https://backend.hook.teamofsilicons.com".into()),
    )?;
    if let Ok(key) = std::env::var("HOOK_TEST_KEY") {
        base = base.with_test_key(key)?;
    }
    let slt = zeroize::Zeroizing::new(std::env::var("HOOK_SLT")?);
    let tokens = base.login(&slt, &Mutation::new()).await?;
    let org = tokens
        .org_id
        .as_deref()
        .map(str::to_owned)
        .or_else(|| std::env::var("HOOK_ORG").ok())
        .ok_or("set HOOK_ORG when the token has no organization")?;
    let target = std::env::var("HOOK_SILICON")
        .ok()
        .or_else(|| (tokens.actor.kind == "silicon").then(|| tokens.actor.id.clone()))
        .ok_or("set HOOK_SILICON for a Carbon management session")?;
    let client = base
        .with_token(tokens.access_token.expose())
        .with_organization(&org);
    let result = client.list_hooks(&target, false).await;
    // This one-shot example does not retain a session. Long-lived hosts store
    // both tokens securely and use explicit refresh instead.
    client
        .with_token(tokens.refresh_token.expose())
        .logout(&Mutation::new())
        .await?;
    println!("{}", serde_json::to_string_pretty(&result?)?);
    Ok(())
}
