//! One-shot management example for a Silicon.
//!
//! ```sh
//! export HOOK_SLT=$(silicon-accounts login --app hook -q)
//! cargo run -p silicon-hook-client --example management_login
//! ```
//!
//! Optional: `ACCOUNTS_URL`, `HOOK_URL`, `HOOK_SILICON` (another Silicon you look
//! after or were granted). The example signs out at the end; a long-lived host
//! keeps both tokens and refreshes one at a time instead.

use silicon_hook_client::{Client, signin::SignIn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sign_in = SignIn::new(
        &std::env::var("ACCOUNTS_URL")
            .unwrap_or_else(|_| silicon_hook_client::signin::DEFAULT_ACCOUNTS_URL.into()),
    )?;
    let slt = zeroize::Zeroizing::new(std::env::var("HOOK_SLT")?);
    let tokens = sign_in.exchange_slt(&slt).await?;
    let me = tokens
        .account
        .clone()
        .ok_or("the token response names no account")?;
    let target = std::env::var("HOOK_SILICON").unwrap_or_else(|_| me.uuid.clone());
    let client = Client::new(
        &std::env::var("HOOK_URL").unwrap_or_else(|_| silicon_hook_client::DEFAULT_URL.into()),
    )?
    .with_token(tokens.access_token.expose());
    let result = client.list_hooks(&target, false).await;
    if let Some(refresh) = &tokens.refresh_token {
        sign_in.revoke(refresh.expose()).await?;
    }
    println!("{}", serde_json::to_string_pretty(&result?)?);
    Ok(())
}
