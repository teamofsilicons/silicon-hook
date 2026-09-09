//! Interactive SDK example: each command performs one caller-selected action.
//! Supply HOOK_SLT, HOOK_RECIPIENT, optional HOOK_URL/HOOK_TEST_KEY,
//! HOOK_RELAY_PORT and comma-separated HOOK_SILICONS through the environment.

use silicon_hook_client::{Client, LoginOptions, Mutation, Recipient, updater};
use tokio::io::{AsyncBufReadExt as _, BufReader};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut base = Client::new(
        &std::env::var("HOOK_URL")
            .unwrap_or_else(|_| "https://backend.hook.teamofsilicons.com".into()),
    )?
    .with_auto_update(false);
    if let Ok(key) = std::env::var("HOOK_TEST_KEY") {
        base = base.with_test_key(key)?;
    }
    let mut options = LoginOptions::new(Recipient::new(&std::env::var("HOOK_RECIPIENT")?)?);
    if let Ok(port) = std::env::var("HOOK_RELAY_PORT") {
        options.port = port.parse()?;
    }
    options.silicons = std::env::var("HOOK_SILICONS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let (notices, mut notice_rx) = tokio::sync::mpsc::channel(64);
    options.notices = Some(notices);
    let slt = zeroize::Zeroizing::new(std::env::var("HOOK_SLT")?);
    let session = base
        .login_with_options(&slt, &options, &Mutation::new())
        .await?;
    let target = options
        .silicons
        .first()
        .cloned()
        .unwrap_or_else(|| session.tokens().actor.id);
    println!("Local relay listening on hook.localhost:{}", session.port());
    println!("Commands: health, list, cursor, version, update-check, logout, quit");
    let display = tokio::spawn(async move {
        while let Some(notice) = notice_rx.recv().await {
            println!("{}", serde_json::to_string(&notice).unwrap_or_default());
        }
    });
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let client = session.client();
        let value = match line.trim() {
            "health" => session.health().await,
            "list" => client
                .list_hooks(&target, false)
                .await
                .and_then(|v| serde_json::to_value(v).map_err(Into::into)),
            "cursor" => client
                .delivery_cursor(&target)
                .await
                .and_then(|v| serde_json::to_value(v).map_err(Into::into)),
            "version" => client.version().await,
            "update-check" => updater::check(updater::CLIENT_PACKAGE, env!("CARGO_PKG_VERSION"))
                .await
                .and_then(|v| serde_json::to_value(v).map_err(Into::into)),
            "logout" => {
                client
                    .with_token(session.tokens().refresh_token.expose())
                    .logout(&Mutation::new())
                    .await?;
                println!("Session family revoked.");
                break;
            }
            "quit" => break,
            _ => {
                println!("Choose health, list, cursor, version, update-check, logout or quit.");
                continue;
            }
        };
        match value {
            Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
            Err(error) => eprintln!("{error}"),
        }
    }
    session.shutdown().await?;
    display.abort();
    Ok(())
}
