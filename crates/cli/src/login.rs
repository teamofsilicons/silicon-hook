//! `hook login` (device flow or short-lived token), `hook logout`, `hook whoami`.

use std::io::Read as _;

use serde_json::{Value, json};
use silicon_hook_client::signin::{DeviceEvent, SignIn, Tokens};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    args::{Cli, Login},
    output::{self, CliError, CliResult, EXIT_INTERRUPTED},
    session::{self, Urls},
    store::{self, Locked, Session},
};

pub fn time_text(unix: Option<i64>) -> Value {
    unix.and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .map_or(Value::Null, Value::String)
}

/// The JSON describing a signed-in session (shared with `login status`).
pub fn session_json(cli: &Cli, session: &Session, verified: bool) -> Value {
    let mut value = json!({
        "authenticated": true,
        "uuid": session.account.uuid,
        "id": session.account.id,
        "kind": session.account.kind.as_str(),
        "expires_at": time_text(Some(session.expires_at)),
        "refresh_expires_at": time_text(session.refresh_expires_at),
        "verified": verified,
        "profile": cli.profile,
        "method": session.method,
        "accounts_url": session.accounts_url,
        "url": session.url,
    });
    if !session.account.display_name.is_empty() {
        value["display_name"] = json!(session.account.display_name);
    }
    value
}

fn hostname() -> String {
    for var in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(value) = std::env::var(var)
            && !value.trim().is_empty()
        {
            return value.trim().to_owned();
        }
    }
    std::process::Command::new("hostname")
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown host".to_owned())
}

fn open_browser(url: &str) -> bool {
    let mut command = if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    } else if cfg!(target_os = "windows") {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    } else {
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return false;
        }
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

/// Reads a short-lived token without echoing it anywhere.
fn read_slt(args: &Login) -> CliResult<Option<zeroize::Zeroizing<String>>> {
    let mut text = zeroize::Zeroizing::new(String::new());
    if let Some(value) = args.slt.as_ref().or(args.token.as_ref()) {
        text.push_str(value);
    } else if args.slt_stdin || args.slt_file.as_deref() == Some("-") {
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|error| {
                CliError::invalid(
                    format!("Could not read the short-lived token from stdin: {error}."),
                    "Pipe it in: `silicon-accounts login --app hook -q | hook login --slt-stdin`.",
                )
            })?;
    } else if let Some(path) = &args.slt_file {
        std::fs::File::open(path)
            .and_then(|mut file| file.read_to_string(&mut text))
            .map_err(|error| CliError::io("read", std::path::Path::new(path), &error))?;
    } else {
        return Ok(None);
    }
    let trimmed = zeroize::Zeroizing::new(text.trim().to_owned());
    if trimmed.is_empty() {
        return Err(CliError::invalid(
            "The short-lived token is empty.",
            "Mint one with `silicon-accounts login --app hook -q` and pipe it into `hook login --slt-stdin`.",
        ));
    }
    Ok(Some(trimmed))
}

pub async fn login(cli: &Cli, args: &Login) -> CliResult<()> {
    let slt = read_slt(args)?;
    let folder = store::folder()?;
    let profile = store::read(&folder)?.profile(&cli.profile);
    let urls = session::urls(cli, &profile);
    // Validate both URLs before anything is sent.
    session::hook_client(&urls.hook, profile.telemetry)?;
    let client = session::sign_in(&urls.accounts)?;
    let (tokens, method) = match slt {
        Some(slt) => (client.exchange_slt(&slt).await?, "slt"),
        None => (device(cli, args, &client).await?, "device"),
    };
    store_session(cli, &client, tokens, &urls, method).await
}

async fn device(cli: &Cli, args: &Login, client: &SignIn) -> CliResult<Tokens> {
    let label = args
        .label
        .as_deref()
        .map(str::trim)
        .filter(|label| !label.is_empty())
        .map_or_else(
            || format!("hook CLI on {} ({})", hostname(), std::env::consts::OS),
            |label| label.chars().take(100).collect(),
        );
    let device = client.start_device(Some(&label), None).await?;
    let expires_at = store::now().saturating_add(i64::try_from(device.expires_in).unwrap_or(600));
    let page = device
        .verification_uri_complete
        .clone()
        .unwrap_or_else(|| device.verification_uri.clone());
    let opened = args.open && open_browser(&page);
    if cli.json {
        output::print_line(&json!({
            "event": "device_code",
            "user_code": device.user_code,
            "verification_uri": device.verification_uri,
            "verification_uri_complete": device.verification_uri_complete,
            "expires_at": time_text(Some(expires_at)),
            "interval": device.interval,
            "browser_opened": opened,
        }));
    } else {
        eprintln!(
            "To sign in to Hook, open {} and enter the code\n\n    {}\n\n{}Waiting for approval (the code expires in {} minutes; Ctrl-C to stop)...",
            device.verification_uri,
            device.user_code,
            if opened {
                "Your browser was opened.\n"
            } else {
                ""
            },
            device.expires_in.div_ceil(60)
        );
    }
    let json = cli.json;
    let wait = client.wait_for_device(&device, |event| match event {
        DeviceEvent::SlowDown(interval) => {
            if json {
                output::print_line(&json!({"event": "slow_down", "interval": interval.as_secs()}));
            } else {
                eprintln!("Silicon Accounts asked to poll more slowly; now every {} s.", interval.as_secs());
            }
        }
        DeviceEvent::Retrying { error, retry_in } => {
            if json {
                output::print_line(&json!({"event": "retrying", "message": error.to_string(), "retry_in": retry_in.as_secs()}));
            } else {
                eprintln!("{error} Retrying in {} s.", retry_in.as_secs());
            }
        }
        _ => {}
    });
    tokio::select! {
        result = wait => Ok(result?),
        _ = tokio::signal::ctrl_c() => Err(CliError::new(
            EXIT_INTERRUPTED,
            "interrupted",
            format!("Stopped waiting for approval of code {}.", device.user_code),
            "Run `hook login` again for a new code.",
        )),
    }
}

async fn store_session(
    cli: &Cli,
    client: &SignIn,
    tokens: Tokens,
    urls: &Urls,
    method: &str,
) -> CliResult<()> {
    let (mut locked, notice) = Locked::open(true)?;
    if let Some(notice) = notice {
        output::hint(cli.json, &notice);
    }
    let previous = locked.profile(&cli.profile).session.clone();
    let session = session::session_from(tokens, urls, client.app_id(), method, None)?;
    {
        let profile = locked.profile(&cli.profile);
        profile.session = Some(session.clone());
        profile.previous_version_session = false;
    }
    locked.save()?;
    drop(locked);
    // The replaced sign-in is ended, not left behind (best effort).
    if let Some(previous) = previous
        && let Some(refresh) = &previous.refresh_token
    {
        let ended = match session::sign_in(&previous.accounts_url) {
            Ok(old) => tokio::time::timeout(
                std::time::Duration::from_secs(10),
                old.with_app_id(&previous.app_id).revoke(refresh.expose()),
            )
            .await
            .is_ok_and(|result| result.is_ok()),
            Err(_) => false,
        };
        output::hint(
            cli.json,
            &if ended {
                format!(
                    "Replaced the previous sign-in as {} (it was signed out).",
                    previous.who()
                )
            } else {
                format!(
                    "Replaced the previous sign-in as {}; it could not be signed out at Silicon Accounts and stays listed in its sessions until it expires.",
                    previous.who()
                )
            },
        );
    }
    let mut value = session_json(cli, &session, true);
    value["signed_in"] = json!(true);
    if cli.json && method == "device" {
        output::print_line(&value);
    } else {
        output::print(&value)?;
    }
    output::hint(
        cli.json,
        &format!(
            "Signed in to Hook as {}. Next: hook login status --json · hook {} · hook --help",
            session.who(),
            if session.account.kind == silicon_hook_client::models::AccountKind::Silicon {
                "list"
            } else {
                "silicons"
            }
        ),
    );
    Ok(())
}

pub async fn logout(cli: &Cli) -> CliResult<()> {
    let folder = store::folder()?;
    if !folder.join(store::STATE_FILE).exists() {
        output::print(
            &json!({"signed_out": false, "reason": "not_signed_in", "profile": cli.profile}),
        )?;
        output::hint(cli.json, "Nothing to do: this profile was not signed in.");
        return Ok(());
    }
    let (mut locked, _) = Locked::open(false)?;
    let Some(session) = locked.profile(&cli.profile).session.clone() else {
        output::print(
            &json!({"signed_out": false, "reason": "not_signed_in", "profile": cli.profile}),
        )?;
        output::hint(cli.json, "Nothing to do: this profile was not signed in.");
        return Ok(());
    };
    let mut revoked = false;
    let mut warning = None;
    if let Some(refresh) = &session.refresh_token {
        match session::sign_in(&session.accounts_url) {
            Ok(client) => match tokio::time::timeout(
                std::time::Duration::from_secs(15),
                client.with_app_id(&session.app_id).revoke(refresh.expose()),
            )
            .await
            {
                Ok(Ok(())) => revoked = true,
                Ok(Err(error)) => warning = Some(error.to_string()),
                Err(_) => {
                    warning = Some("Silicon Accounts did not answer within 15 seconds.".into())
                }
            },
            Err(error) => warning = Some(error.to_string()),
        }
    }
    locked.profile(&cli.profile).session = None;
    locked.save()?;
    let mut value = json!({
        "signed_out": true,
        "uuid": session.account.uuid,
        "id": session.account.id,
        "revoked": revoked,
        "profile": cli.profile,
    });
    if let Some(warning) = &warning {
        value["warning"] = json!(warning);
        output::hint(
            cli.json,
            &format!(
                "Could not sign out at Silicon Accounts: {warning} The local sign-in was deleted anyway; end it from your Silicon Accounts sessions if it is still listed."
            ),
        );
    }
    output::print(&value)?;
    output::hint(
        cli.json,
        &format!(
            "Signed out of Hook ({}). Sign in again: hook login",
            session.who()
        ),
    );
    Ok(())
}

pub fn whoami(cli: &Cli) -> CliResult<()> {
    let folder = store::folder()?;
    let loaded = store::read(&folder)?;
    let profile = loaded.profile(&cli.profile);
    let Some(session) = &profile.session else {
        return Err(if profile.previous_version_session {
            session::previous_version_error(&cli.profile)
        } else {
            CliError::not_signed_in(&cli.profile)
        });
    };
    let mut value = session_json(cli, session, false);
    value["signed_in_at"] = time_text(Some(session.signed_in_at));
    if let Some(scope) = &session.scope {
        value["scope"] = json!(scope);
    }
    output::print(&value)?;
    output::hint(
        cli.json,
        "Saved locally; `hook login status` asks Hook to confirm it.",
    );
    Ok(())
}
