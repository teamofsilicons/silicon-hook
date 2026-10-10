//! `hook login status` and `hook accounts`: the two discovery commands every
//! Silicon Apps app answers signed out, offline, in an empty home.

use serde_json::{Value, json};
use silicon_hook_client::{API_VERSION, Error as ClientError, signin::APP_ID, support};

use crate::{
    args::Cli,
    login::session_json,
    output::{self, CliError, CliResult},
    session::{self, Urls},
    store::{self, Locked, Profile},
};

const INSTALL: &str = "silicon-apps install hook";
const CARBON_LOGIN: &str = "hook login";
const SILICON_LOGIN: &str = "silicon-accounts login --app hook -q | hook login --slt-stdin";

/// `hook accounts --json` (and the hidden `hook iam --json`): offline, exit 0.
pub fn accounts(cli: &Cli) -> Value {
    let mut warnings = Vec::new();
    let folder = store::folder().ok();
    let profile = folder
        .as_ref()
        .and_then(|folder| store::read(folder).ok())
        .map(|loaded| loaded.profile(&cli.profile))
        .unwrap_or_default();
    let urls = session::urls(cli, &profile);
    if let Err(error) = session::hook_client(&urls.hook, false) {
        warnings.push(error.message.clone());
    }
    if let Err(error) = session::sign_in(&urls.accounts) {
        warnings.push(error.message.clone());
    }
    let mut value = json!({
        "app_id": APP_ID,
        "name": "Silicon Hook",
        "version": env!("CARGO_PKG_VERSION"),
        "accounts_url": urls.accounts,
        "api_url": urls.hook,
        "api_version": API_VERSION,
        "docs": support::DOCUMENTATION,
        "repository": support::REPOSITORY,
        "install": INSTALL,
        "sign_in": {
            "carbon": CARBON_LOGIN,
            "silicon": SILICON_LOGIN,
            "slt_command": "silicon-accounts login --app hook -q",
        },
        "state_dir": folder.map(|f| f.display().to_string()),
    });
    if !warnings.is_empty() {
        value["warnings"] = json!(warnings);
    }
    value
}

fn signed_out(reason: Option<&str>, message: Option<&str>) -> Value {
    let mut value = json!({"authenticated": false});
    if let Some(reason) = reason {
        value["reason"] = json!(reason);
    }
    if let Some(message) = message {
        value["message"] = json!(message);
    }
    value
}

/// Prints a signed-out answer: exit 0 with `--json`, else 1 (like
/// `silicon-accounts login status`).
fn finish_signed_out(cli: &Cli, value: &Value) -> CliResult<i32> {
    output::print(value)?;
    output::hint(
        cli.json,
        &format!(
            "Not signed in{}. Carbons: {CARBON_LOGIN}. Silicons: {SILICON_LOGIN}.",
            value["message"]
                .as_str()
                .map_or_else(String::new, |m| format!(": {m}"))
        ),
    );
    Ok(if cli.json { 0 } else { 1 })
}

/// `hook login status [--offline]`. Returns the exit code.
pub async fn status(cli: &Cli, offline: bool) -> CliResult<i32> {
    let Ok(folder) = store::folder() else {
        return finish_signed_out(
            cli,
            &signed_out(
                Some("no_home"),
                Some("neither SILICON_HOME nor HOME is set"),
            ),
        );
    };
    let loaded = match store::read(&folder) {
        Ok(loaded) => loaded,
        Err(error) => {
            return finish_signed_out(
                cli,
                &signed_out(Some("state_unreadable"), Some(&error.message)),
            );
        }
    };
    if let Some(problem) = &loaded.unreadable {
        return finish_signed_out(cli, &signed_out(Some("state_unreadable"), Some(problem)));
    }
    let profile = loaded.profile(&cli.profile);
    let urls = session::urls(cli, &profile);
    let Some(stored) = profile.session.clone() else {
        if profile.previous_version_session {
            let error = session::previous_version_error(&cli.profile);
            return finish_signed_out(
                cli,
                &signed_out(Some("previous_version_session"), Some(&error.message)),
            );
        }
        return finish_signed_out(cli, &signed_out(None, None));
    };
    if let Some(problem) = session::binding_problem(&stored, &urls) {
        let mut value = signed_out(Some("signed_in_elsewhere"), Some(&problem.message));
        value["session_accounts_url"] = json!(stored.accounts_url);
        value["session_url"] = json!(stored.url);
        return finish_signed_out(cli, &value);
    }
    if offline {
        if stored.ended() {
            return finish_signed_out(
                cli,
                &signed_out(Some("session_ended"), Some("the sign-in reached its end")),
            );
        }
        output::print(&session_json(cli, &stored, false))?;
        return Ok(0);
    }
    match online(cli, &urls, &profile).await {
        Ok(code) => Ok(code),
        // `--json` always answers: show the saved sign-in, unconfirmed, with why.
        Err(error) => unverified(cli, &stored, &error.message),
    }
}

async fn online(cli: &Cli, urls: &Urls, profile: &Profile) -> CliResult<i32> {
    let mut forced = false;
    loop {
        let (client, session) = match session::signed_in_client(cli, forced).await {
            Ok((client, session, _)) => (client, session),
            Err(error) if is_unavailable(&error) => {
                let stored = profile
                    .session
                    .clone()
                    .ok_or_else(|| CliError::not_signed_in(&cli.profile))?;
                return unverified(cli, &stored, &error.message);
            }
            Err(error) if error.exit == output::EXIT_AUTH => {
                return finish_signed_out(
                    cli,
                    &signed_out(Some(&error.code), Some(&error.message)),
                );
            }
            Err(error) => return Err(error),
        };
        match client.login_status().await {
            Ok(status) if status.authenticated => {
                let mut session = session;
                if let Some(id) = status.id.filter(|id| *id != session.account.id) {
                    session.account.id.clone_from(&id);
                    save_id(cli, &id)?;
                }
                output::print(&session_json(cli, &session, true))?;
                output::hint(
                    cli.json,
                    &format!("Signed in to Hook ({}) as {}.", urls.hook, session.who()),
                );
                return Ok(0);
            }
            Ok(status) if !forced => {
                // Hook refused the token; one refresh may fix it (for example a
                // sign-out elsewhere that did not end this sign-in).
                let _ = status;
                forced = true;
            }
            Ok(status) => {
                let reason = status.reason.unwrap_or_else(|| "token_refused".into());
                let message = status
                    .message
                    .unwrap_or_else(|| "Hook refused the access token.".into());
                return finish_signed_out(cli, &signed_out(Some(&reason), Some(&message)));
            }
            Err(ClientError::Transport(error)) => {
                return unverified(
                    cli,
                    &session,
                    &format!("Hook could not be reached ({error})"),
                );
            }
            Err(ClientError::Api(api)) if api.status >= 500 => {
                return unverified(
                    cli,
                    &session,
                    &format!("Hook answered {} ({})", api.status, api.code),
                );
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn is_unavailable(error: &CliError) -> bool {
    error.code == "unavailable" || error.code == "hook_unreachable"
}

fn unverified(cli: &Cli, session: &store::Session, why: &str) -> CliResult<i32> {
    let mut value = session_json(cli, session, false);
    value["warning"] = json!(format!(
        "{why}; the saved sign-in is shown without confirmation."
    ));
    output::print(&value)?;
    output::hint(
        cli.json,
        &format!("{why}. Showing the saved sign-in unconfirmed."),
    );
    Ok(0)
}

fn save_id(cli: &Cli, id: &str) -> CliResult<()> {
    let (mut locked, _) = Locked::open(false)?;
    if let Some(session) = locked.profile(&cli.profile).session.as_mut() {
        session.account.id = id.to_owned();
    }
    locked.save()
}
