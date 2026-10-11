//! `hook config`: local settings per profile. Tokens are never shown.

use serde_json::json;

use crate::{
    args::{Cli, Config},
    output::{self, CliError, CliResult},
    session,
    store::{self, Locked},
};

pub fn run(cli: &Cli, action: &Config) -> CliResult<()> {
    match action {
        Config::Show => show(cli),
        Config::Profiles => {
            let folder = store::folder()?;
            let loaded = store::read(&folder)?;
            output::print(&loaded.state.profiles.keys().collect::<Vec<_>>())
        }
        Config::Home { location } => {
            let path = store::set_home(location)?;
            output::print(&json!({"home": path}))?;
            output::hint(
                cli.json,
                "From now on Hook keeps its state there. Sign in again in the new place: hook login",
            );
            Ok(())
        }
        Config::Set { key, value } => set(cli, key, Some(value)),
        Config::Unset { key } => set(cli, key, None),
    }
}

fn show(cli: &Cli) -> CliResult<()> {
    let folder = store::folder()?;
    let loaded = store::read(&folder)?;
    let profile = loaded.profile(&cli.profile);
    let urls = session::urls(cli, &profile);
    let mut value = json!({
        "profile": cli.profile,
        "state_dir": folder,
        "url": urls.hook,
        "url_source": urls.hook_source,
        "accounts_url": urls.accounts,
        "accounts_url_source": urls.accounts_source,
        "silicon": cli.silicon.as_ref().or(profile.silicon.as_ref()),
        "signed_in": profile.session.is_some(),
        "signed_in_as": profile.session.as_ref().map(store::Session::who),
    });
    if profile.previous_version_session {
        value["previous_version_session"] = json!(true);
    }
    if let Some(problem) = &loaded.unreadable {
        value["state_unreadable"] = json!(problem);
    }
    output::print(&value)
}

/// What `hook config set telemetry <value>` prints. Kept so scripts written
/// for earlier releases still succeed.
const TELEMETRY_REMOVED: &str =
    "Telemetry was removed from Hook; there is nothing to turn on or off.";

fn set(cli: &Cli, key: &str, value: Option<&String>) -> CliResult<()> {
    if key == "telemetry" {
        if cli.json {
            output::print(&json!({"telemetry": "removed", "message": TELEMETRY_REMOVED}))?;
        } else {
            println!("{TELEMETRY_REMOVED}");
        }
        return Ok(());
    }
    let value = value.map(|v| v.trim().to_owned());
    match (key, value.as_deref()) {
        ("url", Some(url)) => {
            session::hook_client(url)?;
        }
        ("accounts-url", Some(url)) => {
            session::sign_in(url)?;
        }
        ("silicon", Some(silicon)) => session::validate_silicon(silicon)?,
        _ => {}
    }
    let (mut locked, _) = Locked::open(false)?;
    let profile = locked.profile(&cli.profile);
    if let (Some(session), "url" | "accounts-url") = (&profile.session, key) {
        let bound = if key == "url" {
            &session.url
        } else {
            &session.accounts_url
        };
        let new = value.clone().unwrap_or_else(|| {
            if key == "url" {
                silicon_hook_client::DEFAULT_URL.to_owned()
            } else {
                silicon_hook_client::signin::DEFAULT_ACCOUNTS_URL.to_owned()
            }
        });
        if bound.trim_end_matches('/') != new.trim_end_matches('/') {
            return Err(CliError::invalid(
                format!(
                    "Profile `{}` is signed in for {bound}; changing {key} would send its token elsewhere.",
                    cli.profile
                ),
                "Sign out first (`hook logout`), or use another --profile for the other service.",
            ));
        }
    }
    match key {
        "url" => profile.url = value.map(|v| v.trim_end_matches('/').to_owned()),
        "accounts-url" => profile.accounts_url = value.map(|v| v.trim_end_matches('/').to_owned()),
        "silicon" => profile.silicon = value,
        _ => return Err(CliError::invalid(format!("unknown setting {key}"), "")),
    }
    locked.save()?;
    output::print(&json!({"saved": key, "profile": cli.profile}))
}
