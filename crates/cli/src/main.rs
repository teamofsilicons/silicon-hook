//! `hook`: the Silicon Hook CLI, built on `silicon-hook-client` only.

mod args;
mod commands;
mod config;
mod login;
mod output;
mod session;
mod status;
mod store;

use args::{Cli, Command, LoginAction};
use clap::{CommandFactory as _, FromArgMatches as _};
use output::{CliError, CliResult};
use serde_json::json;

#[tokio::main]
async fn main() {
    let matches = match Cli::command().try_get_matches() {
        Ok(matches) => matches,
        Err(error) => {
            let _ = error.print();
            std::process::exit(error.exit_code());
        }
    };
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    let started = std::time::Instant::now();
    let result = dispatch(&cli).await;
    let code = match &result {
        Ok(code) => *code,
        Err(error) => error.exit_code(),
    };
    telemetry(
        &cli,
        matches.subcommand_name().unwrap_or("commands"),
        code == 0,
        started,
    )
    .await;
    if let Err(error) = result {
        output::error(cli.json, &error, &command_path(&matches));
    }
    std::process::exit(code);
}

fn command_path(mut matches: &clap::ArgMatches) -> String {
    let mut names = Vec::new();
    while let Some((name, nested)) = matches.subcommand() {
        names.push(name);
        matches = nested;
    }
    names.join(" ")
}

/// Flags that existed before 1.0 and no longer mean anything.
fn removed_flags(cli: &Cli) -> CliResult<()> {
    if cli.org.is_some() {
        return Err(CliError::invalid(
            "--org is no longer accepted: Hook 1.0 keys every hook on the Silicon's Silicon Accounts account.",
            "Drop --org. Choose the Silicon with --silicon si:<id> (or its uuid); `hook silicons` lists the ones you can open.",
        ));
    }
    if cli.test.is_some() || cli.production {
        return Err(CliError::invalid(
            "--test and --production are no longer accepted: Hook 1.0 has no test environments.",
            "Drop the flag. For a local Hook, point --url (or SILICON_HOOK_URL) and ACCOUNTS_URL at it and sign in with another --profile.",
        ));
    }
    Ok(())
}

async fn dispatch(cli: &Cli) -> CliResult<i32> {
    removed_flags(cli)?;
    match &cli.command {
        Command::Accounts | Command::Iam => {
            output::print(&status::accounts(cli))?;
            output::hint(
                cli.json,
                "Sign in: hook login (Carbons) · silicon-accounts login --app hook -q | hook login --slt-stdin (Silicons)",
            );
            Ok(0)
        }
        Command::Login(args) => match &args.action {
            Some(LoginAction::Status { offline }) => status::status(cli, *offline).await,
            None => login::login(cli, args).await.map(|()| 0),
        },
        Command::Logout => login::logout(cli).await.map(|()| 0),
        Command::Whoami => login::whoami(cli).map(|()| 0),
        Command::Config { action } => config::run(cli, action).map(|()| 0),
        Command::Commands => commands_tree(cli.json).map(|()| 0),
        Command::Docs { topic } => docs(topic).map(|()| 0),
        Command::Report { message, pr } => report(cli, message, pr.as_deref()).map(|()| 0),
        Command::About => {
            output::print(&json!({
                "name": "Silicon Hook",
                "version": env!("CARGO_PKG_VERSION"),
                "repository": silicon_hook_client::support::REPOSITORY,
                "docs": silicon_hook_client::support::DOCUMENTATION,
                "rust_package": silicon_hook_client::support::PACKAGE,
                "cli_package": "https://crates.io/crates/silicon-hook-cli",
                "install": "silicon-apps install hook",
                "web": "https://hook.teamofsilicons.com",
            }))?;
            Ok(0)
        }
        _ => commands::run(cli).await.map(|()| 0),
    }
}

/// One best-effort diagnostic event per command, only when signed in and
/// telemetry is on. Never refreshes, never blocks more than half a second.
async fn telemetry(cli: &Cli, operation: &str, succeeded: bool, started: std::time::Instant) {
    let Ok(folder) = store::folder() else { return };
    let Ok(loaded) = store::read(&folder) else {
        return;
    };
    let profile = loaded.profile(&cli.profile);
    let Some(session) = &profile.session else {
        return;
    };
    if !profile.telemetry || session.expires_at <= store::now() {
        return;
    }
    let Ok(client) = silicon_hook_client::Client::new(&session.url) else {
        return;
    };
    client
        .with_telemetry(profile.telemetry)
        .with_token(session.access_token.expose())
        .emit_telemetry(
            "cli",
            "command",
            if succeeded { "succeeded" } else { "failed" },
            operation,
            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            1,
        )
        .await;
}

fn commands_tree(json: bool) -> CliResult<()> {
    fn walk(command: &clap::Command, path: String, out: &mut Vec<serde_json::Value>) {
        let mut command = command.clone();
        if command.is_hide_set() {
            return;
        }
        let help = command.render_long_help().to_string();
        out.push(json!({"command": path, "about": command.get_about().map(ToString::to_string), "help": help}));
        for child in command.get_subcommands() {
            walk(child, format!("{path} {}", child.get_name()), out);
        }
    }
    let mut items = Vec::new();
    walk(&Cli::command(), "hook".into(), &mut items);
    if json {
        output::print(&items)
    } else {
        for item in items {
            println!(
                "{:<36} {}",
                item["command"].as_str().unwrap_or_default(),
                item["about"].as_str().unwrap_or_default()
            );
        }
        Ok(())
    }
}

const TOPICS: &str = "overview, signin, cli, client, receiving, signatures (or api), delivery, contracts, configuration, telemetry, deployment, releases";

fn docs(topic: &str) -> CliResult<()> {
    let text = match topic {
        "overview" => include_str!("../docs/README.md"),
        "signin" | "accounts" | "iam" => include_str!("../docs/accounts/README.md"),
        "cli" => include_str!("../docs/cli/README.md"),
        "client" => include_str!("../docs/client/README.md"),
        "receiving" | "relay" => include_str!("../docs/client/relay.md"),
        "api" | "signatures" => include_str!("../docs/api/README.md"),
        "delivery" => include_str!("../docs/ting-delivery.md"),
        "contracts" => include_str!("../docs/contracts.md"),
        "configuration" => include_str!("../docs/configuration.md"),
        "telemetry" => include_str!("../docs/telemetry.md"),
        "deployment" => include_str!("../docs/deployment.md"),
        "releases" => include_str!("../docs/releases.md"),
        _ => {
            return Err(CliError::invalid(
                format!("There is no guide called `{topic}`."),
                format!("Choose one of: {TOPICS}."),
            ));
        }
    };
    println!("{text}");
    Ok(())
}

fn report(cli: &Cli, message: &str, pr: Option<&str>) -> CliResult<()> {
    let url = silicon_hook_client::support::report(message, pr)
        .map_err(|error| CliError::new(output::EXIT_FAILURE, "report_failed", error, ""))?;
    output::print(&json!({"submitted": true, "url": url}))?;
    if pr.is_none() {
        output::hint(
            cli.json,
            "Found the fix too? Open a pull request at https://github.com/teamofsilicons/silicon-hook/pulls and report again with --pr <url>.",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
