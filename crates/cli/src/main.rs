mod args;
mod daemon;
mod store;
mod updater;

use anyhow::{Context as _, Result};
use args::{Cli, Command, Config, Deliveries, Environment, Rotate, System};
use clap::{CommandFactory as _, FromArgMatches as _};
use serde::Serialize;
use silicon_hook_client::{Client, Mutation, models::*};
use std::io::Read as _;
use store::{LockedStore, Session};

#[tokio::main]
async fn main() {
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    let result = run(&cli).await;
    if !matches!(
        cli.command,
        Command::Daemon {
            action: args::Daemon::Run
        }
    ) && let Err(error) = updater::after_command().await
    {
        eprintln!("Hook update check was skipped: {error}");
    }
    if let Err(error) = result {
        if cli.json {
            eprintln!("{}", serde_json::json!({"error":error.to_string()}));
        } else {
            eprintln!(
                "error: {error:#}\nRun hook {} --help for usage, or hook commands to explore.",
                command_path(&matches)
            );
        }
        std::process::exit(1);
    }
}

fn command_path(mut matches: &clap::ArgMatches) -> String {
    let mut names = Vec::new();
    while let Some((name, nested)) = matches.subcommand() {
        names.push(name);
        matches = nested;
    }
    names.join(" ")
}

fn read_text(path: &str) -> Result<String> {
    let mut text = String::new();
    if path == "-" {
        std::io::stdin().read_to_string(&mut text)?;
    } else {
        text = std::fs::read_to_string(path).with_context(|| format!("could not read {path}"))?;
    }
    Ok(text.trim().to_owned())
}
fn input<T: serde::de::DeserializeOwned>(value: &str) -> Result<T> {
    let value = if let Some(path) = value.strip_prefix('@') {
        read_text(path)?
    } else {
        value.to_owned()
    };
    serde_json::from_str(&value).context("invalid JSON input")
}

fn read_secret(path: &str) -> Result<Secret> {
    let mut text = zeroize::Zeroizing::new(String::new());
    if path == "-" {
        std::io::stdin().read_to_string(&mut text)?;
    } else {
        std::fs::File::open(path)
            .with_context(|| format!("could not read {path}"))?
            .read_to_string(&mut text)?;
    }
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    anyhow::ensure!(!text.is_empty(), "secret must not be empty");
    anyhow::ensure!(text.len() <= 4096, "secret must not exceed 4096 bytes");
    anyhow::ensure!(
        !text.chars().any(char::is_control),
        "secret must not contain control characters"
    );
    Ok(Secret::new(std::mem::take(&mut *text)))
}
fn print<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
fn target(cli: &Cli, profile: &store::Profile) -> Result<String> {
    let session = match cli.test {
        Some(id) => profile.test_sessions.get(&id),
        None => profile.session.as_ref(),
    };
    cli.silicon
        .clone()
        .or_else(|| match cli.test {
            Some(id) => profile.test_silicons.get(&id).cloned(),
            None => profile.silicon.clone(),
        })
        .or_else(|| {
            session
                .filter(|s| s.tokens.actor.kind == "silicon")
                .map(|s| s.tokens.actor.id.clone())
        })
        .or_else(|| {
            session
                .filter(|s| s.silicons.len() == 1)
                .and_then(|s| s.silicons.first().cloned())
        })
        .context("Choose a Silicon with --silicon <id>, or sign in as that Silicon")
}

async fn run(cli: &Cli) -> Result<()> {
    if matches!(cli.command, Command::Commands) {
        return commands(cli.json);
    }
    if let Command::Docs { topic } = &cli.command {
        return docs(topic);
    }
    if let Command::Daemon { action } = &cli.command {
        return daemon::command(cli, action).await;
    }
    let mut stored = LockedStore::open()?;
    if let Command::Config { action } = &cli.command {
        return configuration(cli, action, &mut stored);
    }
    if matches!(&cli.command, Command::Login(args) if args.action.is_some()) {
        return login_status(cli, &mut stored).await;
    }
    if matches!(cli.command, Command::Webhook { .. } | Command::Unhook) {
        let recipient = match &cli.command {
            Command::Webhook { webhook_url } => {
                Some(silicon_hook_client::Recipient::new(webhook_url)?)
            }
            _ => None,
        };
        let p = stored.profile(&cli.profile);
        // Validate profile binding before modifying local configuration.
        store::select_client(p, cli.test, cli.url.as_deref(), cli.org.as_deref())?;
        let session = match cli.test {
            Some(id) => p.test_sessions.get_mut(&id),
            None => p.session.as_mut(),
        }
        .context("Not signed in; run hook login <slt> first")?;
        session.webhook_url = recipient.as_ref().map(|r| r.url().to_string());
        let destination = session.webhook_url.clone();
        stored.save()?;
        drop(stored);
        if recipient.is_some() {
            daemon::ensure_started().await?;
        }
        print(
            &serde_json::json!({"hooked":destination.is_some(),"webhook_url":destination,
            "profile":cli.profile,"test":cli.test,"applies_within_seconds":5}),
        )?;
        if !cli.json {
            eprintln!(
                "{}",
                if recipient.is_some() {
                    "Next: hook login status --json; hook daemon status"
                } else {
                    "Delivery detached. Reconnect with hook webhook <webhook-url>."
                }
            );
        }
        return Ok(());
    }
    if let Command::Whoami = &cli.command {
        let p = stored.profile(&cli.profile);
        let session = match cli.test {
            Some(id) => p.test_sessions.get(&id),
            None => p.session.as_ref(),
        };
        let s = session.context("Not signed in; run hook login --help")?;
        return print(
            &serde_json::json!({"profile":cli.profile,"test":cli.test,"actor":s.tokens.actor,"org_id":s.tokens.org_id,"expires_at":s.expires_at,"webhook_url":s.webhook_url}),
        );
    }
    if !matches!(
        cli.command,
        Command::Login(_)
            | Command::Iam
            | Command::Logout
            | Command::System { .. }
            | Command::Env {
                action: Environment::Attach { .. }
                    | Environment::Current
                    | Environment::Clean
                    | Environment::ConfigureIam { .. }
            }
    ) {
        store::refresh_if_needed(
            &mut stored,
            &cli.profile,
            cli.test,
            cli.url.as_deref(),
            cli.org.as_deref(),
        )
        .await?;
    }
    let profile = stored.profile(&cli.profile).clone();
    // Attaching is the bootstrap operation for a test environment, so it
    // must validate the supplied key before the normal test-key selection.
    let client = if matches!(
        cli.command,
        Command::Env {
            action: Environment::Attach { .. }
        }
    ) {
        store::select_client(&profile, None, cli.url.as_deref(), cli.org.as_deref())?
    } else {
        store::select_client(&profile, cli.test, cli.url.as_deref(), cli.org.as_deref())?
    };
    let mutation = cli
        .idempotency_key
        .as_ref()
        .map(|key| Mutation::with_key(key.clone()))
        .transpose()?
        .unwrap_or_default();
    let mut stored = Some(stored);
    if !matches!(
        cli.command,
        Command::Login(_) | Command::Logout | Command::Env { .. }
    ) {
        // Ordinary API operations only need the immutable snapshot. Keep the
        // process lock for refresh and operations that update saved state.
        drop(stored.take());
    }
    match &cli.command {
        Command::Login(args) => {
            let mut stored = stored.take().context("missing login state")?;
            let recipient = args
                .webhook_url
                .as_deref()
                .map(silicon_hook_client::Recipient::new)
                .transpose()?;
            let slt = zeroize::Zeroizing::new(match &args.slt {
                Some(s) => s.clone(),
                None => match &args.token {
                    Some(s) => s.clone(),
                    None => read_text(
                        args.slt_file
                            .as_deref()
                            .context("provide SLT, --slt, or --slt-file")?,
                    )?,
                },
            });
            let tokens = client.authenticate(&slt, &mutation).await?;
            let actor = tokens.actor.clone();
            let p = stored.profile(&cli.profile);
            if let Some(url) = &cli.url {
                p.url = url.clone();
            }
            let org = cli.org.clone().or(tokens.org_id.clone());
            let session = Session {
                expires_at: store::now() + tokens.expires_in,
                silicons: cli
                    .silicon
                    .clone()
                    .into_iter()
                    .chain(if cli.silicon.is_none() && actor.kind == "silicon" {
                        Some(actor.id.clone())
                    } else {
                        None
                    })
                    .collect(),
                relay_token: Some(Secret::new(uuid::Uuid::new_v4().simple().to_string())),
                pending_refresh_key: None,
                tokens,
                webhook_url: args.webhook_url.clone(),
            };
            if let Some(id) = cli.test {
                p.test_sessions.insert(id, session);
                if let Some(org) = org {
                    p.test_orgs.insert(id, org);
                }
            } else {
                p.session = Some(session);
                p.org = org;
            }
            stored.save()?;
            drop(stored);
            daemon::ensure_started().await?;
            print(
                &serde_json::json!({"signed_in":true,"authenticated":true,"actor":actor,"profile":cli.profile,"test":cli.test,"webhook_url":args.webhook_url,"relay":"http://hook.localhost:18479"}),
            )?;
            if !cli.json && recipient.is_none() {
                eprintln!(
                    "Next: hook webhook <webhook-url> to receive events. Check your identity with hook login status --json."
                );
            }
            if !cli.json && actor.kind == "carbon" && cli.silicon.is_none() {
                eprintln!(
                    "Choose streams for this Carbon: hook --profile {} daemon subscribe <silicon-id>...",
                    cli.profile
                );
            }
            return Ok(());
        }
        Command::Iam => print(&client.iam().await?)?,
        Command::Logout => {
            let mut stored = stored.take().context("missing logout state")?;
            let p = stored.profile(&cli.profile);
            let session = match cli.test {
                Some(id) => p.test_sessions.get(&id),
                None => p.session.as_ref(),
            }
            .context("Not signed in")?;
            client
                .with_token(session.tokens.refresh_token.expose())
                .logout(&mutation)
                .await?;
            if let Some(id) = cli.test {
                p.test_sessions.remove(&id);
            } else {
                p.session = None;
            }
            stored.save()?;
            print(&serde_json::json!({"signed_out":true}))?;
        }
        Command::Create {
            name,
            description,
            time_zone,
            signature,
            secret_file,
            unsigned,
        } => {
            let mut signature = signature
                .as_ref()
                .map(|value| input::<Signature>(value))
                .transpose()?;
            if let Some(path) = secret_file {
                let signature = signature.get_or_insert_with(Signature::default);
                anyhow::ensure!(
                    signature.secret.is_none(),
                    "supply a secret in --signature or --secret-file, not both"
                );
                signature.secret = Some(read_secret(path)?);
            }
            if *unsigned {
                signature.get_or_insert_with(Signature::default).required = Some(false);
            }
            print(
                &client
                    .create_hook(
                        &target(cli, &profile)?,
                        &CreateHook {
                            name: name.clone(),
                            description: description.clone(),
                            time_zone: time_zone.clone(),
                            signature,
                        },
                        &mutation,
                    )
                    .await?,
            )?;
        }
        Command::SetSecret {
            id,
            secret_file,
            secret_encoding,
        } => print(
            &client
                .set_secret(
                    &target(cli, &profile)?,
                    *id,
                    read_secret(secret_file)?,
                    secret_encoding.clone(),
                    &mutation,
                )
                .await?,
        )?,
        Command::List { include_deleted } => print(
            &client
                .list_hooks(&target(cli, &profile)?, *include_deleted)
                .await?,
        )?,
        Command::Show { id } => print(&client.get_hook(&target(cli, &profile)?, *id).await?)?,
        Command::Update { id, patch } => print(
            &client
                .update_hook(
                    &target(cli, &profile)?,
                    *id,
                    &input::<UpdateHook>(patch)?,
                    &mutation,
                )
                .await?,
        )?,
        Command::Delete { id } => {
            client
                .delete_hook(&target(cli, &profile)?, *id, &mutation)
                .await?;
            print(&serde_json::json!({"deleted":id,"recoverable_days":45}))?;
        }
        Command::Restore { id } => print(
            &client
                .restore_hook(&target(cli, &profile)?, *id, &mutation)
                .await?,
        )?,
        Command::Enable { ids } | Command::Disable { ids } => print(
            &client
                .set_enabled(
                    &target(cli, &profile)?,
                    ids,
                    matches!(cli.command, Command::Enable { .. }),
                    &mutation,
                )
                .await?,
        )?,
        Command::Rotate { kind } => match kind {
            Rotate::Endpoint { id } => print(
                &client
                    .rotate_endpoint(&target(cli, &profile)?, *id, &mutation)
                    .await?,
            )?,
            Rotate::Secret { id } => print(
                &client
                    .rotate_secret(&target(cli, &profile)?, *id, &mutation)
                    .await?,
            )?,
        },
        Command::Events(q) => print(
            &client
                .events(
                    &target(cli, &profile)?,
                    q.hook,
                    q.limit,
                    q.cursor.as_deref(),
                )
                .await?,
        )?,
        Command::Blocked(q) => print(
            &client
                .blocked_requests(
                    &target(cli, &profile)?,
                    q.hook,
                    q.limit,
                    q.cursor.as_deref(),
                )
                .await?,
        )?,
        Command::Deliveries { action } => match action {
            Deliveries::List { limit, after } => print(
                &client
                    .deliveries(&target(cli, &profile)?, *limit, *after)
                    .await?,
            )?,
            Deliveries::Ack { through } => print(
                &client
                    .acknowledge(&target(cli, &profile)?, *through, &mutation)
                    .await?,
            )?,
            Deliveries::Cursor => print(&client.delivery_cursor(&target(cli, &profile)?).await?)?,
        },
        Command::ConnectIam => print(
            &client
                .connect_iam_hook(&target(cli, &profile)?, &mutation)
                .await?,
        )?,
        Command::Env { action } => {
            environments(
                cli,
                action,
                &client,
                &mutation,
                stored.as_mut().context("missing environment state")?,
            )
            .await?
        }
        Command::System { action } => match action {
            System::Version => print(&client.version().await?)?,
            System::Health => print(&client.health().await?)?,
        },
        Command::Listen { ack } => {
            let silicon = target(cli, &profile)?;
            // Never hold the state lock while a long-lived stream is running.
            drop(stored);
            let mut stream = client.stream(&[silicon]).await?;
            loop {
                tokio::select! {
                    _=tokio::signal::ctrl_c()=>{stream.close().await?;break;},
                    frame=stream.next()=>match frame? {
                        Some(frame)=>{print(&frame)?;if *ack && let silicon_hook_client::ServerFrame::NewEvent{data}=frame {stream.acknowledge(&data.metadata.silicon_id,data.metadata.delivery_sequence).await?;}},
                        None=>break,
                    }
                }
            }
            return Ok(());
        }
        Command::Webhook { .. }
        | Command::Unhook
        | Command::Whoami
        | Command::Commands
        | Command::Docs { .. }
        | Command::Config { .. }
        | Command::Daemon { .. } => {
            unreachable!()
        }
    }
    if !cli.json {
        eprintln!("Next: hook list · hook events · hook deliveries list · hook <command> --help");
    }
    Ok(())
}

async fn login_status(cli: &Cli, stored: &mut LockedStore) -> Result<()> {
    if let Err(error) = store::refresh_if_needed(
        stored,
        &cli.profile,
        cli.test,
        cli.url.as_deref(),
        cli.org.as_deref(),
    )
    .await
    {
        if !matches!(
            error.downcast_ref::<silicon_hook_client::Error>(),
            Some(silicon_hook_client::Error::Api { status: 401, .. })
        ) {
            return Err(error);
        }
        return print(&serde_json::json!({"authenticated":false,"actor":null,
            "profile":cli.profile,"test":cli.test}));
    }
    let p = stored.profile(&cli.profile);
    let session = match cli.test {
        Some(id) => p.test_sessions.get(&id),
        None => p.session.as_ref(),
    };
    let Some(session) = session else {
        return print(&serde_json::json!({"authenticated":false,"actor":null,
            "profile":cli.profile,"test":cli.test}));
    };
    let client = store::select_client(p, cli.test, cli.url.as_deref(), cli.org.as_deref())?;
    let status = client.login_status().await?;
    print(
        &serde_json::json!({"authenticated":status.authenticated,"actor":status.actor,
        "org_id":status.org_id,"profile":cli.profile,"test":cli.test,
        "expires_at":session.expires_at,"webhook_url":session.webhook_url,
        "hooked":session.webhook_url.is_some()}),
    )
}

async fn environments(
    cli: &Cli,
    action: &Environment,
    client: &Client,
    mutation: &Mutation,
    stored: &mut LockedStore,
) -> Result<()> {
    match action {
        Environment::Create {
            name,
            description,
            iam_key_file,
            iam_config,
        } => {
            let iam = iam_config
                .as_ref()
                .map(|path| read_text(path).and_then(|text| Ok(serde_json::from_str(&text)?)))
                .transpose()?;
            let result = client
                .create_environment(
                    &CreateEnvironment {
                        name: name.clone(),
                        description: description.clone(),
                        iam_test_key: Secret::new(read_text(iam_key_file)?),
                        iam,
                    },
                    mutation,
                )
                .await?;
            stored
                .profile(&cli.profile)
                .test_keys
                .insert(result.environment.id, result.key.clone());
            stored.save()?;
            print(&result)?;
        }
        Environment::Attach { id, key_file } => {
            let key = Secret::new(read_text(key_file)?);
            let context = client
                .without_test_environment()
                .with_test_key(key.expose())?
                .current_environment()
                .await?;
            anyhow::ensure!(
                context.id == *id,
                "The key belongs to a different environment"
            );
            let profile = stored.profile(&cli.profile);
            if let Some(url) = &cli.url {
                profile.url = url.clone();
            }
            profile.test_keys.insert(*id, key);
            stored.save()?;
            print(&context)?;
        }
        Environment::List {
            status,
            limit,
            after,
        } => print(
            &client
                .list_environments_page(status, *limit, *after)
                .await?,
        )?,
        Environment::Show { id } => print(&client.environment(*id).await?)?,
        Environment::Key { id } => {
            let result = client.environment_key(*id).await?;
            stored
                .profile(&cli.profile)
                .test_keys
                .insert(*id, result.key.clone());
            stored.save()?;
            print(&result)?;
        }
        Environment::RotateKey { id } => {
            let result = client.rotate_environment_key(*id, mutation).await?;
            stored
                .profile(&cli.profile)
                .test_keys
                .insert(*id, result.key.clone());
            stored.save()?;
            print(&result)?;
        }
        Environment::Delete { id } => print(&client.delete_environment(*id, mutation).await?)?,
        Environment::Restore { id } => print(&client.restore_environment(*id, mutation).await?)?,
        Environment::Current => print(&client.current_environment().await?)?,
        Environment::Clean => print(&client.clean_environment(mutation).await?)?,
        Environment::ConfigureIam { file } => print(
            &client
                .configure_test_iam(
                    &serde_json::from_str::<TestIamConfiguration>(&read_text(file)?)?,
                    mutation,
                )
                .await?,
        )?,
    }
    Ok(())
}

fn configuration(cli: &Cli, action: &Config, stored: &mut LockedStore) -> Result<()> {
    match action {
        Config::Profiles => print(&stored.data.profiles.keys().collect::<Vec<_>>()),
        Config::Home { location } => {
            let path = store::set_home(location)?;
            print(&serde_json::json!({"home":path}))
        }
        Config::Show => {
            let p = stored.profile(&cli.profile);
            print(
                &serde_json::json!({"profile":cli.profile,"home":store::folder()?,"url":p.url,"test":cli.test,"org":cli.test.and_then(|id| p.test_orgs.get(&id)).or(p.org.as_ref()),"silicon":match cli.test {Some(id)=>p.test_silicons.get(&id),None=>p.silicon.as_ref()},"signed_in":match cli.test {Some(id)=>p.test_sessions.contains_key(&id),None=>p.session.is_some()},"test_environments":p.test_keys.keys().collect::<Vec<_>>()}),
            )
        }
        Config::Set { key, value } => {
            match key.as_str() {
                "url" => {
                    Client::new(value)?;
                    let profile = stored.profile(&cli.profile);
                    anyhow::ensure!(
                        profile.session.is_none()
                            && profile.test_sessions.is_empty()
                            && profile.test_keys.is_empty(),
                        "Use a new --profile to change the backend without mixing credentials"
                    );
                    profile.url = value.clone();
                }
                "org" => {
                    let p = stored.profile(&cli.profile);
                    if let Some(id) = cli.test {
                        p.test_orgs.insert(id, value.clone());
                    } else {
                        p.org = Some(value.clone());
                    }
                }
                "silicon" => {
                    let p = stored.profile(&cli.profile);
                    if let Some(id) = cli.test {
                        p.test_silicons.insert(id, value.clone());
                    } else {
                        p.silicon = Some(value.clone());
                    }
                }
                "auto-update" => {
                    stored.data.auto_update = match value.as_str() {
                        "on" | "true" => true,
                        "off" | "false" => false,
                        _ => anyhow::bail!("Use on or off"),
                    }
                }
                _ => anyhow::bail!("unknown configuration key"),
            }
            stored.save()?;
            print(&serde_json::json!({"saved":key}))
        }
    }
}

fn commands(json: bool) -> Result<()> {
    fn walk(command: &clap::Command, path: String, out: &mut Vec<serde_json::Value>) {
        let mut command = command.clone();
        let help = command.render_long_help().to_string();
        out.push(serde_json::json!({"command":path,"help":help}));
        for child in command.get_subcommands() {
            walk(child, format!("{path} {}", child.get_name()), out);
        }
    }
    let mut items = Vec::new();
    walk(&Cli::command(), "hook".into(), &mut items);
    if json {
        print(&items)
    } else {
        for item in items {
            println!("{}", item["command"].as_str().unwrap_or_default());
        }
        Ok(())
    }
}

fn docs(topic: &str) -> Result<()> {
    let text = match topic {
        "overview" => include_str!("../docs/README.md"),
        "api" | "signatures" => include_str!("../docs/api/README.md"),
        "client" => include_str!("../docs/client/README.md"),
        "cli" => include_str!("../docs/cli/README.md"),
        "iam" => include_str!("../docs/iam/README.md"),
        "testing" => include_str!("../docs/testing/README.md"),
        "testing-api" => include_str!("../docs/testing/api.md"),
        "testing-client" => include_str!("../docs/testing/client.md"),
        "testing-cli" => include_str!("../docs/testing/cli.md"),
        "delivery" | "relay" => include_str!("../docs/client/relay.md"),
        _ => anyhow::bail!(
            "Unknown guide; choose overview, api, client, cli, iam, signatures, testing, testing-api, testing-client, testing-cli or relay"
        ),
    };
    println!("{text}");
    Ok(())
}

#[cfg(test)]
mod byos_tests {
    use super::read_secret;

    #[test]
    fn secret_files_preserve_spaces_and_reject_empty_or_multiline_values() -> anyhow::Result<()> {
        let path = std::env::temp_dir().join(format!("hook-byos-{}", uuid::Uuid::new_v4()));
        let result = (|| -> anyhow::Result<()> {
            for ending in ["", "\n", "\r\n"] {
                std::fs::write(&path, format!(" provider secret {ending}"))?;
                assert_eq!(
                    read_secret(
                        path.to_str()
                            .ok_or_else(|| anyhow::anyhow!("invalid path"))?
                    )?
                    .expose(),
                    " provider secret "
                );
            }
            for value in ["", "\n", "first\nsecond", "first\n\n"] {
                std::fs::write(&path, value)?;
                assert!(
                    read_secret(
                        path.to_str()
                            .ok_or_else(|| anyhow::anyhow!("invalid path"))?
                    )
                    .is_err()
                );
            }
            Ok(())
        })();
        std::fs::remove_file(path)?;
        result
    }
}
