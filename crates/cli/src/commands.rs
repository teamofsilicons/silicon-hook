//! The API commands: a Silicon's hooks, history, access and delivery.

use std::io::Read as _;

use serde_json::json;
use silicon_hook_client::{
    Client, Error as ClientError, Mutation, Secret,
    models::{CreateHook, GrantLevel, Signature, UpdateHook},
};

use crate::{
    args::{Access, AllowList, Cli, Command, History, Receiving, Rotate, System},
    output::{self, CliError, CliResult},
    session::{self, signed_in_client, target},
    store::{self, Profile, Session},
};

/// A signed-in client and what it was made from.
pub struct Signed {
    pub client: Client,
    pub session: Session,
    pub profile: Profile,
}

async fn signed(cli: &Cli, force: bool) -> CliResult<Signed> {
    let (client, session, profile) = signed_in_client(cli, force).await?;
    Ok(Signed {
        client,
        session,
        profile,
    })
}

/// Runs one API call; if Hook refuses the token, refreshes once and retries
/// (mutations keep their idempotency key, so a retry never repeats a change).
async fn call<T>(
    cli: &Cli,
    signed_client: &mut Signed,
    request: impl AsyncFn(&Client) -> Result<T, ClientError>,
) -> CliResult<T> {
    match request(&signed_client.client).await {
        Err(error) if error.is_unauthenticated() => {
            *signed_client = signed(cli, true).await?;
            Ok(request(&signed_client.client).await?)
        }
        result => Ok(result?),
    }
}

fn mutation(cli: &Cli) -> CliResult<Mutation> {
    match &cli.idempotency_key {
        Some(key) => Mutation::with_key(key.clone()).map_err(|error| {
            CliError::invalid(error.to_string(), "Use 8 to 255 visible ASCII characters.")
        }),
        None => Ok(Mutation::new()),
    }
}

fn read_text(path: &str) -> CliResult<String> {
    let mut text = String::new();
    if path == "-" {
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|error| CliError::invalid(format!("Could not read stdin: {error}."), ""))?;
    } else {
        text = std::fs::read_to_string(path)
            .map_err(|error| CliError::io("read", std::path::Path::new(path), &error))?;
    }
    Ok(text.trim().to_owned())
}

fn input<T: serde::de::DeserializeOwned>(value: &str, what: &str) -> CliResult<T> {
    let text = match value.strip_prefix('@') {
        Some(path) => read_text(path)?,
        None => value.to_owned(),
    };
    serde_json::from_str(&text).map_err(|error| {
        CliError::invalid(
            format!("The {what} is not valid JSON for Hook: {error}."),
            "Pass JSON inline or @file; `hook docs signatures` shows every field.",
        )
    })
}

/// Reads a secret: spaces kept, one trailing LF or CRLF removed; empty,
/// multi-line, control characters or more than 4096 bytes refused.
pub fn read_secret(path: &str) -> CliResult<Secret> {
    let mut text = zeroize::Zeroizing::new(String::new());
    let result = if path == "-" {
        std::io::stdin().read_to_string(&mut text)
    } else {
        std::fs::File::open(path).and_then(|mut file| file.read_to_string(&mut text))
    };
    result.map_err(|error| CliError::io("read", std::path::Path::new(path), &error))?;
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    let refuse = |why: &str| {
        CliError::invalid(
            format!("The secret in {path} {why}."),
            "Put exactly the secret in the file (one line).",
        )
    };
    if text.is_empty() {
        return Err(refuse("is empty"));
    }
    if text.len() > 4096 {
        return Err(refuse("is longer than 4096 bytes"));
    }
    if text.chars().any(char::is_control) {
        return Err(refuse("contains a line break or another control character"));
    }
    Ok(Secret::new(std::mem::take(&mut *text)))
}

fn next(cli: &Cli, text: &str) {
    output::hint(cli.json, text);
}

pub async fn run(cli: &Cli) -> CliResult<()> {
    match &cli.command {
        Command::System {
            action: System::Version | System::Health,
        } => return system(cli).await,
        Command::Silicons => {
            let mut s = signed(cli, false).await?;
            let items = call(cli, &mut s, async |c| c.silicons().await).await?;
            output::print(&items)?;
            next(
                cli,
                "Next: hook --silicon <si:id> list · hook access list --silicon <si:id>",
            );
            return Ok(());
        }
        Command::System {
            action: System::Delivery,
        } => {
            let mut s = signed(cli, false).await?;
            output::print(&call(cli, &mut s, async |c| c.delivery_status().await).await?)?;
            return Ok(());
        }
        Command::Receiving {
            action: Receiving::Register,
        } => {
            let mut s = signed(cli, false).await?;
            output::print(&call(cli, &mut s, async |c| c.register_recipient().await).await?)?;
            next(
                cli,
                "Ting can now deliver Hook's notifications to you; your app's Ting receiver gets them.",
            );
            return Ok(());
        }
        _ => {}
    }
    let mut s = signed(cli, false).await?;
    let silicon = target(cli, &s.profile, &s.session)?;
    let silicon = silicon.as_str();
    let key = mutation(cli)?;
    match &cli.command {
        Command::Create {
            name,
            description,
            time_zone,
            signature,
            secret_file,
            unsigned,
        } => {
            let mut signature = signature
                .as_deref()
                .map(|value| input::<Signature>(value, "signature policy"))
                .transpose()?;
            if let Some(path) = secret_file {
                let policy = signature.get_or_insert_with(Signature::default);
                if policy.secret.is_some() {
                    return Err(CliError::invalid(
                        "A secret was given both in --signature and with --secret-file.",
                        "Keep one of them.",
                    ));
                }
                policy.secret = Some(read_secret(path)?);
            }
            if *unsigned {
                signature.get_or_insert_with(Signature::default).required = Some(false);
            }
            let input = CreateHook {
                name: name.clone(),
                description: description.clone(),
                time_zone: time_zone.clone(),
                signature,
            };
            let created = call(cli, &mut s, async |c| {
                c.create_hook(silicon, &input, &key).await
            })
            .await?;
            output::print(&created)?;
            next(
                cli,
                "Give the provider endpoint_url. signing_secret (when present) prints only now: store it privately. Next: hook list · hook events",
            );
        }
        Command::SetSecret {
            id,
            secret_file,
            secret_encoding,
        } => {
            let secret = read_secret(secret_file)?;
            let hook = call(cli, &mut s, async |c| {
                c.set_secret(silicon, *id, secret.clone(), secret_encoding.clone(), &key)
                    .await
            })
            .await?;
            output::print(&hook)?;
            next(
                cli,
                "The previous secret stopped verifying. Next: hook show <id>",
            );
        }
        Command::List { include_deleted } => {
            let hooks = call(cli, &mut s, async |c| {
                c.list_hooks(silicon, *include_deleted).await
            })
            .await?;
            output::print(&hooks)?;
            next(
                cli,
                "Next: hook show <id> · hook events --hook <id> · hook create <provider>",
            );
        }
        Command::Show { id } => {
            output::print(&call(cli, &mut s, async |c| c.get_hook(silicon, *id).await).await?)?
        }
        Command::Update { id, patch } => {
            let patch: UpdateHook = input(patch, "patch")?;
            output::print(
                &call(cli, &mut s, async |c| {
                    c.update_hook(silicon, *id, &patch, &key).await
                })
                .await?,
            )?;
        }
        Command::Delete { id } => {
            call(cli, &mut s, async |c| {
                c.delete_hook(silicon, *id, &key).await
            })
            .await?;
            output::print(&json!({"deleted": id, "recoverable_days": 45}))?;
            next(cli, "Restore it within 45 days: hook restore <id>");
        }
        Command::Restore { id } => output::print(
            &call(cli, &mut s, async |c| {
                c.restore_hook(silicon, *id, &key).await
            })
            .await?,
        )?,
        Command::Enable { ids } | Command::Disable { ids } => {
            let enabled = matches!(cli.command, Command::Enable { .. });
            output::print(
                &call(cli, &mut s, async |c| {
                    c.set_enabled(silicon, ids, enabled, &key).await
                })
                .await?,
            )?;
        }
        Command::Rotate { kind } => match kind {
            Rotate::Endpoint { id } => {
                output::print(
                    &call(cli, &mut s, async |c| {
                        c.rotate_endpoint(silicon, *id, &key).await
                    })
                    .await?,
                )?;
                next(
                    cli,
                    "The old URL is retired for good; give the provider the new endpoint_url.",
                );
            }
            Rotate::Secret { id } => {
                output::print(
                    &call(cli, &mut s, async |c| {
                        c.rotate_secret(silicon, *id, &key).await
                    })
                    .await?,
                )?;
                next(
                    cli,
                    "The new secret prints only now; the old one stopped verifying. Give it to the provider.",
                );
            }
        },
        Command::Events(history) | Command::Blocked(history) => {
            let History {
                hook,
                limit,
                cursor,
            } = history;
            if matches!(cli.command, Command::Events(_)) {
                output::print(
                    &call(cli, &mut s, async |c| {
                        c.events(silicon, *hook, *limit, cursor.as_deref()).await
                    })
                    .await?,
                )?;
            } else {
                output::print(
                    &call(cli, &mut s, async |c| {
                        c.blocked_requests(silicon, *hook, *limit, cursor.as_deref())
                            .await
                    })
                    .await?,
                )?;
            }
            next(
                cli,
                "More: repeat with --cursor <next_cursor>. One event in full: hook event <id>",
            );
        }
        Command::Event { id } => {
            output::print(&call(cli, &mut s, async |c| c.event(silicon, *id).await).await?)?
        }
        Command::Publication { event_id } => {
            output::print(
                &call(cli, &mut s, async |c| {
                    c.publication(silicon, *event_id).await
                })
                .await?,
            )?;
        }
        Command::Access { action } => access(cli, &mut s, silicon, action).await?,
        Command::AllowList { action } => allow_list(cli, &mut s, silicon, action).await?,
        Command::ConnectAccounts { secret_file } => {
            let secret = secret_file.as_deref().map(read_secret).transpose()?;
            let prepared = call(cli, &mut s, async |c| {
                c.connect_accounts_hook(silicon, &key).await
            })
            .await?;
            let mut value = serde_json::to_value(&prepared)?;
            if let Some(secret) = secret {
                let id = prepared.hook.id;
                let store_key = Mutation::new();
                let hook = call(cli, &mut s, async |c| {
                    c.set_secret(silicon, id, secret.clone(), None, &store_key)
                        .await
                })
                .await?;
                value["hook"] = serde_json::to_value(&hook)?;
                value["secret_stored_now"] = json!(true);
                next(
                    cli,
                    "Done: the Silicon's Silicon Accounts events now verify and arrive as events of this hook.",
                );
            } else {
                value["secret_stored_now"] = json!(false);
                next(
                    cli,
                    &format!(
                        "Next: {} (it prints a whsec_ secret once), then: hook connect-accounts --secret-file - (paste it). Until then Silicon Accounts deliveries are withheld as unverified. Already stored it? Nothing more to do.",
                        prepared.next_steps.set_webhook
                    ),
                );
            }
            output::print(&value)?;
        }
        Command::Receiving { action } => receiving(cli, &mut s, silicon, action).await?,
        _ => unreachable!("dispatched in main"),
    }
    Ok(())
}

async fn access(cli: &Cli, s: &mut Signed, silicon: &str, action: &Access) -> CliResult<()> {
    match action {
        Access::List => {
            output::print(&call(cli, s, async |c| c.access(silicon).await).await?)?;
            next(
                cli,
                "Grant: hook access grant <c:id|si:id> --level view|manage · Revoke: hook access revoke <id>",
            );
        }
        Access::Grant { account, level } => {
            let level = if level == "manage" {
                GrantLevel::Manage
            } else {
                GrantLevel::View
            };
            output::print(&call(cli, s, async |c| c.grant(silicon, account, level).await).await?)?;
        }
        Access::Revoke { account } => {
            call(cli, s, async |c| c.revoke(silicon, account).await).await?;
            output::print(&json!({"revoked": account, "silicon": silicon}))?;
        }
        Access::Leave => {
            call(cli, s, async |c| c.leave(silicon).await).await?;
            output::print(&json!({"left": silicon}))?;
        }
    }
    Ok(())
}

async fn allow_list(cli: &Cli, s: &mut Signed, silicon: &str, action: &AllowList) -> CliResult<()> {
    match action {
        AllowList::List => {
            output::print(&call(cli, s, async |c| c.allow_list(silicon).await).await?)?
        }
        AllowList::Add { account } => {
            output::print(&call(cli, s, async |c| c.allow(silicon, account).await).await?)?;
            next(
                cli,
                "That account (and the Silicons it looks after) can now give this Silicon access.",
            );
        }
        AllowList::Remove { account } => {
            call(cli, s, async |c| c.disallow(silicon, account).await).await?;
            output::print(&json!({"removed": account, "silicon": silicon}))?;
            next(
                cli,
                "Grants it already gave stay until revoked: hook access revoke <id>",
            );
        }
    }
    Ok(())
}

async fn receiving(cli: &Cli, s: &mut Signed, silicon: &str, action: &Receiving) -> CliResult<()> {
    match action {
        Receiving::Register => unreachable!("handled without a Silicon"),
        Receiving::Status => {
            let subscription =
                call(cli, s, async |c| c.receiving_subscription(silicon).await).await?;
            output::print(
                &json!({"receiving": subscription.is_some(), "subscription": subscription}),
            )?;
        }
        Receiving::Subscribe => {
            output::print(&call(cli, s, async |c| c.subscribe(silicon).await).await?)?
        }
        Receiving::Unsubscribe => {
            call(cli, s, async |c| c.unsubscribe(silicon).await).await?;
            output::print(&json!({"receiving": false, "silicon": silicon}))?;
        }
    }
    Ok(())
}

async fn system(cli: &Cli) -> CliResult<()> {
    let folder = store::folder().ok();
    let profile = folder
        .and_then(|folder| store::read(&folder).ok())
        .map(|loaded| loaded.profile(&cli.profile))
        .unwrap_or_default();
    let urls = session::urls(cli, &profile);
    let client = session::hook_client(&urls.hook, profile.telemetry)?;
    let value = match &cli.command {
        Command::System {
            action: System::Version,
        } => {
            let mut version = client.version().await?;
            version["cli"] = json!(env!("CARGO_PKG_VERSION"));
            version["url"] = json!(urls.hook);
            version
        }
        _ => client.health().await?,
    };
    output::print(&value)
}
