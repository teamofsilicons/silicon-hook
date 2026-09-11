use crate::{
    args::{Cli, Daemon},
    store::{self, LockedStore, Session},
};
use anyhow::{Context as _, Result};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use silicon_hook_client::{
    Recipient, Relay, Secret,
    local::{self, LocalClient, LocalIdentity},
};
use std::{fs::OpenOptions, io::Write as _, process::Stdio, time::Duration};
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct Descriptor {
    port: u16,
    token: Secret,
    pid: u32,
}
fn descriptor() -> Result<Descriptor> {
    let value = zeroize::Zeroizing::new(std::fs::read(store::folder()?.join("relay.json"))?);
    Ok(serde_json::from_slice(&value)?)
}
fn control() -> Result<LocalClient> {
    let d = descriptor()?;
    Ok(LocalClient::new(d.port, d.token)?)
}
fn session<'a>(stored: &'a mut LockedStore, cli: &Cli) -> Result<&'a mut Session> {
    let p = stored.profile(&cli.profile);
    match cli.test {
        Some(id) => p.test_sessions.get_mut(&id),
        None => p.session.as_mut(),
    }
    .context("Sign in first with hook login --help")
}
fn local_token(session: &mut Session) -> Secret {
    session
        .relay_token
        .get_or_insert_with(|| Secret::new(Uuid::new_v4().simple().to_string()))
        .clone()
}
pub async fn command(cli: &Cli, action: &Daemon) -> Result<()> {
    match action {
        Daemon::Run => run().await,
        Daemon::Start => {
            ensure_started().await?;
            crate::print(&control()?.health().await?)
        }
        Daemon::Status => crate::print(
            &control()
                .context("Relay is not started; run hook daemon start")?
                .health()
                .await?,
        ),
        Daemon::Stop => crate::print(&control()?.stop().await?),
        Daemon::Subscribe { silicons } => {
            let mut stored = LockedStore::open()?;
            let s = session(&mut stored, cli)?;
            anyhow::ensure!(
                silicons.len() <= 256,
                "At most 256 Silicons may be subscribed per identity"
            );
            let mut ids = silicons.clone();
            ids.sort();
            ids.dedup();
            for id in &ids {
                anyhow::ensure!(
                    !id.is_empty() && !id.contains(['/', '\\', '?', '#']),
                    "Invalid Silicon identifier"
                );
            }
            s.silicons = ids;
            local_token(s);
            stored.save()?;
            drop(stored);
            ensure_started().await?;
            crate::print(
                &serde_json::json!({"subscribed":silicons,"profile":cli.profile,"test":cli.test,"applies_within_seconds":5}),
            )
        }
        Daemon::Token | Daemon::Request { .. } => {
            let mut stored = LockedStore::open()?;
            let token = local_token(session(&mut stored, cli)?);
            stored.save()?;
            drop(stored);
            if let Daemon::Request { file } = action {
                let bytes = if file == "-" {
                    use std::io::Read as _;
                    let mut bytes = Vec::new();
                    std::io::stdin().read_to_end(&mut bytes)?;
                    bytes
                } else {
                    std::fs::read(file)?
                };
                let d = descriptor()?;
                crate::print(
                    &LocalClient::new(d.port, token)?
                        .request_bytes(&bytes)
                        .await?,
                )
            } else {
                crate::print(
                    &serde_json::json!({"url":format!("http://hook.localhost:{}/request", descriptor()?.port),"token":token}),
                )
            }
        }
    }
}

pub async fn ensure_started() -> Result<()> {
    if let Ok(client) = control()
        && client.health().await.is_ok()
    {
        return Ok(());
    }
    let folder = store::folder()?;
    // Creating the store establishes private directory permissions.
    drop(LockedStore::open()?);
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    store::private_file(&mut options);
    let log = options.open(folder.join("relay.log"))?;
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .args(["daemon", "run"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // Give the daemon its own process group so ending a terminal command
        // does not deliver that command's group signal to the persistent relay.
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    for _ in 0..50 {
        if let Ok(client) = control()
            && client.health().await.is_ok()
        {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "Relay exited with {status}; inspect {}/relay.log",
                folder.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!(
        "Relay did not become ready; inspect {}/relay.log",
        folder.display()
    )
}

struct Workers(Vec<tokio::task::JoinHandle<()>>);
impl Drop for Workers {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

async fn run() -> Result<()> {
    drop(LockedStore::open()?);
    let folder = store::folder()?;
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    store::private_file(&mut options);
    let lock = options.open(folder.join("relay.lock"))?;
    lock.try_lock_exclusive()
        .context("A Hook relay already holds the daemon lock")?;
    let descriptor = Descriptor {
        port: LockedStore::open()?.data.relay_port.get(),
        token: Secret::new(Uuid::new_v4().simple().to_string()),
        pid: std::process::id(),
    };
    let tmp = folder.join(format!(".relay-{}.json", Uuid::now_v7()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    store::private_file(&mut options);
    let mut file = options.open(&tmp)?;
    file.write_all(&zeroize::Zeroizing::new(serde_json::to_vec(&descriptor)?))?;
    file.sync_all()?;
    std::fs::rename(tmp, folder.join("relay.json"))?;
    let (identities, receiver) = watch::channel(Vec::new());
    let (stop, shutdown) = watch::channel(false);
    let serving = local::serve_local(descriptor.port, descriptor.token, receiver, stop.clone());
    let manager = manage(identities, shutdown);
    tokio::pin!(serving);
    tokio::pin!(manager);
    let (completed, result) = tokio::select! {
        result = &mut serving => (true, result.map_err(anyhow::Error::from)),
        result = &mut manager => (false, result),
        _ = shutdown_signal() => (false, Ok(())),
    };
    let _ = stop.send(true);
    if !completed {
        // Let the authenticated stop response and already-started local requests
        // flush before dropping the HTTP server.
        let _ = tokio::time::timeout(Duration::from_secs(40), &mut serving).await;
    }
    // Removing the descriptor is safe while the exclusive daemon lock is held.
    let _ = std::fs::remove_file(folder.join("relay.json"));
    drop(file);
    drop(lock);
    result
}

async fn manage(
    identities: watch::Sender<Vec<LocalIdentity>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut workers = Workers(Vec::new());
    let mut last = zeroize::Zeroizing::new(String::new());
    let (notices, mut updates) = tokio::sync::mpsc::channel(256);
    let logging = tokio::spawn(async move {
        while let Some(notice) = updates.recv().await {
            if let silicon_hook_client::RelayNotice::Retrying { .. } = notice
                && let Ok(json) = serde_json::to_string(&notice)
            {
                eprintln!("{json}");
            }
        }
    });
    let _logging = Workers(vec![logging]);
    loop {
        let mut stored = LockedStore::open()?;
        let names: Vec<_> = stored.data.profiles.keys().cloned().collect();
        for name in &names {
            let tests: Vec<_> = stored.profile(name).test_sessions.keys().copied().collect();
            for env in std::iter::once(None).chain(tests.into_iter().map(Some)) {
                if let Err(error) =
                    store::refresh_if_needed(&mut stored, name, env, None, None).await
                {
                    eprintln!("Session refresh failed for profile {name}, test {env:?}: {error}");
                }
            }
        }
        for profile in stored.data.profiles.values_mut() {
            for session in profile
                .session
                .iter_mut()
                .chain(profile.test_sessions.values_mut())
            {
                local_token(session);
            }
        }
        let validity: Vec<_> = stored
            .data
            .profiles
            .values()
            .flat_map(|p| p.session.iter().chain(p.test_sessions.values()))
            .map(|session| session.expires_at > store::now())
            .collect();
        let current =
            zeroize::Zeroizing::new(serde_json::to_string(&(&stored.data.profiles, validity))?);
        if *current != *last {
            stored.save()?;
            for task in workers.0.drain(..) {
                task.abort();
            }
            let mut selected = Vec::new();
            for profile in stored.data.profiles.values() {
                for (env, session) in profile
                    .session
                    .iter()
                    .map(|s| (None, s))
                    .chain(profile.test_sessions.iter().map(|(id, s)| (Some(*id), s)))
                {
                    if session.expires_at <= store::now() {
                        continue;
                    }
                    let client = match store::select_client(profile, env, None, None) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    let Some(token) = session.relay_token.clone() else {
                        continue;
                    };
                    selected.push(LocalIdentity {
                        token,
                        client: client.clone(),
                    });
                    let Some(url) = &session.webhook_url else {
                        continue;
                    };
                    let recipient = match Recipient::new(url) {
                        Ok(recipient) => recipient,
                        Err(error) => {
                            eprintln!("Skipping invalid recipient: {error}");
                            continue;
                        }
                    };
                    for silicon_id in &session.silicons {
                        let relay = Relay {
                            silicon_id: silicon_id.clone(),
                            recipient: recipient.clone(),
                        };
                        let (sender, credentials) = watch::channel(client.clone());
                        let stop = shutdown.clone();
                        let notices = notices.clone();
                        workers.0.push(tokio::spawn(async move {
                            let _keep_credentials_alive = sender;
                            if let Err(error) = relay.run(credentials, stop, Some(notices)).await {
                                eprintln!("Relay stopped: {error}");
                            }
                        }));
                    }
                }
            }
            identities.send_replace(selected);
            last = current;
        }
        drop(stored);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(5)) => {},
            changed = shutdown.changed() => { if changed.is_err() || *shutdown.borrow() { return Ok(()); } }
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
