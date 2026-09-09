//! Caller-owned, in-memory login and relay lifetime. Nothing is written to disk.

use std::{net::Ipv4Addr, time::Duration};

use tokio::{
    sync::{mpsc, watch},
    task::{JoinHandle, JoinSet},
};

use crate::{
    Client, Error, Mutation, Recipient, Relay, RelayNotice, Result, Secret,
    local::{self, LocalClient, LocalIdentity},
    models::Tokens,
};

/// Local delivery configuration, never transmitted during authentication.
#[derive(Clone, Debug)]
pub struct LoginOptions {
    pub recipient: Option<Recipient>,
    /// Empty selects the signed-in Silicon itself. Carbon callers can name
    /// several visible Silicons; each has an independent ordered relay.
    pub silicons: Vec<String>,
    /// Defaults to 18479. Use another local port when a CLI daemon owns it.
    pub port: u16,
    pub notices: Option<mpsc::Sender<RelayNotice>>,
}

impl Default for LoginOptions {
    fn default() -> Self {
        Self {
            recipient: None,
            silicons: Vec::new(),
            port: local::DEFAULT_RELAY_PORT,
            notices: None,
        }
    }
}

impl LoginOptions {
    pub fn new(recipient: Recipient) -> Self {
        Self {
            recipient: Some(recipient),
            silicons: Vec::new(),
            port: local::DEFAULT_RELAY_PORT,
            notices: None,
        }
    }
}

/// A running local request gateway, WebSocket relays and token refresh task.
/// Keep this value alive while serving events. Dropping it stops background
/// work; `shutdown` waits for graceful termination. It never persists tokens.
pub struct RelaySession {
    clients: watch::Receiver<Client>,
    tokens: watch::Receiver<Tokens>,
    recipient: watch::Sender<Option<Recipient>>,
    local_token: Secret,
    control_token: Secret,
    port: u16,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<Result<()>>>,
}

impl std::fmt::Debug for RelaySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelaySession")
            .field("port", &self.port)
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Exchanges an SLT and starts a local relay with automatic token refresh.
    /// A Silicon subscribes to itself. Carbon callers should use
    /// `login_with_options` to choose their streams. Keep the returned session
    /// alive; use `session.client()` to obtain its current authenticated client.
    pub async fn login(
        &self,
        slt: &str,
        recipient: &Recipient,
        mutation: &Mutation,
    ) -> Result<RelaySession> {
        self.login_with_options(slt, &LoginOptions::new(recipient.clone()), mutation)
            .await
    }

    /// Sign in and start the local gateway; configure event delivery afterward
    /// with `RelaySession::webhook`. Pending events remain unacknowledged.
    pub async fn login_without_webhook(
        &self,
        slt: &str,
        mutation: &Mutation,
    ) -> Result<RelaySession> {
        self.login_with_options(slt, &LoginOptions::default(), mutation)
            .await
    }

    pub async fn login_with_options(
        &self,
        slt: &str,
        options: &LoginOptions,
        mutation: &Mutation,
    ) -> Result<RelaySession> {
        if options.port == 0 || options.silicons.len() > 256 {
            return Err(Error::Invalid(
                "choose a nonzero local port and at most 256 Silicons".into(),
            ));
        }
        // Reserve the listening endpoint before consuming a one-use SLT.
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, options.port))
            .await
            .map_err(|e| Error::Protocol(format!("cannot bind local relay: {e}")))?;
        let tokens = self.authenticate(slt, mutation).await?;
        let mut silicons = options.silicons.clone();
        if silicons.is_empty() && tokens.actor.kind == "silicon" {
            silicons.push(tokens.actor.id.clone());
        }
        silicons.sort();
        silicons.dedup();
        let client = authenticated(self, &tokens);
        let (clients_tx, clients) = watch::channel(client.clone());
        let (tokens_tx, tokens_rx) = watch::channel(tokens.clone());
        let (stop, stop_rx) = watch::channel(false);
        let local_token = random_token();
        let control_token = random_token();
        let (identities_tx, identities) = watch::channel(vec![LocalIdentity {
            token: local_token.clone(),
            client,
        }]);
        let mut tasks = JoinSet::new();
        tasks.spawn(local::serve_listener(
            listener,
            control_token.clone(),
            identities,
            stop.clone(),
        ));
        tasks.spawn(refresh_session(
            self.clone(),
            tokens,
            clients_tx,
            tokens_tx,
            identities_tx,
            local_token.clone(),
            stop_rx.clone(),
        ));
        let (recipient, destinations) = watch::channel(options.recipient.clone());
        tasks.spawn(manage_relays(
            silicons,
            destinations,
            clients.clone(),
            stop_rx,
            options.notices.clone(),
        ));
        let stopping = stop.clone();
        let task = tokio::spawn(async move {
            let result = match tasks.join_next().await {
                Some(Ok(result)) => result,
                Some(Err(error)) => Err(Error::Protocol(format!("relay task failed: {error}"))),
                None => Ok(()),
            };
            stopping.send_replace(true);
            if tokio::time::timeout(Duration::from_secs(5), async {
                while tasks.join_next().await.is_some() {}
            })
            .await
            .is_err()
            {
                tasks.abort_all();
            }
            result
        });
        Ok(RelaySession {
            clients,
            tokens: tokens_rx,
            recipient,
            local_token,
            control_token,
            port: options.port,
            stop,
            task: Some(task),
        })
    }
}

impl RelaySession {
    /// Configure or replace this session's delivery destination locally.
    /// Old delivery work is cancelled and pending events replay to the new URL.
    pub fn webhook(&self, url: &str) -> Result<()> {
        if !self.is_running() {
            return Err(Error::Invalid("relay session is stopped".into()));
        }
        self.recipient.send_replace(Some(Recipient::new(url)?));
        Ok(())
    }

    /// Detach event delivery, preserving authentication and the local request gateway.
    /// In-flight work is cancelled when the relay task next runs.
    pub fn unhook(&self) {
        self.recipient.send_replace(None);
    }

    pub fn recipient(&self) -> Option<Recipient> {
        self.recipient.borrow().clone()
    }

    /// Returns an immutable snapshot; call again after refresh for a newer token.
    pub fn client(&self) -> Client {
        self.clients.borrow().clone()
    }
    pub fn tokens(&self) -> Tokens {
        self.tokens.borrow().clone()
    }
    pub fn local_token(&self) -> Secret {
        self.local_token.clone()
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn is_running(&self) -> bool {
        !*self.stop.borrow() && self.task.as_ref().is_some_and(|task| !task.is_finished())
    }
    pub fn local_client(&self) -> Result<LocalClient> {
        LocalClient::new(self.port, self.local_token.clone())
    }
    pub async fn health(&self) -> Result<serde_json::Value> {
        LocalClient::new(self.port, self.control_token.clone())?
            .health()
            .await
    }

    /// Stops delivery and the local listener, without revoking the IAM session.
    pub async fn shutdown(mut self) -> Result<()> {
        self.stop.send_replace(true);
        self.join().await
    }

    /// Waits until stopped or a terminal local/refresh failure occurs.
    pub async fn wait(mut self) -> Result<()> {
        self.join().await
    }

    async fn join(&mut self) -> Result<()> {
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|e| Error::Protocol(format!("relay task failed: {e}")))??;
        }
        Ok(())
    }
}

impl Drop for RelaySession {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        // Dropping JoinSet aborts all child tasks when the supervisor is aborted.
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn manage_relays(
    silicons: Vec<String>,
    mut destinations: watch::Receiver<Option<Recipient>>,
    clients: watch::Receiver<Client>,
    mut stop: watch::Receiver<bool>,
    notices: Option<mpsc::Sender<RelayNotice>>,
) -> Result<()> {
    let mut relays = JoinSet::new();
    loop {
        if *stop.borrow() {
            return Ok(());
        }
        relays.abort_all();
        while relays.join_next().await.is_some() {}
        let recipient = destinations.borrow_and_update().clone();
        if let Some(recipient) = recipient {
            for silicon_id in &silicons {
                let relay = Relay {
                    silicon_id: silicon_id.clone(),
                    recipient: recipient.clone(),
                };
                let credentials = clients.clone();
                let stopping = stop.clone();
                let notices = notices.clone();
                relays.spawn(async move { relay.run(credentials, stopping, notices).await });
            }
        }
        tokio::select! {
            changed = destinations.changed() => { if changed.is_err() { return Ok(()); } }
            _ = stop.changed() => return Ok(()),
            result = relays.join_next(), if !relays.is_empty() => {
                return match result {
                    Some(Ok(result)) => result,
                    Some(Err(error)) => Err(Error::Protocol(format!("relay failed: {error}"))),
                    None => Ok(()),
                };
            }
        }
    }
}

fn authenticated(base: &Client, tokens: &Tokens) -> Client {
    let client = base.with_token(tokens.access_token.expose());
    tokens
        .org_id
        .as_ref()
        .map_or(client.clone(), |org| client.with_organization(org))
}

fn random_token() -> Secret {
    Secret::new(format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    ))
}

async fn refresh_session(
    base: Client,
    mut tokens: Tokens,
    clients: watch::Sender<Client>,
    updated_tokens: watch::Sender<Tokens>,
    identities: watch::Sender<Vec<LocalIdentity>>,
    local_token: Secret,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        let wait = Duration::from_secs(tokens.expires_in.saturating_sub(60).max(1));
        tokio::select! {
            _ = tokio::time::sleep(wait) => {},
            _ = stop.changed() => return Ok(()),
        }
        if *stop.borrow() {
            return Ok(());
        }
        let mutation = Mutation::new();
        let mut delay = 1u64;
        loop {
            let refresh = tokio::select! {
                result = base.refresh(tokens.refresh_token.expose(), &mutation) => result,
                _ = stop.changed() => return Ok(()),
            };
            match refresh {
                Ok(refreshed) => {
                    tokens = refreshed;
                    let client = authenticated(&base, &tokens);
                    clients.send_replace(client.clone());
                    identities.send_replace(vec![LocalIdentity {
                        token: local_token.clone(),
                        client,
                    }]);
                    updated_tokens.send_replace(tokens.clone());
                    break;
                }
                Err(
                    error @ Error::Api {
                        status: 400 | 401 | 403 | 404 | 409 | 422,
                        ..
                    },
                ) => return Err(error),
                Err(_) => {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(delay)) => {},
                        _ = stop.changed() => return Ok(()),
                    }
                    delay = (delay * 2).min(30);
                }
            }
        }
    }
}
