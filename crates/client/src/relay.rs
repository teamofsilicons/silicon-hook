//! In-memory delivery relay. Persistence and credential refresh belong to the caller.
use crate::{Client, Error, EventData, Result, ServerFrame, models::Event};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Local event consumer. A successful HTTP status acknowledges an event.
/// Redirects are never followed. Consumers must deduplicate by event ID.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "RecipientWire", into = "RecipientWire")]
pub struct Recipient {
    url: url::Url,
    secret: Option<crate::Secret>,
    isi: Option<String>,
    test_destination: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum RecipientWire {
    Legacy(String),
    Options {
        url: String,
        secret: Option<crate::Secret>,
        isi: Option<String>,
        #[serde(default)]
        test_destination: bool,
    },
}
impl TryFrom<RecipientWire> for Recipient {
    type Error = Error;
    fn try_from(value: RecipientWire) -> Result<Self> {
        match value {
            RecipientWire::Legacy(url) => Self::new(&url),
            RecipientWire::Options {
                url,
                secret,
                isi,
                test_destination,
            } => Ok(Self {
                secret,
                isi,
                test_destination,
                ..Self::new(&url)?
            }),
        }
    }
}
impl From<Recipient> for RecipientWire {
    fn from(value: Recipient) -> Self {
        Self::Options {
            url: value.url.to_string(),
            secret: value.secret,
            isi: value.isi,
            test_destination: value.test_destination,
        }
    }
}
impl Recipient {
    pub fn new(value: &str) -> Result<Self> {
        let url = url::Url::parse(value).map_err(|e| Error::Invalid(e.to_string()))?;
        let mut origin = url.clone();
        origin.set_path("/");
        origin.set_query(None);
        crate::client::validate_origin(&origin).map_err(|_| Error::Invalid(
            "recipient must be HTTPS (or HTTP on loopback), without embedded credentials or a fragment".into(),
        ))?;
        Ok(Self {
            url,
            secret: None,
            isi: None,
            test_destination: false,
        })
    }
    /// Sign exact delivery bytes with a local HMAC key; it is never sent to Hook.
    pub fn with_secret(mut self, secret: crate::Secret) -> Self {
        self.secret = Some(secret);
        self
    }
    /// Optional internal Silicon metadata; delivery never requires an ISI.
    pub fn with_isi(mut self, isi: Option<String>) -> Self {
        self.isi = isi;
        self
    }
    /// Explicitly identify a remote endpoint as a test destination.
    pub fn with_test_destination(mut self, enabled: bool) -> Self {
        self.test_destination = enabled;
        self
    }
    /// Refuses production effects from sandbox deliveries unless explicitly marked.
    pub fn validate_plane(&self, testing: bool) -> Result<()> {
        let local = self.url.host_str().is_some_and(|host| {
            host == "localhost"
                || host.ends_with(".localhost")
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if testing && !local && !self.test_destination {
            return Err(Error::Invalid("test delivery requires loopback or an explicitly marked test destination; use --test-destination".into()));
        }
        Ok(())
    }
    pub fn url(&self) -> &url::Url {
        &self.url
    }
}

/// Observable relay progress. Neither tokens nor captured request bodies are logged.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayNotice {
    Connected {
        silicon_id: String,
    },
    Delivered {
        silicon_id: String,
        event_id: uuid::Uuid,
        sequence: i64,
    },
    Retrying {
        silicon_id: String,
        delay_seconds: u64,
        reason: String,
    },
}

/// One Silicon's ordered stream to one identity's destination. Run multiple
/// relays for independent recipients. Credentials can change without disk state.
pub struct Relay {
    pub silicon_id: String,
    pub recipient: Recipient,
}
impl Relay {
    /// Reconnects with exponential backoff until stopped or the credential
    /// channel closes. A credential update cancels old work and reconnects;
    /// unacknowledged events replay. Delivery is at least once, never exactly once.
    pub async fn run(
        &self,
        mut credentials: watch::Receiver<Client>,
        mut stop: watch::Receiver<bool>,
        notices: Option<mpsc::Sender<RelayNotice>>,
    ) -> Result<()> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        let mut backoff = 1u64;
        loop {
            if *stop.borrow() {
                return Ok(());
            }
            let client = credentials.borrow_and_update().clone();
            let started = tokio::time::Instant::now();
            let reason = tokio::select! {
                result = self.connected(&client, &http, &notices) => match result { Ok(()) => "stream closed".to_owned(), Err(error) => error.to_string() },
                changed = credentials.changed() => { if changed.is_err() { return Ok(()); } continue; }
                changed = stop.changed() => { if changed.is_err() || *stop.borrow() { return Ok(()); } continue; }
            };
            if started.elapsed() >= Duration::from_secs(60) {
                backoff = 1;
            }
            notice(
                &notices,
                RelayNotice::Retrying {
                    silicon_id: self.silicon_id.clone(),
                    delay_seconds: backoff,
                    reason,
                },
            );
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
                changed = credentials.changed() => { if changed.is_err() { return Ok(()); } }
                changed = stop.changed() => { if changed.is_err() || *stop.borrow() { return Ok(()); } }
            }
            backoff = (backoff * 2).min(30);
        }
    }

    async fn connected(
        &self,
        client: &Client,
        http: &reqwest::Client,
        notices: &Option<mpsc::Sender<RelayNotice>>,
    ) -> Result<()> {
        self.recipient.validate_plane(client.is_testing())?;
        let mut stream = client
            .stream(std::slice::from_ref(&self.silicon_id))
            .await?;
        notice(
            notices,
            RelayNotice::Connected {
                silicon_id: self.silicon_id.clone(),
            },
        );
        // The backend permits 32 outstanding events per stream. Keep a bounded
        // queue and one sequential delivery future, while always reading pings.
        let mut queue = std::collections::VecDeque::<Box<Event>>::new();
        let mut current: Option<Box<Event>> = None;
        let mut delivery: Option<
            std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>,
        > = None;
        loop {
            if current.is_none()
                && let Some(event) = queue.pop_front()
            {
                current = Some(event.clone());
                delivery = Some(Box::pin(self.deliver(http, event, notices, client)));
            }
            tokio::select! {
                frame = stream.next() => match frame? {
                    Some(ServerFrame::NewEvent { data }) => {
                        let event = data.metadata;
                        if event.silicon_id != self.silicon_id || data.sender != event.provider {
                            return Err(Error::Protocol("relay event does not match its stream".into()));
                        }
                        if queue.len() >= 32 { return Err(Error::Protocol("relay outstanding window exceeded".into())); }
                        queue.push_back(event);
                    }
                    Some(ServerFrame::Error { code, message, .. }) => return Err(Error::Protocol(format!("{code}: {message}"))),
                    None => return Ok(()),
                    _ => {}
                },
                result = async { match delivery.as_mut() { Some(future) => future.await, None => std::future::pending().await } } => {
                    result?;
                    delivery = None;
                    if let Some(event) = current.take() {
                        stream.acknowledge(&self.silicon_id, event.delivery_sequence).await?;
                        notice(notices, RelayNotice::Delivered { silicon_id: self.silicon_id.clone(), event_id: event.id, sequence: event.delivery_sequence });
                    }
                }
            }
        }
    }

    pub(crate) async fn deliver(
        &self,
        http: &reqwest::Client,
        event: Box<Event>,
        notices: &Option<mpsc::Sender<RelayNotice>>,
        telemetry: &Client,
    ) -> Result<()> {
        let event_id = event.id;
        let delivery_sequence = event.delivery_sequence;
        let silicon_id = event.silicon_id.clone();
        let frame = ServerFrame::NewEvent {
            data: EventData {
                sender: event.provider.clone(),
                metadata: event,
            },
        };
        let mut payload = serde_json::to_value(&frame)?;
        payload["metadata"] = serde_json::json!({"event_id":event_id,"delivery_sequence":delivery_sequence,"silicon_id":silicon_id});
        if let Some(isi) = &self.recipient.isi {
            payload["metadata"]["isi"] = serde_json::json!(isi);
        }
        let body = serde_json::to_vec(&payload)?;
        let mut retry = 1u64;
        let mut attempts = 0u32;
        loop {
            let mut request = http
                .post(self.recipient.url().clone())
                .header("silicon-hook-event-id", event_id.to_string())
                .header("silicon-hook-delivery-sequence", delivery_sequence)
                .header("content-type", "application/json")
                .body(body.clone());
            if let Some(secret) = &self.recipient.secret {
                use hmac::Mac as _;
                let timestamp = time::OffsetDateTime::now_utc().unix_timestamp().to_string();
                let mut mac =
                    hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.expose().as_bytes())
                        .map_err(|_| Error::Invalid("invalid recipient signing key".into()))?;
                mac.update(timestamp.as_bytes());
                mac.update(b".");
                mac.update(&body);
                request = request.header(
                    "silicon-hook-signature",
                    format!(
                        "t={timestamp},v1={}",
                        hex::encode(mac.finalize().into_bytes())
                    ),
                );
            }
            attempts = attempts.saturating_add(1);
            let response = request.send().await;
            let reason = match response {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(response) => format!("recipient returned HTTP {}", response.status().as_u16()),
                Err(error) if error.is_timeout() => "recipient request timed out".to_owned(),
                Err(_) => "recipient could not be reached".to_owned(),
            };
            notice(
                notices,
                RelayNotice::Retrying {
                    silicon_id: self.silicon_id.clone(),
                    delay_seconds: retry,
                    reason,
                },
            );
            telemetry
                .emit_telemetry(
                    "client",
                    "deliver",
                    "retrying",
                    "relay",
                    retry * 1000,
                    attempts,
                )
                .await;
            tokio::time::sleep(Duration::from_secs(retry)).await;
            retry = (retry * 2).min(30);
        }
    }
}
fn notice(sender: &Option<mpsc::Sender<RelayNotice>>, value: RelayNotice) {
    if let Some(sender) = sender {
        let _ = sender.try_send(value);
    }
}
