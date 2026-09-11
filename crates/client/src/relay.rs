//! In-memory delivery relay. Persistence and credential refresh belong to the caller.
use crate::{Client, Error, EventData, Result, ServerFrame, models::Event};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Local event consumer. A successful HTTP status acknowledges an event.
/// Redirects are never followed. Consumers must deduplicate by event ID.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Recipient(url::Url);
impl Recipient {
    pub fn new(value: &str) -> Result<Self> {
        let url = url::Url::parse(value).map_err(|e| Error::Invalid(e.to_string()))?;
        let mut origin = url.clone();
        origin.set_path("/");
        origin.set_query(None);
        // Silicon's local virtual hosts are reserved loopback names.
        if url
            .host_str()
            .is_some_and(|host| host.ends_with(".localhost"))
        {
            origin
                .set_host(Some("localhost"))
                .map_err(|e| Error::Invalid(e.to_string()))?;
        }
        crate::client::validate_origin(&origin).map_err(|_| Error::Invalid(
            "recipient must be HTTPS (or HTTP on loopback), without embedded credentials or a fragment".into(),
        ))?;
        Ok(Self(url))
    }
    pub fn url(&self) -> &url::Url {
        &self.0
    }

    fn silicon_host(&self) -> Option<&str> {
        self.0
            .host_str()
            .filter(|host| host.ends_with(".localhost"))
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
        let mut http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        if let Some(host) = self.recipient.silicon_host() {
            http = http.resolve(
                host,
                std::net::SocketAddr::from((
                    [127, 0, 0, 1],
                    self.recipient.url().port_or_known_default().unwrap_or(80),
                )),
            );
        }
        let http = http.build()?;
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
                delivery = Some(Box::pin(self.deliver(http, event, notices)));
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

    async fn deliver(
        &self,
        http: &reqwest::Client,
        event: Box<Event>,
        notices: &Option<mpsc::Sender<RelayNotice>>,
    ) -> Result<()> {
        let event_id = event.id;
        let delivery_sequence = event.delivery_sequence;
        let frame = ServerFrame::NewEvent {
            data: EventData {
                sender: event.provider.clone(),
                metadata: event,
            },
        };
        let mut frame = serde_json::to_value(frame)?;
        if self.recipient.silicon_host().is_some() {
            frame["metadata"] = serde_json::json!({"app":"tos>hook","event_id":event_id,"delivery_sequence":delivery_sequence});
        }
        let mut retry = 1u64;
        loop {
            let response = http
                .post(self.recipient.url().clone())
                .header("silicon-hook-event-id", event_id.to_string())
                .header("silicon-hook-delivery-sequence", delivery_sequence)
                .json(&frame)
                .send()
                .await;
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

#[cfg(test)]
mod recipient_tests {
    use super::Recipient;
    #[test]
    fn reserved_local_hosts_do_not_relax_other_url_checks() {
        assert!(Recipient::new("http://ceo.org.localhost/events").is_ok());
        for url in [
            "http://ceo.localhost.evil.test/events",
            "http://example.com/events",
            "http://user:pass@ceo.org.localhost/events",
            "http://ceo.org.localhost/events#fragment",
            "http://ceo.org.localhost:0/",
        ] {
            assert!(Recipient::new(url).is_err(), "accepted {url}");
        }
    }
}
