//! Prewarmed physical connection for independently authenticated relay identities.
use crate::{Client, Error, Recipient, Relay, RelayNotice, Result, ServerFrame};
use futures::{SinkExt as _, StreamExt as _};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;

/// One identity's subscriptions and local destination. Credentials stay in memory.
#[derive(Clone, Debug)]
pub struct RelayRegistration {
    pub id: String,
    pub client: Client,
    pub silicons: Vec<String>,
    pub recipient: Recipient,
}

/// Maintains one socket even with no recipients, replacing subscriptions after
/// credentials change. Each logical stream retains its own permissions and ACKs.
pub async fn run_shared_relay(
    base: Client,
    mut registrations: watch::Receiver<Vec<RelayRegistration>>,
    mut stop: watch::Receiver<bool>,
    notices: Option<mpsc::Sender<RelayNotice>>,
) -> Result<()> {
    let mut delay = 1;
    while !*stop.borrow() {
        let current = registrations.borrow_and_update().clone();
        tokio::select! {
            result = connected(&base, &current, &notices) => {
                if let Err(error) = result && let Some(sender) = &notices { let _ = sender.try_send(RelayNotice::Retrying { silicon_id: "shared-relay".into(), delay_seconds: delay, reason: error.to_string() }); }
            }
            changed = registrations.changed() => { if changed.is_err() { return Ok(()); } delay = 1; continue; }
            _ = stop.changed() => return Ok(()),
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(delay)) => {},
            changed = registrations.changed() => { if changed.is_err() { return Ok(()); } delay = 1; continue; }
            _ = stop.changed() => return Ok(()),
        }
        delay = (delay * 2).min(30);
    }
    Ok(())
}

async fn connected(
    base: &Client,
    registrations: &[RelayRegistration],
    notices: &Option<mpsc::Sender<RelayNotice>>,
) -> Result<()> {
    base.negotiate().await?;
    if registrations.len() > 256 {
        return Err(Error::Invalid("at most 256 relay registrations".into()));
    }
    for r in registrations {
        r.recipient.validate_plane(r.client.is_testing())?;
        if r.client.base_url != base.base_url {
            return Err(Error::Invalid("one daemon connects to one Hook origin; use the configured origin for every profile".into()));
        }
        if r.silicons.is_empty() || r.silicons.len() > 256 {
            return Err(Error::Invalid(
                "choose 1–256 Silicon streams per registration".into(),
            ));
        }
    }
    let mut url = base.url(&["api", "v1", "relay", "ws"])?;
    url.set_scheme(if base.base_url.scheme() == "https" {
        "wss"
    } else {
        "ws"
    })
    .map_err(|_| Error::Invalid("invalid relay origin".into()))?;
    let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(4 * 1024 * 1024))
        .max_frame_size(Some(4 * 1024 * 1024));
    let (mut socket, _) = tokio::time::timeout(
        Duration::from_secs(30),
        tokio_tungstenite::connect_async_with_config(url.as_str(), Some(config), false),
    )
    .await
    .map_err(|_| Error::Protocol("relay connection timed out".into()))??;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?;
    let (ack_tx, mut acknowledgments) = mpsc::channel::<serde_json::Value>(256);
    let mut workers = tokio::task::JoinSet::new();
    let mut destinations = std::collections::BTreeMap::new();
    let mut active = std::collections::BTreeSet::new();
    let mut handles = std::collections::BTreeMap::<String, Vec<tokio::task::AbortHandle>>::new();
    for r in registrations {
        let token = r
            .client
            .token
            .as_ref()
            .ok_or_else(|| Error::Invalid("sign in before subscribing".into()))?;
        let org =
            r.client.org.as_ref().ok_or_else(|| {
                Error::Invalid("select an organization before subscribing".into())
            })?;
        let message = serde_json::json!({"type":"subscribe","subscription_id":r.id,"token":token,"org_id":org,"silicon_ids":r.silicons,"app_secret":r.client.test_app_secret,"test_key":r.client.test_key});
        send(&mut socket, message).await?;
        active.insert(r.id.clone());
        for silicon in &r.silicons {
            let (sender, mut events) = mpsc::channel::<Box<crate::models::Event>>(32);
            if destinations
                .insert((r.id.clone(), silicon.clone()), sender)
                .is_some()
            {
                return Err(Error::Invalid("duplicate relay stream".into()));
            }
            let relay = Relay {
                silicon_id: silicon.clone(),
                recipient: r.recipient.clone(),
            };
            let http = http.clone();
            let notices = notices.clone();
            let ack = ack_tx.clone();
            let id = r.id.clone();
            let telemetry_client = r.client.clone();
            let handle = workers.spawn(async move {
                while let Some(event) = events.recv().await {
                    let seq = event.delivery_sequence;
                    let started = std::time::Instant::now();
                    let delivered = relay.deliver(&http, event, &notices, &telemetry_client).await;
                    telemetry_client.emit_telemetry("daemon", "deliver", if delivered.is_ok() { "succeeded" } else { "failed" }, "relay", u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX), 1).await;
                    delivered?;
                    ack.send(serde_json::json!({"type":"frame","subscription_id":id,"frame":{"type":"ack","silicon_id":relay.silicon_id,"through_sequence":seq}})).await.map_err(|_| Error::Protocol("relay acknowledgment queue closed".into()))?;
                }
                Ok::<(), Error>(())
            });
            handles.entry(r.id.clone()).or_default().push(handle);
        }
    }
    loop {
        tokio::select! {
            incoming = tokio::time::timeout(Duration::from_secs(125), socket.next()) => {
                let incoming = incoming.map_err(|_| Error::Protocol("relay heartbeat timed out".into()))?.transpose()?;
                let text = match incoming {
                    Some(Message::Text(text)) => text,
                    Some(Message::Ping(bytes)) => { socket.send(Message::Pong(bytes)).await?; continue; },
                    Some(Message::Pong(_)) => continue,
                    Some(Message::Close(_)) | None => return Ok(()),
                    _ => return Err(Error::Protocol("unexpected relay frame".into())),
                };
                let value: serde_json::Value = serde_json::from_str(&text)?;
                match value.get("type").and_then(serde_json::Value::as_str) {
                    Some("relay_ready") => if value["protocol_version"] != 1 { return Err(Error::Protocol("unsupported relay protocol".into())); },
                    Some("ping") => send(&mut socket, serde_json::json!({"type":"pong","ping_id":value["ping_id"]})).await?,
                    Some("frame") => {
                        let id = value["subscription_id"].as_str().ok_or_else(|| Error::Protocol("missing subscription".into()))?;
                        if !active.contains(id) { continue; }
                        let frame: ServerFrame = serde_json::from_value(value["frame"].clone())?;
                        match frame {
                            ServerFrame::Ping { ping_id } => send(&mut socket, serde_json::json!({"type":"frame","subscription_id":id,"frame":{"type":"pong","ping_id":ping_id}})).await?,
                            ServerFrame::NewEvent { data } => {
                                if data.sender != data.metadata.provider { return Err(Error::Protocol("relay sender mismatch".into())); }
                                let sender = destinations.get(&(id.to_owned(), data.metadata.silicon_id.clone())).ok_or_else(|| Error::Protocol("unsubscribed relay event".into()))?;
                                sender.try_send(data.metadata).map_err(|_| Error::Protocol("relay outstanding window exceeded".into()))?;
                            }
                            ServerFrame::Ready { protocol_version, .. } if protocol_version != 1 => return Err(Error::Protocol("unsupported subscription protocol".into())),
                            ServerFrame::Error { code, .. } => return Err(Error::Protocol(code)),
                            _ => {},
                        }
                    }
                    Some("subscription_error" | "subscription_closed") => {
                        if value["code"] == 1013 { return Err(Error::Protocol("IAM temporarily unavailable; reconnecting".into())); }
                        let id = value["subscription_id"].as_str().ok_or_else(|| Error::Protocol("missing subscription".into()))?;
                        active.remove(id);
                        destinations.retain(|(subscription, _), _| subscription != id);
                        if let Some(tasks) = handles.remove(id) { for task in tasks { task.abort(); } }
                        if let Some(sender) = notices { let _ = sender.try_send(RelayNotice::Retrying { silicon_id: id.into(), delay_seconds: 0, reason: "subscription rejected; sign in again or verify sandbox permissions".into() }); }
                    }
                    Some("error") => return Err(Error::Protocol("relay rejected a control frame".into())),
                    _ => return Err(Error::Protocol("unknown relay message".into())),
                }
            }
            ack = acknowledgments.recv() => if let Some(ack) = ack && ack["subscription_id"].as_str().is_some_and(|id| active.contains(id)) { send(&mut socket, ack).await?; },
            result = workers.join_next(), if !workers.is_empty() => {
                if let Some(result) = result { match result { Ok(result) => result?, Err(error) if error.is_cancelled() => {}, Err(_) => return Err(Error::Protocol("recipient worker stopped".into())) } }
            }
        }
    }
}

async fn send(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    value: serde_json::Value,
) -> Result<()> {
    tokio::time::timeout(
        Duration::from_secs(5),
        socket.send(Message::Text(value.to_string().into())),
    )
    .await
    .map_err(|_| Error::Protocol("relay write timed out".into()))??;
    Ok(())
}
