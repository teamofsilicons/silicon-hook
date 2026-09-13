//! One physical transport with independently authorized logical subscriptions.
use super::session::{self, SessionAuthority, SessionSocket};
use crate::{
    api::{
        environments, extractors,
        handlers::{authorize_management, map_application_error},
        state::ApiState,
    },
    error::AppError,
};
use axum::{
    Extension,
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::Response,
};
use futures::StreamExt as _;
use http::HeaderMap;
use serde::Deserialize;
use std::collections::BTreeMap;
use tokio::{sync::mpsc, task::JoinSet};

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum RelayInput {
    Subscribe {
        subscription_id: String,
        token: secrecy::SecretString,
        org_id: String,
        silicon_ids: Vec<String>,
        app_secret: Option<secrecy::SecretString>,
        test_key: Option<secrecy::SecretString>,
    },
    Frame {
        subscription_id: String,
        frame: serde_json::Value,
    },
    Pong {
        ping_id: String,
    },
}

pub(crate) async fn upgrade(
    Extension(state): Extension<ApiState>,
    upgrade: WebSocketUpgrade,
) -> Response {
    upgrade
        .max_message_size(64 * 1024)
        .on_upgrade(move |socket| async move {
            let _ = serve(socket, state).await;
        })
}

async fn serve(mut socket: WebSocket, state: ApiState) -> anyhow::Result<()> {
    let (outgoing, mut output) = mpsc::channel::<(String, Message)>(32);
    let mut inputs = BTreeMap::new();
    let mut tasks = JoinSet::new();
    let mut heartbeat = tokio::time::interval(state.realtime.heartbeat_interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ping = String::new();
    let mut last_pong = tokio::time::Instant::now();
    send(
        &mut socket,
        serde_json::json!({"type":"relay_ready","protocol_version":1}),
    )
    .await?;
    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if last_pong.elapsed() >= state.realtime.heartbeat_timeout { return Ok(()); }
                // Keep one outstanding challenge until it is answered.
                if ping.is_empty() { ping = uuid::Uuid::now_v7().to_string(); }
                send(&mut socket, serde_json::json!({"type":"ping","ping_id":ping})).await?;
            }
            item = output.recv() => if let Some((id, message)) = item {
                let value = match message {
                    Message::Text(text) => serde_json::json!({"type":"frame","subscription_id":id,"frame":serde_json::from_str::<serde_json::Value>(&text)?}),
                    Message::Close(frame) => serde_json::json!({"type":"subscription_closed","subscription_id":id,"code":frame.map(|f| f.code)}),
                    _ => continue,
                };
                send(&mut socket, value).await?;
            },
            incoming = socket.next() => {
                let Some(Ok(message)) = incoming else { return Ok(()); };
                let text = match message {
                    Message::Text(text) => text,
                    Message::Ping(bytes) => { socket.send(Message::Pong(bytes)).await?; continue; },
                    Message::Pong(_) => continue,
                    Message::Binary(_) | Message::Close(_) => return Ok(()),
                };
                // Never echo a parsing error: it may contain a credential value.
                let Ok(frame) = serde_json::from_str::<RelayInput>(&text) else {
                    send(&mut socket, serde_json::json!({"type":"error","code":"invalid_relay_frame"})).await?;
                    continue;
                };
                match frame {
                    RelayInput::Pong { ping_id } => if !ping.is_empty() && ping_id == ping { last_pong = tokio::time::Instant::now(); ping.clear(); },
                    RelayInput::Frame { subscription_id, frame } => {
                        if let Some(input) = inputs.get(&subscription_id) {
                            let input: &mpsc::Sender<Message> = input;
                            // Bounded control queues: a flooding subscriber cannot stall heartbeats.
                            if input.try_send(Message::Text(frame.to_string().into())).is_err() { return Ok(()); }
                        } else { return Ok(()); }
                    }
                    RelayInput::Subscribe { subscription_id, token, org_id, silicon_ids, app_secret, test_key } => {
                        if subscription_id.is_empty() || subscription_id.len() > 128 || !subscription_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') || inputs.contains_key(&subscription_id) || inputs.len() >= 256 {
                            return Ok(());
                        }
                        match authorize(&state, token, org_id, silicon_ids, app_secret, test_key).await {
                            Ok((scoped, streams, authority)) => {
                                let (input, incoming) = mpsc::channel(64);
                                inputs.insert(subscription_id.clone(), input);
                                tasks.spawn(session::serve(SessionSocket::Shared { id: subscription_id, incoming, outgoing: outgoing.clone() }, scoped.application, scoped.wakeups, scoped.realtime, streams, authority));
                            }
                            Err(error) => send(&mut socket, serde_json::json!({"type":"subscription_error","subscription_id":subscription_id,"status":error.status().as_u16()})).await?,
                        }
                    }
                }
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {},
        }
    }
}

async fn send(socket: &mut WebSocket, value: serde_json::Value) -> anyhow::Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.send(Message::Text(value.to_string().into())),
    )
    .await??;
    Ok(())
}

async fn authorize(
    state: &ApiState,
    token: secrecy::SecretString,
    org: String,
    silicons: Vec<String>,
    app_secret: Option<secrecy::SecretString>,
    key: Option<secrecy::SecretString>,
) -> Result<
    (
        ApiState,
        Vec<crate::application::StreamAccess>,
        SessionAuthority,
    ),
    AppError,
> {
    use secrecy::ExposeSecret as _;
    if silicons.is_empty() || silicons.len() > state.realtime.max_silicons_per_connection.get() {
        return Err(AppError::validation("invalid_silicon_id"));
    }
    let ids = silicons
        .into_iter()
        .map(|id| {
            crate::domain::SiliconId::new(id)
                .map_err(|_| AppError::validation("invalid_silicon_id"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Bearer {}", token.expose_secret())
            .parse()
            .map_err(|_| AppError::Unauthenticated)?,
    );
    headers.insert(
        "x-org-id",
        org.parse().map_err(|_| AppError::Unauthenticated)?,
    );
    if let Some(secret) = app_secret {
        headers.insert(
            environments::TEST_APP_HEADER,
            secret
                .expose_secret()
                .parse()
                .map_err(|_| AppError::Unauthenticated)?,
        );
    }
    if let Some(key) = key {
        headers.insert(
            environments::TEST_KEY_HEADER,
            key.expose_secret()
                .parse()
                .map_err(|_| AppError::Unauthenticated)?,
        );
    }
    let mut scoped = state.clone();
    environments::resolve(&mut scoped, "/api/v1/ws", &headers).await?;
    super::super::contracts::admit(&scoped).await?;
    let authorization = authorize_management(&scoped, &headers, &ids).await?;
    let streams = ids
        .iter()
        .map(|id| {
            scoped
                .application
                .authorize_stream(&authorization, id)
                .map_err(map_application_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let authority = SessionAuthority {
        epoch: scoped.wakeups.authorization_epoch(),
        iam: scoped.iam.clone(),
        request: crate::infrastructure::iam::AuthorizationRequest {
            token: extractors::bearer_token(&headers)?,
            org_id: extractors::organization_id(&headers)?,
            targets: ids,
        },
    };
    Ok((scoped, streams, authority))
}
