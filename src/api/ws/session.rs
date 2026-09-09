//! Authenticated WebSocket lifecycle: replay, live delivery, heartbeat, ACKs.

use std::collections::{BTreeMap, VecDeque};

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures::StreamExt as _;
use tokio::{
    sync::broadcast,
    time::{Instant, MissedTickBehavior, interval_at},
};
use uuid::Uuid;

use super::protocol::{
    ClientFrame, HEARTBEAT_CLOSE_CODE, HEARTBEAT_CLOSE_REASON, PROTOCOL_VERSION, ServerFrame,
};
use crate::{
    api::dto::EventResponse,
    application::{ApplicationError, HookApplication, StreamAccess},
    config::RealtimeSettings,
    domain::SiliconId,
    infrastructure::postgres::DeliveryWakeups,
};

const MAX_OUTSTANDING_PINGS: usize = 8;
const MAX_IN_FLIGHT_PER_STREAM: usize = 32;

pub(super) struct SessionAuthority {
    pub(super) epoch: u64,
    pub(super) iam: crate::infrastructure::iam::IamClient,
    pub(super) request: crate::infrastructure::iam::AuthorizationRequest,
}

/// Runs one already-authorized WebSocket until disconnect or heartbeat timeout.
pub(super) async fn serve_socket(
    mut socket: WebSocket,
    application: HookApplication,
    wakeups: DeliveryWakeups,
    settings: RealtimeSettings,
    streams: Vec<StreamAccess>,
    authority: SessionAuthority,
) {
    let connection_id = Uuid::now_v7();
    let mut runtime = SessionRuntime {
        checked_epoch: authority.epoch,
        last_authorized: Instant::now(),
        wakeup_registry: wakeups.clone(),
        authority,
        application,
        settings,
        streams: BTreeMap::new(),
        last_valid_pong: Instant::now(),
        outstanding_pings: VecDeque::new(),
        connection_id,
        wakeups: wakeups.subscribe(),
    };
    for access in streams {
        runtime.streams.insert(
            access.silicon_id().clone(),
            StreamState {
                access,
                sent_through: 0,
                pending: VecDeque::new(),
            },
        );
    }
    let exit = match runtime.run(&mut socket).await {
        Ok(exit) => exit,
        Err(_)
            if matches!(
                runtime.application.environment_is_available().await,
                Ok(false)
            ) =>
        {
            SocketExit::server(4001, "environment-changed")
        }
        Err(error) => {
            tracing::warn!(%connection_id, error = %error, "realtime session failed");
            let _sent = send_frame(
                &mut socket,
                &ServerFrame::Error {
                    code: "internal_error".to_owned(),
                    message: "The session failed and will close.".to_owned(),
                    recoverable: false,
                },
            )
            .await;
            SocketExit::server(1011, "internal-error")
        }
    };
    if exit.send_close {
        let _closed = socket
            .send(Message::Close(Some(CloseFrame {
                code: exit.code,
                reason: exit.reason.into(),
            })))
            .await;
    }
    tracing::info!(%connection_id, code = exit.code, reason = exit.reason, "realtime session closed");
}

struct StreamState {
    access: StreamAccess,
    sent_through: i64,
    pending: VecDeque<i64>,
}

struct SessionRuntime {
    checked_epoch: u64,
    last_authorized: Instant,
    wakeup_registry: DeliveryWakeups,
    authority: SessionAuthority,
    application: HookApplication,
    settings: RealtimeSettings,
    streams: BTreeMap<SiliconId, StreamState>,
    last_valid_pong: Instant,
    outstanding_pings: VecDeque<String>,
    connection_id: Uuid,
    wakeups: broadcast::Receiver<SiliconId>,
}

struct SocketExit {
    code: u16,
    reason: &'static str,
    send_close: bool,
}

impl SocketExit {
    const fn server(code: u16, reason: &'static str) -> Self {
        Self {
            code,
            reason,
            send_close: true,
        }
    }

    const fn peer(code: u16, reason: &'static str) -> Self {
        Self {
            code,
            reason,
            send_close: false,
        }
    }
}

enum SessionEvent {
    Incoming(Option<Result<Message, axum::Error>>),
    Wakeup(Result<SiliconId, broadcast::error::RecvError>),
    Heartbeat,
    Poll,
}

impl SessionRuntime {
    async fn run(&mut self, socket: &mut WebSocket) -> Result<SocketExit, ApplicationError> {
        if let Some(exit) = self.refresh_authority_if_due().await {
            return Ok(exit);
        }
        self.send_ready(socket).await?;
        // Unacknowledged events are attached to every new connection.
        for silicon_id in self.streams.keys().cloned().collect::<Vec<_>>() {
            self.deliver_pending(socket, &silicon_id).await?;
        }

        let heartbeat_interval = self.settings.heartbeat_interval;
        let mut heartbeat = interval_at(Instant::now() + heartbeat_interval, heartbeat_interval);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut poll = interval_at(
            Instant::now() + self.settings.poll_interval,
            self.settings.poll_interval,
        );
        poll.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            let event = tokio::select! {
                incoming = socket.next() => SessionEvent::Incoming(incoming),
                wakeup = self.wakeups.recv() => SessionEvent::Wakeup(wakeup),
                _ = heartbeat.tick() => SessionEvent::Heartbeat,
                _ = poll.tick() => SessionEvent::Poll,
            };
            if !self.application.environment_is_available().await? {
                return Ok(SocketExit::server(4001, "environment-changed"));
            }
            if let Some(exit) = self.refresh_authority_if_due().await {
                return Ok(exit);
            }
            match event {
                SessionEvent::Incoming(Some(Ok(message))) => {
                    if let Some(exit) = self.handle_message(socket, message).await? {
                        return Ok(exit);
                    }
                }
                SessionEvent::Incoming(Some(Err(_))) => {
                    return Ok(SocketExit::peer(1006, "transport-error"));
                }
                SessionEvent::Incoming(None) => {
                    return Ok(SocketExit::peer(1000, "client-disconnected"));
                }
                SessionEvent::Wakeup(Ok(silicon_id)) => {
                    if self.streams.contains_key(&silicon_id) {
                        self.deliver_pending(socket, &silicon_id).await?;
                    }
                }
                SessionEvent::Wakeup(Err(broadcast::error::RecvError::Lagged(_))) => {
                    self.deliver_all_pending(socket).await?;
                }
                SessionEvent::Wakeup(Err(broadcast::error::RecvError::Closed)) => {
                    // The listener is gone; polling continues to deliver.
                }
                SessionEvent::Heartbeat => {
                    if self.last_valid_pong.elapsed() >= self.settings.heartbeat_timeout {
                        return Ok(SocketExit::server(
                            HEARTBEAT_CLOSE_CODE,
                            HEARTBEAT_CLOSE_REASON,
                        ));
                    }
                    self.send_ping(socket).await?;
                }
                SessionEvent::Poll => self.deliver_all_pending(socket).await?,
            }
        }
    }

    async fn refresh_authority_if_due(&mut self) -> Option<SocketExit> {
        let epoch = self.wakeup_registry.authorization_epoch();
        if epoch == self.checked_epoch
            && self.last_authorized.elapsed() < std::time::Duration::from_secs(30)
        {
            return None;
        }
        let context = match self.authority.iam.authorize(&self.authority.request).await {
            Ok(context) => context,
            Err(
                crate::infrastructure::iam::IamError::InvalidCredential
                | crate::infrastructure::iam::IamError::Forbidden
                | crate::infrastructure::iam::IamError::NotFound,
            ) => return Some(SocketExit::server(4003, "authorization-changed")),
            Err(_) => return Some(SocketExit::server(1013, "iam-unavailable")),
        };
        for (silicon, stream) in &mut self.streams {
            let Ok(access) = self.application.authorize_stream(&context, silicon) else {
                return Some(SocketExit::server(4003, "authorization-changed"));
            };
            if access.consumer() != stream.access.consumer() {
                return Some(SocketExit::server(4003, "authorization-changed"));
            }
            stream.access = access;
        }
        self.checked_epoch = epoch;
        self.last_authorized = Instant::now();
        None
    }

    async fn send_ready(&mut self, socket: &mut WebSocket) -> Result<(), ApplicationError> {
        let mut acknowledged_through = BTreeMap::new();
        for (silicon_id, stream) in &mut self.streams {
            let cursor = self.application.stream_cursor(&stream.access).await?;
            stream.sent_through = cursor.acknowledged_through;
            acknowledged_through
                .insert(silicon_id.as_str().to_owned(), cursor.acknowledged_through);
        }
        send_frame(
            socket,
            &ServerFrame::Ready {
                protocol_version: PROTOCOL_VERSION,
                connection_id: self.connection_id,
                silicon_ids: self.streams.keys().cloned().collect(),
                acknowledged_through,
                heartbeat_interval_seconds: self.settings.heartbeat_interval.as_secs(),
                heartbeat_timeout_seconds: self.settings.heartbeat_timeout.as_secs(),
            },
        )
        .await
    }

    async fn send_ping(&mut self, socket: &mut WebSocket) -> Result<(), ApplicationError> {
        let ping_id = Uuid::now_v7().to_string();
        if self.outstanding_pings.len() >= MAX_OUTSTANDING_PINGS {
            self.outstanding_pings.pop_front();
        }
        self.outstanding_pings.push_back(ping_id.clone());
        send_frame(socket, &ServerFrame::Ping { ping_id }).await
    }

    async fn deliver_all_pending(
        &mut self,
        socket: &mut WebSocket,
    ) -> Result<(), ApplicationError> {
        for silicon_id in self.streams.keys().cloned().collect::<Vec<_>>() {
            self.deliver_pending(socket, &silicon_id).await?;
        }
        Ok(())
    }

    /// Bound outstanding delivery so a slow recipient cannot starve heartbeat
    /// processing or force the client to buffer the entire retained history.
    async fn deliver_pending(
        &mut self,
        socket: &mut WebSocket,
        silicon_id: &SiliconId,
    ) -> Result<(), ApplicationError> {
        let Some(stream) = self.streams.get(silicon_id) else {
            return Ok(());
        };
        let available = MAX_IN_FLIGHT_PER_STREAM.saturating_sub(stream.pending.len());
        if available == 0 {
            return Ok(());
        }
        let batch_size = self
            .settings
            .replay_batch_size
            .get()
            .min(u32::try_from(available).unwrap_or(32));
        let events = self
            .application
            .fetch_after(&stream.access, stream.sent_through, batch_size)
            .await?;
        for event in events {
            let sequence = event.delivery_sequence().get();
            send_frame(
                socket,
                &ServerFrame::Event {
                    silicon_id: silicon_id.clone(),
                    delivery_sequence: sequence,
                    event: Box::new(EventResponse::from(&event)),
                },
            )
            .await?;
            if let Some(stream) = self.streams.get_mut(silicon_id) {
                stream.sent_through = stream.sent_through.max(sequence);
                stream.pending.push_back(sequence);
            }
        }
        Ok(())
    }

    async fn handle_message(
        &mut self,
        socket: &mut WebSocket,
        message: Message,
    ) -> Result<Option<SocketExit>, ApplicationError> {
        let text = match message {
            Message::Text(text) => text,
            Message::Close(_) => return Ok(Some(SocketExit::peer(1000, "client-closed"))),
            Message::Binary(_) => {
                send_frame(
                    socket,
                    &ServerFrame::recoverable_error(
                        "unsupported_frame",
                        "Only JSON text frames are accepted.",
                    ),
                )
                .await?;
                return Ok(None);
            }
            Message::Ping(_) | Message::Pong(_) => return Ok(None),
        };
        let frame = match serde_json::from_str::<ClientFrame>(text.as_str()) {
            Ok(frame) => frame,
            Err(error) => {
                send_frame(
                    socket,
                    &ServerFrame::recoverable_error("invalid_frame", error.to_string()),
                )
                .await?;
                return Ok(None);
            }
        };
        match frame {
            ClientFrame::Pong { ping_id } => {
                if let Some(index) = self.outstanding_pings.iter().position(|id| *id == ping_id) {
                    self.outstanding_pings.drain(..=index);
                    self.last_valid_pong = Instant::now();
                }
            }
            ClientFrame::Ack {
                silicon_id,
                through_sequence,
            } => {
                self.acknowledge(socket, &silicon_id, through_sequence)
                    .await?;
            }
            ClientFrame::Resume {
                silicon_id,
                after_sequence,
            } => {
                if after_sequence < 0 {
                    send_frame(
                        socket,
                        &ServerFrame::recoverable_error(
                            "invalid_resume",
                            "after_sequence must not be negative.",
                        ),
                    )
                    .await?;
                } else if let Some(stream) = self.streams.get_mut(&silicon_id) {
                    stream.sent_through = after_sequence;
                    stream.pending.clear();
                    self.deliver_pending(socket, &silicon_id).await?;
                } else {
                    send_unknown_stream(socket).await?;
                }
            }
        }
        Ok(None)
    }

    async fn acknowledge(
        &mut self,
        socket: &mut WebSocket,
        silicon_id: &SiliconId,
        through_sequence: i64,
    ) -> Result<(), ApplicationError> {
        let Some(stream) = self.streams.get(silicon_id) else {
            return send_unknown_stream(socket).await;
        };
        match self
            .application
            .acknowledge_stream(&stream.access, through_sequence)
            .await
        {
            Ok(cursor) => {
                if let Some(stream) = self.streams.get_mut(silicon_id) {
                    stream
                        .pending
                        .retain(|sequence| *sequence > cursor.acknowledged_through);
                }
                send_frame(
                    socket,
                    &ServerFrame::AckRecorded {
                        silicon_id: silicon_id.clone(),
                        acknowledged_through: cursor.acknowledged_through,
                    },
                )
                .await?;
                self.deliver_pending(socket, silicon_id).await
            }
            Err(ApplicationError::Validation { .. }) => {
                send_frame(
                    socket,
                    &ServerFrame::recoverable_error(
                        "invalid_ack",
                        "through_sequence must be between zero and the latest allocated sequence.",
                    ),
                )
                .await
            }
            Err(error) => Err(error),
        }
    }
}

async fn send_unknown_stream(socket: &mut WebSocket) -> Result<(), ApplicationError> {
    send_frame(
        socket,
        &ServerFrame::recoverable_error(
            "unknown_stream",
            "This connection is not subscribed to that Silicon.",
        ),
    )
    .await
}

async fn send_frame(socket: &mut WebSocket, frame: &ServerFrame) -> Result<(), ApplicationError> {
    let encoded = serde_json::to_string(frame).map_err(|error| {
        ApplicationError::Internal(anyhow::Error::new(error).context("encode realtime frame"))
    })?;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.send(Message::Text(encoded.into())),
    )
    .await
    .map_err(|error| {
        ApplicationError::Internal(anyhow::Error::new(error).context("realtime write timed out"))
    })?
    .map_err(|error| ApplicationError::Internal(anyhow::Error::new(error).context("send frame")))
}
