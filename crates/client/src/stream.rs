use crate::{Client, Error, Result, models::Event};
use futures::{SinkExt as _, StreamExt as _};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Duration};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{Message, client::IntoClientRequest as _},
};

/// Application-level frames; receipt of Event does not acknowledge it.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    Ready {
        protocol_version: u16,
        connection_id: uuid::Uuid,
        silicon_ids: Vec<String>,
        acknowledged_through: BTreeMap<String, i64>,
        heartbeat_interval_seconds: u64,
        heartbeat_timeout_seconds: u64,
    },
    Ping {
        ping_id: String,
    },
    Event {
        silicon_id: String,
        delivery_sequence: i64,
        event: Box<Event>,
    },
    AckRecorded {
        silicon_id: String,
        acknowledged_through: i64,
    },
    Error {
        code: String,
        message: String,
        recoverable: bool,
    },
}

/// One authenticated WebSocket. Call `next` continuously to answer heartbeats.
/// A relay should process recipient HTTP calls concurrently with this reader.
pub struct Stream {
    socket: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
}

impl Client {
    pub async fn stream(&self, silicons: &[String]) -> Result<Stream> {
        self.negotiate().await?;
        if silicons.is_empty() || silicons.len() > 256 {
            return Err(Error::Invalid(
                "choose between 1 and 256 silicon streams".into(),
            ));
        }
        let mut url = self.url(&["api", "v1", "ws"])?;
        let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
        url.set_scheme(scheme)
            .map_err(|_| Error::Invalid("invalid WebSocket scheme".into()))?;
        {
            let mut query = url.query_pairs_mut();
            for silicon in silicons {
                query.append_pair("silicon_id", silicon);
            }
        }
        let mut request = url.as_str().into_client_request()?;
        let headers = request.headers_mut();
        if let Some(token) = &self.token {
            headers.insert(
                "authorization",
                format!("Bearer {}", token.expose())
                    .parse()
                    .map_err(|_| Error::Invalid("invalid token header".into()))?,
            );
        }
        if let Some(org) = &self.org {
            headers.insert(
                "x-org-id",
                org.parse()
                    .map_err(|_| Error::Invalid("invalid organization header".into()))?,
            );
        }
        if let Some(key) = &self.test_key {
            headers.insert(
                "x-hook-test-key",
                key.expose()
                    .parse()
                    .map_err(|_| Error::Invalid("invalid test key header".into()))?,
            );
        }
        headers.insert(
            "silicon-hook-api-version",
            "v1".parse()
                .map_err(|_| Error::Invalid("invalid version".into()))?,
        );
        let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(4 * 1024 * 1024))
            .max_frame_size(Some(4 * 1024 * 1024));
        let (socket, _) = tokio::time::timeout(
            Duration::from_secs(30),
            tokio_tungstenite::connect_async_with_config(request, Some(config), false),
        )
        .await
        .map_err(|_| Error::Protocol("WebSocket connection timed out".into()))??;
        Ok(Stream { socket })
    }
}

impl Stream {
    /// Receives a frame, immediately replying to application or wire pings.
    pub async fn next(&mut self) -> Result<Option<ServerFrame>> {
        loop {
            match tokio::time::timeout(Duration::from_secs(125), self.socket.next())
                .await
                .map_err(|_| {
                    Error::Protocol("no WebSocket traffic or heartbeat for 125 seconds".into())
                })?
                .transpose()?
            {
                Some(Message::Text(text)) => {
                    let frame: ServerFrame = serde_json::from_str(&text)?;
                    if let ServerFrame::Ready {
                        protocol_version, ..
                    } = &frame
                        && *protocol_version != 1
                    {
                        return Err(Error::Protocol(
                            "unsupported stream protocol version".into(),
                        ));
                    }
                    if let ServerFrame::Ping { ping_id } = &frame {
                        self.send(serde_json::json!({"type":"pong","ping_id":ping_id}))
                            .await?;
                    }
                    return Ok(Some(frame));
                }
                Some(Message::Ping(bytes)) => self.send_message(Message::Pong(bytes)).await?,
                Some(Message::Close(Some(frame))) if u16::from(frame.code) != 1000 => {
                    return Err(Error::StreamClosed {
                        code: frame.code.into(),
                        reason: frame.reason.to_string(),
                    });
                }
                Some(Message::Close(_)) | None => return Ok(None),
                Some(Message::Pong(_)) => {}
                _ => return Err(Error::Protocol("unexpected binary WebSocket frame".into())),
            }
        }
    }
    pub async fn acknowledge(&mut self, silicon: &str, through_sequence: i64) -> Result<()> {
        self.send(serde_json::json!({"type":"ack","silicon_id":silicon,"through_sequence":through_sequence})).await
    }
    pub async fn resume(&mut self, silicon: &str, after_sequence: i64) -> Result<()> {
        self.send(serde_json::json!({"type":"resume","silicon_id":silicon,"after_sequence":after_sequence})).await
    }
    pub async fn close(&mut self) -> Result<()> {
        self.send_message(Message::Close(None)).await
    }
    async fn send(&mut self, value: serde_json::Value) -> Result<()> {
        self.send_message(Message::Text(value.to_string().into()))
            .await
    }
    async fn send_message(&mut self, message: Message) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(5), self.socket.send(message))
            .await
            .map_err(|_| Error::Protocol("WebSocket write timed out".into()))??;
        Ok(())
    }
}
