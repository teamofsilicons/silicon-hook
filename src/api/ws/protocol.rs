//! Versioned WebSocket frame schema for ordered, acknowledged delivery.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{api::dto::EventResponse, domain::SiliconId};

/// Current application-level WebSocket protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Close code sent when no valid `pong` arrives within the heartbeat timeout.
pub const HEARTBEAT_CLOSE_CODE: u16 = 4000;
/// Close reason accompanying [`HEARTBEAT_CLOSE_CODE`].
pub const HEARTBEAT_CLOSE_REASON: &str = "heartbeat-timeout";

/// Frames accepted from an authenticated client.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientFrame {
    /// Application heartbeat response. It is never stored or sequenced.
    Pong {
        /// Echoed server ping identifier.
        ping_id: String,
    },
    /// Cumulative acknowledgment for one Silicon stream.
    Ack {
        /// Stream owner.
        silicon_id: SiliconId,
        /// Highest contiguously processed delivery sequence.
        through_sequence: i64,
    },
    /// Requests replay after a client-owned position without acknowledging.
    Resume {
        /// Stream owner.
        silicon_id: SiliconId,
        /// Last sequence the client holds; zero replays from the beginning.
        after_sequence: i64,
    },
}

/// Frames emitted by Hook.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    /// Initial session metadata and server-observed acknowledgment cursors.
    Ready {
        /// Protocol version used by this connection.
        protocol_version: u16,
        /// Unique connection identifier.
        connection_id: Uuid,
        /// Silicon streams the connection receives.
        silicon_ids: Vec<SiliconId>,
        /// Highest acknowledged sequence keyed by Silicon identifier.
        acknowledged_through: BTreeMap<String, i64>,
        /// Seconds between server pings.
        heartbeat_interval_seconds: u64,
        /// Seconds without a valid pong before the server closes.
        heartbeat_timeout_seconds: u64,
    },
    /// Application heartbeat request. It is never stored or sequenced.
    Ping {
        /// Unique heartbeat identifier the client must echo.
        ping_id: String,
    },
    /// One verified provider request in stream order.
    NewEvent {
        /// Provider and retained event details.
        data: EventData,
    },
    /// Confirms that an acknowledgment was stored.
    AckRecorded {
        /// Stream owner.
        silicon_id: SiliconId,
        /// Highest acknowledged sequence after this acknowledgment.
        acknowledged_through: i64,
    },
    /// Structured protocol or command failure.
    Error {
        /// Stable machine-readable category.
        code: String,
        /// Safe human-readable summary.
        message: String,
        /// Whether the connection remains usable.
        recoverable: bool,
    },
}

/// Contents of a hook delivery's `data` field.
#[derive(Clone, Debug, Serialize)]
pub struct EventData {
    /// Hook provider name recorded when the request was received.
    pub sender: String,
    /// Retained event, including stream position, summary and raw request.
    pub metadata: Box<EventResponse>,
}

impl ServerFrame {
    /// Creates a safe recoverable error frame.
    #[must_use]
    pub fn recoverable_error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Error {
            code: code.into(),
            message: message.into(),
            recoverable: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientFrame, PROTOCOL_VERSION, ServerFrame};

    #[test]
    fn client_frames_match_the_published_shapes() -> Result<(), serde_json::Error> {
        let pong: ClientFrame = serde_json::from_str(r#"{"type":"pong","ping_id":"p-1"}"#)?;
        assert!(matches!(pong, ClientFrame::Pong { ping_id } if ping_id == "p-1"));
        let ack: ClientFrame =
            serde_json::from_str(r#"{"type":"ack","silicon_id":"cos:tos","through_sequence":7}"#)?;
        assert!(matches!(
            ack,
            ClientFrame::Ack {
                through_sequence: 7,
                ..
            }
        ));
        assert!(serde_json::from_str::<ClientFrame>(r#"{"type":"unknown"}"#).is_err());
        Ok(())
    }

    #[test]
    fn heartbeat_has_no_delivery_sequence() -> Result<(), serde_json::Error> {
        let encoded = serde_json::to_value(ServerFrame::Ping {
            ping_id: "p-1".to_owned(),
        })?;
        assert_eq!(encoded.get("type"), Some(&serde_json::json!("ping")));
        assert!(encoded.get("delivery_sequence").is_none());
        assert_eq!(PROTOCOL_VERSION, 1);
        Ok(())
    }
}
