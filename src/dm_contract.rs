//! Silicon DM's immutable Hook-event wire contract.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::domain::{EventId, EventRecord, EventType, OrganizationId, SiliconId, TraceId};

/// Largest serialized DM request that Hook may durably accept.
///
/// Every supported worker configuration accepts at least this many bytes, so
/// an event admitted by the API can never become a deterministic local dead
/// letter solely because normalization expanded its JSON representation.
pub const MAX_DM_REQUEST_BODY_BYTES: usize = 1_052_672;

/// Minimal system event published to DM's internal Hook endpoint.
#[derive(Clone, Deserialize, Serialize)]
pub struct SystemEvent {
    /// Stable event identity used by DM for deduplication.
    pub event_id: EventId,
    /// Organization authorization boundary.
    pub org_id: OrganizationId,
    /// Silicon that should receive the event.
    pub silicon_id: SiliconId,
    /// Namespaced event type.
    #[serde(rename = "type")]
    pub event_type: EventType,
    /// Correlation trace propagated from ingress, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<TraceId>,
    /// Original webhook payload. Domain validation guarantees an object.
    pub payload: Map<String, Value>,
}

impl From<&EventRecord> for SystemEvent {
    fn from(event: &EventRecord) -> Self {
        Self {
            event_id: event.id(),
            org_id: event.organization_id().clone(),
            silicon_id: event.silicon_id().clone(),
            event_type: event.envelope().event_type().clone(),
            trace_id: Some(event.envelope().trace_id().clone()),
            payload: event.envelope().payload().clone(),
        }
    }
}

impl fmt::Debug for SystemEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemEvent")
            .field("event_id", &self.event_id)
            .field("org_id", &self.org_id)
            .field("silicon_id", &self.silicon_id)
            .field("event_type", &self.event_type)
            .field("trace_id", &self.trace_id)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

/// Exact, bounded JSON bytes committed to the transactional outbox.
#[derive(Clone, Eq, PartialEq)]
pub struct DmRequestBody(Vec<u8>);

impl DmRequestBody {
    /// Serializes the published DM representation once and enforces its
    /// durable-acceptance bound.
    ///
    /// # Errors
    ///
    /// Returns [`DmRequestBodyError::TooLarge`] when normalization produced a
    /// request that no valid worker configuration is required to send.
    pub fn from_event(event: &EventRecord) -> Result<Self, DmRequestBodyError> {
        let bytes = serde_json::to_vec(&SystemEvent::from(event))
            .map_err(DmRequestBodyError::Serialization)?;
        if bytes.len() > MAX_DM_REQUEST_BODY_BYTES {
            return Err(DmRequestBodyError::TooLarge {
                actual: bytes.len(),
                maximum: MAX_DM_REQUEST_BODY_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    /// Borrows the exact bytes to persist or transmit.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the exact serialized byte count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether this body contains no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for DmRequestBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DmRequestBody")
            .field("bytes", &self.len())
            .finish()
    }
}

/// Failure to construct the exact DM bytes for a newly accepted event.
#[derive(Debug, Error)]
pub enum DmRequestBodyError {
    /// A validated event could not be represented as JSON.
    #[error("failed to serialize the DM request body")]
    Serialization(#[source] serde_json::Error),
    /// The normalized representation exceeds the common API/worker bound.
    #[error("serialized DM request is {actual} bytes; maximum is {maximum}")]
    TooLarge {
        /// Actual serialized size.
        actual: usize,
        /// Maximum accepted serialized size.
        maximum: usize,
    },
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use time::macros::datetime;

    use crate::domain::{
        EventEnvelopeInput, EventId, EventRecord, HookId, OrganizationId, RequestDigest, SiliconId,
        TraceId,
    };

    use super::{DmRequestBody, DmRequestBodyError, MAX_DM_REQUEST_BODY_BYTES, SystemEvent};

    fn event_from_raw(raw: &[u8]) -> Result<EventRecord, Box<dyn std::error::Error>> {
        let input = serde_json::from_slice::<EventEnvelopeInput>(raw)?;
        let received_at = datetime!(2026-08-31 12:00 UTC);
        let envelope = input.normalize(received_at, TraceId::new("req_contract")?)?;
        Ok(EventRecord::accept(
            EventId::new(),
            OrganizationId::new("org:contract")?,
            SiliconId::new("silicon:contract")?,
            HookId::new(),
            envelope,
            RequestDigest::sha256(raw),
            received_at,
        ))
    }

    #[test]
    fn request_body_is_the_exact_published_representation() -> Result<(), Box<dyn std::error::Error>>
    {
        let event = event_from_raw(br#"{"type":"contract.created","payload":{"ok":true}}"#)?;
        let request = DmRequestBody::from_event(&event)?;
        let decoded = serde_json::from_slice::<Value>(request.as_bytes())?;

        assert_eq!(
            decoded,
            serde_json::json!({
                "event_id": event.id(),
                "org_id": "org:contract",
                "silicon_id": "silicon:contract",
                "type": "contract.created",
                "trace_id": "req_contract",
                "payload": {"ok": true}
            })
        );
        assert!(request.len() <= MAX_DM_REQUEST_BODY_BYTES);
        Ok(())
    }

    #[test]
    fn compact_numeric_input_cannot_expand_past_delivery_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        const NUMBER_COUNT: usize = 100_000;

        let numbers = std::iter::repeat_n("1e10", NUMBER_COUNT)
            .collect::<Vec<_>>()
            .join(",");
        let raw = format!(r#"{{"type":"contract.created","payload":{{"numbers":[{numbers}]}}}}"#);
        assert!(raw.len() <= 1024 * 1024);

        let event = event_from_raw(raw.as_bytes())?;
        let normalized = serde_json::to_vec(&SystemEvent::from(&event))?;
        assert!(normalized.len() > MAX_DM_REQUEST_BODY_BYTES);
        assert!(matches!(
            DmRequestBody::from_event(&event),
            Err(DmRequestBodyError::TooLarge {
                maximum: MAX_DM_REQUEST_BODY_BYTES,
                ..
            })
        ));
        Ok(())
    }
}
