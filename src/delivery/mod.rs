//! Internal Ting publication and authorized event hydration.
//!
//! Raw provider requests remain in Hook. Ting carries a compact, immutable
//! reference so every accepted Hook request fits Ting's smaller send limit.

pub mod credentials;
pub mod observer_authority;
pub mod publisher;
pub mod subscriptions;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::{EventId, EventRecord, HookId};

/// Ting type suffix owned by the configured Hook application.
pub const EVENT_TYPE_SUFFIX: &str = ".webhook.received";

/// Generation-bound pointer to a retained, authenticated Hook event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventReference {
    /// Immutable Hook event identifier, also used for consumer deduplication.
    pub id: EventId,
    /// Organization owning the original request.
    pub org_id: String,
    /// Silicon whose webhook received the request.
    pub silicon_id: String,
    /// Receiving webhook.
    pub hook_id: HookId,
    /// Original Hook stream sequence; arrival order is not implied.
    pub delivery_sequence: i64,
    /// Original provider-receipt timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: OffsetDateTime,
    /// Provider and original trigger time formatted in the hook's IANA time zone.
    pub summary: String,
    /// Production is the nil UUID; tests use their isolated environment UUID.
    pub environment_id: Uuid,
    /// Original event generation, retained across credential rotations; production is zero.
    pub environment_generation: i64,
}

/// Serializes one complete Ting send exactly once, before committing its outbox row.
///
/// The caller persists these bytes and reuses them with a fresh IAM proof on
/// every retry. No provider body, captured credentials or remote URL is included.
///
/// # Errors
/// Returns serialization failures. Application identity and recipient authority
/// are validated by configuration and IAM, not inferred from this envelope.
pub fn prepare_event(
    app_id: &str,
    event: &EventRecord,
    recipient: &str,
    environment_id: Uuid,
    environment_generation: i64,
    delivery: crate::infrastructure::ting::TingDeliveryMode,
) -> Result<Vec<u8>, serde_json::Error> {
    let reference = EventReference {
        id: event.id(),
        org_id: event.organization_id().as_str().to_owned(),
        silicon_id: event.silicon_id().as_str().to_owned(),
        hook_id: event.hook_id(),
        delivery_sequence: event.delivery_sequence().get(),
        received_at: event.received_at(),
        summary: event.summary().to_owned(),
        environment_id,
        environment_generation,
    };
    // Hash the recipient so even the longest valid actor ID fits Ting's
    // 200-byte producer-key limit. Event IDs never repeat after a test clean.
    let recipient_digest = hex::encode(Sha256::digest(recipient.as_bytes()));
    let mut body = serde_json::json!({
        "org_id": event.organization_id().as_str(),
        "type": format!("{app_id}{EVENT_TYPE_SUFFIX}"),
        "for": recipient,
        "key": format!("hook:{}:{recipient_digest}", event.id()),
        "data": {
            "type": "new_event",
            "data": {
                "sender": event.provider().as_str(),
                "metadata": reference,
            },
        },
        "metadata": {},
    });
    if delivery == crate::infrastructure::ting::TingDeliveryMode::Required {
        body["delivery"] = serde_json::json!("required");
    }
    serde_json::to_vec(&body)
}
