//! Delivery of accepted events through Ting, and authorized hydration.
//!
//! Raw provider requests remain in Hook. Ting carries a compact, immutable
//! reference so every accepted request fits Ting's smaller send limit; the
//! recipient fetches the full request from Hook with its own access token.
//!
//! Delivery is optional: it runs only when `HOOK_TING_URL` is set. Without it
//! Hook still receives, verifies and stores every event, and queues nothing.

pub mod adapter;
pub mod publisher;
pub mod subscriptions;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use crate::{
    domain::{EventId, EventRecord, HookId},
    infrastructure::ting::{EVENT_TYPE_SUFFIX, TingDeliveryMode, TingRecipient},
};

/// The Silicon a delivered event belongs to.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReferencedSilicon {
    /// Permanent Silicon Accounts uuid; use it to fetch the event.
    pub uuid: String,
    /// The Silicon's public id when the event was accepted (display only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// Pointer to a retained, verified Hook event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventReference {
    /// Immutable Hook event identifier, also used for consumer deduplication.
    pub id: EventId,
    /// The Silicon whose webhook received the request.
    pub silicon: ReferencedSilicon,
    /// Receiving webhook.
    pub hook_id: HookId,
    /// Original Hook stream sequence; arrival order is not implied.
    pub delivery_sequence: i64,
    /// Original provider-receipt timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: OffsetDateTime,
    /// Provider and original trigger time formatted in the hook's IANA time zone.
    pub summary: String,
}

/// Serializes one complete Ting send exactly once, before committing its outbox row.
///
/// The caller persists these bytes and reuses them with a fresh proof on every
/// retry. No provider body, captured credential or remote URL is included. The
/// event envelope keeps the documented shape: `type: new_event` and
/// `data: {sender, metadata}`.
///
/// # Errors
/// Returns serialization failures.
pub fn prepare_event(
    app_id: &str,
    event: &EventRecord,
    silicon: &ReferencedSilicon,
    recipient: &TingRecipient,
    delivery: TingDeliveryMode,
) -> Result<Vec<u8>, serde_json::Error> {
    let reference = EventReference {
        id: event.id(),
        silicon: silicon.clone(),
        hook_id: event.hook_id(),
        delivery_sequence: event.delivery_sequence().get(),
        received_at: event.received_at(),
        summary: event.summary().to_owned(),
    };
    // Hash the recipient so the producer key stays short and stable.
    let recipient_digest = hex::encode(Sha256::digest(recipient.uuid.as_bytes()));
    let mut body = serde_json::json!({
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
    if delivery == TingDeliveryMode::Required {
        body["delivery"] = serde_json::json!("required");
    }
    serde_json::to_vec(&body)
}
