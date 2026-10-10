//! Receiving Hook events through Ting, for the app that hosts a Silicon (or a
//! Carbon's tools).
//!
//! Hook never sends provider bodies through Ting. Each Ting notification
//! carries a compact [`EventReference`]; the receiver checks the callback, then
//! fetches the full request from Hook with its own Hook access token
//! ([`Receiver::hydrate`] / [`Receiver::resolve`]). Nothing here starts a
//! listener or acknowledges anything: the host owns its Ting destination,
//! durable acceptance, deduplication by event id, and the HTTP 204.
//!
//! Delivery through Ting is optional on the server: when the operator has not
//! configured Ting, Hook still receives and stores every event, queues nothing,
//! and the delivery routes answer `delivery_disabled`. Read the history API
//! instead in that case.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{Error, Result, Secret, models::Event};

mod calls;
pub use calls::{
    DeliveryMode, DestinationReceipt, Publication, PublicationState, ReceivingSubscription,
    Recipient, RecipientReceipt, RecipientRegistration,
};

const MAX_BATCH_BYTES: usize = 2 * 1024 * 1024;
const MAX_BATCH_ITEMS: usize = 100;

/// The receiving account, chosen by the host (never taken from a callback).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryContext {
    /// Hook's app id (`hook`); notifications have type `{app_id}.webhook.received`.
    pub app_id: String,
    /// The receiving account's Silicon Accounts uuid.
    pub recipient_uuid: String,
    /// Its current `c:`/`si:` id, when known (only used to match a `for` that
    /// names the id instead of the uuid).
    pub recipient_id: Option<String>,
}

/// The Silicon a delivered event belongs to.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReferencedSilicon {
    /// Permanent uuid: fetch the event with it.
    pub uuid: String,
    /// The Silicon's id when the event arrived (display only; ids can change).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// The pointer to a retained Hook event inside a Ting notification.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EventReference {
    /// Event id; deduplicate accepted work on it.
    pub id: Uuid,
    /// The Silicon whose hook received the request.
    pub silicon: ReferencedSilicon,
    /// The receiving hook.
    pub hook_id: Uuid,
    /// Position in the hook's stream (arrival order is not implied).
    pub delivery_sequence: i64,
    /// RFC 3339 receipt time.
    pub received_at: String,
    /// `{provider} triggered at HH:MM:SS DD-MM-YYYY {zone}`.
    pub summary: String,
}

/// One Ting callback record. Native Ting callbacks omit `for`; socket records
/// include it (an account uuid, an id, or `{uuid, id}`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TingNotification {
    /// Ting's record id.
    pub id: String,
    /// RFC 3339.
    pub created_at: String,
    /// `{app_id}.webhook.received`.
    #[serde(rename = "type")]
    pub event_type: String,
    /// The recipient, when Ting includes it.
    #[serde(rename = "for", default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<Value>,
    /// Producer key `hook:{event_id}:{sha256(recipient uuid)}`.
    pub key: String,
    /// `{"type": "new_event", "data": {"sender", "metadata": EventReference}}`.
    pub data: Value,
    /// Ting metadata.
    pub metadata: Value,
}

/// A Ting callback body.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TingBatch {
    /// 1 to 100 notifications.
    pub tings: Vec<TingNotification>,
}

/// A hydrated event, ready for the host's durable acceptance.
#[derive(Clone, Debug, Serialize)]
pub struct ReceivedEvent {
    /// Ting's record id.
    pub ting_id: String,
    /// Producer key.
    pub key: String,
    /// The full event from Hook.
    pub event: Event,
}

/// A valid reference whose event Hook no longer has (retention or deletion).
/// Record it as a final delivery result, not as completed work.
#[derive(Clone, Debug, Serialize)]
pub struct UnavailableEvent {
    /// Ting's record id.
    pub ting_id: String,
    /// Producer key.
    pub key: String,
    /// The reference that could not be hydrated.
    pub reference: EventReference,
}

/// What [`Receiver::resolve`] found for one notification. Authentication,
/// authorization, transport and protocol errors are never turned into results.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "outcome", content = "delivery", rename_all = "snake_case")]
pub enum DeliveryOutcome {
    /// The event, hydrated.
    Event(Box<ReceivedEvent>),
    /// The event is gone.
    Unavailable(Box<UnavailableEvent>),
}

/// Checks Ting callbacks for one receiving account. Starts nothing.
#[derive(Clone, Debug)]
pub struct Receiver {
    context: DeliveryContext,
    webhook_id: String,
    secret: Secret,
}

impl Receiver {
    /// Uses the destination id and the high-entropy bearer secret the host
    /// registered with Ting (at least 32 visible characters).
    ///
    /// # Errors
    /// [`Error::Invalid`] for an incomplete context, destination or secret.
    pub fn new(context: DeliveryContext, webhook_id: &str, secret: Secret) -> Result<Self> {
        validate_context(&context)?;
        if !identifier(webhook_id, 255)
            || !(32..=4096).contains(&secret.expose().len())
            || !secret.expose().bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(Error::Invalid(
                "the receiving destination id or callback secret is invalid (the secret needs 32 to 4096 visible characters)".into(),
            ));
        }
        Ok(Self {
            context,
            webhook_id: webhook_id.to_owned(),
            secret,
        })
    }

    /// The receiving account.
    #[must_use]
    pub fn context(&self) -> &DeliveryContext {
        &self.context
    }

    /// Validates a complete Ting callback before any network call: exactly one
    /// `Authorization: Bearer <secret>` and `Ting-Webhook-Id` value, a batch of
    /// 1 to 100 Hook notifications for this account. Other types fail the
    /// batch; a shared host dispatches other apps' notifications itself.
    ///
    /// # Errors
    /// [`Error::Invalid`] for authentication or size failures,
    /// [`Error::Protocol`]/[`Error::Json`] for malformed notifications.
    pub fn decode(
        &self,
        authorization: &str,
        webhook_id: &str,
        body: &[u8],
    ) -> Result<Vec<TingNotification>> {
        let supplied = authorization.strip_prefix("Bearer ").unwrap_or("");
        let provided = Sha256::digest(supplied.as_bytes());
        let expected = Sha256::digest(self.secret.expose().as_bytes());
        if webhook_id != self.webhook_id || !bool::from(provided.ct_eq(&expected)) {
            return Err(Error::Invalid(
                "the receiving callback failed authentication".into(),
            ));
        }
        if body.len() > MAX_BATCH_BYTES {
            return Err(Error::Invalid("the receiving batch exceeds 2 MiB".into()));
        }
        let batch: TingBatch = serde_json::from_slice(body)?;
        validate_batch(&batch.tings)?;
        for notification in &batch.tings {
            reference(&self.context, notification)?;
        }
        Ok(batch.tings)
    }

    /// Fetches every event without acknowledging anything. After success the
    /// host durably accepts and deduplicates the whole batch, then answers 204.
    /// Any error leaves the batch for Ting to retry.
    ///
    /// # Errors
    /// Validation errors, and any Hook failure (a missing event included).
    pub async fn hydrate(
        &self,
        client: &crate::Client,
        notifications: &[TingNotification],
    ) -> Result<Vec<ReceivedEvent>> {
        validate_batch(notifications)?;
        for notification in notifications {
            reference(&self.context, notification)?;
        }
        let mut events = Vec::with_capacity(notifications.len());
        for notification in notifications {
            events.push(
                client
                    .hydrate_notification(&self.context, notification)
                    .await?,
            );
        }
        Ok(events)
    }

    /// Like [`Receiver::hydrate`], but an event Hook no longer has becomes
    /// [`DeliveryOutcome::Unavailable`] instead of failing the batch. Save both
    /// kinds durably before answering 204.
    ///
    /// # Errors
    /// Validation errors and Hook failures other than a missing event.
    pub async fn resolve(
        &self,
        client: &crate::Client,
        notifications: &[TingNotification],
    ) -> Result<Vec<DeliveryOutcome>> {
        validate_batch(notifications)?;
        for notification in notifications {
            reference(&self.context, notification)?;
        }
        let mut outcomes = Vec::with_capacity(notifications.len());
        for notification in notifications {
            outcomes.push(
                client
                    .resolve_notification(&self.context, notification)
                    .await?,
            );
        }
        Ok(outcomes)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HookEnvelope {
    #[serde(rename = "type")]
    event_type: String,
    data: HookData,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookData {
    pub(crate) sender: String,
    pub(crate) metadata: EventReference,
}

pub(crate) fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn validate_context(context: &DeliveryContext) -> Result<()> {
    if !identifier(&context.app_id, 255)
        || !identifier(&context.recipient_uuid, 255)
        || context
            .recipient_id
            .as_deref()
            .is_some_and(|id| !identifier(id, 255))
    {
        return Err(Error::Invalid(
            "the receiving context needs the app id and the recipient's uuid".into(),
        ));
    }
    Ok(())
}

fn validate_batch(notifications: &[TingNotification]) -> Result<()> {
    if notifications.is_empty() || notifications.len() > MAX_BATCH_ITEMS {
        return Err(Error::Invalid(
            "a receiving batch holds 1 to 100 notifications".into(),
        ));
    }
    Ok(())
}

/// Whether a callback's `for` names this recipient.
fn names_recipient(context: &DeliveryContext, value: &Value) -> bool {
    match value {
        Value::String(text) => {
            text == &context.recipient_uuid || context.recipient_id.as_deref() == Some(text)
        }
        Value::Object(object) => {
            object.get("uuid").and_then(Value::as_str) == Some(context.recipient_uuid.as_str())
        }
        _ => false,
    }
}

pub(crate) fn reference(
    context: &DeliveryContext,
    notification: &TingNotification,
) -> Result<HookData> {
    validate_context(context)?;
    if notification.event_type != format!("{}.webhook.received", context.app_id)
        || notification
            .recipient
            .as_ref()
            .is_some_and(|value| !names_recipient(context, value))
        || !identifier(&notification.id, 255)
        || !identifier(&notification.key, 200)
        || !notification.metadata.is_object()
        || OffsetDateTime::parse(&notification.created_at, &Rfc3339).is_err()
    {
        return Err(Error::Protocol(
            "the notification is not a Hook event for this recipient".into(),
        ));
    }
    let envelope: HookEnvelope = serde_json::from_value(notification.data.clone())?;
    let reference = &envelope.data.metadata;
    let recipient_digest = hex::encode(Sha256::digest(context.recipient_uuid.as_bytes()));
    if envelope.event_type != "new_event"
        || envelope.data.sender.is_empty()
        || reference.id.is_nil()
        || reference.hook_id.is_nil()
        || !identifier(&reference.silicon.uuid, 255)
        || reference.delivery_sequence <= 0
        || reference.summary.is_empty()
        || OffsetDateTime::parse(&reference.received_at, &Rfc3339).is_err()
        || notification.key != format!("hook:{}:{recipient_digest}", reference.id)
    {
        return Err(Error::Protocol(
            "the Hook event reference is invalid".into(),
        ));
    }
    Ok(envelope.data)
}
