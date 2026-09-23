//! Stateless publisher setup and integration with the application's Ting receiver.
//!
//! The host owns Ting login, its shared transport, token refresh and durable
//! event deduplication. This module verifies the local callback and hydrates
//! references through Hook using current authorization. It never acknowledges
//! Ting or treats fetching a payload as accepting application work.

use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{Client, Error, Mutation, Result, Secret, models::Event};

mod receiver;
pub use receiver::{ReceiverCapability, ReceiverEnvironment, ReceiverKind, ReceiverScope};

const MAX_BATCH_BYTES: usize = 2 * 1024 * 1024;
const MAX_BATCH_ITEMS: usize = 100;

/// Non-secret metadata for the organization's dedicated internal publisher.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublisherMetadata {
    pub org_id: String,
    pub actor_id: String,
    pub expires_at: String,
}

/// Trusted receiving identity selected by the enclosing app, never by a callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryContext {
    pub app_id: String,
    pub org_id: String,
    pub recipient_id: String,
    /// Nil in production; the shared environment UUID in testing.
    pub environment_id: Uuid,
}

/// Original event identity inside a Ting notification, without provider payloads.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventReference {
    pub id: Uuid,
    pub org_id: String,
    pub silicon_id: String,
    pub hook_id: Uuid,
    pub delivery_sequence: i64,
    pub received_at: String,
    pub summary: String,
    pub environment_id: Uuid,
    /// Original generation, which can precede the current credential generation.
    pub environment_generation: i64,
}

/// Ting's local callback record. Native Ting omits `for`; socket records include it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TingNotification {
    pub id: String,
    pub created_at: String,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(rename = "for", default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    pub key: String,
    pub data: Value,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TingBatch {
    pub tings: Vec<TingNotification>,
}

/// A hydrated event, ready for the host's durable acceptance/deduplication step.
#[derive(Clone, Debug, Serialize)]
pub struct ReceivedEvent {
    pub ting_id: String,
    pub key: String,
    pub event: Event,
}

/// A validated reference whose payload is no longer available from Hook.
/// The host must retain this as a terminal delivery result, not completed work.
#[derive(Clone, Debug, Serialize)]
pub struct UnavailableEvent {
    pub ting_id: String,
    pub key: String,
    pub reference: EventReference,
}

/// A delivery the host can durably accept or record as unavailable before ACK.
/// Authentication, authorization, transport and protocol errors are never
/// converted into terminal results.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "outcome", content = "delivery", rename_all = "snake_case")]
pub enum DeliveryOutcome {
    Event(Box<ReceivedEvent>),
    Unavailable(Box<UnavailableEvent>),
}

/// Immutable callback authentication and routing. No listener or daemon is started.
#[derive(Clone, Debug)]
pub struct Receiver {
    context: DeliveryContext,
    webhook_id: String,
    secret: Secret,
}

impl Receiver {
    /// Use the stable destination ID and high-entropy bearer secret registered
    /// internally with Ting. A receiving URL never goes to Hook.
    pub fn new(context: DeliveryContext, webhook_id: &str, secret: Secret) -> Result<Self> {
        validate_context(&context)?;
        if !identifier(webhook_id, 255)
            || !(32..=4096).contains(&secret.expose().len())
            || !secret.expose().bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(Error::Invalid(
                "invalid receiving destination or secret".into(),
            ));
        }
        Ok(Self {
            context,
            webhook_id: webhook_id.to_owned(),
            secret,
        })
    }

    pub fn context(&self) -> &DeliveryContext {
        &self.context
    }

    /// Validate a complete native Ting callback before any network I/O. Supply
    /// exactly one Authorization and Ting-Webhook-Id header. Unhandled types
    /// fail the batch: a shared host must dispatch other apps separately.
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
                "receiving callback authentication failed".into(),
            ));
        }
        if body.len() > MAX_BATCH_BYTES {
            return Err(Error::Invalid("receiving batch exceeds 2 MiB".into()));
        }
        let batch: TingBatch = serde_json::from_slice(body)?;
        validate_batch(&batch.tings)?;
        for notification in &batch.tings {
            reference(&self.context, notification)?;
        }
        Ok(batch.tings)
    }

    /// Fetch every payload without acknowledging any item. After success, the
    /// host must durably accept/deduplicate the entire batch before HTTP204.
    /// Errors leave the batch retryable; never acknowledge missing payloads.
    pub async fn hydrate(
        &self,
        client: &Client,
        notifications: &[TingNotification],
    ) -> Result<Vec<ReceivedEvent>> {
        validate_batch(notifications)?;
        // Validate all routes before fetching any raw payload.
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

    /// Resolve the complete batch, including references whose retained payload
    /// has disappeared. Validate every reference before fetching any event.
    ///
    /// The host must durably save both events and unavailable results, dedupe
    /// retries, and report unavailable items before returning HTTP 204. Nothing
    /// is acknowledged here. A transient or authority failure rejects the batch.
    pub async fn resolve(
        &self,
        client: &Client,
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
struct HookData {
    sender: String,
    metadata: EventReference,
}

fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn validate_context(context: &DeliveryContext) -> Result<()> {
    if !identifier(&context.app_id, 255)
        || !identifier(&context.org_id, 255)
        || !identifier(&context.recipient_id, 255)
    {
        return Err(Error::Invalid(
            "receiving context requires application, organization and actor".into(),
        ));
    }
    Ok(())
}

fn validate_batch(notifications: &[TingNotification]) -> Result<()> {
    if notifications.is_empty() || notifications.len() > MAX_BATCH_ITEMS {
        return Err(Error::Invalid(
            "receiving batch requires 1–100 notifications".into(),
        ));
    }
    Ok(())
}

fn reference(context: &DeliveryContext, notification: &TingNotification) -> Result<HookData> {
    validate_context(context)?;
    if notification.event_type != format!("{}.webhook.received", context.app_id)
        || notification
            .recipient
            .as_ref()
            .is_some_and(|id| id != &context.recipient_id)
        || !identifier(&notification.id, 255)
        || !identifier(&notification.key, 200)
        || !notification.metadata.is_object()
        || OffsetDateTime::parse(&notification.created_at, &Rfc3339).is_err()
    {
        return Err(Error::Protocol(
            "notification does not match the receiving context".into(),
        ));
    }
    let envelope: HookEnvelope = serde_json::from_value(notification.data.clone())?;
    let reference = &envelope.data.metadata;
    let recipient_digest = hex::encode(Sha256::digest(context.recipient_id.as_bytes()));
    if envelope.event_type != "new_event"
        || envelope.data.sender.is_empty()
        || reference.org_id != context.org_id
        || reference.environment_id != context.environment_id
        || reference.environment_generation < 0
        || (reference.environment_id.is_nil() && reference.environment_generation != 0)
        || reference.id.is_nil()
        || reference.hook_id.is_nil()
        || !identifier(&reference.silicon_id, 255)
        || reference.delivery_sequence <= 0
        || reference.summary.is_empty()
        || OffsetDateTime::parse(&reference.received_at, &Rfc3339).is_err()
        || notification.key != format!("hook:{}:{recipient_digest}", reference.id)
    {
        return Err(Error::Protocol("invalid Hook event reference".into()));
    }
    Ok(envelope.data)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecipientRegistration {
    pub id: String,
    pub app_id: String,
    #[serde(rename = "for")]
    pub recipient: String,
    pub active: bool,
    /// Explicit recipient opt-in; ordinary registration does not enable it.
    pub required_delivery: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceivingSubscription {
    pub id: Uuid,
    pub org_id: String,
    pub silicon_id: String,
    pub recipient_id: String,
    pub created_at: String,
}

#[derive(Deserialize)]
struct SubscriptionResponse {
    receiving: bool,
    subscription: Option<ReceivingSubscription>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationState {
    Pending,
    AcceptedByTing,
    AcceptedSilently,
}

/// Original delivery policy; this does not prove receipt or completed work.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    Ordinary,
    Required,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicationStatus {
    pub event_id: Uuid,
    pub recipient_id: String,
    pub state: PublicationState,
    pub delivery: DeliveryMode,
    /// Notification preference at acceptance; absent until Ting accepts.
    pub silent: Option<bool>,
    pub attempts: i64,
    pub ting_id: Option<String>,
    pub last_error_code: Option<String>,
    pub accepted_at: Option<String>,
    pub next_attempt_at: String,
    pub expires_at: String,
    pub recipient_receipt: Option<RecipientReceipt>,
    pub recipient_status_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecipientReceipt {
    pub id: String,
    pub read: bool,
    pub silent: bool,
    pub delivery: DeliveryMode,
    pub deliveries: Vec<DestinationReceipt>,
    pub more_destinations: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DestinationReceipt {
    pub webhook_id: String,
    pub delivery_acked: bool,
    pub read_acked: bool,
}

impl Client {
    /// Provision the selected organization's dedicated internal publisher.
    /// The caller must be a Carbon owner/admin; `slt` belongs to the dedicated
    /// Silicon's Hook login. Repeat the same SLT and mutation after uncertainty.
    /// Hook stores and refreshes the publisher credentials; only metadata returns.
    pub async fn provision_publisher(
        &self,
        slt: &Secret,
        mutation: &Mutation,
    ) -> Result<PublisherMetadata> {
        self.configure_publisher(slt, false, mutation).await
    }

    /// Explicitly recover a publisher whose existing refresh family was rejected.
    /// A usable publisher cannot be replaced. The owner/admin authority, dedicated
    /// Silicon SLT and stable retry key requirements match `provision_publisher`.
    pub async fn replace_rejected_publisher(
        &self,
        slt: &Secret,
        mutation: &Mutation,
    ) -> Result<PublisherMetadata> {
        self.configure_publisher(slt, true, mutation).await
    }

    async fn configure_publisher(
        &self,
        slt: &Secret,
        replace_rejected: bool,
        mutation: &Mutation,
    ) -> Result<PublisherMetadata> {
        if !(1..=4096).contains(&slt.expose().len())
            || !slt.expose().bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(Error::Invalid(
                "publisher SLT requires 1–4096 visible ASCII characters".into(),
            ));
        }
        #[derive(Serialize)]
        struct Request<'a> {
            slt: &'a Secret,
            replace_rejected: bool,
        }
        self.call(
            Method::POST,
            &["delivery", "publisher"],
            &[],
            Some(&Request {
                slt,
                replace_rejected,
            }),
            Some(mutation),
        )
        .await
    }

    /// Resolve a trusted-route notification without acknowledging it. Only an
    /// authenticated Hook `404 not_found` becomes an unavailable result; it may
    /// represent retention or cleanup, so no more specific cause is claimed.
    pub async fn resolve_notification(
        &self,
        context: &DeliveryContext,
        notification: &TingNotification,
    ) -> Result<DeliveryOutcome> {
        let data = reference(context, notification)?;
        match self.hydrate_notification(context, notification).await {
            Ok(event) => Ok(DeliveryOutcome::Event(Box::new(event))),
            Err(Error::Api {
                status: 404, code, ..
            }) if code == "not_found" => {
                Ok(DeliveryOutcome::Unavailable(Box::new(UnavailableEvent {
                    ting_id: notification.id.clone(),
                    key: notification.key.clone(),
                    reference: data.metadata,
                })))
            }
            Err(error) => Err(error),
        }
    }

    /// Resolve the selected app, live actor/org and sandbox into trusted routing.
    pub async fn delivery_context(&self) -> Result<DeliveryContext> {
        let iam = self.iam().await?;
        let status = self.login_status().await?;
        if !status.authenticated || iam.testing != self.is_testing() {
            return Err(Error::Invalid(
                "receiving requires a current authenticated context".into(),
            ));
        }
        let context = DeliveryContext {
            app_id: iam
                .app_id
                .ok_or_else(|| Error::Protocol("Hook application is not configured".into()))?,
            org_id: status
                .org_id
                .ok_or_else(|| Error::Invalid("select an organization before receiving".into()))?,
            recipient_id: status
                .actor
                .ok_or_else(|| Error::Protocol("authenticated actor missing".into()))?
                .id,
            environment_id: if self.is_testing() {
                self.selected_environment().await?.id
            } else {
                Uuid::nil()
            },
        };
        validate_context(&context)?;
        Ok(context)
    }

    /// Register this actor's Hook grant internally. This does not log in to Ting
    /// or start a receiving transport; the enclosing app already owns those.
    pub async fn register_recipient(&self) -> Result<RecipientRegistration> {
        self.call(
            Method::POST,
            &["delivery", "recipient"],
            &[],
            None::<&()>,
            None,
        )
        .await
    }

    pub async fn receiving_subscription(
        &self,
        silicon: &str,
    ) -> Result<Option<ReceivingSubscription>> {
        let response: SubscriptionResponse = self
            .call(
                Method::GET,
                &["silicons", silicon, "delivery", "subscription"],
                &[],
                None::<&()>,
                None,
            )
            .await?;
        if response.receiving != response.subscription.is_some() {
            return Err(Error::Protocol(
                "inconsistent receiving subscription".into(),
            ));
        }
        Ok(response.subscription)
    }

    /// Subscribe the current Carbon to future events after checking live IAM visibility.
    pub async fn subscribe(&self, silicon: &str) -> Result<ReceivingSubscription> {
        let response: SubscriptionResponse = self
            .call(
                Method::POST,
                &["silicons", silicon, "delivery", "subscription"],
                &[],
                None::<&()>,
                None,
            )
            .await?;
        if !response.receiving {
            return Err(Error::Protocol(
                "receiving subscription was not activated".into(),
            ));
        }
        response
            .subscription
            .ok_or_else(|| Error::Protocol("receiving subscription missing".into()))
    }

    pub async fn unsubscribe(&self, silicon: &str) -> Result<()> {
        self.empty(
            Method::DELETE,
            &["silicons", silicon, "delivery", "subscription"],
            None,
            None,
        )
        .await
    }

    /// Fetch one retained provider request using current Hook authorization.
    /// A Ting consumer must supply its original reference, including both selectors.
    pub async fn event(
        &self,
        silicon: &str,
        id: Uuid,
        reference: Option<&EventReference>,
    ) -> Result<Event> {
        let query = if let Some(reference) = reference {
            if reference.id != id || reference.silicon_id != silicon {
                return Err(Error::Invalid(
                    "event route does not match its reference".into(),
                ));
            }
            vec![
                ("environment_id", reference.environment_id.to_string()),
                (
                    "environment_generation",
                    reference.environment_generation.to_string(),
                ),
            ]
        } else {
            Vec::new()
        };
        self.call(
            Method::GET,
            &["silicons", silicon, "events", &id.to_string()],
            &query,
            None::<&()>,
            None,
        )
        .await
    }

    /// Distinguish queued, stored/silent and recipient acceptance. No state here
    /// implies the receiving Silicon finished its application work.
    pub async fn publication(&self, silicon: &str, id: Uuid) -> Result<PublicationStatus> {
        self.call(
            Method::GET,
            &[
                "silicons",
                silicon,
                "events",
                &id.to_string(),
                "publication",
            ],
            &[],
            None::<&()>,
            None,
        )
        .await
    }

    /// Hydrate one trusted-route notification from either Ting transport. The
    /// caller authenticates its transport; use `Receiver::decode` for callbacks.
    pub async fn hydrate_notification(
        &self,
        context: &DeliveryContext,
        notification: &TingNotification,
    ) -> Result<ReceivedEvent> {
        if self.org.as_deref() != Some(&context.org_id)
            || self.is_testing() == context.environment_id.is_nil()
        {
            return Err(Error::Invalid(
                "Hook client differs from receiving context".into(),
            ));
        }
        let data = reference(context, notification)?;
        let expected = &data.metadata;
        let event = self
            .event(&expected.silicon_id, expected.id, Some(expected))
            .await?;
        if event.id != expected.id
            || event.org_id != expected.org_id
            || event.silicon_id != expected.silicon_id
            || event.hook_id != expected.hook_id
            || event.delivery_sequence != expected.delivery_sequence
            || event.received_at != expected.received_at
            || event.summary != expected.summary
            || event.provider != data.sender
        {
            return Err(Error::Protocol(
                "hydrated event differs from its notification".into(),
            ));
        }
        Ok(ReceivedEvent {
            ting_id: notification.id.clone(),
            key: notification.key.clone(),
            event,
        })
    }
}
