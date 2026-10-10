//! Hook API calls around delivery: enrolment, Carbon subscriptions, event
//! lookup, publication status and hydration of Ting notifications.

use reqwest::Method;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    DeliveryContext, DeliveryOutcome, ReceivedEvent, TingNotification, UnavailableEvent, reference,
};
use crate::{Client, Error, Result, models::Event};

/// The account Ting delivers to.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Recipient {
    /// Permanent uuid.
    pub uuid: String,
    /// Current id.
    #[serde(default)]
    pub id: Option<String>,
}

/// The result of enrolling the caller with Ting.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecipientRegistration {
    /// The enrolled account.
    pub recipient: Recipient,
    /// Ting's subscription id.
    pub ting_subscription_id: String,
    /// Whether the recipient opted in to required (automation) delivery; only
    /// the recipient can turn this on, in its own app.
    pub required_delivery: bool,
}

/// One Carbon's interest in a Silicon's future events.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceivingSubscription {
    /// Subscription id (new after every subscribe).
    pub id: Uuid,
    /// The observed Silicon's uuid.
    pub silicon_uuid: String,
    /// The receiving Carbon's uuid.
    pub recipient_uuid: String,
    /// RFC 3339; earlier events are never sent.
    pub created_at: String,
}

#[derive(Deserialize)]
struct SubscriptionResponse {
    receiving: bool,
    subscription: Option<ReceivingSubscription>,
}

/// Where one event's send to its Silicon stands.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PublicationState {
    /// The server does not deliver through Ting; read the history API.
    DeliveryDisabled,
    /// Nothing was queued (received while delivery was off, or before the
    /// Silicon was linked to its Silicon Accounts account).
    NotQueued,
    /// Queued; Ting has not accepted it yet.
    Pending,
    /// Ting stored it for the recipient.
    AcceptedByTing,
    /// Ting stored it silently (ordinary delivery, notifications muted).
    AcceptedSilently,
    /// Queued under the previous sign-in system and never accepted by Ting.
    NotDeliveredLegacy,
    /// A state this client does not know yet.
    #[serde(other)]
    Unknown,
}

/// Automation policy of a send; it does not prove receipt.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    /// Follows the recipient's notification preferences.
    Ordinary,
    /// Automation delivery the recipient opted in to.
    Required,
}

/// One destination's acknowledgments.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DestinationReceipt {
    /// Opaque Ting destination id.
    pub webhook_id: String,
    /// The destination durably received the event.
    pub delivery_acked: bool,
    /// The destination marked it read.
    pub read_acked: bool,
}

/// Ting's receipt for the recipient.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecipientReceipt {
    /// Ting's record id.
    pub id: String,
    /// Any destination accepted it, or a Carbon viewed it.
    pub read: bool,
    /// Notification muted.
    pub silent: bool,
    /// Automation policy.
    pub delivery: DeliveryMode,
    /// First page of destinations.
    pub deliveries: Vec<DestinationReceipt>,
    /// More destinations exist.
    pub more_destinations: bool,
}

/// Publication status of one event (`GET /silicons/{s}/events/{e}/publication`).
/// No state means the receiving Silicon finished its work.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Publication {
    /// The event.
    pub event_id: Uuid,
    /// Where the send stands.
    pub state: PublicationState,
    /// Explanation for `delivery_disabled` and `not_queued`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Recipient uuid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// Automation policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<DeliveryMode>,
    /// Notification preference at acceptance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub silent: Option<bool>,
    /// Send attempts so far.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<i64>,
    /// Ting's record id once accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ting_id: Option<String>,
    /// Why the last attempt failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_code: Option<String>,
    /// RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<String>,
    /// RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<String>,
    /// RFC 3339; the send is abandoned after this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Ting's receipt, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_receipt: Option<RecipientReceipt>,
    /// Why the receipt could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_status_error: Option<String>,
}

impl Client {
    /// Enrols the caller with Ting so it can receive Hook's notifications
    /// (Hook proves the caller's agreement to Ting with a Silicon Accounts
    /// User verification proof made from the caller's own token).
    ///
    /// # Errors
    /// `delivery_disabled` when the server has no Ting, and other refusals.
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

    /// The caller's (a Carbon's) subscription to a Silicon's future events.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
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
        Ok(response.subscription)
    }

    /// Subscribes the caller (a Carbon with access to the Silicon) to copies of
    /// the Silicon's future events. Hook re-checks access before every send.
    ///
    /// # Errors
    /// `delivery_disabled`, `forbidden`, `observer_limit_reached` and others.
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
                "Hook did not activate the receiving subscription".into(),
            ));
        }
        response
            .subscription
            .ok_or_else(|| Error::Protocol("Hook returned no subscription".into()))
    }

    /// Stops the caller's copies of the Silicon's events (works even after
    /// losing access).
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn unsubscribe(&self, silicon: &str) -> Result<()> {
        self.empty(
            Method::DELETE,
            &["silicons", silicon, "delivery", "subscription"],
            None,
        )
        .await
    }

    /// One retained event with its original provider request.
    ///
    /// # Errors
    /// `not_found` once retention removed it, and other refusals.
    pub async fn event(&self, silicon: &str, id: Uuid) -> Result<Event> {
        self.call(
            Method::GET,
            &["silicons", silicon, "events", &id.to_string()],
            &[],
            None::<&()>,
            None,
        )
        .await
    }

    /// Where the event's send to its Silicon stands.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn publication(&self, silicon: &str, id: Uuid) -> Result<Publication> {
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

    /// The receiving context for the signed-in account: Hook's app id and the
    /// account's uuid and current id, confirmed by Hook.
    ///
    /// # Errors
    /// [`Error::Invalid`] when Hook does not accept the token.
    pub async fn delivery_context(&self) -> Result<DeliveryContext> {
        let information = self.sign_in_information().await?;
        let status = self.login_status().await?;
        let uuid = match (status.authenticated, status.uuid) {
            (true, Some(uuid)) => uuid,
            _ => {
                return Err(Error::Invalid(format!(
                    "receiving needs a token Hook accepts ({})",
                    status
                        .message
                        .or(status.reason)
                        .unwrap_or_else(|| "no token".into())
                )));
            }
        };
        Ok(DeliveryContext {
            app_id: information.app_id,
            recipient_uuid: uuid,
            recipient_id: status.id,
        })
    }

    /// Resolves one notification without acknowledging it. Only Hook's
    /// `404 not_found` becomes [`DeliveryOutcome::Unavailable`] (retention or
    /// deletion; no finer cause is claimed).
    ///
    /// # Errors
    /// Validation errors and Hook failures other than a missing event.
    pub async fn resolve_notification(
        &self,
        context: &DeliveryContext,
        notification: &TingNotification,
    ) -> Result<DeliveryOutcome> {
        let data = reference(context, notification)?;
        match self.hydrate_notification(context, notification).await {
            Ok(event) => Ok(DeliveryOutcome::Event(Box::new(event))),
            Err(Error::Api(api)) if api.status == 404 && api.code == "not_found" => {
                Ok(DeliveryOutcome::Unavailable(Box::new(UnavailableEvent {
                    ting_id: notification.id.clone(),
                    key: notification.key.clone(),
                    reference: data.metadata,
                })))
            }
            Err(error) => Err(error),
        }
    }

    /// Fetches the event a notification points to and checks that it matches
    /// the reference exactly (ids, hook, sequence, time, summary, provider).
    ///
    /// # Errors
    /// Validation errors, Hook failures, and [`Error::Protocol`] on a mismatch.
    pub async fn hydrate_notification(
        &self,
        context: &DeliveryContext,
        notification: &TingNotification,
    ) -> Result<ReceivedEvent> {
        let data = reference(context, notification)?;
        let expected = &data.metadata;
        let event = self.event(&expected.silicon.uuid, expected.id).await?;
        if event.id != expected.id
            || event.silicon.uuid != expected.silicon.uuid
            || event.hook_id != expected.hook_id
            || event.delivery_sequence != expected.delivery_sequence
            || event.received_at != expected.received_at
            || event.summary != expected.summary
            || event.provider != data.sender
        {
            return Err(Error::Protocol(
                "the event Hook returned differs from its notification".into(),
            ));
        }
        Ok(ReceivedEvent {
            ting_id: notification.id.clone(),
            key: notification.key.clone(),
            event,
        })
    }
}
