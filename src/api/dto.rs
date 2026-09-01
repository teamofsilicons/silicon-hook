//! HTTP request and response representations kept separate from domain models.

use std::fmt;

use serde::{Deserialize, Serialize, Serializer};
use time::{Duration, OffsetDateTime};
use url::Url;
use zeroize::Zeroizing;

use crate::domain::{
    ActorRef, DeliveryState, EventEnvelope, EventId, EventRecord, Hook, HookId, HookStatus,
};

/// JSON body used to create a normal webhook connection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateHookRequest {
    pub(super) name: String,
    #[serde(default)]
    pub(super) description: Option<String>,
}

/// Desired enabled state for one hook.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SetHookEnabledRequest {
    pub(super) enabled: bool,
}

/// Desired enabled state for an atomic set of hooks.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SetHooksEnabledRequest {
    pub(super) hook_ids: Vec<HookId>,
    pub(super) enabled: bool,
}

/// JSON body used by IAM to provision a Silicon's default hook.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisionIamHookRequest {
    pub(super) org_id: String,
    pub(super) silicon_id: String,
}

/// Optional hook-list query parameters.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListHooksQuery {
    #[serde(default)]
    pub(super) include_deleted: bool,
}

/// Event-history filters and keyset pagination input.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListEventsQuery {
    #[serde(default)]
    pub(super) hook_id: Option<HookId>,
    #[serde(default)]
    pub(super) event_type: Option<String>,
    #[serde(default = "default_event_limit")]
    pub(super) limit: u32,
    #[serde(default)]
    pub(super) cursor: Option<String>,
}

const fn default_event_limit() -> u32 {
    100
}

/// Public hook metadata; encrypted secret fields never enter this type.
#[derive(Clone, Debug, Serialize)]
pub(super) struct HookResponse {
    id: HookId,
    org_id: String,
    silicon_id: String,
    name: String,
    description: Option<String>,
    endpoint_url: Url,
    endpoint_key: String,
    status: HookStatus,
    created_by: ActorRef,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    disabled_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    deleted_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    recoverable_until: Option<OffsetDateTime>,
}

impl HookResponse {
    pub(super) fn from_domain(hook: &Hook, public_base_url: &Url) -> anyhow::Result<Self> {
        let mut endpoint_url = public_base_url.clone();
        endpoint_url.set_query(None);
        endpoint_url.set_fragment(None);
        endpoint_url
            .path_segments_mut()
            .map_err(|()| anyhow::anyhow!("public Hook URL cannot contain path segments"))?
            .clear()
            .push("silicon")
            .push(hook.silicon_id().as_str())
            .push(hook.endpoint_key().as_str());
        let deleted_at = hook.deleted_at();
        let recoverable_until = deleted_at.and_then(|value| value.checked_add(Duration::days(45)));

        Ok(Self {
            id: hook.id(),
            org_id: hook.organization_id().as_str().to_owned(),
            silicon_id: hook.silicon_id().as_str().to_owned(),
            name: hook.name().as_str().to_owned(),
            description: hook.description().map(|value| value.as_str().to_owned()),
            endpoint_url,
            endpoint_key: hook.endpoint_key().as_str().to_owned(),
            status: hook.status(),
            created_by: hook.created_by().clone(),
            created_at: hook.created_at(),
            disabled_at: hook.disabled_at(),
            deleted_at,
            recoverable_until,
        })
    }
}

/// Hook list envelope.
#[derive(Debug, Serialize)]
pub(super) struct HookPageResponse {
    pub(super) items: Vec<HookResponse>,
}

/// Secret-bearing value that serializes normally but never reveals itself in
/// debug output and zeroizes its allocation on drop.
pub(super) struct OneTimeSecret(Zeroizing<String>);

impl OneTimeSecret {
    pub(super) const fn new(value: Zeroizing<String>) -> Self {
        Self(value)
    }
}

impl fmt::Debug for OneTimeSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OneTimeSecret([REDACTED])")
    }
}

impl Serialize for OneTimeSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

/// Hook creation/provisioning response with a bounded one-time credential.
#[derive(Debug, Serialize)]
pub(super) struct HookWithSecretResponse {
    #[serde(flatten)]
    pub(super) hook: HookResponse,
    pub(super) signing_secret: OneTimeSecret,
}

/// Secret rotation response.
#[derive(Debug, Serialize)]
pub(super) struct SigningSecretResponse {
    pub(super) signing_secret: OneTimeSecret,
}

/// Public retained event with its current DM delivery projection.
#[derive(Clone, Debug, Serialize)]
pub(super) struct EventRecordResponse {
    #[serde(flatten)]
    envelope: EventEnvelope,
    id: EventId,
    org_id: String,
    silicon_id: String,
    hook_id: HookId,
    #[serde(with = "time::serde::rfc3339")]
    received_at: OffsetDateTime,
    delivery: DeliveryState,
}

impl From<EventRecord> for EventRecordResponse {
    fn from(event: EventRecord) -> Self {
        Self {
            envelope: event.envelope().clone(),
            id: event.id(),
            org_id: event.organization_id().as_str().to_owned(),
            silicon_id: event.silicon_id().as_str().to_owned(),
            hook_id: event.hook_id(),
            received_at: event.received_at(),
            delivery: event.delivery().clone(),
        }
    }
}

/// Event-history response with an authenticated next cursor.
#[derive(Debug, Serialize)]
pub(super) struct EventPageResponse {
    pub(super) items: Vec<EventRecordResponse>,
    pub(super) next_cursor: Option<String>,
}

/// Stable public-ingress acceptance receipt.
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct EventAcceptedResponse {
    pub(super) event_id: EventId,
    pub(super) status: &'static str,
}

impl EventAcceptedResponse {
    pub(super) const fn new(event_id: EventId) -> Self {
        Self {
            event_id,
            status: "accepted",
        }
    }
}

/// Liveness/readiness response.
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct HealthResponse {
    pub(super) status: &'static str,
}

/// Running package version.
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct VersionResponse {
    pub(super) service: &'static str,
    pub(super) version: &'static str,
}

#[cfg(test)]
mod tests {
    use super::OneTimeSecret;

    #[test]
    fn one_time_secret_debug_is_redacted() {
        let secret = OneTimeSecret::new(zeroize::Zeroizing::new("whsec_secret".to_owned()));
        let output = format!("{secret:?}");
        assert!(!output.contains("whsec_secret"));
        assert!(output.contains("REDACTED"));
    }
}
