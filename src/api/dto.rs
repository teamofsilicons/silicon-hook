//! HTTP request and response representations kept separate from domain models.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::{Duration, OffsetDateTime};
use url::Url;
use zeroize::Zeroizing;

use crate::infrastructure::iam::IssuedTokens;
use crate::{
    application::{HookWithSecret, SigningPatch},
    domain::{
        ActorRef, BlockedRequest, BlockedRequestId, DeliveryCursor, EventId, EventRecord, Hook,
        HookId, HookStatus, SigningSecret,
        request::CapturedRequest,
        signature::{
            Expression, SecretEncoding, SignatureAlgorithm, SignatureConfig, SignatureEncoding,
        },
    },
    error::AppError,
};

/// Signing policy supplied at creation or update.
///
/// Every field is optional; omitted fields keep the Standard Webhooks defaults
/// on creation or the current values on update.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignatureRequest {
    #[serde(default)]
    pub(super) required: Option<bool>,
    #[serde(default)]
    pub(super) algorithm: Option<SignatureAlgorithm>,
    #[serde(default)]
    pub(super) payload: Option<String>,
    #[serde(default)]
    pub(super) signature: Option<String>,
    #[serde(default)]
    pub(super) signature_encoding: Option<SignatureEncoding>,
    #[serde(default)]
    pub(super) secret_encoding: Option<SecretEncoding>,
    /// `Some(None)` clears the key; `None` leaves it unchanged.
    #[allow(clippy::option_option)]
    #[serde(default, deserialize_with = "double_option")]
    pub(super) public_key: Option<Option<String>>,
    #[serde(default)]
    pub(super) secret: Option<String>,
}

impl SignatureRequest {
    pub(super) fn into_patch(self) -> Result<SigningPatch, AppError> {
        let payload = self
            .payload
            .as_deref()
            .map(Expression::parse)
            .transpose()
            .map_err(|error| {
                AppError::validation_with_details("invalid_signature_payload", error.to_string())
            })?;
        let signature = self
            .signature
            .as_deref()
            .map(Expression::parse)
            .transpose()
            .map_err(|error| {
                AppError::validation_with_details("invalid_signature_locator", error.to_string())
            })?;
        let secret = self
            .secret
            .map(SigningSecret::from_text)
            .transpose()
            .map_err(|error| {
                AppError::validation_with_details("invalid_secret", error.to_string())
            })?;
        Ok(SigningPatch {
            required: self.required,
            algorithm: self.algorithm,
            payload,
            signature,
            signature_encoding: self.signature_encoding,
            secret_encoding: self.secret_encoding,
            public_key: self.public_key,
            secret,
        })
    }
}

/// JSON body used to create a webhook connection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateHookRequest {
    pub(super) name: String,
    #[serde(default)]
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) time_zone: Option<String>,
    #[serde(default)]
    pub(super) signature: Option<SignatureRequest>,
}

/// JSON body used to change one hook.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UpdateHookRequest {
    #[serde(default)]
    pub(super) name: Option<String>,
    /// `Some(None)` clears the description; `None` leaves it unchanged.
    #[allow(clippy::option_option)]
    #[serde(default, deserialize_with = "double_option")]
    pub(super) description: Option<Option<String>>,
    #[serde(default)]
    pub(super) time_zone: Option<String>,
    #[serde(default)]
    pub(super) enabled: Option<bool>,
    #[serde(default)]
    pub(super) signature: Option<SignatureRequest>,
}

/// Desired enabled state for an atomic set of hooks.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SetHooksEnabledRequest {
    pub(super) hook_ids: Vec<HookId>,
    pub(super) enabled: bool,
}

/// Acknowledgment of ordered deliveries.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AcknowledgeRequest {
    pub(super) through_sequence: i64,
}

/// Optional hook-list query parameters.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListHooksQuery {
    #[serde(default)]
    pub(super) include_deleted: bool,
}

/// History filters and keyset pagination input.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HistoryQuery {
    #[serde(default)]
    pub(super) hook_id: Option<HookId>,
    #[serde(default = "default_history_limit")]
    pub(super) limit: u32,
    #[serde(default)]
    pub(super) cursor: Option<String>,
}

const fn default_history_limit() -> u32 {
    100
}

/// Ordered delivery pull input.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeliveriesQuery {
    #[serde(default)]
    pub(super) after_sequence: Option<i64>,
    #[serde(default = "default_delivery_limit")]
    pub(super) limit: u32,
}

const fn default_delivery_limit() -> u32 {
    100
}

/// Distinguishes an omitted member from an explicit `null`.
#[allow(clippy::option_option)]
fn double_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// Public signing policy; secrets never enter this type.
#[derive(Clone, Debug, Serialize)]
pub(super) struct SignatureResponse {
    required: bool,
    algorithm: SignatureAlgorithm,
    payload: String,
    signature: String,
    signature_encoding: SignatureEncoding,
    secret_encoding: SecretEncoding,
    public_key: Option<String>,
    has_secret: bool,
}

impl SignatureResponse {
    fn from_domain(hook: &Hook) -> Self {
        let policy = hook.signing();
        let config: &SignatureConfig = &policy.config;
        Self {
            required: policy.required,
            algorithm: config.algorithm,
            payload: config.payload.source().to_owned(),
            signature: config.signature.source().to_owned(),
            signature_encoding: config.signature_encoding,
            secret_encoding: config.secret_encoding,
            public_key: config.public_key.clone(),
            has_secret: policy.encrypted_secret.is_some(),
        }
    }
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
    signature: SignatureResponse,
    time_zone: String,
    created_by: ActorRef,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    disabled_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    deleted_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    recoverable_until: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    last_received_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    last_blocked_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    endpoint_rotated_at: Option<OffsetDateTime>,
}

impl HookResponse {
    pub(super) fn from_domain(hook: &Hook, endpoint_url: Url) -> Self {
        let deleted_at = hook.deleted_at();
        let recoverable_until = deleted_at.and_then(|value| value.checked_add(Duration::days(45)));
        Self {
            id: hook.id(),
            org_id: hook.organization_id().as_str().to_owned(),
            silicon_id: hook.silicon_id().as_str().to_owned(),
            name: hook.name().as_str().to_owned(),
            description: hook.description().map(|value| value.as_str().to_owned()),
            endpoint_url,
            endpoint_key: hook.endpoint_key().as_str().to_owned(),
            status: hook.status(),
            signature: SignatureResponse::from_domain(hook),
            time_zone: hook.time_zone().as_str().to_owned(),
            created_by: hook.created_by().clone(),
            created_at: hook.created_at(),
            disabled_at: hook.disabled_at(),
            deleted_at,
            recoverable_until,
            last_received_at: hook.last_received_at(),
            last_blocked_at: hook.last_blocked_at(),
            endpoint_rotated_at: hook.endpoint_rotated_at(),
        }
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
    pub(super) signing_secret: Option<OneTimeSecret>,
}

impl HookWithSecretResponse {
    pub(super) fn from_result(result: &HookWithSecret, endpoint_url: Url) -> Self {
        Self {
            hook: HookResponse::from_domain(&result.hook, endpoint_url),
            signing_secret: result
                .signing_secret
                .as_ref()
                .map(|secret| OneTimeSecret::new(secret.to_exposed())),
        }
    }
}

/// Secret rotation response.
#[derive(Debug, Serialize)]
pub(super) struct SigningSecretResponse {
    pub(super) signing_secret: OneTimeSecret,
}

/// Exact provider request as retained.
#[derive(Clone, Debug, Serialize)]
pub struct CapturedRequestResponse {
    method: String,
    url: String,
    path: String,
    query_string: String,
    headers: Vec<(String, String)>,
    content_type: Option<String>,
    /// Body text when it is valid UTF-8.
    body: Option<String>,
    /// Standard base64 of the body when it is not UTF-8 text.
    body_base64: Option<String>,
    remote_ip: String,
}

impl CapturedRequestResponse {
    pub(super) fn from_domain(request: &CapturedRequest) -> Self {
        let (body, body_base64) = match request.body_text() {
            Some(text) => (Some(text.to_owned()), None),
            None => (None, Some(STANDARD.encode(request.body()))),
        };
        Self {
            method: request.method().to_owned(),
            url: request.url().to_string(),
            path: request.path().to_owned(),
            query_string: request.query_string().to_owned(),
            headers: request.headers().to_vec(),
            content_type: request.content_type(),
            body,
            body_base64,
            remote_ip: request.remote_ip().to_string(),
        }
    }
}

/// Public verified event with its delivery position.
#[derive(Clone, Debug, Serialize)]
pub struct EventResponse {
    id: EventId,
    org_id: String,
    silicon_id: String,
    hook_id: HookId,
    provider: String,
    summary: String,
    delivery_sequence: i64,
    #[serde(with = "time::serde::rfc3339")]
    received_at: OffsetDateTime,
    request: CapturedRequestResponse,
}

impl From<&EventRecord> for EventResponse {
    fn from(event: &EventRecord) -> Self {
        Self {
            id: event.id(),
            org_id: event.organization_id().as_str().to_owned(),
            silicon_id: event.silicon_id().as_str().to_owned(),
            hook_id: event.hook_id(),
            provider: event.provider().as_str().to_owned(),
            summary: event.summary().to_owned(),
            delivery_sequence: event.delivery_sequence().get(),
            received_at: event.received_at(),
            request: CapturedRequestResponse::from_domain(event.request()),
        }
    }
}

/// Public withheld request.
#[derive(Clone, Debug, Serialize)]
pub(super) struct BlockedRequestResponse {
    id: BlockedRequestId,
    org_id: String,
    silicon_id: String,
    hook_id: HookId,
    provider: String,
    reason_code: String,
    reason_detail: String,
    #[serde(with = "time::serde::rfc3339")]
    received_at: OffsetDateTime,
    request: CapturedRequestResponse,
}

impl From<&BlockedRequest> for BlockedRequestResponse {
    fn from(blocked: &BlockedRequest) -> Self {
        let snapshot = blocked.snapshot();
        Self {
            id: snapshot.id,
            org_id: snapshot.organization_id.as_str().to_owned(),
            silicon_id: snapshot.silicon_id.as_str().to_owned(),
            hook_id: snapshot.hook_id,
            provider: snapshot.provider.as_str().to_owned(),
            reason_code: snapshot.reason.code().to_owned(),
            reason_detail: snapshot.reason.detail().to_owned(),
            received_at: snapshot.received_at,
            request: CapturedRequestResponse::from_domain(&snapshot.request),
        }
    }
}

/// History response with an authenticated next cursor.
#[derive(Debug, Serialize)]
pub(super) struct HistoryPageResponse<T> {
    pub(super) items: Vec<T>,
    pub(super) next_cursor: Option<String>,
}

/// Consumer position in a Silicon's delivery stream.
#[derive(Debug, Serialize)]
pub(super) struct DeliveryCursorResponse {
    silicon_id: String,
    acknowledged_through: i64,
    #[serde(with = "time::serde::rfc3339::option")]
    acknowledged_at: Option<OffsetDateTime>,
}

impl From<&DeliveryCursor> for DeliveryCursorResponse {
    fn from(cursor: &DeliveryCursor) -> Self {
        Self {
            silicon_id: cursor.silicon_id.as_str().to_owned(),
            acknowledged_through: cursor.acknowledged_through,
            acknowledged_at: cursor.updated_at,
        }
    }
}

/// Ordered deliveries pulled over HTTP.
#[derive(Debug, Serialize)]
pub(super) struct DeliveryBatchResponse {
    pub(super) items: Vec<EventResponse>,
    pub(super) cursor: DeliveryCursorResponse,
    pub(super) latest_sequence: i64,
}

/// Stable public-ingress receipt.
#[derive(Clone, Debug, Serialize)]
pub(super) struct ReceiptResponse {
    pub(super) status: &'static str,
    pub(super) receipt_id: uuid::Uuid,
}

impl ReceiptResponse {
    pub(super) const fn ok(receipt_id: uuid::Uuid) -> Self {
        Self {
            status: "webhook.ok",
            receipt_id,
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

/// Outcome of the unversioned API-version handshake.
#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct ApiVersionResponse {
    pub(super) service: &'static str,
    pub(super) selected_api_version: &'static str,
    pub(super) supported_api_versions: &'static [&'static str],
    pub(super) build: &'static str,
    pub(super) commit: &'static str,
}

#[cfg(test)]
mod tests {
    use super::{OneTimeSecret, SignatureRequest, UpdateHookRequest};

    #[test]
    fn one_time_secret_debug_is_redacted() {
        let secret = OneTimeSecret::new(zeroize::Zeroizing::new("v1.secret".to_owned()));
        let output = format!("{secret:?}");
        assert!(!output.contains("v1.secret"));
        assert!(output.contains("REDACTED"));
    }

    #[test]
    fn explicit_nulls_clear_while_omissions_keep() -> Result<(), serde_json::Error> {
        let cleared: UpdateHookRequest =
            serde_json::from_str(r#"{"description": null, "signature": {"public_key": null}}"#)?;
        assert_eq!(cleared.description, Some(None));
        assert!(matches!(
            cleared.signature,
            Some(SignatureRequest {
                public_key: Some(None),
                ..
            })
        ));
        let kept: UpdateHookRequest = serde_json::from_str(r#"{"name": "GitLab"}"#)?;
        assert_eq!(kept.description, None);
        assert!(kept.signature.is_none());
        Ok(())
    }

    #[test]
    fn signature_requests_validate_expressions_eagerly() {
        let request = SignatureRequest {
            payload: Some("md5(request.raw_body)".to_owned()),
            ..SignatureRequest::default()
        };
        assert!(request.into_patch().is_err());
        let valid = SignatureRequest {
            payload: Some("request.raw_body".to_owned()),
            secret: Some("provider".to_owned()),
            ..SignatureRequest::default()
        };
        assert!(valid.into_patch().is_ok());
    }
}

/// IAM-hosted login produces this single-use token. Hook never accepts OTPs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LoginRequest {
    pub(super) slt: String,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginRequest([REDACTED])")
    }
}

/// Refresh-token rotation input.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RefreshRequest {
    pub(super) refresh_token: String,
}

impl fmt::Debug for RefreshRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RefreshRequest([REDACTED])")
    }
}

/// Tokens IAM issued to Hook for an actor.
#[derive(Debug, Serialize)]
pub(super) struct TokensResponse {
    pub(super) access_token: OneTimeSecret,
    pub(super) refresh_token: OneTimeSecret,
    pub(super) token_type: &'static str,
    pub(super) expires_in: u64,
    pub(super) scopes: Vec<String>,
    pub(super) actor: ActorRef,
    pub(super) org_id: Option<String>,
}

impl TokensResponse {
    pub(super) fn from_issued(tokens: IssuedTokens) -> Self {
        Self {
            access_token: OneTimeSecret::new(tokens.access_token),
            refresh_token: OneTimeSecret::new(tokens.refresh_token),
            token_type: "Bearer",
            expires_in: tokens.expires_in.as_secs(),
            scopes: tokens.scopes,
            actor: tokens.actor,
            org_id: tokens
                .organization_id
                .map(|organization_id| organization_id.as_str().to_owned()),
        }
    }
}

/// The Silicon's IAM hook after registration with IAM.
#[derive(Debug, Serialize)]
pub(super) struct IamHookResponse {
    #[serde(flatten)]
    pub(super) hook: HookResponse,
    pub(super) iam_webhook: IamWebhookResponse,
}

/// IAM-side facts about the registered webhook.
#[derive(Debug, Serialize)]
pub(super) struct IamWebhookResponse {
    pub(super) secret_version: u64,
}
