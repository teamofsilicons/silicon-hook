//! HTTP request and response representations kept separate from domain models.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::{Duration, OffsetDateTime};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    application::{HookWithSecret, SigningPatch},
    domain::{
        AccountUuid, ActorKind, ActorRef, BlockedRequest, BlockedRequestId, EventId, EventRecord,
        Hook, HookId, HookStatus, SigningSecret, SiliconRef,
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
#[derive(Default, Deserialize)]
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

impl fmt::Debug for SignatureRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignatureRequest")
            .field("required", &self.required)
            .field("algorithm", &self.algorithm)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .finish_non_exhaustive()
    }
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

/// A Silicon as responses show it: its permanent uuid and current id.
#[derive(Clone, Debug, Serialize)]
pub(super) struct SiliconResponse {
    pub(super) uuid: String,
    pub(super) id: Option<String>,
}

impl From<&SiliconRef> for SiliconResponse {
    fn from(silicon: &SiliconRef) -> Self {
        Self {
            uuid: silicon.uuid().as_str().to_owned(),
            id: silicon.id().map(|id| id.as_str().to_owned()),
        }
    }
}

/// An account as responses show it. `uuid` is absent only for attribution
/// recorded before Silicon Accounts that was never linked; `id` is the
/// account's current id, or the stored IAM-era id for such records.
#[derive(Clone, Debug, Serialize)]
pub(super) struct AccountResponse {
    pub(super) uuid: Option<String>,
    pub(super) kind: ActorKind,
    pub(super) id: Option<String>,
}

impl AccountResponse {
    /// Shows stored attribution with the current id when Hook knows it.
    pub(super) fn from_attribution(actor: &ActorRef, current_id: Option<&str>) -> Self {
        match actor.uuid() {
            Some(uuid) => Self {
                uuid: Some(uuid.as_str().to_owned()),
                kind: actor.kind(),
                id: current_id.map(ToOwned::to_owned),
            },
            None => Self {
                uuid: None,
                kind: actor.kind(),
                id: Some(actor.id().as_str().to_owned()),
            },
        }
    }

    pub(super) fn of(uuid: &AccountUuid, kind: ActorKind, id: Option<&str>) -> Self {
        Self {
            uuid: Some(uuid.as_str().to_owned()),
            kind,
            id: id.map(ToOwned::to_owned),
        }
    }
}

/// Public hook metadata; encrypted secret fields never enter this type.
#[derive(Clone, Debug, Serialize)]
pub(super) struct HookResponse {
    id: HookId,
    silicon: SiliconResponse,
    name: String,
    description: Option<String>,
    endpoint_url: Url,
    endpoint_key: String,
    status: HookStatus,
    signature: SignatureResponse,
    time_zone: String,
    created_by: AccountResponse,
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
    pub(super) fn from_domain(
        hook: &Hook,
        endpoint_url: Url,
        silicon: &SiliconRef,
        created_by: AccountResponse,
    ) -> Self {
        let deleted_at = hook.deleted_at();
        let recoverable_until = deleted_at.and_then(|value| value.checked_add(Duration::days(45)));
        Self {
            id: hook.id(),
            silicon: SiliconResponse::from(silicon),
            name: hook.name().as_str().to_owned(),
            description: hook.description().map(|value| value.as_str().to_owned()),
            endpoint_url,
            endpoint_key: hook.endpoint_key().as_str().to_owned(),
            status: hook.status(),
            signature: SignatureResponse::from_domain(hook),
            time_zone: hook.time_zone().as_str().to_owned(),
            created_by,
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
    pub(super) fn from_result(result: &HookWithSecret, hook: HookResponse) -> Self {
        Self {
            hook,
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
    silicon: SiliconResponse,
    hook_id: HookId,
    provider: String,
    delivery_sequence: i64,
    summary: String,
    #[serde(with = "time::serde::rfc3339")]
    received_at: OffsetDateTime,
    request: CapturedRequestResponse,
}

impl EventResponse {
    pub(super) fn new(event: &EventRecord, silicon: &SiliconRef) -> Self {
        Self {
            id: event.id(),
            silicon: SiliconResponse::from(silicon),
            hook_id: event.hook_id(),
            provider: event.provider().as_str().to_owned(),
            delivery_sequence: event.delivery_sequence().get(),
            summary: event.summary().to_owned(),
            received_at: event.received_at(),
            request: CapturedRequestResponse::from_domain(event.request()),
        }
    }
}

/// Public withheld request.
#[derive(Clone, Debug, Serialize)]
pub(super) struct BlockedRequestResponse {
    id: BlockedRequestId,
    silicon: SiliconResponse,
    hook_id: HookId,
    provider: String,
    reason_code: String,
    reason_detail: String,
    #[serde(with = "time::serde::rfc3339")]
    received_at: OffsetDateTime,
    request: CapturedRequestResponse,
}

impl BlockedRequestResponse {
    pub(super) fn new(blocked: &BlockedRequest, silicon: &SiliconRef) -> Self {
        let snapshot = blocked.snapshot();
        Self {
            id: snapshot.id,
            silicon: SiliconResponse::from(silicon),
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

    #[test]
    fn byos_requests_preserve_secret_text_and_redact_debug()
    -> Result<(), Box<dyn std::error::Error>> {
        let request: UpdateHookRequest = serde_json::from_str(
            r#"{"signature":{"secret":" provider-secret ","secret_encoding":"utf8"}}"#,
        )?;
        assert!(!format!("{request:?}").contains("provider-secret"));
        let patch = request.signature.ok_or("missing signature")?.into_patch()?;
        assert_eq!(
            patch
                .secret
                .as_ref()
                .map(crate::domain::SigningSecret::as_str),
            Some(" provider-secret ")
        );
        Ok(())
    }
}
