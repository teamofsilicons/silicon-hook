//! Internal Ting delivery using fresh IAM proofs over durable request bytes.

use std::{fmt, net::IpAddr, time::Duration};

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::{Host, Url};

use super::iam::{IamClient, IamError};

pub(crate) mod receiver;

/// Ting's limit for the entire serialized send request, including its wrapper.
pub const MAX_TING_SEND_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_ORDINARY_REQUEST_BYTES: usize = 1024 * 1024;

pub(crate) struct TingTestingCredentials {
    pub(crate) app_secret: SecretString,
    pub(crate) environment_key: SecretString,
}

pub(crate) struct TingProof {
    pub(crate) token: SecretString,
    pub(crate) testing: Option<TingTestingCredentials>,
    pub(crate) expires_at: OffsetDateTime,
}

/// Redacted delivery failure. Provider bodies and credentials are never retained.
pub enum TingError {
    /// Locally invalid configuration or prepared request.
    InvalidInput(&'static str),
    /// IAM could not authorize the fixed downstream operation.
    Iam(IamError),
    /// The network outcome is unknown; retry with the same key and a fresh proof.
    Transport,
    /// Ting returned an invalid success body or unexpected HTTP success status.
    InvalidResponse,
    /// Ting's response exceeded the configured hard bound.
    ResponseTooLarge,
    /// Ting rejected this operation with a sanitized, documented classification.
    Rejected {
        /// HTTP status code, without any provider body.
        status: u16,
        /// A known Ting error code, or the constant `ting_rejected`.
        code: &'static str,
        /// Whether an unchanged operation can be retried with a new proof.
        retryable: bool,
        /// A bounded delay obtained from an integer `Retry-After` header.
        retry_after: Option<Duration>,
    },
}

impl TingError {
    /// Safe classification suitable for logs and persisted delivery status.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(code) | Self::Rejected { code, .. } => code,
            Self::Iam(IamError::InvalidCredential) => "ting_subject_expired",
            Self::Iam(IamError::Forbidden) => "ting_authorization_denied",
            Self::Iam(IamError::NotConfigured) => "ting_iam_not_configured",
            Self::Iam(_) => "ting_iam_unavailable",
            Self::Transport => "ting_transport_unavailable",
            Self::InvalidResponse => "ting_invalid_response",
            Self::ResponseTooLarge => "ting_response_too_large",
        }
    }

    /// Whether retrying with the same body/key and a newly issued proof can help.
    #[must_use]
    pub fn retryable(&self) -> bool {
        match self {
            Self::InvalidInput(_) => false,
            Self::Iam(error) => !matches!(
                error,
                IamError::InvalidCredential
                    | IamError::Forbidden
                    | IamError::NotFound
                    | IamError::InvalidInput(_)
                    | IamError::NotConfigured
                    | IamError::Rejected { status: 400..=499 }
            ),
            Self::Transport | Self::InvalidResponse | Self::ResponseTooLarge => true,
            Self::Rejected { retryable, .. } => *retryable,
        }
    }

    /// The upstream HTTP status when one is available.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Rejected { status, .. }
            | Self::Iam(IamError::Rejected { status } | IamError::UnexpectedStatus(status)) => {
                Some(*status)
            }
            _ => None,
        }
    }

    /// A server-provided retry delay, if available.
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Rejected { retry_after, .. } => *retry_after,
            Self::Iam(IamError::RateLimited { retry_after }) => Some(*retry_after),
            _ => None,
        }
    }
}

impl fmt::Debug for TingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TingError")
            .field("code", &self.code())
            .field("status", &self.status())
            .field("retryable", &self.retryable())
            .finish()
    }
}

impl fmt::Display for TingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for TingError {}

impl From<IamError> for TingError {
    fn from(error: IamError) -> Self {
        Self::Iam(error)
    }
}

/// Automation policy, independent of notification visibility or destination ACKs.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TingDeliveryMode {
    /// Ordinary notifications follow the recipient's notification preferences.
    #[default]
    Ordinary,
    /// Automation delivery requires the recipient's separate explicit opt-in.
    Required,
}

impl TryFrom<String> for TingDeliveryMode {
    type Error = TingError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "ordinary" => Ok(Self::Ordinary),
            "required" => Ok(Self::Required),
            _ => Err(TingError::InvalidResponse),
        }
    }
}

// The Ting wire contract omits ordinary mode; only an explicit "required" is valid.
pub(crate) fn deserialize_delivery<'de, D>(deserializer: D) -> Result<TingDeliveryMode, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value == "required" {
        Ok(TingDeliveryMode::Required)
    } else {
        Err(serde::de::Error::custom(
            "delivery must be required when present",
        ))
    }
}

/// Ting has durably stored a send. This does not prove recipient delivery.
#[derive(Clone, Debug)]
pub struct TingAcceptance {
    /// Stable Ting notification identifier.
    pub id: String,
    /// Exact sender idempotency key confirmed by Ting.
    pub key: String,
    /// Notification visibility; required automation may still deliver when silent.
    pub silent: bool,
    /// Policy confirmed by Ting, matching the immutable request.
    pub delivery: TingDeliveryMode,
    /// Original acceptance time, unchanged on an idempotent retry.
    pub created_at: OffsetDateTime,
}

/// Verified registration of a recipient's grant to Hook.
#[derive(Clone, Debug, Deserialize)]
pub struct TingSubscription {
    /// Stable Ting subscription identifier.
    pub id: String,
    /// The issuing Hook application.
    pub app_id: String,
    /// The recipient proven by IAM's represented actor.
    #[serde(rename = "for")]
    pub recipient: String,
    /// Whether Ting confirmed the grant is active.
    pub active: bool,
    /// Current recipient opt-in; ordinary registration never enables it.
    #[serde(default)]
    pub required_delivery: bool,
}

/// Ting's live receipt state; acceptance by a receiver does not mean completed work.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TingReceipt {
    /// Ting's stable record identity.
    pub id: String,
    /// True once any destination accepted the event, or a Carbon viewed it.
    pub read: bool,
    /// Whether notification visibility was muted; separate from automation policy.
    pub silent: bool,
    /// Original automation policy, never a claim of successful delivery.
    pub delivery: TingDeliveryMode,
    /// First page of per-destination acknowledgments.
    pub deliveries: Vec<TingDestinationReceipt>,
    /// More destination records exist when true.
    pub more_destinations: bool,
}

/// Receipt for one Ting-controlled destination; no local URL or secret is exposed.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TingDestinationReceipt {
    /// Opaque Ting destination identity.
    pub webhook_id: String,
    /// Ting's daemon durably received this event.
    pub delivery_acked: bool,
    /// The local destination accepted this event.
    pub read_acked: bool,
}

#[derive(Deserialize)]
struct SentDetail {
    id: String,
    #[serde(rename = "type")]
    event_type: String,
    #[serde(rename = "for")]
    recipient: String,
    read: bool,
    silent: bool,
    #[serde(default, deserialize_with = "deserialize_delivery")]
    delivery: TingDeliveryMode,
    deliveries: Vec<TingDestinationReceipt>,
    deliveries_next_cursor: Option<String>,
}

/// HTTPS Ting transport with redirects disabled and bounded response bodies.
#[derive(Clone)]
pub struct TingClient {
    http: reqwest::Client,
    origin: Url,
}

impl fmt::Debug for TingClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("TingClient").finish_non_exhaustive()
    }
}

impl TingClient {
    /// Reads actual downstream receipts with fresh proof and validates record ownership.
    ///
    /// # Errors
    /// Returns an authorization, transport or response-validation failure.
    pub async fn receipt(
        &self,
        iam: &IamClient,
        subject: &SecretString,
        org_id: &str,
        id: &str,
        recipient: &str,
        delivery: TingDeliveryMode,
    ) -> Result<TingReceipt, TingError> {
        if !identifier(org_id, 255) || !identifier(id, 255) || !identifier(recipient, 255) {
            return Err(TingError::InvalidInput("invalid_ting_receipt"));
        }
        let app_id = iam
            .application_id()
            .ok_or(TingError::InvalidInput("ting_iam_not_configured"))?;
        let body =
            serde_json::to_vec(&serde_json::json!({"org_id":org_id,"app_id":app_id,"id":id}))
                .map_err(|_| TingError::InvalidInput("invalid_ting_receipt"))?;
        let proof = iam
            .ting_proof(subject, org_id, "sent.query", "/v1/sent/query", &body)
            .await?;
        let (status, body) = self.post("/v1/sent/query", &body, &proof).await?;
        if status != 200 {
            return Err(TingError::InvalidResponse);
        }
        let detail: SentDetail =
            serde_json::from_slice(&body).map_err(|_| TingError::InvalidResponse)?;
        if detail.id != id
            || detail.recipient != recipient
            || detail.event_type != format!("{app_id}.webhook.received")
            || detail.delivery != delivery
            || detail.deliveries.len() > 100
            || detail
                .deliveries
                .iter()
                .any(|d| !identifier(&d.webhook_id, 255) || (d.read_acked && !d.delivery_acked))
        {
            return Err(TingError::InvalidResponse);
        }
        Ok(TingReceipt {
            id: detail.id,
            read: detail.read,
            silent: detail.silent,
            delivery: detail.delivery,
            deliveries: detail.deliveries,
            more_destinations: detail.deliveries_next_cursor.is_some(),
        })
    }

    /// Creates an internal delivery transport; HTTP is allowed only on loopback.
    ///
    /// # Errors
    /// Rejects credentials, non-root paths, fragments, queries, insecure remote
    /// origins, zero timeouts, and a TLS client that cannot be constructed.
    pub fn new(base_url: &str, request_timeout: Duration) -> Result<Self, TingError> {
        let origin =
            Url::parse(base_url).map_err(|_| TingError::InvalidInput("invalid_ting_origin"))?;
        let loopback = match origin.host() {
            Some(Host::Domain("localhost")) => true,
            Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
            Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
            _ => false,
        };
        if origin.host().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
            || !(origin.scheme() == "https" || (origin.scheme() == "http" && loopback))
            || request_timeout.is_zero()
        {
            return Err(TingError::InvalidInput("invalid_ting_origin"));
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(request_timeout.min(Duration::from_secs(5)))
            .timeout(request_timeout)
            .user_agent(concat!("silicon-hook/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| TingError::InvalidInput("ting_transport_configuration"))?;
        Ok(Self { http, origin })
    }

    /// Sends the exact persisted bytes with a fresh request-bound IAM proof.
    ///
    /// # Errors
    /// Rejects invalid payloads before obtaining a proof, IAM failures, provider
    /// failures, and a response whose status or key does not confirm this send.
    pub async fn send(
        &self,
        iam: &IamClient,
        subject_token: &SecretString,
        prepared_body: &[u8],
    ) -> Result<TingAcceptance, TingError> {
        let request = send_request(iam, prepared_body)?;
        let proof = iam
            .ting_proof(
                subject_token,
                &request.org_id,
                "tings.send",
                "/v1/tings",
                prepared_body,
            )
            .await?;
        let (status, body) = self.post("/v1/tings", prepared_body, &proof).await?;
        if !matches!(status, 200 | 202) {
            return Err(TingError::InvalidResponse);
        }
        decode_acceptance(&body, &request.key, request.delivery)
    }

    /// Registers the authenticated Hook actor as a Ting recipient internally.
    ///
    /// The prepared body must include `for`; IAM and Ting verify that it is
    /// the proof's actor, and this boundary checks the returned grant matches.
    ///
    /// # Errors
    /// Rejects mismatched app/recipient fields, unavailable authorization, and
    /// any response that fails to confirm the requested active subscription.
    pub async fn register_recipient(
        &self,
        iam: &IamClient,
        subject_token: &SecretString,
        prepared_body: &[u8],
    ) -> Result<TingSubscription, TingError> {
        if prepared_body.len() > MAX_ORDINARY_REQUEST_BYTES {
            return Err(TingError::InvalidInput("ting_request_too_large"));
        }
        let request: RegisterRequest = serde_json::from_slice(prepared_body)
            .map_err(|_| TingError::InvalidInput("invalid_ting_registration"))?;
        if !identifier(&request.org_id, 255)
            || !identifier(&request.recipient, 255)
            || iam.application_id() != Some(request.app_id.as_str())
        {
            return Err(TingError::InvalidInput("invalid_ting_registration"));
        }
        let proof = iam
            .ting_proof(
                subject_token,
                &request.org_id,
                "subscriptions.register",
                "/v1/subscriptions",
                prepared_body,
            )
            .await?;
        let (status, body) = self
            .post("/v1/subscriptions", prepared_body, &proof)
            .await?;
        if !matches!(status, 200 | 201) {
            return Err(TingError::InvalidResponse);
        }
        let subscription: TingSubscription =
            serde_json::from_slice(&body).map_err(|_| TingError::InvalidResponse)?;
        if !identifier(&subscription.id, 255)
            || !subscription.active
            || subscription.app_id != request.app_id
            || subscription.recipient != request.recipient
        {
            return Err(TingError::InvalidResponse);
        }
        Ok(subscription)
    }

    async fn post(
        &self,
        path: &str,
        body: &[u8],
        proof: &TingProof,
    ) -> Result<(u16, Vec<u8>), TingError> {
        let url = self
            .origin
            .join(path)
            .map_err(|_| TingError::InvalidInput("invalid_ting_path"))?;
        let mut request = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .bearer_auth(proof.token.expose_secret())
            .body(body.to_vec());
        if let Some(test) = &proof.testing {
            request = request
                .header("IAM_TEST_APP_SECRET", test.app_secret.expose_secret())
                .header(
                    "X-Testing-Environment-Key",
                    test.environment_key.expose_secret(),
                );
        }
        let mut response = request.send().await.map_err(|_| TingError::Transport)?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(|seconds| Duration::from_secs(seconds.min(3600)));
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(TingError::ResponseTooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| TingError::Transport)? {
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(TingError::ResponseTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        if !(200..300).contains(&status) {
            return Err(rejection(status, &bytes, retry_after));
        }
        Ok((status, bytes))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendRequest {
    org_id: String,
    #[serde(rename = "type")]
    event_type: String,
    #[serde(rename = "for")]
    recipient: String,
    key: String,
    data: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    metadata: serde_json::Map<String, serde_json::Value>,
    #[serde(default, deserialize_with = "deserialize_delivery")]
    delivery: TingDeliveryMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    org_id: String,
    app_id: String,
    #[serde(rename = "for")]
    recipient: String,
}

fn identifier(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

fn send_request(iam: &IamClient, body: &[u8]) -> Result<SendRequest, TingError> {
    if body.len() > MAX_TING_SEND_BYTES {
        return Err(TingError::InvalidInput("ting_request_too_large"));
    }
    let request: SendRequest =
        serde_json::from_slice(body).map_err(|_| TingError::InvalidInput("invalid_ting_send"))?;
    let app = iam
        .application_id()
        .ok_or(TingError::InvalidInput("ting_iam_not_configured"))?;
    let prefix = format!("{app}.");
    let suffix = request
        .event_type
        .strip_prefix(&prefix)
        .ok_or(TingError::InvalidInput("invalid_ting_type"))?;
    let pieces = suffix.split('.').collect::<Vec<_>>();
    if !identifier(&request.org_id, 255)
        || !identifier(&request.recipient, 255)
        || !identifier(&request.key, 200)
        || request.event_type.len() > 255
        || pieces.len() != 2
        || pieces.iter().any(|part| {
            !part.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                || !part.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'-')
                })
        })
    {
        return Err(TingError::InvalidInput("invalid_ting_send"));
    }
    // Deserializing these into maps also rejects non-object outer payloads.
    let _ = (&request.data, &request.metadata);
    Ok(request)
}

#[derive(Deserialize)]
struct AcceptanceResponse {
    id: String,
    key: String,
    status: String,
    silent: bool,
    #[serde(default, deserialize_with = "deserialize_delivery")]
    delivery: TingDeliveryMode,
    created_at: String,
}

fn decode_acceptance(
    body: &[u8],
    key: &str,
    delivery: TingDeliveryMode,
) -> Result<TingAcceptance, TingError> {
    let response: AcceptanceResponse =
        serde_json::from_slice(body).map_err(|_| TingError::InvalidResponse)?;
    let created_at = OffsetDateTime::parse(&response.created_at, &Rfc3339)
        .map_err(|_| TingError::InvalidResponse)?;
    if response.status != "accepted"
        || response.key != key
        || response.delivery != delivery
        || !identifier(&response.id, 255)
        || !response.created_at.ends_with('Z')
        || created_at.offset() != time::UtcOffset::UTC
    {
        return Err(TingError::InvalidResponse);
    }
    Ok(TingAcceptance {
        id: response.id,
        key: response.key,
        silent: response.silent,
        delivery: response.delivery,
        created_at,
    })
}

fn rejection(status: u16, body: &[u8], retry_after: Option<Duration>) -> TingError {
    let value = serde_json::from_slice::<serde_json::Value>(body).ok();
    let raw = value
        .as_ref()
        .and_then(|value| value.get("error"))
        .and_then(|error| error.get("code"))
        .and_then(serde_json::Value::as_str);
    let code = match raw {
        Some("authentication_required") => "authentication_required",
        Some("invalid_proof") => "invalid_proof",
        Some("proof_expired") => "proof_expired",
        Some("proof_consumed") => "proof_consumed",
        Some("proof_verification_uncertain") => "proof_verification_uncertain",
        Some("recipient_not_registered") => "recipient_not_registered",
        Some("required_delivery_not_enabled") => "required_delivery_not_enabled",
        Some("permission_denied") => "permission_denied",
        Some("test_context_required") => "test_context_required",
        Some("test_context_mismatch") => "test_context_mismatch",
        Some("idempotency_conflict") => "idempotency_conflict",
        Some("payload_too_large") => "payload_too_large",
        Some("invalid_input") => "invalid_input",
        Some("not_found") => "not_found",
        Some("rate_limited") => "rate_limited",
        Some("dependency_unavailable") => "dependency_unavailable",
        Some("storage_unavailable") => "storage_unavailable",
        _ => "ting_rejected",
    };
    let retryable = matches!(status, 408 | 425 | 429 | 500..=599)
        || (status == 401 && matches!(code, "proof_expired" | "proof_consumed" | "invalid_proof"));
    TingError::Rejected {
        status,
        code,
        retryable,
        retry_after,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IamSettings;
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn proof() -> TingProof {
        TingProof {
            token: SecretString::from("fixture-proof"),
            testing: None,
            expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(30),
        }
    }

    fn acceptance(key: &str) -> serde_json::Value {
        json!({"id":"msg_fixture", "key":key, "status":"accepted", "silent":false,
            "created_at":"2026-09-22T10:00:00Z"})
    }

    async fn iam_fixture() -> Result<(MockServer, IamClient), Box<dyn std::error::Error>> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/version"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("silicon-iam-api-version", "v1")
                    .insert_header("vary", "Silicon-IAM-Supported-API-Versions")
                    .set_body_json(json!({"service":"silicon-iam", "selected_api_version":"v1",
                    "supported_api_versions":["v1"], "build":"test", "commit":"test"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/obo-access/applications/tos%3Eting/endpoints"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "application":{"app_id":"tos>ting","org_id":"tos"},
                "endpoints":[{"endpoint_id":"tings.send","path":"/v1/tings","metadata":{},
                    "critical":true,"ttl_seconds":60},
                    {"endpoint_id":"subscriptions.register","path":"/v1/subscriptions",
                    "metadata":{},"critical":true,"ttl_seconds":60},
                    {"endpoint_id":"sent.query","path":"/v1/sent/query",
                    "metadata":{},"critical":true,"ttl_seconds":60}]})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/obo-access/exchanges"))
            .respond_with(|_: &wiremock::Request| {
                let expiry = OffsetDateTime::now_utc() + time::Duration::seconds(30);
                ResponseTemplate::new(200).set_body_json(json!({
                    "access_proof":format!("proof_{}", uuid::Uuid::new_v4()),
                    "proof_id":uuid::Uuid::new_v4(), "expires_in":30,
                    "expires_at":expiry.format(&Rfc3339).unwrap_or_default()}))
            })
            .mount(&server)
            .await;
        let iam = IamClient::connect(&IamSettings {
            base_url: Url::parse(&server.uri())?,
            app_id: Some("tos>hook".to_owned()),
            app_secret: Some(SecretString::from("ask_fixture_signing_secret")),
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(2),
            max_response_bytes: 65_536,
            allow_insecure_local_http: true,
            local_auth: false,
            webhook: None,
        })
        .await?;
        Ok((server, iam))
    }

    #[test]
    fn origins_are_restricted_and_have_no_credentials() -> TestResult {
        for origin in [
            "http://ting.example",
            "https://name:secret@ting.example/",
            "https://ting.example/v1",
            "https://ting.example/?token=secret",
            "https://ting.example/#secret",
        ] {
            assert!(TingClient::new(origin, Duration::from_secs(2)).is_err());
        }
        for origin in [
            "https://ting.example",
            "http://127.0.0.1:8000",
            "http://[::1]:8000",
        ] {
            TingClient::new(origin, Duration::from_secs(2))?;
        }
        Ok(())
    }

    #[test]
    fn acceptance_requires_exact_key_status_and_timestamp() -> TestResult {
        let value = acceptance("expected");
        decode_acceptance(
            &serde_json::to_vec(&value)?,
            "expected",
            TingDeliveryMode::Ordinary,
        )?;
        assert!(
            decode_acceptance(
                &serde_json::to_vec(&value)?,
                "another",
                TingDeliveryMode::Ordinary
            )
            .is_err()
        );
        for (field, wrong) in [
            ("status", json!("delivered")),
            ("id", json!("")),
            ("created_at", json!("not-a-time")),
            ("silent", json!("false")),
        ] {
            let mut bad = value.clone();
            bad[field] = wrong;
            assert!(
                decode_acceptance(
                    &serde_json::to_vec(&bad)?,
                    "expected",
                    TingDeliveryMode::Ordinary
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn required_acceptance_must_confirm_policy_even_when_notifications_are_silent() -> TestResult {
        let mut value = acceptance("required-key");
        assert!(
            decode_acceptance(
                &serde_json::to_vec(&value)?,
                "required-key",
                TingDeliveryMode::Required
            )
            .is_err()
        );
        value["delivery"] = json!("required");
        value["silent"] = json!(true);
        let accepted = decode_acceptance(
            &serde_json::to_vec(&value)?,
            "required-key",
            TingDeliveryMode::Required,
        )?;
        assert!(accepted.silent);
        assert_eq!(accepted.delivery, TingDeliveryMode::Required);
        assert!(
            decode_acceptance(
                &serde_json::to_vec(&value)?,
                "required-key",
                TingDeliveryMode::Ordinary
            )
            .is_err()
        );
        for mode in [Value::Null, json!("ordinary"), json!("other")] {
            value["delivery"] = mode;
            assert!(
                decode_acceptance(
                    &serde_json::to_vec(&value)?,
                    "required-key",
                    TingDeliveryMode::Required
                )
                .is_err()
            );
        }
        assert_eq!(
            rejection(
                403,
                br#"{"error":{"code":"required_delivery_not_enabled"}}"#,
                None
            )
            .code(),
            "required_delivery_not_enabled"
        );
        Ok(())
    }

    #[test]
    fn provider_failure_text_is_never_exposed() {
        let secret = b"{\"error\":{\"code\":\"stolen_token\",\"message\":\"stolen_token\",\"retryable\":true}}";
        let error = rejection(403, secret, None);
        assert_eq!(error.code(), "ting_rejected");
        assert!(!error.retryable());
        assert!(!format!("{error:?} {error}").contains("stolen_token"));
        assert!(rejection(503, secret, None).retryable());
        assert!(rejection(401, br#"{"error":{"code":"proof_consumed"}}"#, None).retryable());
    }

    #[tokio::test]
    async fn sends_exact_bytes_with_a_different_proof_for_every_attempt() -> TestResult {
        let (issuer, iam) = iam_fixture().await?;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tings"))
            .respond_with(ResponseTemplate::new(202).set_body_json(acceptance("key-fixture")))
            .expect(2)
            .mount(&server)
            .await;
        let client = TingClient::new(&server.uri(), Duration::from_secs(2))?;
        let subject = SecretString::from("oat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let body = br#"{ "key": "key-fixture", "org_id":"tos", "type":"tos>hook.webhook.received", "for":"worker:tos", "data": {"type":"new_event","data":{}} }"#;
        client.send(&iam, &subject, body).await?;
        client.send(&iam, &subject, body).await?;
        let requests = server.received_requests().await.ok_or("missing requests")?;
        assert!(requests.iter().all(|request| request.body == body));
        assert_ne!(
            requests[0].headers.get("authorization"),
            requests[1].headers.get("authorization")
        );
        assert!(
            requests
                .iter()
                .all(|request| !request.headers.contains_key("iam_test_app_secret"))
        );
        let exchanges = issuer
            .received_requests()
            .await
            .ok_or("missing issuer requests")?
            .into_iter()
            .filter(|request| request.url.path() == "/api/v1/obo-access/exchanges")
            .collect::<Vec<_>>();
        assert_eq!(exchanges.len(), 2);
        assert_ne!(
            exchanges[0].headers.get("idempotency-key"),
            exchanges[1].headers.get("idempotency-key")
        );
        for exchange in exchanges {
            let request: serde_json::Value = serde_json::from_slice(&exchange.body)?;
            assert_eq!(
                request["request"]["body_sha256"],
                hex::encode(Sha256::digest(body))
            );
            assert_eq!(request["request"]["method"], "POST");
            assert_eq!(request["audience"], "tos>ting");
            assert_eq!(request["org_id"], "tos");
        }
        Ok(())
    }

    #[tokio::test]
    async fn subscription_response_must_match_requested_actor() -> TestResult {
        let (_issuer, iam) = iam_fixture().await?;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/subscriptions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id":"sub_fixture","app_id":"tos>hook","for":"different:tos","active":true})))
            .mount(&server)
            .await;
        let client = TingClient::new(&server.uri(), Duration::from_secs(2))?;
        let result = client
            .register_recipient(
                &iam,
                &SecretString::from("oat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                br#"{"org_id":"tos","app_id":"tos>hook","for":"worker:tos"}"#,
            )
            .await;
        assert!(matches!(result, Err(TingError::InvalidResponse)));
        Ok(())
    }

    #[tokio::test]
    async fn receipt_validates_identity_and_preserves_incomplete_destination_state() -> TestResult {
        let (_issuer, iam) = iam_fixture().await?;
        let server = MockServer::start().await;
        let detail = json!({"id":"msg_fixture", "type":"tos>hook.webhook.received", "for":"worker:tos",
            "read":false,"silent":false,"deliveries":[{"webhook_id":"hook_a","delivery_acked":true,"read_acked":false}],
            "deliveries_next_cursor":"another-page"});
        Mock::given(method("POST"))
            .and(path("/v1/sent/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&detail))
            .mount(&server)
            .await;
        let client = TingClient::new(&server.uri(), Duration::from_secs(2))?;
        let token = SecretString::from("oat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let receipt = client
            .receipt(
                &iam,
                &token,
                "tos",
                "msg_fixture",
                "worker:tos",
                TingDeliveryMode::Ordinary,
            )
            .await?;
        assert!(!receipt.read);
        assert!(receipt.more_destinations);
        assert!(receipt.deliveries[0].delivery_acked);
        assert!(!receipt.deliveries[0].read_acked);
        assert!(matches!(
            client
                .receipt(
                    &iam,
                    &token,
                    "tos",
                    "msg_other",
                    "worker:tos",
                    TingDeliveryMode::Ordinary
                )
                .await,
            Err(TingError::InvalidResponse)
        ));
        assert!(matches!(
            client
                .receipt(
                    &iam,
                    &token,
                    "tos",
                    "msg_fixture",
                    "another:tos",
                    TingDeliveryMode::Ordinary
                )
                .await,
            Err(TingError::InvalidResponse)
        ));
        assert!(matches!(
            client
                .receipt(
                    &iam,
                    &token,
                    "tos",
                    "msg_fixture",
                    "worker:tos",
                    TingDeliveryMode::Required
                )
                .await,
            Err(TingError::InvalidResponse)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn redirect_does_not_forward_proof_and_response_is_bounded() -> TestResult {
        let destination = MockServer::start().await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tings"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", destination.uri()))
            .mount(&server)
            .await;
        let client = TingClient::new(&server.uri(), Duration::from_secs(2))?;
        assert!(matches!(
            client.post("/v1/tings", b"{}", &proof()).await,
            Err(TingError::Rejected { status: 307, .. })
        ));
        assert!(
            destination
                .received_requests()
                .await
                .ok_or("missing request collection")?
                .is_empty()
        );
        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/v1/tings"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![b'x'; MAX_RESPONSE_BYTES + 1]),
            )
            .mount(&server)
            .await;
        assert!(matches!(
            client.post("/v1/tings", b"{}", &proof()).await,
            Err(TingError::ResponseTooLarge)
        ));
        Ok(())
    }
}
