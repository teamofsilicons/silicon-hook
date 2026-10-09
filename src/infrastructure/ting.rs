//! Internal Ting delivery: the hardened HTTP transport.
//!
//! Every request carries a Silicon Accounts proof (`Authorization: Proof
//! sap_...`) that the caller obtained for the receiving app `ting`: an App
//! verification proof to send and to read receipts, a User verification proof
//! to enrol a recipient. Redirects are never followed (a proof is only ever
//! sent to the configured origin) and response bodies are bounded.
//!
//! The request shapes are Hook's Accounts-era contract with Ting: no
//! organization, recipients addressed by Silicon Accounts `{uuid, id}`.

use std::{fmt, net::IpAddr, time::Duration};

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::{Host, Url};

/// Ting's limit for the entire serialized send request, including its wrapper.
pub const MAX_TING_SEND_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// A Ting recipient: a Silicon Accounts account by uuid, with its current id
/// for display.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TingRecipient {
    /// The account's permanent uuid.
    pub uuid: String,
    /// The account's current public id, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// Redacted delivery failure. Provider bodies and credentials are never retained.
pub enum TingError {
    /// Locally invalid configuration or prepared request.
    InvalidInput(&'static str),
    /// The network outcome is unknown; retry with the same key and a valid proof.
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
            Self::Transport | Self::InvalidResponse | Self::ResponseTooLarge => true,
            Self::Rejected { retryable, .. } => *retryable,
        }
    }

    /// Whether Ting refused the proof itself (a fresh proof may succeed).
    #[must_use]
    pub fn proof_refused(&self) -> bool {
        matches!(
            self,
            Self::Rejected {
                status: 401,
                code: "invalid_proof" | "proof_expired" | "proof_consumed" | "proof_revoked",
                ..
            }
        )
    }

    /// The upstream HTTP status when one is available.
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::Rejected { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// A server-provided retry delay, if available.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Rejected { retry_after, .. } => *retry_after,
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
    /// The recipient the User verification proof speaks for.
    #[serde(rename = "for")]
    pub recipient: TingRecipient,
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
    recipient: TingRecipient,
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
        formatter
            .debug_struct("TingClient")
            .field("origin", &self.origin.as_str())
            .finish_non_exhaustive()
    }
}

impl TingClient {
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

    /// The configured origin.
    #[must_use]
    pub fn origin(&self) -> &Url {
        &self.origin
    }

    /// Sends the exact persisted bytes with an App verification proof.
    ///
    /// # Errors
    /// Rejects invalid payloads before any network I/O, Ting failures, and a
    /// response whose status or key does not confirm this send.
    pub async fn send(
        &self,
        proof: &SecretString,
        app_id: &str,
        prepared_body: &[u8],
    ) -> Result<TingAcceptance, TingError> {
        let request = send_request(app_id, prepared_body)?;
        let (status, body) = self.post("/v1/tings", prepared_body, proof).await?;
        if !matches!(status, 200 | 202) {
            return Err(TingError::InvalidResponse);
        }
        decode_acceptance(&body, &request.key, request.delivery)
    }

    /// Registers a recipient for Hook's notifications with a User verification
    /// proof that speaks for that recipient.
    ///
    /// # Errors
    /// Rejects an invalid recipient, Ting failures, and any response that does
    /// not confirm the requested active subscription.
    pub async fn register_recipient(
        &self,
        proof: &SecretString,
        app_id: &str,
        recipient: &TingRecipient,
    ) -> Result<TingSubscription, TingError> {
        if !identifier(&recipient.uuid, 64) || !identifier(app_id, 80) {
            return Err(TingError::InvalidInput("invalid_ting_registration"));
        }
        let body = serde_json::to_vec(&serde_json::json!({"app_id": app_id, "for": recipient}))
            .map_err(|_| TingError::InvalidInput("invalid_ting_registration"))?;
        let (status, response) = self.post("/v1/subscriptions", &body, proof).await?;
        if !matches!(status, 200 | 201) {
            return Err(TingError::InvalidResponse);
        }
        let subscription: TingSubscription =
            serde_json::from_slice(&response).map_err(|_| TingError::InvalidResponse)?;
        if !identifier(&subscription.id, 255)
            || !subscription.active
            || subscription.app_id != app_id
            || subscription.recipient.uuid != recipient.uuid
        {
            return Err(TingError::InvalidResponse);
        }
        Ok(subscription)
    }

    /// Reads Ting's receipt for one accepted send with an App verification proof.
    ///
    /// # Errors
    /// Returns a transport or response-validation failure.
    pub async fn receipt(
        &self,
        proof: &SecretString,
        app_id: &str,
        ting_id: &str,
        recipient_uuid: &str,
        delivery: TingDeliveryMode,
    ) -> Result<TingReceipt, TingError> {
        if !identifier(ting_id, 255) || !identifier(recipient_uuid, 64) {
            return Err(TingError::InvalidInput("invalid_ting_receipt"));
        }
        let body = serde_json::to_vec(&serde_json::json!({"app_id": app_id, "id": ting_id}))
            .map_err(|_| TingError::InvalidInput("invalid_ting_receipt"))?;
        let (status, body) = self.post("/v1/sent/query", &body, proof).await?;
        if status != 200 {
            return Err(TingError::InvalidResponse);
        }
        let detail: SentDetail =
            serde_json::from_slice(&body).map_err(|_| TingError::InvalidResponse)?;
        if detail.id != ting_id
            || detail.recipient.uuid != recipient_uuid
            || detail.event_type != format!("{app_id}{EVENT_TYPE_SUFFIX}")
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

    async fn post(
        &self,
        path: &str,
        body: &[u8],
        proof: &SecretString,
    ) -> Result<(u16, Vec<u8>), TingError> {
        let url = self
            .origin
            .join(path)
            .map_err(|_| TingError::InvalidInput("invalid_ting_path"))?;
        let mut response = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Proof {}", proof.expose_secret()),
            )
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| TingError::Transport)?;
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

/// Ting type suffix owned by the Hook application.
pub const EVENT_TYPE_SUFFIX: &str = ".webhook.received";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendRequest {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(rename = "for")]
    recipient: TingRecipient,
    key: String,
    data: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    metadata: serde_json::Map<String, serde_json::Value>,
    #[serde(default, deserialize_with = "deserialize_delivery")]
    delivery: TingDeliveryMode,
}

fn identifier(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

fn send_request(app_id: &str, body: &[u8]) -> Result<SendRequest, TingError> {
    if body.len() > MAX_TING_SEND_BYTES {
        return Err(TingError::InvalidInput("ting_request_too_large"));
    }
    let request: SendRequest =
        serde_json::from_slice(body).map_err(|_| TingError::InvalidInput("invalid_ting_send"))?;
    if request.event_type != format!("{app_id}{EVENT_TYPE_SUFFIX}")
        || !identifier(&request.recipient.uuid, 64)
        || !identifier(&request.key, 200)
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
        Some("proof_revoked") => "proof_revoked",
        Some("proof_verification_uncertain") => "proof_verification_uncertain",
        Some("recipient_not_registered") => "recipient_not_registered",
        Some("required_delivery_not_enabled") => "required_delivery_not_enabled",
        Some("permission_denied") => "permission_denied",
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
        || (status == 401
            && matches!(
                code,
                "proof_expired" | "proof_consumed" | "proof_revoked" | "invalid_proof"
            ));
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
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn proof() -> SecretString {
        SecretString::from("sap_fixture-proof")
    }

    fn acceptance(key: &str) -> Value {
        json!({"id":"msg_fixture", "key":key, "status":"accepted", "silent":false,
            "created_at":"2026-09-22T10:00:00Z"})
    }

    fn send_body(key: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "key": key, "type": "hook.webhook.received",
            "for": {"uuid": "8HV", "id": "si:worker"},
            "data": {"type": "new_event", "data": {}}
        }))
        .unwrap_or_default()
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
    fn sends_must_be_hook_events_addressed_by_uuid() {
        assert!(send_request("hook", &send_body("k")).is_ok());
        assert!(send_request("other", &send_body("k")).is_err());
        let legacy = br#"{"org_id":"tos","key":"k","type":"hook.webhook.received","for":"si:worker","data":{}}"#;
        assert!(send_request("hook", legacy).is_err());
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
        let mut required = acceptance("required-key");
        required["delivery"] = json!("required");
        required["silent"] = json!(true);
        let accepted = decode_acceptance(
            &serde_json::to_vec(&required)?,
            "required-key",
            TingDeliveryMode::Required,
        )?;
        assert!(accepted.silent);
        Ok(())
    }

    #[test]
    fn provider_failure_text_is_never_exposed() {
        let secret = b"{\"error\":{\"code\":\"stolen_token\",\"message\":\"stolen_token\"}}";
        let error = rejection(403, secret, None);
        assert_eq!(error.code(), "ting_rejected");
        assert!(!error.retryable());
        assert!(!format!("{error:?} {error}").contains("stolen_token"));
        assert!(rejection(503, secret, None).retryable());
        let refused = rejection(401, br#"{"error":{"code":"proof_expired"}}"#, None);
        assert!(refused.retryable());
        assert!(refused.proof_refused());
    }

    #[tokio::test]
    async fn sends_exact_bytes_with_the_proof_scheme() -> TestResult {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/tings"))
            .and(header("authorization", "Proof sap_fixture-proof"))
            .respond_with(ResponseTemplate::new(202).set_body_json(acceptance("key-fixture")))
            .expect(2)
            .mount(&server)
            .await;
        let client = TingClient::new(&server.uri(), Duration::from_secs(2))?;
        let body = send_body("key-fixture");
        client.send(&proof(), "hook", &body).await?;
        client.send(&proof(), "hook", &body).await?;
        let requests = server.received_requests().await.ok_or("missing requests")?;
        assert!(requests.iter().all(|request| request.body == body));
        Ok(())
    }

    #[tokio::test]
    async fn enrolment_must_confirm_the_requested_recipient() -> TestResult {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/subscriptions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id":"sub_fixture","app_id":"hook","for":{"uuid":"zQo","id":"c:other"},"active":true})))
            .mount(&server)
            .await;
        let client = TingClient::new(&server.uri(), Duration::from_secs(2))?;
        let recipient = TingRecipient {
            uuid: "8HV".to_owned(),
            id: Some("si:worker".to_owned()),
        };
        let result = client
            .register_recipient(&proof(), "hook", &recipient)
            .await;
        assert!(matches!(result, Err(TingError::InvalidResponse)));
        let requests = server.received_requests().await.ok_or("missing requests")?;
        let sent: Value = serde_json::from_slice(&requests[0].body)?;
        assert_eq!(
            sent,
            json!({"app_id":"hook","for":{"uuid":"8HV","id":"si:worker"}})
        );
        Ok(())
    }

    #[tokio::test]
    async fn receipt_validates_identity_and_preserves_incomplete_destination_state() -> TestResult {
        let server = MockServer::start().await;
        let detail = json!({"id":"msg_fixture", "type":"hook.webhook.received",
            "for":{"uuid":"8HV","id":"si:worker"},
            "read":false,"silent":false,"deliveries":[{"webhook_id":"hook_a","delivery_acked":true,"read_acked":false}],
            "deliveries_next_cursor":"another-page"});
        Mock::given(method("POST"))
            .and(path("/v1/sent/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&detail))
            .mount(&server)
            .await;
        let client = TingClient::new(&server.uri(), Duration::from_secs(2))?;
        let receipt = client
            .receipt(
                &proof(),
                "hook",
                "msg_fixture",
                "8HV",
                TingDeliveryMode::Ordinary,
            )
            .await?;
        assert!(!receipt.read);
        assert!(receipt.more_destinations);
        for (id, recipient, mode) in [
            ("msg_other", "8HV", TingDeliveryMode::Ordinary),
            ("msg_fixture", "zQo", TingDeliveryMode::Ordinary),
            ("msg_fixture", "8HV", TingDeliveryMode::Required),
        ] {
            assert!(matches!(
                client.receipt(&proof(), "hook", id, recipient, mode).await,
                Err(TingError::InvalidResponse)
            ));
        }
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
