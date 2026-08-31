//! Bounded HTTP delivery client for Silicon DM's internal Hook endpoint.

use std::{fmt, time::Duration};

use http::{HeaderValue, StatusCode, header};
use reqwest::{Client, Url, redirect::Policy};
use secrecy::ExposeSecret as _;
use thiserror::Error;

use crate::{config::DmSettings, domain::EventId};

pub use crate::dm_contract::SystemEvent;

const USER_AGENT: &str = concat!("silicon-hook/", env!("CARGO_PKG_VERSION"));

/// Classification consumed by the durable outbox worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
    /// DM durably accepted the event with exactly `202 Accepted`.
    Accepted,
    /// A transient failure should be retried under worker policy.
    Retryable {
        /// Provider-requested delay, already capped to worker policy.
        retry_after: Option<Duration>,
        /// Stable, redacted diagnostic reason.
        reason: DeliveryFailureReason,
    },
    /// Retrying this unchanged request cannot succeed.
    Terminal {
        /// Stable, redacted diagnostic reason.
        reason: DeliveryFailureReason,
    },
}

/// Redacted reason persisted with a delivery attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryFailureReason {
    /// The serialized request exceeds the configured delivery bound.
    RequestTooLarge,
    /// The complete request exceeded its deadline.
    Timeout,
    /// A connection could not be established.
    Connection,
    /// Another request transport failure occurred.
    Transport,
    /// DM returned a non-accepted HTTP status.
    HttpStatus(u16),
}

impl fmt::Display for DeliveryFailureReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestTooLarge => formatter.write_str("dm_request_too_large"),
            Self::Timeout => formatter.write_str("dm_timeout"),
            Self::Connection => formatter.write_str("dm_connection_failed"),
            Self::Transport => formatter.write_str("dm_transport_failed"),
            Self::HttpStatus(status) => write!(formatter, "dm_http_{status}"),
        }
    }
}

/// Configuration-time DM client construction failure.
#[derive(Debug, Error)]
pub enum DmClientBuildError {
    /// The service token cannot be represented as an HTTP bearer credential.
    #[error("DM service token contains characters invalid in an HTTP header")]
    InvalidServiceToken(#[source] http::header::InvalidHeaderValue),
    /// Reqwest rejected the bounded client policy.
    #[error("failed to construct the DM HTTP client")]
    HttpClient(#[source] reqwest::Error),
}

/// Cloneable, redirect-free, deadline-bound Silicon DM client.
#[derive(Clone)]
pub struct DmClient {
    client: Client,
    endpoint: Url,
    authorization: HeaderValue,
    max_request_bytes: usize,
    max_retry_delay: Duration,
}

impl fmt::Debug for DmClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DmClient")
            .field("endpoint", &self.endpoint)
            .field("authorization", &"[REDACTED]")
            .field("max_request_bytes", &self.max_request_bytes)
            .field("max_retry_delay", &self.max_retry_delay)
            .finish_non_exhaustive()
    }
}

impl DmClient {
    /// Builds a DM client with an explicit `Retry-After` cap.
    ///
    /// # Errors
    ///
    /// Returns an error if the bearer token or HTTP client policy is invalid.
    /// No credential value appears in the returned error.
    pub fn new(
        settings: &DmSettings,
        max_retry_delay: Duration,
    ) -> Result<Self, DmClientBuildError> {
        let mut endpoint = settings.base_url.clone();
        endpoint.set_path("/api/v1/internal/hook-events");
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        let mut authorization = HeaderValue::from_str(&format!(
            "Bearer {}",
            settings.service_token.expose_secret()
        ))
        .map_err(DmClientBuildError::InvalidServiceToken)?;
        authorization.set_sensitive(true);

        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(settings.connect_timeout)
            .timeout(settings.request_timeout)
            .user_agent(USER_AGENT)
            .build()
            .map_err(DmClientBuildError::HttpClient)?;

        Ok(Self {
            client,
            endpoint,
            authorization,
            max_request_bytes: settings.max_request_bytes,
            max_retry_delay,
        })
    }

    /// Attempts one delivery without performing an implicit retry.
    ///
    /// Only `202 Accepted` is successful. Connection failures, timeouts, HTTP
    /// `408`, `425`, `429`, and `5xx` are retryable. All other responses are
    /// terminal for this unchanged outbox record.
    pub async fn send(&self, event: &SystemEvent) -> DeliveryOutcome {
        let Ok(body) = serde_json::to_vec(event) else {
            return DeliveryOutcome::Terminal {
                reason: DeliveryFailureReason::RequestTooLarge,
            };
        };

        self.send_serialized(event.event_id, &body).await
    }

    /// Sends an already validated, immutable outbox representation verbatim.
    pub(crate) async fn send_serialized(&self, event_id: EventId, body: &[u8]) -> DeliveryOutcome {
        if body.len() > self.max_request_bytes {
            return DeliveryOutcome::Terminal {
                reason: DeliveryFailureReason::RequestTooLarge,
            };
        }

        let response = self
            .client
            .post(self.endpoint.clone())
            .header(header::AUTHORIZATION, self.authorization.clone())
            .header("Idempotency-Key", event_id.to_string())
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .await;

        match response {
            Ok(response) => self.classify_response(&response),
            Err(error) => DeliveryOutcome::Retryable {
                retry_after: None,
                reason: if error.is_timeout() {
                    DeliveryFailureReason::Timeout
                } else if error.is_connect() {
                    DeliveryFailureReason::Connection
                } else {
                    DeliveryFailureReason::Transport
                },
            },
        }
    }

    fn classify_response(&self, response: &reqwest::Response) -> DeliveryOutcome {
        let status = response.status();
        if status == StatusCode::ACCEPTED {
            return DeliveryOutcome::Accepted;
        }

        let reason = DeliveryFailureReason::HttpStatus(status.as_u16());
        if is_retryable_status(status) {
            DeliveryOutcome::Retryable {
                retry_after: parse_retry_after(response, self.max_retry_delay),
                reason,
            }
        } else {
            DeliveryOutcome::Terminal { reason }
        }
    }
}

fn is_retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
}

fn parse_retry_after(response: &reqwest::Response, maximum: Duration) -> Option<Duration> {
    let value = response.headers().get(header::RETRY_AFTER)?.to_str().ok()?;
    let delay = if let Ok(seconds) = value.parse::<u64>() {
        Duration::from_secs(seconds)
    } else {
        let retry_at = httpdate::parse_http_date(value).ok()?;
        retry_at.duration_since(std::time::SystemTime::now()).ok()?
    };
    Some(delay.min(maximum))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use secrecy::SecretString;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    use crate::{
        config::DmSettings,
        domain::{EventId, EventType, OrganizationId, SiliconId, TraceId},
    };

    use super::{DeliveryFailureReason, DeliveryOutcome, DmClient, SystemEvent};

    fn event() -> Result<SystemEvent, crate::domain::DomainError> {
        let mut payload = serde_json::Map::new();
        payload.insert("ref".to_owned(), json!("main"));
        Ok(SystemEvent {
            event_id: EventId::new(),
            org_id: OrganizationId::new("tos")?,
            silicon_id: SiliconId::new("cos:tos")?,
            event_type: EventType::new("github.push")?,
            trace_id: Some(TraceId::new("req_01")?),
            payload,
        })
    }

    fn client(
        server: &MockServer,
        max_request_bytes: usize,
    ) -> Result<DmClient, Box<dyn std::error::Error>> {
        let settings = DmSettings {
            base_url: format!("{}/api/v1/", server.uri()).parse()?,
            service_token: SecretString::from("dm-service-token"),
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(2),
            max_request_bytes,
        };
        Ok(DmClient::new(&settings, Duration::from_mins(15))?)
    }

    #[tokio::test]
    async fn only_202_is_accepted_and_request_matches_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        let event = event()?;
        Mock::given(method("POST"))
            .and(path("/api/v1/internal/hook-events"))
            .and(header("authorization", "Bearer dm-service-token"))
            .and(header("idempotency-key", event.event_id.to_string()))
            .and(body_json(json!({
                "event_id": event.event_id,
                "org_id": "tos",
                "silicon_id": "cos:tos",
                "type": "github.push",
                "trace_id": "req_01",
                "payload": { "ref": "main" }
            })))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            client(&server, 4096)?.send(&event).await,
            DeliveryOutcome::Accepted
        );
        Ok(())
    }

    #[tokio::test]
    async fn generic_success_status_is_terminal() -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        assert_eq!(
            client(&server, 4096)?.send(&event()?).await,
            DeliveryOutcome::Terminal {
                reason: DeliveryFailureReason::HttpStatus(200)
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn retryable_status_honors_bounded_retry_after() -> Result<(), Box<dyn std::error::Error>>
    {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "3600"))
            .mount(&server)
            .await;

        assert_eq!(
            client(&server, 4096)?.send(&event()?).await,
            DeliveryOutcome::Retryable {
                retry_after: Some(Duration::from_mins(15)),
                reason: DeliveryFailureReason::HttpStatus(429)
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn normal_client_errors_are_terminal() -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(422))
            .mount(&server)
            .await;

        assert_eq!(
            client(&server, 4096)?.send(&event()?).await,
            DeliveryOutcome::Terminal {
                reason: DeliveryFailureReason::HttpStatus(422)
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn oversized_outbox_payload_never_reaches_dm() -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(202))
            .expect(0)
            .mount(&server)
            .await;

        assert_eq!(
            client(&server, 16)?.send(&event()?).await,
            DeliveryOutcome::Terminal {
                reason: DeliveryFailureReason::RequestTooLarge
            }
        );
        Ok(())
    }

    #[test]
    fn corrupt_persisted_event_fails_typed_rehydration_without_a_request() {
        let value = json!({
            "event_id": uuid::Uuid::now_v7(),
            "org_id": "tos",
            "silicon_id": "cos:tos",
            "type": "UPPERCASE-IS-INVALID",
            "payload": []
        });

        assert!(serde_json::from_value::<SystemEvent>(value).is_err());
    }
}
