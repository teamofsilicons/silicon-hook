//! Stable application errors and their redacted HTTP representation.

use std::borrow::Cow;

use axum::{Json, http::StatusCode, response::IntoResponse};
use http::{HeaderValue, header};
use serde::Serialize;
use thiserror::Error;
use tracing::error;

/// Error returned across application and HTTP boundaries.
#[derive(Debug, Error)]
pub enum AppError {
    /// HTTP syntax or protocol input is malformed.
    #[error("the request is malformed")]
    BadRequest {
        /// Stable, machine-readable reason.
        code: Cow<'static, str>,
    },
    /// Syntactically valid input violates domain validation.
    #[error("request validation failed")]
    Validation {
        /// Stable, machine-readable validation reason.
        code: Cow<'static, str>,
        /// Optional safe explanation for the caller.
        details: Option<String>,
    },
    /// Credential is absent, invalid, expired, or revoked.
    #[error("authentication is required")]
    Unauthenticated,
    /// Authenticated actor lacks authority for this action.
    #[error("the actor is not authorized for this action")]
    Forbidden,
    /// The client address is blocked for the endpoint.
    #[error("the client address is blocked for this endpoint")]
    Blocked {
        /// Remaining block duration, or `None` when permanent.
        retry_after: Option<std::time::Duration>,
    },
    /// Resource does not exist in the caller-visible organization scope.
    #[error("resource was not found")]
    NotFound,
    /// A retained resource can no longer be restored or consumed.
    #[error("resource is no longer available")]
    Gone {
        /// Stable, machine-readable reason.
        code: Cow<'static, str>,
    },
    /// Mutation conflicts with current state or idempotency history.
    #[error("request conflicts with current state")]
    Conflict {
        /// Stable, machine-readable conflict reason.
        code: Cow<'static, str>,
    },
    /// Request exceeded an abuse-control limit.
    #[error("rate limit exceeded")]
    RateLimited {
        /// Delay advertised to the caller.
        retry_after: std::time::Duration,
    },
    /// Request processing exceeded its deadline.
    #[error("request processing deadline exceeded")]
    Timeout,
    /// Request body exceeds the configured maximum.
    #[error("request body is too large")]
    PayloadTooLarge,
    /// The request content type cannot be processed by the route.
    #[error("request media type is not supported")]
    UnsupportedMediaType,
    /// Route exists but not for this HTTP method.
    #[error("method is not allowed for this route")]
    MethodNotAllowed,
    /// A required dependency is unavailable or violated its contract.
    #[error("a required dependency is unavailable")]
    ProviderUnavailable,
    /// Unexpected failure whose details must never cross the API boundary.
    #[error("internal service error")]
    Internal(#[source] anyhow::Error),
}

/// Documented top-level JSON error envelope.
#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: PublicError,
}

/// Error object from `openapi.yaml`; the request ID is deliberately nested.
#[derive(Debug, Serialize)]
struct PublicError {
    code: Cow<'static, str>,
    message: Cow<'static, str>,
    request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

impl AppError {
    /// Creates a malformed-request error with a stable code.
    #[must_use]
    pub fn bad_request(code: impl Into<Cow<'static, str>>) -> Self {
        Self::BadRequest { code: code.into() }
    }

    /// Creates a domain validation error with a stable code.
    #[must_use]
    pub fn validation(code: impl Into<Cow<'static, str>>) -> Self {
        Self::Validation {
            code: code.into(),
            details: None,
        }
    }

    /// Creates a domain validation error with a safe explanation.
    #[must_use]
    pub fn validation_with_details(
        code: impl Into<Cow<'static, str>>,
        details: impl Into<String>,
    ) -> Self {
        Self::Validation {
            code: code.into(),
            details: Some(details.into()),
        }
    }

    /// Creates a conflict error with a stable code.
    #[must_use]
    pub fn conflict(code: impl Into<Cow<'static, str>>) -> Self {
        Self::Conflict { code: code.into() }
    }

    /// Creates a gone error with a stable code.
    #[must_use]
    pub fn gone(code: impl Into<Cow<'static, str>>) -> Self {
        Self::Gone { code: code.into() }
    }

    /// Wraps an unexpected internal error for redacted presentation.
    #[must_use]
    pub fn internal(error: impl Into<anyhow::Error>) -> Self {
        Self::Internal(error.into())
    }

    /// Returns the HTTP status associated with this stable error class.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest { .. } => StatusCode::BAD_REQUEST,
            Self::Validation { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden | Self::Blocked { .. } => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Gone { .. } => StatusCode::GONE,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Timeout => StatusCode::REQUEST_TIMEOUT,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::ProviderUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn public_parts(self) -> (Cow<'static, str>, Cow<'static, str>, Option<String>) {
        match self {
            Self::BadRequest { code } => (code, Cow::Borrowed("The request is malformed."), None),
            Self::Validation { code, details } => (
                code,
                Cow::Borrowed("The request contains invalid data."),
                details,
            ),
            Self::Unauthenticated => (
                Cow::Borrowed("unauthenticated"),
                Cow::Borrowed("Authentication is required."),
                None,
            ),
            Self::Forbidden => (
                Cow::Borrowed("forbidden"),
                Cow::Borrowed("The actor is not authorized for this action."),
                None,
            ),
            Self::Blocked { .. } => (
                Cow::Borrowed("ip_blocked"),
                Cow::Borrowed("The client address is blocked for this endpoint."),
                None,
            ),
            Self::NotFound => (
                Cow::Borrowed("not_found"),
                Cow::Borrowed("The requested resource was not found."),
                None,
            ),
            Self::Gone { code } => (
                code,
                Cow::Borrowed("The requested resource is no longer available."),
                None,
            ),
            Self::Conflict { code } => (
                code,
                Cow::Borrowed("The request conflicts with the current resource state."),
                None,
            ),
            Self::RateLimited { .. } => (
                Cow::Borrowed("rate_limited"),
                Cow::Borrowed("Too many requests. Retry later."),
                None,
            ),
            Self::Timeout => (
                Cow::Borrowed("request_timeout"),
                Cow::Borrowed("The request exceeded its processing deadline."),
                None,
            ),
            Self::PayloadTooLarge => (
                Cow::Borrowed("payload_too_large"),
                Cow::Borrowed("The request body exceeds the allowed size."),
                None,
            ),
            Self::UnsupportedMediaType => (
                Cow::Borrowed("unsupported_media_type"),
                Cow::Borrowed("The request media type is not supported."),
                None,
            ),
            Self::MethodNotAllowed => (
                Cow::Borrowed("method_not_allowed"),
                Cow::Borrowed("The HTTP method is not allowed for this route."),
                None,
            ),
            Self::ProviderUnavailable => (
                Cow::Borrowed("provider_unavailable"),
                Cow::Borrowed("A required dependency is temporarily unavailable."),
                None,
            ),
            Self::Internal(_source) => {
                error!("unhandled internal application error");
                (
                    Cow::Borrowed("internal_error"),
                    Cow::Borrowed("An internal service error occurred."),
                    None,
                )
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = self.status();
        let retry_after = match &self {
            Self::RateLimited { retry_after } => Some(*retry_after),
            Self::Blocked { retry_after } => *retry_after,
            _ => None,
        };
        let (code, message, details) = self.public_parts();
        let mut response = (
            status,
            Json(ErrorEnvelope {
                error: PublicError {
                    code,
                    message,
                    request_id: request_id(),
                    details,
                },
            }),
        )
            .into_response();

        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"silicon-hook\""),
            );
        }
        if let Some(retry_after) = retry_after
            && let Ok(value) = HeaderValue::from_str(&retry_after.as_secs().max(1).to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

fn request_id() -> String {
    crate::request_context::current_request_id().unwrap_or_else(|| "unavailable".to_owned())
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        Self::Internal(error.into())
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::to_bytes, response::IntoResponse as _};
    use http::StatusCode;
    use serde_json::Value;

    use super::AppError;

    #[tokio::test]
    async fn error_envelope_nests_the_request_id() -> Result<(), Box<dyn std::error::Error>> {
        let response = crate::request_context::scope("req_01".to_owned(), async {
            AppError::NotFound.into_response()
        })
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(body["error"]["code"], "not_found");
        assert_eq!(body["error"]["request_id"], "req_01");
        assert!(body.get("request_id").is_none());
        assert!(body["error"].get("details").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn internal_details_never_cross_the_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let response =
            AppError::internal(anyhow::anyhow!("database-password=secret")).into_response();
        let body = to_bytes(response.into_body(), 4096).await?;
        let encoded = std::str::from_utf8(&body)?;

        assert!(!encoded.contains("database-password"));
        assert!(!encoded.contains("secret"));
        assert!(encoded.contains("internal_error"));
        Ok(())
    }

    #[tokio::test]
    async fn blocked_addresses_receive_retry_after_and_validation_details()
    -> Result<(), Box<dyn std::error::Error>> {
        let blocked = AppError::Blocked {
            retry_after: Some(std::time::Duration::from_secs(90)),
        }
        .into_response();
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            blocked
                .headers()
                .get(http::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("90")
        );

        let detailed =
            AppError::validation_with_details("invalid_signature", "unknown function md5")
                .into_response();
        let body: Value = serde_json::from_slice(&to_bytes(detailed.into_body(), 4096).await?)?;
        assert_eq!(body["error"]["details"], "unknown function md5");
        Ok(())
    }
}
