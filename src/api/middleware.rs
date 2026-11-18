//! Cross-cutting HTTP request policy and error normalization.

use std::time::{Duration, Instant};

use axum::{
    extract::{MatchedPath, Request, State},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use http::{HeaderName, Method, header};
use tower::{Layer as _, ServiceExt as _};
use tower_http::cors::{Any, CorsLayer};
use tracing::{Instrument as _, info_span};
use uuid::Uuid;

use crate::{error::AppError, request_context};

const REQUEST_ID_HEADER: http::HeaderName = http::HeaderName::from_static("x-request-id");
const MAX_REQUEST_ID_BYTES: usize = 64;
const MANAGEMENT_VARY: &str = "authorization";

/// Interfaces can use their app bearer from any origin. Provider ingress also
/// accepts OPTIONS as a provider event, so it must never pass through this layer.
pub(super) fn interface_cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            HeaderName::from_static("idempotency-key"),
            REQUEST_ID_HEADER,
            super::version::API_VERSION_HEADER,
            super::version::SUPPORTED_API_VERSIONS_HEADER,
        ])
        .expose_headers([
            REQUEST_ID_HEADER,
            super::version::API_VERSION_HEADER,
            header::RETRY_AFTER,
            header::WWW_AUTHENTICATE,
            header::LINK,
            HeaderName::from_static("deprecation"),
            HeaderName::from_static("sunset"),
        ])
        .max_age(Duration::from_secs(600))
}

pub(super) async fn apply_interface_cors(
    State(cors): State<CorsLayer>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if path.starts_with("/api/v3/")
        || matches!(
            path,
            "/api/version" | "/api/contracts" | "/api/openapi.yaml" | "/healthz" | "/readyz"
        )
    {
        return cors
            .layer(next)
            .oneshot(request)
            .await
            .unwrap_or_else(|never| match never {});
    }
    next.run(request).await
}

pub(super) async fn request_scope(mut request: Request, next: Next) -> Response {
    let contains_management_data = is_management_path(request.uri().path());
    let request_id = validated_request_id(&request).unwrap_or_else(|| Uuid::now_v7().to_string());
    if let Ok(header_value) = request_id.parse() {
        request
            .headers_mut()
            .insert(REQUEST_ID_HEADER, header_value);
    }

    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |path| path.as_str().to_owned());
    let started_at = Instant::now();
    let span = info_span!(
        "http.request",
        request_id = %request_id,
        method = %method,
        route = %route,
        status = tracing::field::Empty,
        latency_ms = tracing::field::Empty,
    );

    let future = async move { normalize_error_response(next.run(request).await) };
    let mut response = request_context::scope(request_id.clone(), future)
        .instrument(span.clone())
        .await;
    span.record("status", response.status().as_u16());
    let latency_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
    span.record("latency_ms", latency_ms);
    tracing::info!(parent: &span, "request completed");

    if let Ok(header_value) = request_id.parse() {
        response
            .headers_mut()
            .insert(REQUEST_ID_HEADER, header_value);
    }
    if contains_management_data {
        prevent_shared_caching(&mut response);
    }
    response
}

fn is_management_path(path: &str) -> bool {
    super::version::split_path(path).is_some_and(|(_, relative)| {
        relative == "silicons"
            || relative.starts_with("silicons/")
            || relative.starts_with("auth/")
            || relative == "delivery"
            || relative.starts_with("delivery/")
    })
}

/// Refuses versioned requests pinned to another API major before any handler
/// runs, so a client that negotiated a different contract is never served
/// this one by accident.
pub(super) async fn enforce_api_version(request: Request, next: Next) -> Response {
    let major = super::version::split_path(request.uri().path()).map(|(major, _)| major);
    match super::version::check_pinned(request.headers(), request.uri().path()) {
        Ok(()) => {
            let mut response = next.run(request).await;
            if let Some(major) = major {
                response.headers_mut().insert(
                    super::version::API_VERSION_HEADER,
                    http::HeaderValue::from_static(major),
                );
            }
            response
        }
        Err(error) => error.into_response(),
    }
}

fn prevent_shared_caching(response: &mut Response) {
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        http::header::PRAGMA,
        http::HeaderValue::from_static("no-cache"),
    );
    response.headers_mut().insert(
        http::header::VARY,
        http::HeaderValue::from_static(MANAGEMENT_VARY),
    );
}

pub(super) async fn enforce_timeout(
    State(request_timeout): State<Duration>,
    request: Request,
    next: Next,
) -> Response {
    match tokio::time::timeout(request_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => AppError::Timeout.into_response(),
    }
}

fn validated_request_id(request: &Request) -> Option<String> {
    let value = request.headers().get(REQUEST_ID_HEADER)?.to_str().ok()?;
    let is_valid = (1..=MAX_REQUEST_ID_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    is_valid.then(|| value.to_owned())
}

fn normalize_error_response(response: Response) -> Response {
    if !response.status().is_client_error() && !response.status().is_server_error() {
        return response;
    }
    let is_json = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if is_json {
        return response;
    }

    match response.status() {
        http::StatusCode::BAD_REQUEST => AppError::bad_request("invalid_request").into_response(),
        http::StatusCode::UNAUTHORIZED => AppError::Unauthenticated.into_response(),
        http::StatusCode::FORBIDDEN => AppError::Forbidden.into_response(),
        http::StatusCode::NOT_FOUND => AppError::NotFound.into_response(),
        http::StatusCode::METHOD_NOT_ALLOWED => AppError::MethodNotAllowed.into_response(),
        http::StatusCode::REQUEST_TIMEOUT => AppError::Timeout.into_response(),
        http::StatusCode::PAYLOAD_TOO_LARGE => AppError::PayloadTooLarge.into_response(),
        http::StatusCode::UNSUPPORTED_MEDIA_TYPE => AppError::UnsupportedMediaType.into_response(),
        http::StatusCode::UNPROCESSABLE_ENTITY => {
            AppError::validation("validation_failed").into_response()
        }
        http::StatusCode::TOO_MANY_REQUESTS => AppError::RateLimited {
            retry_after: Duration::from_secs(1),
        }
        .into_response(),
        http::StatusCode::SERVICE_UNAVAILABLE => AppError::ProviderUnavailable.into_response(),
        _ => AppError::internal(anyhow::anyhow!("non-JSON middleware failure")).into_response(),
    }
}

pub(super) fn handle_panic(_panic: Box<dyn std::any::Any + Send + 'static>) -> Response {
    AppError::internal(anyhow::anyhow!("request handler panicked")).into_response()
}

#[cfg(test)]
mod tests {
    use axum::{Router, body::Body, middleware, routing::get};
    use http::{Request, StatusCode};
    use tower::ServiceExt as _;

    use super::request_scope;

    #[tokio::test]
    async fn replaces_an_invalid_request_id() -> Result<(), Box<dyn std::error::Error>> {
        let app = Router::new()
            .route("/", get(|| async { StatusCode::NO_CONTENT }))
            .layer(middleware::from_fn(request_scope));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-request-id", "contains spaces")
                    .body(Body::empty())?,
            )
            .await?;
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok());

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(request_id.is_some_and(|value| !value.contains(' ')));
        Ok(())
    }

    #[tokio::test]
    async fn management_responses_are_private_and_never_cacheable()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = Router::new()
            .route(
                "/api/v3/silicons/{silicon_id}/hooks",
                get(|| async { StatusCode::UNAUTHORIZED }),
            )
            .layer(middleware::from_fn(request_scope));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v3/silicons/acme/hooks")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(
            response.headers().get(http::header::CACHE_CONTROL),
            Some(&http::HeaderValue::from_static("private, no-store"))
        );
        assert_eq!(
            response.headers().get(http::header::PRAGMA),
            Some(&http::HeaderValue::from_static("no-cache"))
        );
        assert_eq!(
            response.headers().get(http::header::VARY),
            Some(&http::HeaderValue::from_static(super::MANAGEMENT_VARY))
        );
        Ok(())
    }
}
