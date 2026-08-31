//! Axum route table and cross-cutting request policy.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware as axum_middleware,
    routing::{get, post},
};
use http::{HeaderName, header};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    catch_panic::CatchPanicLayer, sensitive_headers::SetSensitiveRequestHeadersLayer,
};

use super::{handlers, middleware, state::ApiState};
use crate::config::ServerSettings;

const OBO_PROOF_HEADER: HeaderName = HeaderName::from_static("x-iam-obo-access-proof");
const HOOK_SIGNATURE_HEADER: HeaderName = HeaderName::from_static("x-hook-signature");

pub(super) fn router(state: ApiState, settings: &ServerSettings) -> Router {
    let system = Router::new()
        .route("/healthz", get(handlers::liveness))
        .route("/readyz", get(handlers::readiness))
        .route("/api/v1/version", get(handlers::version));

    let management = Router::new()
        .route(
            "/api/v1/silicons/{silicon_id}/hooks",
            get(handlers::list_hooks).post(handlers::create_hook),
        )
        .route(
            "/api/v1/silicons/{silicon_id}/hooks/{hook_id}",
            get(handlers::get_hook).delete(handlers::delete_hook),
        )
        .route(
            "/api/v1/silicons/{silicon_id}/hooks/{hook_id}/restore",
            post(handlers::restore_hook),
        )
        .route(
            "/api/v1/silicons/{silicon_id}/hooks/{hook_id}/secret/rotate",
            post(handlers::rotate_hook_secret),
        )
        .route(
            "/api/v1/silicons/{silicon_id}/events",
            get(handlers::list_events),
        )
        .route(
            "/api/v1/internal/iam/hooks",
            post(handlers::provision_iam_hook),
        )
        .layer(DefaultBodyLimit::max(settings.max_management_body_bytes));

    let ingress = Router::new()
        .route(
            "/silicon/{silicon_id}/{endpoint_key}",
            post(handlers::receive_event),
        )
        .route(
            "/silicon/{silicon_id}/{endpoint_key}/",
            post(handlers::receive_event),
        )
        .route(
            "/api/v1/silicon/{silicon_id}/{endpoint_key}",
            post(handlers::receive_event),
        )
        .route(
            "/api/v1/silicon/{silicon_id}/{endpoint_key}/",
            post(handlers::receive_event),
        )
        .layer(DefaultBodyLimit::max(settings.max_ingress_body_bytes));

    system
        .merge(management)
        .merge(ingress)
        .fallback(handlers::not_found)
        .method_not_allowed_fallback(handlers::method_not_allowed)
        .with_state(state)
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
            header::COOKIE,
            OBO_PROOF_HEADER,
            HOOK_SIGNATURE_HEADER,
        ]))
        .layer(ConcurrencyLimitLayer::new(settings.concurrency_limit))
        .layer(axum_middleware::from_fn_with_state(
            settings.request_timeout,
            middleware::enforce_timeout,
        ))
        .layer(CatchPanicLayer::custom(middleware::handle_panic))
        .layer(axum_middleware::from_fn(middleware::request_scope))
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use axum::body::{Body, to_bytes};
    use http::{Request, StatusCode};
    use secrecy::SecretString;
    use serde_json::Value;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt as _;
    use url::Url;

    use super::router;
    use crate::{
        api::state::ApiState,
        application::{HookApplication, SystemClock},
        config::{IamSettings, LocalAuthSettings, ServerSettings},
        domain::EncryptionKeyId,
        infrastructure::{
            crypto::{
                CursorCodec, SecretCipher, SecretKey, SecretKeyring, WebhookSignatureVerifier,
            },
            iam::IamClient,
            postgres::PostgresStore,
        },
    };

    fn test_router() -> Result<axum::Router, Box<dyn std::error::Error>> {
        let database_url = "postgres://hook:hook@127.0.0.1:9/hook";
        let pool = PgPoolOptions::new().connect_lazy(database_url)?;
        let key_id = EncryptionKeyId::new("1")?;
        let cipher = SecretCipher::new(SecretKeyring::new(
            key_id.clone(),
            [(key_id, SecretKey::from_bytes([7_u8; 32]))],
        )?);
        let application = HookApplication::new(
            PostgresStore::new(pool),
            Arc::new(cipher),
            Arc::new(CursorCodec::new(SecretKey::from_bytes([8_u8; 32]))),
            WebhookSignatureVerifier::new(Duration::from_secs(300)),
            Arc::new(SystemClock),
        );
        let iam = IamClient::new(&IamSettings {
            base_url: Url::parse("http://127.0.0.1:9")?,
            app_id: None,
            app_secret: None,
            audience: "silicon-hook".to_owned(),
            connect_timeout: Duration::from_millis(10),
            request_timeout: Duration::from_millis(10),
            max_response_bytes: 1_024,
            local_auth: Some(LocalAuthSettings {
                iam_service_token: SecretString::from("local-service-token".to_owned()),
            }),
        })?;
        let settings = ServerSettings {
            bind_addr: "127.0.0.1:0".parse()?,
            public_base_url: Url::parse("https://hook.example.test")?,
            request_timeout: Duration::from_secs(1),
            max_ingress_body_bytes: 16,
            max_management_body_bytes: 16,
            concurrency_limit: 8,
        };
        Ok(router(
            ApiState {
                application,
                iam,
                allow_local_credentials: true,
                public_base_url: settings.public_base_url.clone(),
            },
            &settings,
        ))
    }

    #[tokio::test]
    async fn system_routes_return_json_and_a_correlation_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = test_router()?
            .oneshot(Request::get("/healthz").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("x-request-id"));
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(body, serde_json::json!({"status": "ok"}));
        Ok(())
    }

    #[tokio::test]
    async fn routing_errors_use_the_stable_error_envelope() -> Result<(), Box<dyn std::error::Error>>
    {
        for request in [
            Request::get("/does-not-exist").body(Body::empty())?,
            Request::post("/healthz").body(Body::empty())?,
        ] {
            let response = test_router()?.oneshot(request).await?;
            assert!(matches!(
                response.status(),
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ));
            let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
            assert!(body["error"]["code"].is_string());
            assert!(body["error"]["request_id"].is_string());
        }
        Ok(())
    }

    #[tokio::test]
    async fn every_ingress_alias_reaches_the_same_strict_handler()
    -> Result<(), Box<dyn std::error::Error>> {
        for path in [
            "/silicon/cos:tos/ABC123",
            "/silicon/cos:tos/ABC123/",
            "/api/v1/silicon/cos:tos/ABC123",
            "/api/v1/silicon/cos:tos/ABC123/",
        ] {
            let response = test_router()?
                .oneshot(Request::post(path).body(Body::empty())?)
                .await?;
            assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        Ok(())
    }

    #[tokio::test]
    async fn ingress_streams_are_bounded_before_handler_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = test_router()?
            .oneshot(
                Request::post("/silicon/cos:tos/ABC123")
                    .header("content-type", "application/json")
                    .header("x-hook-signature", format!("v1={}", "0".repeat(64)))
                    .header("x-hook-timestamp", "1700000000")
                    .header("idempotency-key", "request-123")
                    .body(Body::from(vec![b'x'; 17]))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(body["error"]["code"], "payload_too_large");
        Ok(())
    }
}
