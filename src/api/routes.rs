//! Axum route table and cross-cutting request policy.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware as axum_middleware,
    routing::{any, get, post},
};
use http::header;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    catch_panic::CatchPanicLayer, sensitive_headers::SetSensitiveRequestHeadersLayer,
};

use super::{handlers, middleware, state::ApiState, ws};
use crate::config::ServerSettings;

const IAM_EVENT_BODY_LIMIT: usize = 1024 * 1024;

pub(super) fn router(state: ApiState, settings: &ServerSettings) -> Router {
    let system = Router::new()
        .route("/healthz", get(handlers::liveness))
        .route("/readyz", get(handlers::readiness))
        .route("/api/v1/version", get(handlers::version));

    // Sign-in runs before any bearer exists, so it lives outside management.
    let auth = Router::new()
        .route("/api/v1/auth/login", post(handlers::login_begin))
        .route("/api/v1/auth/callback", post(handlers::login_callback))
        .route("/api/v1/auth/refresh", post(handlers::refresh_tokens))
        .route("/api/v1/auth/logout", post(handlers::logout))
        .layer(DefaultBodyLimit::max(settings.max_management_body_bytes));

    // IAM signs deliveries over the exact body, which may carry complete
    // directory state; the verifier's own bound is the same one megabyte.
    let iam_events = Router::new()
        .route("/api/v1/iam/events", post(handlers::receive_iam_event))
        .layer(DefaultBodyLimit::max(IAM_EVENT_BODY_LIMIT));

    let ingress = Router::new()
        .route(
            "/silicon/{silicon_id}/{endpoint_key}",
            any(handlers::receive),
        )
        .route(
            "/silicon/{silicon_id}/{endpoint_key}/",
            any(handlers::receive),
        )
        .route(
            "/api/v1/silicon/{silicon_id}/{endpoint_key}",
            any(handlers::receive),
        )
        .route(
            "/api/v1/silicon/{silicon_id}/{endpoint_key}/",
            any(handlers::receive),
        )
        .layer(DefaultBodyLimit::max(settings.max_ingress_body_bytes));

    system
        .merge(management_router(settings))
        .merge(auth)
        .merge(iam_events)
        .merge(ingress)
        .fallback(handlers::not_found)
        .method_not_allowed_fallback(handlers::method_not_allowed)
        .with_state(state)
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
            header::COOKIE,
        ]))
        .layer(ConcurrencyLimitLayer::new(settings.concurrency_limit))
        .layer(axum_middleware::from_fn_with_state(
            settings.request_timeout,
            middleware::enforce_timeout,
        ))
        .layer(CatchPanicLayer::custom(middleware::handle_panic))
        .layer(axum_middleware::from_fn(middleware::request_scope))
}

fn management_router(settings: &ServerSettings) -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/silicons/{silicon_id}/hooks",
            get(handlers::list_hooks)
                .post(handlers::create_hook)
                .patch(handlers::set_hooks_enabled),
        )
        .route(
            "/api/v1/silicons/{silicon_id}/hooks/{hook_id}",
            get(handlers::get_hook)
                .patch(handlers::update_hook)
                .delete(handlers::delete_hook),
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
            "/api/v1/silicons/{silicon_id}/hooks/{hook_id}/endpoint/rotate",
            post(handlers::rotate_hook_endpoint),
        )
        .route(
            "/api/v1/silicons/{silicon_id}/hooks/{hook_id}/events",
            get(handlers::list_hook_events),
        )
        .route(
            "/api/v1/silicons/{silicon_id}/hooks/{hook_id}/blocked-requests",
            get(handlers::list_hook_blocked_requests),
        )
        .route(
            "/api/v1/silicons/{silicon_id}/events",
            get(handlers::list_events),
        )
        .route(
            "/api/v1/silicons/{silicon_id}/blocked-requests",
            get(handlers::list_blocked_requests),
        )
        .route(
            "/api/v1/silicons/{silicon_id}/deliveries",
            get(handlers::pull_deliveries),
        )
        .route(
            "/api/v1/silicons/{silicon_id}/deliveries/ack",
            post(handlers::acknowledge_deliveries),
        )
        .route(
            "/api/v1/silicons/{silicon_id}/deliveries/cursor",
            get(handlers::delivery_cursor),
        )
        .route(
            "/api/v1/silicons/{silicon_id}/hooks/iam",
            post(handlers::connect_iam_hook),
        )
        .route("/api/v1/ws", get(ws::upgrade))
        .layer(DefaultBodyLimit::max(settings.max_management_body_bytes))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        num::{NonZeroU32, NonZeroUsize},
        sync::Arc,
        time::Duration,
    };

    use axum::{
        body::{Body, to_bytes},
        extract::ConnectInfo,
    };
    use http::{Request, StatusCode};
    use serde_json::Value;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt as _;
    use url::Url;

    use super::router;
    use crate::{
        api::state::ApiState,
        application::{HookApplication, SystemClock},
        config::{IamSettings, RealtimeSettings, ServerSettings},
        domain::EncryptionKeyId,
        infrastructure::{
            crypto::{CursorCodec, SecretCipher, SecretKey, SecretKeyring},
            iam::IamClient,
            postgres::{DeliveryWakeups, PostgresStore},
        },
    };

    async fn test_router() -> Result<axum::Router, Box<dyn std::error::Error>> {
        let database_url = "postgres://hook:hook@127.0.0.1:9/hook";
        let pool = PgPoolOptions::new().connect_lazy(database_url)?;
        let key_id = EncryptionKeyId::new("1")?;
        let cipher = SecretCipher::new(SecretKeyring::new(
            key_id.clone(),
            [(key_id, SecretKey::from_bytes([7_u8; 32]))],
        )?);
        let public_base_url = Url::parse("https://hook.example.test")?;
        let application = HookApplication::new(
            PostgresStore::new(pool),
            Arc::new(cipher),
            Arc::new(CursorCodec::new(SecretKey::from_bytes([8_u8; 32]))),
            Arc::new(SystemClock),
            public_base_url.clone(),
        );
        let iam = IamClient::connect(&IamSettings {
            base_url: Url::parse("http://127.0.0.1:9")?,
            app_id: None,
            app_secret: None,
            connect_timeout: Duration::from_millis(10),
            request_timeout: Duration::from_millis(10),
            max_response_bytes: 1_024,
            allow_insecure_local_http: true,
            local_auth: true,
            login: None,
            webhook: None,
        })
        .await?;
        let settings = ServerSettings {
            bind_addr: "127.0.0.1:0".parse()?,
            public_base_url: public_base_url.clone(),
            request_timeout: Duration::from_secs(1),
            max_ingress_body_bytes: 16,
            max_management_body_bytes: 16,
            concurrency_limit: 8,
            trusted_proxy_hops: 0,
        };
        Ok(router(
            ApiState {
                application,
                iam,
                trusted_proxy_hops: 0,
                realtime: RealtimeSettings {
                    heartbeat_interval: Duration::from_secs(30),
                    heartbeat_timeout: Duration::from_secs(120),
                    replay_batch_size: NonZeroU32::MIN,
                    poll_interval: Duration::from_secs(1),
                    max_silicons_per_connection: NonZeroUsize::MIN,
                },
                wakeups: DeliveryWakeups::new(),
            },
            &settings,
        ))
    }

    #[tokio::test]
    async fn system_routes_return_json_and_a_correlation_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = test_router()
            .await?
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
            let response = test_router().await?.oneshot(request).await?;
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
    async fn ingress_bodies_are_bounded_before_handler_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut request = Request::post("/silicon/cos:tos/ABC123")
            .header("content-type", "application/json")
            .body(Body::from(vec![b'x'; 17]))?;
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            5000,
        )));
        let response = test_router().await?.oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(body["error"]["code"], "payload_too_large");
        Ok(())
    }

    #[tokio::test]
    async fn websocket_route_rejects_non_upgrade_and_unauthenticated_requests()
    -> Result<(), Box<dyn std::error::Error>> {
        // Without a real connection the upgrade extractor refuses first; the
        // credential and Silicon checks are covered end to end over a listener.
        let plain = test_router()
            .await?
            .oneshot(Request::get("/api/v1/ws?silicon_id=cos:tos").body(Body::empty())?)
            .await?;
        assert!(plain.status().is_client_error());
        let body: Value = serde_json::from_slice(&to_bytes(plain.into_body(), 4096).await?)?;
        assert!(body["error"]["code"].is_string());
        Ok(())
    }
}
