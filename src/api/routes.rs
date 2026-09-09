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

use super::{environments, handlers, middleware, state::ApiState, ws};
use crate::config::ServerSettings;

const IAM_EVENT_BODY_LIMIT: usize = 1024 * 1024;

pub(super) fn router(state: ApiState, settings: &ServerSettings) -> Router {
    let system = Router::new()
        .route("/healthz", get(handlers::liveness))
        .route("/readyz", get(handlers::readiness))
        .route("/api/version", get(handlers::negotiate_api_version))
        .route("/api/v1/version", get(handlers::version));

    // Sign-in runs before any bearer exists, so it lives outside management.
    let auth = Router::new()
        .route("/api/v1/auth/iam", get(handlers::iam_information))
        .route("/api/v1/auth/status", get(handlers::login_status))
        .route("/api/v1/auth/login", post(handlers::login))
        .route("/api/v1/auth/refresh", post(handlers::refresh_tokens))
        .route("/api/v1/auth/logout", post(handlers::logout))
        .layer(DefaultBodyLimit::max(settings.max_management_body_bytes));

    // IAM signs deliveries over the exact body, which may carry complete
    // directory state; the verifier's own bound is the same one megabyte.
    let iam_events = Router::new()
        .route("/api/v1/iam/events", post(handlers::receive_iam_event))
        .route("/webhook/", post(handlers::receive_iam_event))
        .route("/webhook", post(handlers::receive_iam_event))
        .layer(DefaultBodyLimit::max(IAM_EVENT_BODY_LIMIT));

    let ingress = Router::new()
        .route(
            "/test/silicon/{silicon_id}/{endpoint_key}",
            any(handlers::receive),
        )
        .route(
            "/test/silicon/{silicon_id}/{endpoint_key}/",
            any(handlers::receive),
        )
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

    let testing = Router::new()
        .route(
            "/api/v1/testing-environments",
            get(environments::list).post(environments::create),
        )
        .route(
            "/api/v1/testing-environments/{id}",
            get(environments::get).delete(environments::delete),
        )
        .route(
            "/api/v1/testing-environments/{id}/key",
            get(environments::key),
        )
        .route(
            "/api/v1/testing-environments/{id}/key/rotate",
            post(environments::rotate),
        )
        .route(
            "/api/v1/testing-environments/{id}/restore",
            post(environments::restore),
        )
        .route("/api/v1/testing-environment", get(environments::current))
        .route(
            "/api/v1/testing-environment/clean",
            post(environments::clean),
        )
        .route(
            "/api/v1/testing-environment/iam",
            axum::routing::put(environments::configure_iam),
        )
        .layer(DefaultBodyLimit::max(settings.max_management_body_bytes));

    system
        .merge(testing)
        .merge(management_router(settings))
        .merge(auth)
        .merge(iam_events)
        .merge(ingress)
        .fallback(handlers::not_found)
        .method_not_allowed_fallback(handlers::method_not_allowed)
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            environments::scope,
        ))
        .with_state(state)
        .layer(axum_middleware::from_fn(middleware::enforce_api_version))
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
            header::COOKIE,
            http::HeaderName::from_static("x-hook-test-key"),
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
                environments: None,
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
    async fn login_discovery_and_online_status_do_not_expose_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = test_router().await?;
        let response = app
            .clone()
            .oneshot(Request::get("/api/v1/auth/iam").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()["cache-control"]
                .to_str()?
                .contains("no-store")
        );
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(
            body,
            serde_json::json!({"app_id":null,"iam_url":"http://127.0.0.1:9/",
            "testing":false,"login_method":"short_lived_token"})
        );
        for (token, actor) in [
            ("local:carbon:owner:alice", "carbon"),
            ("local:silicon:member:cos:tos", "silicon"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::get("/api/v1/auth/status")
                        .header("authorization", format!("Bearer {token}"))
                        .header("x-org-id", "tos")
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert!(
                response.headers()["cache-control"]
                    .to_str()?
                    .contains("no-store")
            );
            let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
            assert_eq!(body["authenticated"], true);
            assert_eq!(body["actor"]["type"], actor);
            assert_eq!(body["org_id"], "tos");
            assert!(body.get("access_token").is_none());
        }
        let response = app
            .oneshot(
                Request::get("/api/v1/auth/status")
                    .header("x-org-id", "tos")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        Ok(())
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
    async fn api_version_handshake_pins_the_shared_major() -> Result<(), Box<dyn std::error::Error>>
    {
        let negotiated = test_router()
            .await?
            .oneshot(
                Request::get("/api/version")
                    .header("silicon-hook-supported-api-versions", "v2,v1")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(negotiated.status(), StatusCode::OK);
        assert_eq!(
            negotiated
                .headers()
                .get("silicon-hook-api-version")
                .and_then(|value| value.to_str().ok()),
            Some("v1")
        );
        assert_eq!(
            negotiated
                .headers()
                .get("vary")
                .and_then(|value| value.to_str().ok()),
            Some("Silicon-Hook-Supported-API-Versions")
        );
        let body: Value = serde_json::from_slice(&to_bytes(negotiated.into_body(), 4096).await?)?;
        assert_eq!(body["service"], "silicon-hook");
        assert_eq!(body["selected_api_version"], "v1");
        assert_eq!(body["supported_api_versions"], serde_json::json!(["v1"]));

        let unsupported = test_router()
            .await?
            .oneshot(
                Request::get("/api/version")
                    .header("silicon-hook-supported-api-versions", "v9")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(unsupported.status(), StatusCode::NOT_ACCEPTABLE);

        let mismatched = test_router()
            .await?
            .oneshot(
                Request::get("/api/v1/version")
                    .header("silicon-hook-api-version", "v2")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(mismatched.status(), StatusCode::BAD_REQUEST);
        let body: Value = serde_json::from_slice(&to_bytes(mismatched.into_body(), 4096).await?)?;
        assert_eq!(body["error"]["code"], "api_version_mismatch");

        let pinned = test_router()
            .await?
            .oneshot(
                Request::get("/api/v1/version")
                    .header("silicon-hook-api-version", "v1")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(pinned.status(), StatusCode::OK);
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
