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
use crate::{config::ServerSettings, error::AppError};

const IAM_EVENT_BODY_LIMIT: usize = 1024 * 1024;

pub(super) fn router(state: ApiState, settings: &ServerSettings) -> Router {
    let system = Router::new()
        .route("/healthz", get(handlers::liveness))
        .route("/readyz", get(handlers::readiness))
        .route("/api/version", get(handlers::negotiate_api_version))
        .route("/api/contracts", get(super::contracts::catalog));
    let iam_events = Router::new()
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
        .layer(DefaultBodyLimit::max(settings.max_ingress_body_bytes));

    system
        .merge(versioned_router("/api/v1", true, settings))
        .merge(versioned_router("/api/v2", false, settings))
        .merge(iam_events)
        .merge(ingress)
        .fallback(handlers::not_found)
        .method_not_allowed_fallback(handlers::method_not_allowed)
        .layer(axum_middleware::from_fn_with_state(state.clone(), environments::scope))
        .merge(Router::new().route(
            "/internal/honeycomb/organizations/{org}/testing-environments/{environment}/operations/{operation}",
            axum::routing::put(super::lifecycle::apply).get(super::lifecycle::status),
        ).layer(DefaultBodyLimit::max(settings.max_management_body_bytes)))
        .with_state(state)
        .layer(axum_middleware::from_fn(middleware::enforce_api_version))
        .layer(SetSensitiveRequestHeadersLayer::new([
            header::AUTHORIZATION,
            header::COOKIE,
            http::HeaderName::from_static("x-hook-test-key"),
            http::HeaderName::from_static("x-hook-test-app-secret"),
        ]))
        .layer(ConcurrencyLimitLayer::new(settings.concurrency_limit))
        .layer(axum_middleware::from_fn_with_state(settings.request_timeout, middleware::enforce_timeout))
        .layer(CatchPanicLayer::custom(middleware::handle_panic))
        .layer(axum_middleware::from_fn(middleware::request_scope))
}

fn versioned_router(
    prefix: &str,
    legacy_delivery: bool,
    settings: &ServerSettings,
) -> Router<ApiState> {
    let route = |suffix: &str| format!("{prefix}{suffix}");
    let system = Router::new()
        .route(&route("/version"), get(handlers::version))
        .route(
            &route("/telemetry"),
            post(super::telemetry_events::ingest).layer(DefaultBodyLimit::max(8192)),
        );
    // Sign-in must work before any bearer exists.
    let auth = Router::new()
        .route(&route("/auth/iam"), get(handlers::iam_information))
        .route(&route("/auth/status"), get(handlers::login_status))
        .route(&route("/auth/login"), post(handlers::login))
        .route(&route("/auth/refresh"), post(handlers::refresh_tokens))
        .route(&route("/auth/logout"), post(handlers::logout))
        .layer(DefaultBodyLimit::max(settings.max_management_body_bytes));
    let iam = Router::new()
        .route(&route("/iam/events"), post(handlers::receive_iam_event))
        .layer(DefaultBodyLimit::max(IAM_EVENT_BODY_LIMIT));
    let ingress = Router::new()
        .route(
            &route("/silicon/{silicon_id}/{endpoint_key}"),
            any(handlers::receive),
        )
        .route(
            &route("/silicon/{silicon_id}/{endpoint_key}/"),
            any(handlers::receive),
        )
        .layer(DefaultBodyLimit::max(settings.max_ingress_body_bytes));
    system
        .merge(auth)
        .merge(iam)
        .merge(ingress)
        .merge(testing_router(prefix, settings))
        .merge(management_router(prefix, legacy_delivery, settings))
}

fn testing_router(prefix: &str, settings: &ServerSettings) -> Router<ApiState> {
    let route = |suffix: &str| format!("{prefix}{suffix}");
    Router::new()
        .route(&route("/contracts"), get(super::contracts::catalog))
        .route(&route("/testing-session"), get(environments::selected))
        .route(
            &route("/testing-environments"),
            get(environments::list).post(environments::create),
        )
        .route(
            &route("/testing-environments/{id}"),
            get(environments::get).delete(environments::delete),
        )
        .route(
            &route("/testing-environments/{id}/key"),
            get(environments::key),
        )
        .route(
            &route("/testing-environments/{id}/key/rotate"),
            post(environments::rotate),
        )
        .route(
            &route("/testing-environments/{id}/restore"),
            post(environments::restore),
        )
        .route(&route("/testing-environment"), get(environments::current))
        .route(
            &route("/testing-environment/clean"),
            post(environments::clean),
        )
        .route(
            &route("/testing-environment/iam"),
            axum::routing::put(environments::configure_iam),
        )
        .layer(DefaultBodyLimit::max(settings.max_management_body_bytes))
}

#[allow(
    clippy::too_many_lines,
    reason = "shared declarative management and transport routes"
)]
fn management_router(
    prefix: &str,
    legacy_delivery: bool,
    settings: &ServerSettings,
) -> Router<ApiState> {
    let route = |suffix: &str| format!("{prefix}{suffix}");
    let management = Router::new()
        .route(
            &route("/delivery/publisher"),
            post(super::delivery::provision_publisher),
        )
        .route(
            &route("/delivery/recipient"),
            post(super::delivery::register_recipient),
        )
        .route(
            &route("/silicons/{silicon_id}/events/{event_id}/publication"),
            get(super::delivery::publication_status),
        )
        .route(
            &route("/silicons/{silicon_id}/hooks"),
            get(handlers::list_hooks)
                .post(handlers::create_hook)
                .patch(handlers::set_hooks_enabled),
        )
        .route(
            &route("/silicons/{silicon_id}/hooks/{hook_id}"),
            get(handlers::get_hook)
                .patch(handlers::update_hook)
                .delete(handlers::delete_hook),
        )
        .route(
            &route("/silicons/{silicon_id}/hooks/{hook_id}/restore"),
            post(handlers::restore_hook),
        )
        .route(
            &route("/silicons/{silicon_id}/hooks/{hook_id}/secret/rotate"),
            post(handlers::rotate_hook_secret),
        )
        .route(
            &route("/silicons/{silicon_id}/hooks/{hook_id}/endpoint/rotate"),
            post(handlers::rotate_hook_endpoint),
        )
        .route(
            &route("/silicons/{silicon_id}/hooks/{hook_id}/events"),
            get(handlers::list_hook_events),
        )
        .route(
            &route("/silicons/{silicon_id}/hooks/{hook_id}/blocked-requests"),
            get(handlers::list_hook_blocked_requests),
        )
        .route(
            &route("/silicons/{silicon_id}/events"),
            get(handlers::list_events),
        )
        .route(
            &route("/silicons/{silicon_id}/events/{event_id}"),
            get(super::delivery::event),
        )
        .route(
            &route("/silicons/{silicon_id}/blocked-requests"),
            get(handlers::list_blocked_requests),
        )
        .route(
            &route("/silicons/{silicon_id}/hooks/iam"),
            post(handlers::connect_iam_hook),
        );
    let management = if legacy_delivery {
        management
            .route(
                &route("/silicons/{silicon_id}/deliveries"),
                get(handlers::pull_deliveries),
            )
            .route(
                &route("/silicons/{silicon_id}/deliveries/ack"),
                post(handlers::acknowledge_deliveries),
            )
            .route(
                &route("/silicons/{silicon_id}/deliveries/cursor"),
                get(handlers::delivery_cursor),
            )
            .route(&route("/ws"), get(ws::upgrade))
            .route(&route("/relay/ws"), get(ws::upgrade_relay))
    } else {
        management
            .route(
                &route("/delivery/receiver"),
                get(super::receivers::get).post(super::receivers::bootstrap),
            )
            .route(
                &route("/silicons/{silicon_id}/delivery/subscription"),
                get(super::subscriptions::get)
                    .post(super::subscriptions::subscribe)
                    .delete(super::subscriptions::unsubscribe),
            )
            .route(
                &route("/silicons/{silicon_id}/deliveries"),
                any(ting_delivery_required),
            )
            .route(
                &route("/silicons/{silicon_id}/deliveries/pull"),
                any(ting_delivery_required),
            )
            .route(
                &route("/silicons/{silicon_id}/deliveries/ack"),
                any(ting_delivery_required),
            )
            .route(
                &route("/silicons/{silicon_id}/deliveries/cursor"),
                any(ting_delivery_required),
            )
            .route(&route("/ws"), any(ting_delivery_required))
            .route(&route("/relay/ws"), any(ting_delivery_required))
    };
    management.layer(DefaultBodyLimit::max(settings.max_management_body_bytes))
}

async fn ting_delivery_required() -> AppError {
    AppError::gone("delivery_transport_replaced")
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
        use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
        let container = testcontainers_modules::postgres::Postgres::default()
            .with_tag("16-alpine")
            .start()
            .await?;
        let database_url = format!(
            "postgres://postgres:postgres@{}:{}/postgres",
            container.get_host().await?,
            container.get_host_port_ipv4(5432).await?
        );
        let pool = PgPoolOptions::new().connect(&database_url).await?;
        crate::infrastructure::postgres::migrate(&pool).await?;
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
        let container = Arc::new(container);
        Ok(router(
            ApiState {
                environments: None,
                ting: crate::infrastructure::ting::TingClient::new(
                    "http://127.0.0.1:1",
                    Duration::from_secs(1),
                )?,
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
        )
        .layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let container = container.clone();
                async move {
                    let response = next.run(request).await;
                    drop(container);
                    response
                }
            },
        )))
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
            Some("v2")
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
        assert_eq!(body["selected_api_version"], "v2");
        assert_eq!(
            body["supported_api_versions"],
            serde_json::json!(["v2", "v1"])
        );

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
