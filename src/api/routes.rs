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

use super::{handlers, middleware, state::ApiState};
use crate::{config::ServerSettings, error::AppError};

const IAM_EVENT_BODY_LIMIT: usize = 1024 * 1024;
/// Path prefixes that once served provider ingress. Provider URLs are never
/// versioned in responses, but any URL a provider already holds keeps working.
const INGRESS_ALIASES: &[&str] = &["/api/v1", "/api/v2"];

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
    let mut ingress = Router::new()
        .route(
            "/silicon/{silicon_id}/{endpoint_key}",
            any(handlers::receive),
        )
        .route(
            "/silicon/{silicon_id}/{endpoint_key}/",
            any(handlers::receive),
        );
    for prefix in INGRESS_ALIASES {
        ingress = ingress
            .route(
                &format!("{prefix}/silicon/{{silicon_id}}/{{endpoint_key}}"),
                any(handlers::receive),
            )
            .route(
                &format!("{prefix}/silicon/{{silicon_id}}/{{endpoint_key}}/"),
                any(handlers::receive),
            );
    }
    let ingress = ingress.layer(DefaultBodyLimit::max(settings.max_ingress_body_bytes));

    system
        .merge(versioned_router("/api/v2", settings))
        .merge(iam_events)
        .merge(ingress)
        .fallback(handlers::not_found)
        .method_not_allowed_fallback(handlers::method_not_allowed)
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            super::scope::scope,
        ))
        .with_state(state)
        .layer(axum_middleware::from_fn(middleware::enforce_api_version))
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

fn versioned_router(prefix: &str, settings: &ServerSettings) -> Router<ApiState> {
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
    system
        .merge(auth)
        .merge(iam)
        .merge(management_router(prefix, settings))
}

#[allow(
    clippy::too_many_lines,
    reason = "shared declarative management and transport routes"
)]
fn management_router(prefix: &str, settings: &ServerSettings) -> Router<ApiState> {
    let route = |suffix: &str| format!("{prefix}{suffix}");
    let management = Router::new()
        .route(
            &route("/delivery/publisher"),
            post(super::delivery::provision_publisher),
        )
        .route(
            &route("/delivery/authorization"),
            get(super::delivery::ting_authorization_status)
                .post(super::delivery::start_ting_authorization),
        )
        .route(
            &route("/delivery/authorization/complete"),
            post(super::delivery::complete_ting_authorization),
        )
        .route(
            &route("/delivery/authorization/disconnect"),
            post(super::delivery::disconnect_ting_authorization),
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
    let management = management
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
        .route(&route("/relay/ws"), any(ting_delivery_required));
    management.layer(DefaultBodyLimit::max(settings.max_management_body_bytes))
}

async fn ting_delivery_required() -> AppError {
    AppError::gone("delivery_transport_replaced")
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use axum::{
        body::{Body, to_bytes},
        extract::ConnectInfo,
    };
    use http::{Request, StatusCode};
    use serde_json::Value;
    use tower::ServiceExt as _;
    use url::Url;

    use super::router;
    use crate::{
        api::state::ApiState,
        application::{HookApplication, SystemClock},
        config::{IamSettings, ServerSettings},
        domain::EncryptionKeyId,
        infrastructure::{
            crypto::{CursorCodec, SecretCipher, SecretKey, SecretKeyring},
            iam::IamClient,
            postgres::PostgresStore,
        },
        test_postgres::TestDatabase,
    };

    async fn test_router()
    -> Result<Option<(axum::Router, TestDatabase)>, Box<dyn std::error::Error>> {
        let Some(database) = TestDatabase::create().await? else {
            return Ok(None);
        };
        let pool = database.connect(4).await?;
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
        Ok(Some((
            router(
                ApiState {
                    ting: crate::infrastructure::ting::TingClient::new(
                        "http://127.0.0.1:1",
                        Duration::from_secs(1),
                    )?,
                    application,
                    iam,
                    trusted_proxy_hops: 0,
                },
                &settings,
            ),
            database,
        )))
    }

    #[tokio::test]
    async fn login_discovery_and_online_status_do_not_expose_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let Some((app, _database)) = test_router().await? else {
            return Ok(());
        };
        let response = app
            .clone()
            .oneshot(Request::get("/api/v2/auth/iam").body(Body::empty())?)
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
            ("local:silicon:member:si:cos", "silicon"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::get("/api/v2/auth/status")
                        .header("authorization", format!("Bearer {token}"))
                        .header("x-org-id", "tos")
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
            assert_eq!(body["authenticated"], true);
            assert_eq!(body["actor"]["type"], actor);
            assert!(body.get("access_token").is_none());
        }
        let response = app
            .oneshot(
                Request::get("/api/v2/auth/status")
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
        let Some((app, _database)) = test_router().await? else {
            return Ok(());
        };
        let response = app
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
        let Some((app, _database)) = test_router().await? else {
            return Ok(());
        };
        let negotiated = app
            .clone()
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
        let body: Value = serde_json::from_slice(&to_bytes(negotiated.into_body(), 4096).await?)?;
        assert_eq!(body["service"], "silicon-hook");
        assert_eq!(body["selected_api_version"], "v2");
        assert_eq!(body["supported_api_versions"], serde_json::json!(["v2"]));

        let unsupported = app
            .clone()
            .oneshot(
                Request::get("/api/version")
                    .header("silicon-hook-supported-api-versions", "v1")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(unsupported.status(), StatusCode::NOT_ACCEPTABLE);

        let mismatched = app
            .oneshot(
                Request::get("/api/v2/version")
                    .header("silicon-hook-api-version", "v1")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(mismatched.status(), StatusCode::BAD_REQUEST);
        let body: Value = serde_json::from_slice(&to_bytes(mismatched.into_body(), 4096).await?)?;
        assert_eq!(body["error"]["code"], "api_version_mismatch");
        Ok(())
    }

    #[tokio::test]
    async fn routing_errors_use_the_stable_error_envelope() -> Result<(), Box<dyn std::error::Error>>
    {
        let Some((app, _database)) = test_router().await? else {
            return Ok(());
        };
        for request in [
            Request::get("/does-not-exist").body(Body::empty())?,
            Request::post("/healthz").body(Body::empty())?,
            Request::get("/api/v1/version").body(Body::empty())?,
        ] {
            let response = app.clone().oneshot(request).await?;
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
        let Some((app, _database)) = test_router().await? else {
            return Ok(());
        };
        for path in ["/silicon/si:cos/ABC123", "/api/v1/silicon/si:cos/ABC123"] {
            let mut request = Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from(vec![b'x'; 17]))?;
            request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                5000,
            )));
            let response = app.clone().oneshot(request).await?;
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
            assert_eq!(body["error"]["code"], "payload_too_large");
        }
        Ok(())
    }
}
