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
            get(handlers::list_hooks)
                .post(handlers::create_hook)
                .patch(handlers::set_hooks_enabled),
        )
        .route(
            "/api/v1/silicons/{silicon_id}/hooks/{hook_id}",
            get(handlers::get_hook)
                .patch(handlers::set_hook_enabled)
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
    use testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _};
    use testcontainers_modules::postgres::Postgres;
    use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};
    use tower::ServiceExt as _;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };

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
            postgres::{PostgresStore, migrate},
        },
    };

    const ROUTER_TEST_ORG: &str = "org:routes";
    const ROUTER_TEST_SILICON: &str = "silicon:routes";
    const ROUTER_TEST_APP: &str = "silicon-console";
    const ROUTER_TEST_PROOF: &str = "obo_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const FIRST_HOOK_ID: &str = "018eb4ce-e57a-7d2c-8f9f-a35928ef9101";
    const SECOND_HOOK_ID: &str = "018eb4ce-e57a-7d2c-8f9f-a35928ef9102";

    struct ActivationRouterFixture {
        app: axum::Router,
        store: PostgresStore,
        _postgres: ContainerAsync<Postgres>,
        _iam: MockServer,
    }

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

    async fn activation_router_fixture()
    -> Result<ActivationRouterFixture, Box<dyn std::error::Error>> {
        let postgres = Postgres::default().with_tag("16-alpine").start().await?;
        let host = postgres.get_host().await?;
        let port = postgres.get_host_port_ipv4(5432).await?;
        let database_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect(&database_url)
            .await?;
        migrate(&pool).await?;
        seed_activation_hooks(&pool).await?;

        let iam = MockServer::start().await;
        mount_activation_authorization(&iam, FIRST_HOOK_ID, 1).await?;
        mount_activation_authorization(&iam, ROUTER_TEST_SILICON, 2).await?;

        let key_id = EncryptionKeyId::new("1")?;
        let cipher = SecretCipher::new(SecretKeyring::new(
            key_id.clone(),
            [(key_id, SecretKey::from_bytes([7_u8; 32]))],
        )?);
        let store = PostgresStore::new(pool);
        let application = HookApplication::new(
            store.clone(),
            Arc::new(cipher),
            Arc::new(CursorCodec::new(SecretKey::from_bytes([8_u8; 32]))),
            WebhookSignatureVerifier::new(Duration::from_secs(300)),
            Arc::new(SystemClock),
        );
        let iam_client = IamClient::new(&IamSettings {
            base_url: iam.uri().parse()?,
            app_id: Some("silicon-hook".to_owned()),
            app_secret: Some(SecretString::from("iam-secret")),
            audience: "silicon-hook".to_owned(),
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(2),
            max_response_bytes: 4_096,
            local_auth: None,
        })?;
        let settings = ServerSettings {
            bind_addr: "127.0.0.1:0".parse()?,
            public_base_url: Url::parse("https://hook.example.test")?,
            request_timeout: Duration::from_secs(5),
            max_ingress_body_bytes: 1_024,
            max_management_body_bytes: 8_192,
            concurrency_limit: 8,
        };
        let app = router(
            ApiState {
                application,
                iam: iam_client,
                allow_local_credentials: false,
                public_base_url: settings.public_base_url.clone(),
            },
            &settings,
        );

        Ok(ActivationRouterFixture {
            app,
            store,
            _postgres: postgres,
            _iam: iam,
        })
    }

    async fn seed_activation_hooks(pool: &sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::query(
            r"
            INSERT INTO hook.hooks (
                id, org_id, silicon_id, endpoint_key, name,
                created_by_kind, created_by_id, created_via_app_id, encryption_key_id,
                secret_nonce, encrypted_signing_secret, created_at, updated_at
            ) VALUES
                ($1::uuid, $3, $4, 'A00001', 'First route hook',
                 'carbon', 'route-admin', $5, '1', decode(repeat('11', 12), 'hex'),
                 decode(repeat('22', 48), 'hex'), clock_timestamp(), clock_timestamp()),
                ($2::uuid, $3, $4, 'A00002', 'Second route hook',
                 'carbon', 'route-admin', $5, '1', decode(repeat('33', 12), 'hex'),
                 decode(repeat('44', 48), 'hex'), clock_timestamp(), clock_timestamp())
            ",
        )
        .bind(FIRST_HOOK_ID)
        .bind(SECOND_HOOK_ID)
        .bind(ROUTER_TEST_ORG)
        .bind(ROUTER_TEST_SILICON)
        .bind(ROUTER_TEST_APP)
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn mount_activation_authorization(
        server: &MockServer,
        resource: &str,
        expected_calls: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let expires_at = (OffsetDateTime::now_utc() + TimeDuration::minutes(2)).format(&Rfc3339)?;
        Mock::given(method("POST"))
            .and(path("/api/v1/obo-access/verify"))
            .and(body_json(serde_json::json!({
                "access_proof": ROUTER_TEST_PROOF,
                "audience": "silicon-hook",
                "action": "hook.hooks.enabled.update",
                "resource": resource
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "valid": true,
                "actor": {
                    "actor_type": "carbon",
                    "public_id": "route-admin"
                },
                "org_id": ROUTER_TEST_ORG,
                "organization_role": "admin",
                "capabilities": ["hook.hooks.enabled.update"],
                "visible_silicon_ids": [ROUTER_TEST_SILICON],
                "audience": "silicon-hook",
                "action": "hook.hooks.enabled.update",
                "issuer_app_id": ROUTER_TEST_APP,
                "resource": resource,
                "expires_at": expires_at
            })))
            .expect(expected_calls)
            .mount(server)
            .await;
        Ok(())
    }

    fn activation_request(
        path: &str,
        body: &Value,
    ) -> Result<Request<Body>, Box<dyn std::error::Error>> {
        Ok(Request::patch(path)
            .header("content-type", "application/json")
            .header("x-org-id", ROUTER_TEST_ORG)
            .header("x-app-id", ROUTER_TEST_APP)
            .header("x-iam-obo-access-proof", ROUTER_TEST_PROOF)
            .body(Body::from(serde_json::to_vec(&body)?))?)
    }

    async fn response_json(
        response: axum::response::Response,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        Ok(serde_json::from_slice(
            &to_bytes(response.into_body(), 65_536).await?,
        )?)
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

    #[tokio::test]
    async fn activation_routes_bind_iam_preserve_order_and_reject_atomically()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = activation_router_fixture().await?;

        let single = fixture
            .app
            .clone()
            .oneshot(activation_request(
                &format!("/api/v1/silicons/{ROUTER_TEST_SILICON}/hooks/{FIRST_HOOK_ID}"),
                &serde_json::json!({"enabled": false}),
            )?)
            .await?;
        assert_eq!(single.status(), StatusCode::OK);
        let single_body = response_json(single).await?;
        assert_eq!(single_body["id"], FIRST_HOOK_ID);
        assert_eq!(single_body["status"], "disabled");
        assert!(single_body["disabled_at"].is_string());

        let batch = fixture
            .app
            .clone()
            .oneshot(activation_request(
                &format!("/api/v1/silicons/{ROUTER_TEST_SILICON}/hooks"),
                &serde_json::json!({
                    "hook_ids": [SECOND_HOOK_ID, FIRST_HOOK_ID],
                    "enabled": false
                }),
            )?)
            .await?;
        assert_eq!(batch.status(), StatusCode::OK);
        let batch_body = response_json(batch).await?;
        assert_eq!(batch_body["items"][0]["id"], SECOND_HOOK_ID);
        assert_eq!(batch_body["items"][1]["id"], FIRST_HOOK_ID);
        assert_eq!(batch_body["items"][0]["status"], "disabled");
        assert_eq!(batch_body["items"][1]["status"], "disabled");

        let missing_hook_id = "018eb4ce-e57a-7d2c-8f9f-a35928ef9199";
        let rejected = fixture
            .app
            .clone()
            .oneshot(activation_request(
                &format!("/api/v1/silicons/{ROUTER_TEST_SILICON}/hooks"),
                &serde_json::json!({
                    "hook_ids": [FIRST_HOOK_ID, missing_hook_id],
                    "enabled": true
                }),
            )?)
            .await?;
        assert_eq!(rejected.status(), StatusCode::NOT_FOUND);
        assert_eq!(response_json(rejected).await?["error"]["code"], "not_found");

        let disabled_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM hook.hooks WHERE disabled_at IS NOT NULL",
        )
        .fetch_one(fixture.store.pool())
        .await?;
        let audit_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM hook_private.audit_log WHERE action = 'hook.disabled'",
        )
        .fetch_one(fixture.store.pool())
        .await?;
        assert_eq!(disabled_count, 2);
        assert_eq!(audit_count, 2);
        Ok(())
    }
}
