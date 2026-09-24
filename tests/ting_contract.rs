//! API v2 delivery removal and persisted compatibility lifecycle contracts.

use std::{
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use axum::{
    Router,
    body::{Body, to_bytes},
};
use http::{Request, StatusCode};
use serde_json::{Value, json};
use silicon_hook::{
    api::{ApiDependencies, router},
    application::{HookApplication, SystemClock},
    config::{IamSettings, RealtimeSettings, ServerSettings},
    domain::EncryptionKeyId,
    infrastructure::{
        crypto::{CursorCodec, SecretCipher, SecretKey, SecretKeyring},
        iam::IamClient,
        postgres::{DeliveryWakeups, PostgresStore, migrate},
        ting::TingClient,
    },
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;
use tower::ServiceExt as _;
use url::Url;

struct Fixture {
    router: Router,
    pool: PgPool,
    _container: ContainerAsync<Postgres>,
}

impl Fixture {
    async fn start() -> Result<Self> {
        let container = Postgres::default().with_tag("16-alpine").start().await?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&format!(
                "postgres://postgres:postgres@{}:{}/postgres",
                container.get_host().await?,
                container.get_host_port_ipv4(5432).await?,
            ))
            .await?;
        migrate(&pool).await?;
        let key_id = EncryptionKeyId::new("contract-test-key")?;
        let cipher = SecretCipher::new(SecretKeyring::new(
            key_id.clone(),
            [(key_id, SecretKey::from_bytes([7; 32]))],
        )?);
        let origin = Url::parse("https://hook.contract.test")?;
        let application = HookApplication::new(
            PostgresStore::new(pool.clone()),
            Arc::new(cipher),
            Arc::new(CursorCodec::new(SecretKey::from_bytes([8; 32]))),
            Arc::new(SystemClock),
            origin.clone(),
        );
        let iam = IamClient::connect(&IamSettings {
            base_url: Url::parse("http://127.0.0.1:9")?,
            app_id: None,
            app_secret: None,
            connect_timeout: Duration::from_millis(10),
            request_timeout: Duration::from_millis(10),
            max_response_bytes: 1024,
            allow_insecure_local_http: true,
            local_auth: true,
            webhook: None,
        })
        .await?;
        let settings = ServerSettings {
            bind_addr: "127.0.0.1:0".parse()?,
            public_base_url: origin,
            request_timeout: Duration::from_secs(5),
            max_ingress_body_bytes: 1024 * 1024,
            max_management_body_bytes: 64 * 1024,
            concurrency_limit: 8,
            trusted_proxy_hops: 0,
        };
        let router = router(
            ApiDependencies {
                application,
                environments: None,
                iam,
                ting: TingClient::new("http://127.0.0.1:1", Duration::from_millis(10))?,
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
        );
        Ok(Self {
            router,
            pool,
            _container: container,
        })
    }

    async fn request(
        &self,
        request: Request<Body>,
    ) -> Result<(StatusCode, http::HeaderMap, Value)> {
        let response = self.router.clone().oneshot(request).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await?)?;
        Ok((status, headers, body))
    }

    async fn get(&self, path: &str) -> Result<(StatusCode, http::HeaderMap, Value)> {
        self.request(Request::get(path).body(Body::empty())?).await
    }
}

#[tokio::test]
async fn v2_is_preferred_and_shares_auth_management_and_test_selection() -> Result<()> {
    let fixture = Fixture::start().await?;
    let (status, headers, body) = fixture.get("/api/version").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["silicon-hook-api-version"], "v2");
    assert_eq!(body["selected_api_version"], "v2");
    assert_eq!(body["supported_api_versions"], json!(["v2", "v1"]));
    let (_, _, catalog) = fixture.get("/api/contracts").await?;
    assert_eq!(catalog["contracts"][0]["api_version"], "v2");
    assert_eq!(catalog["contracts"][0]["status"], "active");
    assert_eq!(catalog["contracts"][0]["delivery_transport"], "ting");
    assert_eq!(catalog["contracts"][0]["websocket_protocols"], json!([]));
    assert_eq!(catalog["contracts"][0]["relay_protocols"], json!([]));
    assert_eq!(catalog["contracts"][1]["api_version"], "v1");
    assert_eq!(catalog["contracts"][1]["status"], "deprecated");
    assert_eq!(catalog["policy"]["sunset_after_idle_days"], 7);
    for path in [
        "/api/v2/auth/iam",
        "/api/v2/auth/status",
        "/api/v2/silicons/si:cos/hooks",
    ] {
        let (status, headers, _) = fixture
            .request(
                Request::get(path)
                    .header("authorization", "Bearer local:silicon:member:si:cos")
                    .header("x-org-id", "tos")
                    .header("silicon-hook-api-version", "v2")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(headers["silicon-hook-api-version"], "v2");
        assert!(headers["cache-control"].to_str()?.contains("no-store"));
        assert!(!headers.contains_key("deprecation"));
    }
    let (status, _, body) = fixture
        .request(
            Request::get("/api/v2/auth/iam")
                .header("x-hook-test-app-secret", format!("ask_{}", "A".repeat(43)))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "testing_not_configured");
    let (status, _, _) = fixture
        .request(Request::post("/api/v2/delivery/recipient").body(Body::empty())?)
        .await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "v2 exposes the authenticated Ting route"
    );
    Ok(())
}

#[tokio::test]
async fn v2_refuses_every_legacy_delivery_surface_and_pins_the_requested_major() -> Result<()> {
    let fixture = Fixture::start().await?;
    for suffix in [
        "/silicons/si:cos/deliveries",
        "/silicons/si:cos/deliveries/pull",
        "/silicons/si:cos/deliveries/ack",
        "/silicons/si:cos/deliveries/cursor",
        "/ws",
        "/relay/ws",
    ] {
        let (status, headers, body) = fixture
            .request(
                Request::post(format!("/api/v2{suffix}"))
                    .header("silicon-hook-api-version", "v2")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(status, StatusCode::GONE, "{suffix}");
        assert_eq!(headers["silicon-hook-api-version"], "v2");
        assert_eq!(body["error"]["code"], "delivery_transport_replaced");
    }
    let (status, headers, _) = fixture
        .request(
            Request::get("/api/v1/silicons/si:cos/deliveries")
                .header("authorization", "Bearer local:silicon:member:si:cos")
                .header("x-org-id", "tos")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.contains_key("deprecation"));
    for (path, pin) in [("/api/v2/version", "v1"), ("/api/v1/version", "v2")] {
        let (status, _, body) = fixture
            .request(
                Request::get(path)
                    .header("silicon-hook-api-version", pin)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "api_version_mismatch");
    }
    Ok(())
}

#[tokio::test]
async fn scoped_receiver_is_v2_only_and_rejects_production() -> Result<()> {
    let fixture = Fixture::start().await?;
    let (status, _, body) = fixture.get("/api/v2/delivery/receiver").await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "test_environment_required");
    let (status, _, body) = fixture
        .request(
            Request::post("/api/v2/delivery/receiver")
                .header("authorization", "Bearer local:silicon:member:si:cos")
                .header("x-org-id", "tos")
                .header("content-type", "application/json")
                .header("idempotency-key", "receiver-production-denied")
                .body(Body::from(
                    json!({"environment_id":uuid::Uuid::new_v4(),"generation":1}).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "test_environment_required");
    assert_eq!(
        fixture.get("/api/v1/delivery/receiver").await?.0,
        StatusCode::NOT_FOUND
    );
    Ok(())
}

#[tokio::test]
async fn seven_idle_days_sunset_only_v1_and_discovery_never_revives_it() -> Result<()> {
    let fixture = Fixture::start().await?;
    let _ = fixture.get("/api/version").await?;
    sqlx::query("UPDATE hook_private.contract_versions SET deprecated_at=clock_timestamp()-INTERVAL '8 days', last_requested_at=clock_timestamp()-INTERVAL '6 days' WHERE major='v1'")
        .execute(&fixture.pool).await?;
    let (status, headers, _) = fixture.get("/api/v1/version").await?;
    assert_eq!(status, StatusCode::OK, "recent v1 use postpones sunset");
    assert!(headers.contains_key("deprecation"));
    let before: i64 = sqlx::query_scalar(
        "SELECT request_count FROM hook_private.contract_versions WHERE major='v1'",
    )
    .fetch_one(&fixture.pool)
    .await?;
    sqlx::query("UPDATE hook_private.contract_versions SET last_requested_at=clock_timestamp()-INTERVAL '7 days' WHERE major='v1'")
        .execute(&fixture.pool).await?;
    let (status, _, body) = fixture
        .request(
            Request::get("/api/version")
                .header("silicon-hook-supported-api-versions", "v1")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_ACCEPTABLE);
    assert_eq!(body["error"]["code"], "api_version_unsupported");
    let (status, _, body) = fixture.get("/api/version").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["supported_api_versions"], json!(["v2"]));
    let (status, _, body) = fixture.get("/api/v1/version").await?;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(body["error"]["code"], "api_version_sunset");
    assert_eq!(fixture.get("/api/v2/version").await?.0, StatusCode::OK);
    let v1: (String, i64, bool) = sqlx::query_as("SELECT status,request_count,sunset_at IS NOT NULL FROM hook_private.contract_versions WHERE major='v1'")
        .fetch_one(&fixture.pool).await?;
    assert_eq!(v1, ("sunset".to_owned(), before, true));
    let v2: String =
        sqlx::query_scalar("SELECT status FROM hook_private.contract_versions WHERE major='v2'")
            .fetch_one(&fixture.pool)
            .await?;
    assert_eq!(v2, "active");
    Ok(())
}
