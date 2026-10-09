//! An in-process Hook API for HTTP tests: a throwaway database reached as the
//! API runtime role (so the real grant manifest is exercised), a stub Silicon
//! Accounts and, when asked, a Ting origin.
#![allow(dead_code, reason = "each test target uses a different subset")]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, Result};
use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
};
use http::{HeaderMap, Method, Request, StatusCode};
use secrecy::SecretString;
use serde_json::Value;
use silicon_hook::{
    api::{ApiDependencies, router},
    application::{HookApplication, SystemClock},
    config::{AccountsSettings, ServerSettings},
    delivery::adapter::TingAdapter,
    domain::EncryptionKeyId,
    infrastructure::{
        accounts::AccountsGateway,
        crypto::{CursorCodec, SecretCipher, SecretKey, SecretKeyring},
        postgres::{PostgresStore, migrate},
        ting::TingClient,
    },
};
use sqlx::PgPool;
use tower::ServiceExt as _;
use url::Url;

use super::{
    accounts::{self, StubAccounts},
    postgres::TestDatabase,
};

/// Public origin of the Hook under test.
pub const PUBLIC_BASE_URL: &str = "https://hook.example.test/";
/// Address every provider request comes from.
pub const PROVIDER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

/// A response: status, headers and JSON body (`Null` when empty).
pub type Reply = (StatusCode, HeaderMap, Value);

/// The running API and everything behind it.
pub struct TestApi {
    /// The complete HTTP router, exactly as `hook-api` serves it.
    pub router: axum::Router,
    /// The stub Silicon Accounts.
    pub accounts: StubAccounts,
    /// The application the router uses (API role).
    pub application: HookApplication,
    /// The schema owner's store, for assertions and fixtures.
    pub owner: PostgresStore,
    database: TestDatabase,
}

impl TestApi {
    /// Starts Hook with delivery through Ting turned off.
    pub async fn start() -> Result<Option<Self>> {
        Self::start_with_ting(None).await
    }

    /// Starts Hook; `ting` is the Ting origin (`HOOK_TING_URL`) or `None`.
    pub async fn start_with_ting(ting: Option<&str>) -> Result<Option<Self>> {
        let Some(database) = TestDatabase::create().await? else {
            return Ok(None);
        };
        let owner = database.connect(4).await?;
        migrate(&owner).await?;
        Self::build(database, owner, ting).await.map(Some)
    }

    async fn build(mut database: TestDatabase, owner: PgPool, ting: Option<&str>) -> Result<Self> {
        let roles = database.runtime_roles().await?;
        let api_pool = TestDatabase::connect_as(&roles.api, 8).await?;
        let accounts = StubAccounts::start().await;
        let gateway = AccountsGateway::new(&AccountsSettings {
            public_url: Url::parse(&accounts.url)?,
            api_url: Url::parse(&accounts.url)?,
            app_id: accounts::APP_ID.to_owned(),
            app_secret: SecretString::from(accounts::APP_SECRET),
            webhook_secrets: vec![SecretString::from(accounts::WEBHOOK_SECRET)],
            request_timeout: Duration::from_secs(5),
        })
        .map_err(|error| anyhow::anyhow!("{error}"))?;
        let key_id = EncryptionKeyId::new("1")?;
        let cipher = SecretCipher::new(SecretKeyring::new(
            key_id.clone(),
            [(key_id, SecretKey::from_bytes([7_u8; 32]))],
        )?);
        let public_base_url = Url::parse(PUBLIC_BASE_URL)?;
        let mut application = HookApplication::new(
            PostgresStore::new(api_pool),
            Arc::new(cipher),
            Arc::new(CursorCodec::new(SecretKey::from_bytes([8_u8; 32]))),
            Arc::new(SystemClock),
            public_base_url.clone(),
            gateway.clone(),
        );
        if let Some(origin) = ting {
            let client = TingClient::new(origin, Duration::from_secs(5))
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            application = application.with_delivery(TingAdapter::new(client, gateway));
        }
        let settings = ServerSettings {
            bind_addr: "127.0.0.1:0".parse()?,
            public_base_url,
            request_timeout: Duration::from_secs(10),
            max_ingress_body_bytes: 64 * 1024,
            max_management_body_bytes: 64 * 1024,
            concurrency_limit: 32,
            trusted_proxy_hops: 0,
        };
        let router = router(
            ApiDependencies {
                application: application.clone(),
                trusted_proxy_hops: 0,
            },
            &settings,
        );
        Ok(Self {
            router,
            accounts,
            application,
            owner: PostgresStore::new(owner),
            database,
        })
    }

    /// The URL of the throwaway database (the schema owner's login).
    #[must_use]
    pub fn database_url(&self) -> &str {
        self.database.url()
    }

    /// Sends one request from [`PROVIDER_IP`].
    pub async fn send(&self, mut request: Request<Body>) -> Result<Reply> {
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(PROVIDER_IP, 40_000)));
        let response = self.router.clone().oneshot(request).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .with_context(|| format!("{status}: {}", String::from_utf8_lossy(&bytes)))?
        };
        Ok((status, headers, body))
    }

    /// A management call with an optional bearer token and JSON body.
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Value)> {
        let mut request = Request::builder().method(method.clone()).uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        if matches!(
            method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) {
            request = request.header("idempotency-key", format!("key-{}", uuid::Uuid::now_v7()));
        }
        let request = match body {
            Some(body) => request
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(body)?))?,
            None => request.body(Body::empty())?,
        };
        let (status, _, body) = self.send(request).await?;
        Ok((status, body))
    }

    /// Delivers a signed Silicon Accounts webhook event.
    pub async fn webhook(&self, event: &Value) -> Result<(StatusCode, Value)> {
        let (timestamp, signature, body) = accounts::webhook(accounts::WEBHOOK_SECRET, event);
        self.raw_webhook(&timestamp, &signature, body).await
    }

    /// Delivers a webhook body with the given headers, unchanged.
    pub async fn raw_webhook(
        &self,
        timestamp: &str,
        signature: &str,
        body: Vec<u8>,
    ) -> Result<(StatusCode, Value)> {
        let request = Request::post("/webhook")
            .header("content-type", "application/json")
            .header("x-accounts-timestamp", timestamp)
            .header("x-accounts-signature", signature)
            .body(Body::from(body))?;
        let (status, _, body) = self.send(request).await?;
        Ok((status, body))
    }

    /// Posts a provider request to an endpoint path such as `/silicon/si:cos/KEY`.
    pub async fn deliver(
        &self,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(StatusCode, Value)> {
        let mut request = Request::post(path);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let (status, _, body) = self.send(request.body(Body::from(body.to_vec()))?).await?;
        Ok((status, body))
    }
}

/// A database migrated only up to an earlier version, to be filled with
/// older data and then upgraded.
pub struct Upgrade {
    database: TestDatabase,
    owner: PgPool,
}

impl Upgrade {
    /// Creates a database and applies migrations up to `version`.
    pub async fn at(version: i64) -> Result<Option<Self>> {
        let Some(database) = TestDatabase::create().await? else {
            return Ok(None);
        };
        let owner = database.connect(4).await?;
        sqlx::migrate!("./migrations")
            .run_to(version, &owner)
            .await?;
        Ok(Some(Self { database, owner }))
    }

    /// The schema owner's pool, for writing the older fixture.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.owner
    }

    /// Applies the remaining migrations and starts Hook on the result.
    pub async fn finish(self, ting: Option<&str>) -> Result<TestApi> {
        migrate(&self.owner).await?;
        TestApi::build(self.database, self.owner, ting).await
    }
}

/// A Silicon Accounts webhook event.
#[must_use]
pub fn event(event_id: &str, event_type: &str, data: &Value) -> Value {
    serde_json::json!({
        "event_id": event_id,
        "type": event_type,
        "occurred_at": time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        "data": data,
    })
}
