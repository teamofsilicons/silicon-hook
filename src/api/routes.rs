//! Axum route table and cross-cutting request policy.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware as axum_middleware,
    routing::{any, get, post, put},
};
use http::header;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    catch_panic::CatchPanicLayer, sensitive_headers::SetSensitiveRequestHeadersLayer,
};

use super::{accounts, handlers, middleware, state::ApiState};
use crate::{config::ServerSettings, error::AppError};

const WEBHOOK_BODY_LIMIT: usize = 1024 * 1024;
/// Path prefixes that once served provider ingress. Provider URLs are never
/// versioned in responses, but any URL a provider already holds keeps working.
const INGRESS_ALIASES: &[&str] = &["/api/v1", "/api/v2"];

pub(super) fn router(state: ApiState, settings: &ServerSettings) -> Router {
    let system = Router::new()
        .route("/healthz", get(handlers::liveness))
        .route("/readyz", get(handlers::readiness))
        .route("/api/version", get(handlers::negotiate_api_version))
        .route("/api/contracts", get(super::contracts::catalog));
    let webhook = Router::new()
        .route("/webhook/", post(accounts::receive_webhook))
        .route("/webhook", post(accounts::receive_webhook))
        .layer(DefaultBodyLimit::max(WEBHOOK_BODY_LIMIT));
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
    let retired = Router::new()
        .route("/api/v1/{*rest}", any(retired_api_version))
        .route("/api/v2/{*rest}", any(retired_api_version));

    system
        .merge(versioned_router("/api/v3", settings))
        .merge(webhook)
        .merge(ingress)
        .merge(retired)
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

/// API v1 and v2 signed in with Silicon IAM; they end with Hook 1.0.
async fn retired_api_version() -> AppError {
    AppError::refused(
        http::StatusCode::GONE,
        "api_version_sunset",
        "Hook API v1 and v2 used Silicon IAM sign-in and are retired. Use /api/v3 with a Silicon Accounts access token issued to Hook (Authorization: Bearer). See https://docs.hook.teamofsilicons.com/api/.",
    )
}

fn versioned_router(prefix: &str, settings: &ServerSettings) -> Router<ApiState> {
    let route = |suffix: &str| format!("{prefix}{suffix}");
    let system = Router::new()
        .route(&route("/version"), get(handlers::version))
        .route(
            &route("/telemetry"),
            post(super::telemetry_events::ingest).layer(DefaultBodyLimit::max(8192)),
        )
        // Sign-in discovery works before any bearer exists.
        .route(&route("/auth/accounts"), get(accounts::sign_in_information))
        .route(&route("/auth/status"), get(accounts::status));
    system.merge(management_router(prefix, settings))
}

#[allow(
    clippy::too_many_lines,
    reason = "one declarative table of every management route"
)]
fn management_router(prefix: &str, settings: &ServerSettings) -> Router<ApiState> {
    let route = |suffix: &str| format!("{prefix}{suffix}");
    Router::new()
        .route(&route("/delivery"), get(super::delivery::status))
        .route(
            &route("/delivery/recipient"),
            post(super::delivery::register_recipient),
        )
        .route(&route("/silicons"), get(accounts::list_silicons))
        .route(
            &route("/silicons/{silicon_id}/access"),
            get(accounts::access),
        )
        .route(
            &route("/silicons/{silicon_id}/access/{account}"),
            put(accounts::grant).delete(accounts::revoke),
        )
        .route(
            &route("/silicons/{silicon_id}/allow-list"),
            get(accounts::allow_list),
        )
        .route(
            &route("/silicons/{silicon_id}/allow-list/{account}"),
            put(accounts::allow).delete(accounts::disallow),
        )
        .route(
            &route("/silicons/{silicon_id}/hooks"),
            get(handlers::list_hooks)
                .post(handlers::create_hook)
                .patch(handlers::set_hooks_enabled),
        )
        .route(
            &route("/silicons/{silicon_id}/hooks/accounts"),
            post(accounts::connect_accounts_hook),
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
            get(handlers::get_event),
        )
        .route(
            &route("/silicons/{silicon_id}/events/{event_id}/publication"),
            get(super::delivery::publication_status),
        )
        .route(
            &route("/silicons/{silicon_id}/blocked-requests"),
            get(handlers::list_blocked_requests),
        )
        .route(
            &route("/silicons/{silicon_id}/delivery/subscription"),
            get(super::subscriptions::get)
                .post(super::subscriptions::subscribe)
                .delete(super::subscriptions::unsubscribe),
        )
        .layer(DefaultBodyLimit::max(settings.max_management_body_bytes))
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
    use secrecy::SecretString;
    use serde_json::{Value, json};
    use tower::ServiceExt as _;
    use url::Url;

    use super::router;
    use crate::{
        api::state::ApiState,
        application::{HookApplication, SystemClock},
        config::{AccountsSettings, ServerSettings},
        domain::EncryptionKeyId,
        infrastructure::{
            accounts::AccountsGateway,
            crypto::{CursorCodec, SecretCipher, SecretKey, SecretKeyring},
            postgres::PostgresStore,
        },
        test_accounts::{self, StubAccounts},
        test_postgres::TestDatabase,
    };

    struct TestApi {
        router: axum::Router,
        accounts: StubAccounts,
        _database: TestDatabase,
    }

    async fn test_api() -> Result<Option<TestApi>, Box<dyn std::error::Error>> {
        let Some(database) = TestDatabase::create().await? else {
            return Ok(None);
        };
        let pool = database.connect(4).await?;
        crate::infrastructure::postgres::migrate(&pool).await?;
        let accounts = StubAccounts::start().await;
        let gateway = AccountsGateway::new(&AccountsSettings {
            public_url: Url::parse(&accounts.url)?,
            api_url: Url::parse(&accounts.url)?,
            app_id: test_accounts::APP_ID.to_owned(),
            app_secret: SecretString::from(test_accounts::APP_SECRET),
            webhook_secrets: vec![SecretString::from(test_accounts::WEBHOOK_SECRET)],
            request_timeout: Duration::from_secs(5),
        })
        .map_err(|error| error.to_string())?;
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
            gateway,
        );
        let settings = ServerSettings {
            bind_addr: "127.0.0.1:0".parse()?,
            public_base_url,
            request_timeout: Duration::from_secs(5),
            max_ingress_body_bytes: 16,
            max_management_body_bytes: 1024,
            concurrency_limit: 8,
            trusted_proxy_hops: 0,
        };
        Ok(Some(TestApi {
            router: router(
                ApiState {
                    application,
                    trusted_proxy_hops: 0,
                },
                &settings,
            ),
            accounts,
            _database: database,
        }))
    }

    async fn call(
        api: &TestApi,
        request: Request<Body>,
    ) -> Result<(StatusCode, http::HeaderMap, Value), Box<dyn std::error::Error>> {
        let response = api.router.clone().oneshot(request).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 65_536).await?;
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        };
        Ok((status, headers, body))
    }

    fn get(path: &str, token: Option<&str>) -> Result<Request<Body>, http::Error> {
        let mut request = Request::get(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        request.body(Body::empty())
    }

    #[tokio::test]
    async fn sign_in_discovery_is_public_and_status_reports_the_account()
    -> Result<(), Box<dyn std::error::Error>> {
        let Some(api) = test_api().await? else {
            return Ok(());
        };
        let (status, headers, body) = call(&api, get("/api/v3/auth/accounts", None)?).await?;
        assert_eq!(status, StatusCode::OK);
        assert!(headers["cache-control"].to_str()?.contains("no-store"));
        assert_eq!(body["app_id"], "hook");
        assert_eq!(body["accounts_url"], api.accounts.url.as_str());
        assert_eq!(body["delivery"], "disabled");
        assert!(!body.to_string().contains("secret"));

        let token = api.accounts.token("8HV", "silicon", "si:cos");
        let (status, _, body) = call(&api, get("/api/v3/auth/status", Some(&token))?).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            json!({"authenticated": true, "app_id": "hook", "uuid": "8HV", "id": "si:cos", "kind": "silicon"})
        );
        let (status, headers, body) = call(&api, get("/api/v3/auth/status", None)?).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(headers.contains_key("www-authenticate"));
        assert_eq!(body["error"]["code"], "unauthenticated");
        Ok(())
    }

    #[tokio::test]
    async fn tokens_hook_does_not_accept_are_refused_with_the_reason()
    -> Result<(), Box<dyn std::error::Error>> {
        let Some(api) = test_api().await? else {
            return Ok(());
        };
        let now = test_accounts::now();
        let base = json!({"iss": api.accounts.url, "sub": "8HV", "aud": "hook", "exp": now + 600,
            "iat": now, "kind": "silicon", "id": "si:cos"});
        let with = |field: &str, value: Value| {
            let mut claims = base.clone();
            claims[field] = value;
            api.accounts.sign(&claims)
        };
        let other_key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        for (token, code) in [
            (with("aud", json!("briefcase")), "token_wrong_audience"),
            (
                with("iss", json!("https://accounts.example.com")),
                "token_wrong_issuer",
            ),
            (with("exp", json!(now - 3_600)), "token_expired"),
            (
                test_accounts::sign_with(&other_key, "unknown-kid", &base),
                "token_unknown_key",
            ),
            (
                test_accounts::sign_with(&other_key, test_accounts::KEY_ID, &base),
                "token_bad_signature",
            ),
            ("not-a-jwt".to_owned(), "token_malformed"),
        ] {
            let (status, _, body) = call(&api, get("/api/v3/auth/status", Some(&token))?).await?;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{code}: {body}");
            assert_eq!(body["error"]["code"], code, "{body}");
            assert!(
                body["error"]["message"]
                    .as_str()
                    .is_some_and(|message| message.len() > 20)
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn rotated_signing_keys_are_fetched_on_first_sight()
    -> Result<(), Box<dyn std::error::Error>> {
        let Some(api) = test_api().await? else {
            return Ok(());
        };
        let first = api.accounts.token("8HV", "silicon", "si:cos");
        assert_eq!(
            call(&api, get("/api/v3/auth/status", Some(&first))?)
                .await?
                .0,
            StatusCode::OK
        );
        let rotated = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        api.accounts.add_key("rotated", &rotated);
        // Past the refetch floor, so the unknown key id triggers one fetch.
        tokio::time::sleep(crate::infrastructure::accounts::JWKS_REFETCH_INTERVAL).await;
        let now = test_accounts::now();
        let token = test_accounts::sign_with(
            &rotated,
            "rotated",
            &json!({"iss": api.accounts.url, "sub": "8HV", "aud": "hook", "exp": now + 600,
                "iat": now, "kind": "silicon", "id": "si:cos"}),
        );
        // The cached set predates the key; the first unknown kid refetches.
        let (status, _, body) = call(&api, get("/api/v3/auth/status", Some(&token))?).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        Ok(())
    }

    #[tokio::test]
    async fn system_routes_return_json_and_a_correlation_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let Some(api) = test_api().await? else {
            return Ok(());
        };
        let (status, headers, body) = call(&api, get("/healthz", None)?).await?;
        assert_eq!(status, StatusCode::OK);
        assert!(headers.contains_key("x-request-id"));
        assert_eq!(body, json!({"status": "ok"}));
        let (status, _, body) = call(&api, get("/readyz", None)?).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["delivery"]["ting"], "disabled");
        Ok(())
    }

    #[tokio::test]
    async fn api_version_handshake_offers_only_v3_and_retires_v1_v2()
    -> Result<(), Box<dyn std::error::Error>> {
        let Some(api) = test_api().await? else {
            return Ok(());
        };
        let negotiated = Request::get("/api/version")
            .header("silicon-hook-supported-api-versions", "v3,v2")
            .body(Body::empty())?;
        let (status, headers, body) = call(&api, negotiated).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["silicon-hook-api-version"], "v3");
        assert_eq!(body["selected_api_version"], "v3");
        assert_eq!(body["supported_api_versions"], json!(["v3"]));
        let old = Request::get("/api/version")
            .header("silicon-hook-supported-api-versions", "v2,v1")
            .body(Body::empty())?;
        assert_eq!(call(&api, old).await?.0, StatusCode::NOT_ACCEPTABLE);
        for path in [
            "/api/v2/silicons/si:cos/hooks",
            "/api/v1/auth/iam",
            "/api/v2/auth/login",
        ] {
            let (status, _, body) = call(&api, get(path, None)?).await?;
            assert_eq!(status, StatusCode::GONE, "{path}");
            assert_eq!(body["error"]["code"], "api_version_sunset");
            assert!(
                body["error"]["message"]
                    .as_str()
                    .is_some_and(|text| text.contains("/api/v3"))
            );
        }
        let (_, _, contracts) = call(&api, get("/api/contracts", None)?).await?;
        let statuses = contracts["contracts"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .map(|item| (item["api_version"].clone(), item["status"].clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        assert_eq!(
            statuses,
            vec![
                (json!("v3"), json!("active")),
                (json!("v2"), json!("sunset")),
                (json!("v1"), json!("sunset"))
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn routing_errors_use_the_stable_error_envelope() -> Result<(), Box<dyn std::error::Error>>
    {
        let Some(api) = test_api().await? else {
            return Ok(());
        };
        for request in [
            Request::get("/does-not-exist").body(Body::empty())?,
            Request::post("/healthz").body(Body::empty())?,
        ] {
            let (status, _, body) = call(&api, request).await?;
            assert!(matches!(
                status,
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ));
            assert!(body["error"]["code"].is_string());
            assert!(body["error"]["request_id"].is_string());
        }
        Ok(())
    }

    #[tokio::test]
    async fn ingress_bodies_are_bounded_before_handler_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let Some(api) = test_api().await? else {
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
            let (status, _, body) = call(&api, request).await?;
            assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
            assert_eq!(body["error"]["code"], "payload_too_large");
        }
        Ok(())
    }
}
