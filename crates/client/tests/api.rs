//! The Hook API v3 contract as the client sends it: negotiation, paths, verbs,
//! bodies, headers, and Hook's error envelope.

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use silicon_hook_client::{
    Client, Error, Mutation,
    delivery::PublicationState,
    models::{AccountKind, GrantLevel},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    query: Option<String>,
    authorization: Option<String>,
    idempotency_key: Option<String>,
    pinned: Option<String>,
    body: Value,
}

/// A scripted answer: status, extra headers, body.
type Scripted = (StatusCode, Vec<(String, String)>, Value);

#[derive(Default)]
struct Stub {
    seen: Mutex<Vec<Seen>>,
    responses: Mutex<HashMap<String, Scripted>>,
    version: Mutex<String>,
}

async fn handle(State(stub): State<Arc<Stub>>, request: Request<Body>) -> Response {
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().map(str::to_owned);
    let headers = request.headers().clone();
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let authorization = header("authorization");
    let idempotency_key = header("idempotency-key");
    let pinned = header("silicon-hook-api-version");
    let bytes = to_bytes(request.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if path == "/api/version" {
        let version = stub.version.lock().unwrap().clone();
        return Json(json!({"service": "silicon-hook", "selected_api_version": version}))
            .into_response();
    }
    stub.seen.lock().unwrap().push(Seen {
        method: method.clone(),
        path: path.clone(),
        query,
        authorization,
        idempotency_key,
        pinned,
        body,
    });
    let key = format!("{method} {path}");
    match stub.responses.lock().unwrap().get(&key).cloned() {
        Some((status, headers, body)) => {
            let mut response = (status, Json(body)).into_response();
            for (name, value) in headers {
                response.headers_mut().insert(
                    axum::http::HeaderName::try_from(name).unwrap(),
                    value.parse().unwrap(),
                );
            }
            response
        }
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

struct Fixture {
    base: Client,
    stub: Arc<Stub>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let stub = Arc::new(Stub::default());
        *stub.version.lock().unwrap() = "v3".into();
        let router = Router::new().fallback(handle).with_state(stub.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base =
            Client::new(&format!("http://{}", listener.local_addr()?))?.with_telemetry(false);
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("stub server");
        });
        Ok(Self { base, stub, server })
    }

    fn client(&self) -> Client {
        self.base.with_token("at-silicon")
    }

    fn respond(&self, key: &str, status: StatusCode, body: Value) {
        self.respond_with(key, status, &[], body);
    }

    fn respond_with(&self, key: &str, status: StatusCode, headers: &[(&str, &str)], body: Value) {
        self.stub.responses.lock().unwrap().insert(
            key.into(),
            (
                status,
                headers
                    .iter()
                    .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                    .collect(),
                body,
            ),
        );
    }

    fn take(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.stub.seen.lock().unwrap())
    }
}

fn silicon() -> Value {
    json!({"uuid": "Sx1", "id": "si:cos"})
}

fn hook(id: &str) -> Value {
    json!({
        "id": id, "silicon": silicon(), "name": "GitHub", "description": null,
        "endpoint_url": "https://api.hook.teamofsilicons.com/silicon/si:cos/ABCDEFGH",
        "endpoint_key": "ABCDEFGH", "status": "active",
        "signature": {"required": true, "algorithm": "hmac-sha256", "payload": "request.raw_body",
            "signature": "request.headers[\"x-signature\"]", "signature_encoding": "hex",
            "secret_encoding": "utf8", "public_key": null, "has_secret": true},
        "time_zone": "UTC", "created_by": {"uuid": "Sx1", "kind": "silicon", "id": "si:cos"},
        "created_at": "2026-10-10T00:00:00Z", "disabled_at": null, "deleted_at": null,
        "recoverable_until": null, "last_received_at": null, "last_blocked_at": null,
        "endpoint_rotated_at": null
    })
}

const HOOK_ID: &str = "0198c21a-6330-7000-8000-000000000002";

#[tokio::test]
async fn a_server_that_is_not_api_v3_is_refused_before_any_token_is_sent() -> TestResult {
    let fixture = Fixture::start().await?;
    *fixture.stub.version.lock().unwrap() = "v2".into();
    let error = fixture
        .client()
        .list_hooks("si:cos", false)
        .await
        .expect_err("v2 is retired");
    assert!(matches!(error, Error::Protocol(_)), "{error}");
    assert!(
        fixture.take().is_empty(),
        "nothing but the handshake may be sent"
    );
    Ok(())
}

#[tokio::test]
async fn hooks_and_history_use_the_v3_paths_with_bearer_and_idempotency() -> TestResult {
    let fixture = Fixture::start().await?;
    let client = fixture.client();
    fixture.respond(
        "GET /api/v3/silicons/Sx1/hooks",
        StatusCode::OK,
        json!({"items": [hook(HOOK_ID)]}),
    );
    let hooks = client.list_hooks("Sx1", true).await?;
    assert_eq!(hooks.items[0].silicon.uuid, "Sx1");
    assert_eq!(hooks.items[0].created_by.kind, AccountKind::Silicon);
    fixture.respond(
        &format!("POST /api/v3/silicons/si:cos/hooks/{HOOK_ID}/endpoint/rotate"),
        StatusCode::OK,
        hook(HOOK_ID),
    );
    let key = Mutation::with_key("retry-key-0001")?;
    client
        .rotate_endpoint("si:cos", HOOK_ID.parse()?, &key)
        .await?;
    fixture.respond(
        "PATCH /api/v3/silicons/si:cos/hooks",
        StatusCode::OK,
        json!({"items": [hook(HOOK_ID)]}),
    );
    client
        .set_enabled("si:cos", &[HOOK_ID.parse()?], false, &Mutation::new())
        .await?;
    fixture.respond(
        &format!("GET /api/v3/silicons/si:cos/hooks/{HOOK_ID}/events"),
        StatusCode::OK,
        json!({"items": [], "next_cursor": null}),
    );
    client
        .events("si:cos", Some(HOOK_ID.parse()?), 5, Some("c1"))
        .await?;
    fixture.respond(
        "GET /api/v3/silicons/si:cos/blocked-requests",
        StatusCode::OK,
        json!({"items": [], "next_cursor": "c2"}),
    );
    let page = client.blocked_requests("si:cos", None, 10, None).await?;
    assert_eq!(page.next_cursor.as_deref(), Some("c2"));
    client.delete_hook("si:cos", HOOK_ID.parse()?, &key).await?;
    let seen = fixture.take();
    let summary: Vec<_> = seen
        .iter()
        .map(|s| (s.method.as_str(), s.path.as_str(), s.query.as_deref()))
        .collect();
    assert_eq!(
        summary,
        vec![
            (
                "GET",
                "/api/v3/silicons/Sx1/hooks",
                Some("include_deleted=true")
            ),
            (
                "POST",
                &*format!("/api/v3/silicons/si:cos/hooks/{HOOK_ID}/endpoint/rotate"),
                None
            ),
            ("PATCH", "/api/v3/silicons/si:cos/hooks", None),
            (
                "GET",
                &*format!("/api/v3/silicons/si:cos/hooks/{HOOK_ID}/events"),
                Some("limit=5&cursor=c1")
            ),
            (
                "GET",
                "/api/v3/silicons/si:cos/blocked-requests",
                Some("limit=10")
            ),
            (
                "DELETE",
                &*format!("/api/v3/silicons/si:cos/hooks/{HOOK_ID}"),
                None
            ),
        ]
    );
    for s in &seen {
        assert_eq!(s.authorization.as_deref(), Some("Bearer at-silicon"));
        assert_eq!(s.pinned.as_deref(), Some("v3"));
    }
    assert_eq!(seen[1].idempotency_key.as_deref(), Some("retry-key-0001"));
    assert_eq!(seen[5].idempotency_key.as_deref(), Some("retry-key-0001"));
    assert_eq!(
        seen[2].body,
        json!({"hook_ids": [HOOK_ID], "enabled": false})
    );
    Ok(())
}

#[tokio::test]
async fn access_allow_list_and_accounts_hook_calls() -> TestResult {
    let fixture = Fixture::start().await?;
    let client = fixture.client();
    let account = json!({"uuid": "Cz9", "kind": "carbon", "id": "c:ada"});
    fixture.respond(
        "GET /api/v3/silicons",
        StatusCode::OK,
        json!({"items": [{"silicon": silicon(), "access": "custodian", "custodian": "Cz9"}]}),
    );
    assert_eq!(client.silicons().await?.items[0].access, "custodian");
    fixture.respond(
        "GET /api/v3/silicons/si:cos/access",
        StatusCode::OK,
        json!({"silicon": silicon(), "you": {"account": account, "access": "custodian"},
               "custodian": account, "grants": []}),
    );
    let summary = client.access("si:cos").await?;
    assert_eq!(summary.you.access, "custodian");
    let grant = json!({"account": {"uuid": "Bb2", "kind": "carbon", "id": "c:bob"}, "level": "view",
        "granted_by": account, "created_at": "2026-10-10T00:00:00Z", "updated_at": "2026-10-10T00:00:00Z"});
    fixture.respond(
        "PUT /api/v3/silicons/si:cos/access/c:bob",
        StatusCode::OK,
        json!({"silicon": silicon(), "grant": grant}),
    );
    let granted = client.grant("si:cos", "c:bob", GrantLevel::View).await?;
    assert_eq!(granted.grant.level, GrantLevel::View);
    client.revoke("si:cos", "c:bob").await?;
    client.leave("si:cos").await?;
    assert!(matches!(
        client.revoke("si:cos", "me").await,
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        client.grant("si:cos", " ", GrantLevel::Manage).await,
        Err(Error::Invalid(_))
    ));
    fixture.respond(
        "PUT /api/v3/silicons/si:cos/allow-list/si:friend",
        StatusCode::OK,
        json!({"account": {"uuid": "Ff3", "kind": "silicon", "id": "si:friend"}, "added_by": "Cz9", "created_at": "2026-10-10T00:00:00Z"}),
    );
    assert_eq!(
        client
            .allow("si:cos", "si:friend")
            .await?
            .account
            .id
            .as_deref(),
        Some("si:friend")
    );
    client.disallow("si:cos", "si:friend").await?;
    fixture.respond(
        "POST /api/v3/silicons/si:cos/hooks/accounts",
        StatusCode::OK,
        json!({"hook": hook(HOOK_ID), "next_steps": {"set_webhook": "silicon-accounts webhook set https://x", "store_secret": "PATCH ...", "explanation": "..."}}),
    );
    let connected = client
        .connect_accounts_hook("si:cos", &Mutation::with_key("accounts-hook-1")?)
        .await?;
    assert!(
        connected
            .next_steps
            .set_webhook
            .starts_with("silicon-accounts webhook set")
    );
    let seen = fixture.take();
    let summary: Vec<_> = seen
        .iter()
        .map(|s| format!("{} {}", s.method, s.path))
        .collect();
    assert_eq!(
        summary,
        vec![
            "GET /api/v3/silicons",
            "GET /api/v3/silicons/si:cos/access",
            "PUT /api/v3/silicons/si:cos/access/c:bob",
            "DELETE /api/v3/silicons/si:cos/access/c:bob",
            "DELETE /api/v3/silicons/si:cos/access/me",
            "PUT /api/v3/silicons/si:cos/allow-list/si:friend",
            "DELETE /api/v3/silicons/si:cos/allow-list/si:friend",
            "POST /api/v3/silicons/si:cos/hooks/accounts",
        ]
    );
    assert_eq!(seen[2].body, json!({"level": "view"}));
    assert_eq!(seen[7].idempotency_key.as_deref(), Some("accounts-hook-1"));
    Ok(())
}

#[tokio::test]
async fn sign_in_status_and_delivery_answers() -> TestResult {
    let fixture = Fixture::start().await?;
    // No token: answered locally.
    let status = fixture.base.login_status().await?;
    assert!(!status.authenticated);
    assert!(fixture.take().is_empty());
    fixture.respond(
        "GET /api/v3/auth/status",
        StatusCode::UNAUTHORIZED,
        json!({"error": {"code": "session_ended", "message": "This sign-in ended.", "request_id": "r1"}}),
    );
    let status = fixture.client().login_status().await?;
    assert!(!status.authenticated);
    assert_eq!(status.reason.as_deref(), Some("session_ended"));
    fixture.respond(
        "GET /api/v3/auth/status",
        StatusCode::OK,
        json!({"authenticated": true, "app_id": "hook", "uuid": "Sx1", "id": "si:cos", "kind": "silicon"}),
    );
    let status = fixture.client().login_status().await?;
    assert_eq!(
        (status.authenticated, status.uuid.as_deref(), status.kind),
        (true, Some("Sx1"), Some(AccountKind::Silicon))
    );
    fixture.respond(
        "GET /api/v3/auth/accounts",
        StatusCode::OK,
        json!({"app_id": "hook", "accounts_url": "http://localhost:9590", "token": {}, "sign_in": {}, "delivery": "disabled"}),
    );
    let information = fixture.base.sign_in_information().await?;
    assert_eq!(information.delivery.as_deref(), Some("disabled"));
    fixture.respond(
        "GET /api/v3/delivery",
        StatusCode::OK,
        json!({"enabled": false, "reason": "Delivery through Ting is turned off on this Hook."}),
    );
    assert!(!fixture.client().delivery_status().await?.enabled);
    fixture.respond(
        "GET /api/v3/silicons/si:cos/events/0198c21a-6330-7000-8000-000000000001/publication",
        StatusCode::OK,
        json!({"event_id": "0198c21a-6330-7000-8000-000000000001", "state": "delivery_disabled", "detail": "off"}),
    );
    let publication = fixture
        .client()
        .publication("si:cos", "0198c21a-6330-7000-8000-000000000001".parse()?)
        .await?;
    assert_eq!(publication.state, PublicationState::DeliveryDisabled);
    fixture.respond(
        "POST /api/v3/delivery/recipient",
        StatusCode::CONFLICT,
        json!({"error": {"code": "delivery_disabled", "message": "Delivery through Ting is turned off."}}),
    );
    let error = fixture
        .client()
        .register_recipient()
        .await
        .expect_err("disabled");
    assert!(error.is_code("delivery_disabled"));
    let seen = fixture.take();
    let accounts = seen
        .iter()
        .find(|s| s.path == "/api/v3/auth/accounts")
        .expect("discovery");
    assert_eq!(accounts.authorization, None, "discovery is public");
    Ok(())
}

#[tokio::test]
async fn hook_refusals_keep_code_message_details_hint_request_id_and_retry_after() -> TestResult {
    let fixture = Fixture::start().await?;
    fixture.respond_with(
        "GET /api/v3/silicons/si:cos/hooks",
        StatusCode::TOO_MANY_REQUESTS,
        &[("retry-after", "7")],
        json!({"error": {"code": "rate_limited", "message": "Too many requests.", "details": "slow down", "hint": "wait", "request_id": "req-9"}}),
    );
    let error = fixture
        .client()
        .list_hooks("si:cos", false)
        .await
        .expect_err("429");
    let Error::Api(api) = &error else {
        panic!("{error}")
    };
    assert_eq!(
        (
            api.status,
            api.code.as_str(),
            api.details.as_deref(),
            api.hint.as_deref(),
            api.request_id.as_deref(),
            api.retry_after
        ),
        (
            429,
            "rate_limited",
            Some("slow down"),
            Some("wait"),
            Some("req-9"),
            Some(7)
        )
    );
    assert!(
        error
            .to_string()
            .contains("rate_limited: Too many requests.")
    );
    assert_eq!(error.hint(), Some("wait"));
    fixture.respond(
        "GET /api/v3/silicons/si:cos/hooks",
        StatusCode::UNAUTHORIZED,
        json!({"error": {"code": "token_expired", "message": "expired"}}),
    );
    assert!(
        fixture
            .client()
            .list_hooks("si:cos", false)
            .await
            .expect_err("401")
            .is_unauthenticated()
    );
    Ok(())
}

#[test]
fn urls_must_be_https_or_this_machine() {
    for good in [
        "https://api.hook.teamofsilicons.com",
        "http://127.0.0.1:4201",
        "http://localhost:4201/",
        "http://[::1]:9",
    ] {
        assert!(Client::new(good).is_ok(), "{good}");
    }
    for bad in [
        "http://hook.example.com",
        "https://hook.example.com/api",
        "https://u:p@hook.example.com",
        "ftp://x",
        "not a url",
        "https://x?y=1",
    ] {
        assert!(matches!(Client::new(bad), Err(Error::Invalid(_))), "{bad}");
    }
    assert!(Mutation::with_key("short").is_err());
    assert!(Mutation::with_key("long-enough-key").is_ok());
}
