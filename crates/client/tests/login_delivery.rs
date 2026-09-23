//! Stateless authentication and v2 management must not start receiving work.

use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use serde_json::{Value, json};
use silicon_hook_client::{Client, Error, Mutation};
use tokio::sync::Mutex;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone, Default)]
struct Fixture {
    calls: Arc<Mutex<Vec<Call>>>,
    version: Arc<AtomicU8>,
}

struct Call {
    path: String,
    headers: HeaderMap,
    body: Value,
}

struct Server {
    url: String,
    fixture: Fixture,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Server {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let fixture = Fixture::default();
        fixture.version.store(2, Ordering::SeqCst);
        let app = Router::new()
            .route("/{*path}", any(handle))
            .with_state(fixture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(Self { url, fixture, task })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn tokens(refreshed: bool) -> Value {
    json!({"access_token":if refreshed {"oat_rotated"} else {"oat_test"},
        "refresh_token":if refreshed {"ort_rotated"} else {"ort_test"},
        "token_type":"Bearer","expires_in":1,"scopes":[],
        "actor":{"type":"silicon","id":"cos:tos"},"org_id":"tos"})
}

async fn handle(State(fixture): State<Fixture>, request: Request<Body>) -> Response {
    let path = request.uri().path().to_owned();
    let headers = request.headers().clone();
    let bytes = to_bytes(request.into_body(), 65_536)
        .await
        .expect("fixture body bound");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("fixture JSON")
    };
    fixture.calls.lock().await.push(Call {
        path: path.clone(),
        headers: headers.clone(),
        body,
    });
    match path.as_str() {
        "/api/version" => {
            assert_eq!(headers["silicon-hook-supported-api-versions"], "v2");
            assert!(!headers.contains_key("authorization"));
            let version = fixture.version.load(Ordering::SeqCst);
            Json(json!({"service":if version == 3 {"another-service"} else {"silicon-hook"},
                "selected_api_version":if version == 1 {"v1"} else {"v2"}})).into_response()
        }
        "/api/v2/auth/login" => Json(tokens(false)).into_response(),
        "/api/v2/auth/refresh" => Json(tokens(true)).into_response(),
        "/api/v2/auth/logout" => StatusCode::NO_CONTENT.into_response(),
        "/api/v2/auth/status" if headers.get("authorization").is_some_and(|value| value == "Bearer revoked") => {
            (StatusCode::UNAUTHORIZED, Json(json!({"error":{"code":"unauthenticated","message":"revoked"}}))).into_response()
        }
        "/api/v2/auth/status" => Json(json!({"authenticated":true,"actor":{"type":"silicon","id":"cos:tos"},"org_id":"tos"})).into_response(),
        "/api/v2/auth/iam" => Json(json!({"app_id":"tos>hook","iam_url":"https://iam.example.test",
            "testing":headers.contains_key("x-hook-test-key") || headers.contains_key("x-hook-test-app-secret"),
            "login_method":"short_lived_token"})).into_response(),
        "/api/v2/silicons/cos:tos/hooks" => Json(json!({"items":[]})).into_response(),
        _ => (StatusCode::NOT_FOUND, Json(json!({"error":{"code":"unexpected_request","message":"fixture rejected path"}}))).into_response(),
    }
}

#[tokio::test]
async fn login_and_refresh_return_tokens_without_delivery_or_background_requests() -> TestResult {
    let server = Server::start().await?;
    let base = Client::new(&server.url)?.with_telemetry(false);
    assert!(!base.login_status().await?.authenticated);
    assert!(server.fixture.calls.lock().await.is_empty());
    let login = Mutation::with_key("login-fixture-operation")?;
    let tokens = base.login("opaque-slt", &login).await?;
    assert_eq!(tokens.access_token.expose(), "oat_test");
    assert!(!format!("{tokens:?}").contains("oat_test"));
    assert!(
        !base.login_status().await?.authenticated,
        "login does not mutate its client"
    );
    let client = base
        .with_token(tokens.access_token.expose())
        .with_organization("tos");
    assert!(client.login_status().await?.authenticated);
    assert!(client.list_hooks("cos:tos", false).await?.items.is_empty());
    // A near-expiry token starts no automatic refresh, relay, subscription,
    // listener registration, downstream callback, or telemetry request.
    tokio::task::yield_now().await;
    let recorded = server.fixture.calls.lock().await;
    assert_eq!(
        recorded
            .iter()
            .map(|call| call.path.as_str())
            .collect::<Vec<_>>(),
        [
            "/api/version",
            "/api/v2/auth/login",
            "/api/v2/auth/status",
            "/api/v2/silicons/cos:tos/hooks"
        ]
    );
    assert_eq!(recorded[1].body, json!({"slt":"opaque-slt"}));
    assert_eq!(recorded[1].headers["idempotency-key"], login.key());
    assert!(!recorded[1].headers.contains_key("authorization"));
    for call in &recorded[1..] {
        assert_eq!(call.headers["silicon-hook-api-version"], "v2");
        assert_eq!(call.headers["x-hook-telemetry"], "off");
    }
    assert_eq!(recorded[3].headers["authorization"], "Bearer oat_test");
    drop(recorded);
    let refresh = Mutation::with_key("refresh-fixture-operation")?;
    let rotated = client
        .refresh(tokens.refresh_token.expose(), &refresh)
        .await?;
    assert_eq!(rotated.access_token.expose(), "oat_rotated");
    assert_eq!(rotated.refresh_token.expose(), "ort_rotated");
    let latest = base
        .with_token(rotated.access_token.expose())
        .with_organization("tos");
    assert!(latest.login_status().await?.authenticated);
    latest
        .with_token(rotated.refresh_token.expose())
        .logout(&Mutation::new())
        .await?;
    let recorded = server.fixture.calls.lock().await;
    assert_eq!(recorded[4].body, json!({"refresh_token":"ort_test"}));
    assert_eq!(recorded[4].headers["idempotency-key"], refresh.key());
    assert_eq!(recorded[5].headers["authorization"], "Bearer oat_rotated");
    assert_eq!(recorded[6].headers["authorization"], "Bearer ort_rotated");
    assert_eq!(recorded.len(), 7);
    Ok(())
}

#[tokio::test]
async fn negotiation_rejects_old_or_wrong_service_before_consuming_slt_and_can_retry() -> TestResult
{
    let server = Server::start().await?;
    let client = Client::new(&server.url)?;
    let mutation = Mutation::new();
    for version in [1, 3] {
        server.fixture.version.store(version, Ordering::SeqCst);
        assert!(matches!(
            client.login("not-yet-consumed", &mutation).await,
            Err(Error::Protocol(_))
        ));
    }
    assert!(
        server
            .fixture
            .calls
            .lock()
            .await
            .iter()
            .all(|call| call.path == "/api/version")
    );
    server.fixture.version.store(2, Ordering::SeqCst);
    let token = client.authenticate("not-yet-consumed", &mutation).await?;
    assert_eq!(token.access_token.expose(), "oat_test");
    let calls = server.fixture.calls.lock().await;
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[3].body, json!({"slt":"not-yet-consumed"}));
    assert_eq!(calls[3].headers["idempotency-key"], mutation.key());
    Ok(())
}

#[tokio::test]
async fn immutable_identity_and_test_selection_share_only_version_negotiation() -> TestResult {
    let server = Server::start().await?;
    let base = Client::new(&server.url)?
        .with_token("original-token")
        .with_organization("tos");
    let root = base.with_test_key("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")?;
    let secret = format!("ask_{}", "A".repeat(43));
    let selected = root.with_test_app_secret(&secret)?;
    assert!(!selected.login_status().await?.authenticated);
    let (production_iam, root_iam, selected_iam) =
        tokio::join!(base.iam(), root.iam(), selected.iam());
    assert!(!production_iam?.testing);
    assert!(root_iam?.testing);
    assert!(selected_iam?.testing);
    assert!(
        !base
            .without_test_environment()
            .login_status()
            .await?
            .authenticated
    );
    let calls = server.fixture.calls.lock().await;
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.path == "/api/version")
            .count(),
        1
    );
    let app_secret = calls
        .iter()
        .find(|call| call.headers.contains_key("x-hook-test-app-secret"))
        .ok_or("selected request")?;
    assert_eq!(app_secret.headers["x-hook-test-app-secret"], secret);
    assert!(!app_secret.headers.contains_key("x-hook-test-key"));
    assert!(!app_secret.headers.contains_key("authorization"));
    assert!(!app_secret.headers.contains_key("x-org-id"));
    let root = calls
        .iter()
        .find(|call| call.headers.contains_key("x-hook-test-key"))
        .ok_or("root request")?;
    assert_eq!(root.headers["authorization"], "Bearer original-token");
    assert_eq!(root.headers["x-org-id"], "tos");
    Ok(())
}

#[tokio::test]
async fn revoked_status_and_invalid_identifiers_do_not_start_receiving_or_retry() -> TestResult {
    let server = Server::start().await?;
    let client = Client::new(&server.url)?
        .with_token("revoked")
        .with_organization("tos");
    assert!(!client.login_status().await?.authenticated);
    assert!(matches!(
        client.list_hooks("../cos:tos", false).await,
        Err(Error::Invalid(_))
    ));
    assert_eq!(
        server
            .fixture
            .calls
            .lock()
            .await
            .iter()
            .map(|call| call.path.as_str())
            .collect::<Vec<_>>(),
        ["/api/version", "/api/v2/auth/status"]
    );
    Ok(())
}
