//! Dedicated publisher setup is an org-admin operation with a stable retry key.

use std::sync::{
    Arc,
    atomic::{AtomicU16, Ordering},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use silicon_hook_client::{Client, Error, Mutation, Secret};
use tokio::sync::Mutex;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone, Default)]
struct Fixture {
    calls: Arc<Mutex<Vec<(HeaderMap, Value)>>>,
    status: Arc<AtomicU16>,
}

struct Server {
    client: Client,
    fixture: Fixture,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Server {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let fixture = Fixture::default();
        fixture.status.store(200, Ordering::SeqCst);
        let app = Router::new()
            .route(
                "/api/version",
                get(|| async {
                    Json(json!({"service":"silicon-hook","selected_api_version":"v2"}))
                }),
            )
            .route("/api/v2/delivery/publisher", post(publish))
            .with_state(fixture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let client = Client::new(&format!("http://{}", listener.local_addr()?))?
            .with_token("admin-access")
            .with_organization("tos")
            .with_telemetry(false);
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        Ok(Self {
            client,
            fixture,
            task,
        })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn publish(
    State(fixture): State<Fixture>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    fixture.calls.lock().await.push((headers, body));
    let status = StatusCode::from_u16(fixture.status.load(Ordering::SeqCst)).unwrap();
    if status != StatusCode::OK {
        return (
            status,
            Json(json!({"error":{"code":if status == StatusCode::FORBIDDEN {"forbidden"} else {"publisher_unavailable"},"message":"publisher setup unavailable"}})),
        )
            .into_response();
    }
    Json(
        json!({"org_id":"tos","actor_id":"hook-publisher:tos","expires_at":"2026-09-24T00:00:00Z",
        "access_token":"unexpected-server-secret"}),
    )
    .into_response()
}

#[tokio::test]
async fn provision_retries_same_slt_and_operation_under_admin_authority() -> TestResult {
    let server = Server::start().await?;
    let slt = Secret::new("dedicated-publisher-slt");
    let mutation = Mutation::with_key("publisher-provision-retry")?;
    server.fixture.status.store(503, Ordering::SeqCst);
    assert!(matches!(
        server.client.provision_publisher(&slt, &mutation).await,
        Err(Error::Api { status: 503, .. })
    ));
    server.fixture.status.store(200, Ordering::SeqCst);
    let result = server.client.provision_publisher(&slt, &mutation).await?;
    assert_eq!(
        serde_json::to_value(&result)?,
        json!({"org_id":"tos","actor_id":"hook-publisher:tos","expires_at":"2026-09-24T00:00:00Z"})
    );
    assert!(!format!("{result:?}").contains("unexpected-server-secret"));
    let calls = server.fixture.calls.lock().await;
    assert_eq!(calls.len(), 2);
    for (headers, body) in calls.iter() {
        assert_eq!(headers["authorization"], "Bearer admin-access");
        assert_eq!(headers["x-org-id"], "tos");
        assert_eq!(headers["silicon-hook-api-version"], "v2");
        assert_eq!(headers["idempotency-key"], mutation.key());
        assert_eq!(headers["content-type"], "application/json");
        assert!(!headers.contains_key("x-hook-test-key"));
        assert_eq!(
            body,
            &json!({"slt":"dedicated-publisher-slt","replace_rejected":false})
        );
    }
    Ok(())
}

#[tokio::test]
async fn rejected_family_replacement_is_explicit_and_keeps_test_context() -> TestResult {
    let server = Server::start().await?;
    let secret = format!("ask_{}", "a".repeat(43));
    let client = server
        .client
        .with_test_app_secret(secret.clone())?
        .with_token("test-admin-access")
        .with_organization("tos");
    let slt = Secret::new("test-publisher-slt");
    let mutation = Mutation::with_key("publisher-recovery-test")?;
    client.replace_rejected_publisher(&slt, &mutation).await?;
    let calls = server.fixture.calls.lock().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0["x-hook-test-app-secret"], secret);
    assert_eq!(calls[0].0["authorization"], "Bearer test-admin-access");
    assert_eq!(calls[0].0["x-org-id"], "tos");
    assert_eq!(calls[0].0["idempotency-key"], mutation.key());
    assert_eq!(
        calls[0].1,
        json!({"slt":"test-publisher-slt","replace_rejected":true})
    );
    Ok(())
}

#[tokio::test]
async fn permission_failure_does_not_trigger_replacement_or_retry() -> TestResult {
    let server = Server::start().await?;
    server.fixture.status.store(403, Ordering::SeqCst);
    let error = server
        .client
        .provision_publisher(
            &Secret::new("forbidden-publisher-slt"),
            &Mutation::with_key("publisher-forbidden")?,
        )
        .await
        .expect_err("org authority must be enforced by Hook");
    assert!(matches!(&error, Error::Api { status: 403, code, .. } if code == "forbidden"));
    assert!(!error.to_string().contains("forbidden-publisher-slt"));
    assert_eq!(server.fixture.calls.lock().await.len(), 1);
    Ok(())
}

#[tokio::test]
async fn malformed_slt_is_rejected_without_a_request_or_secret_in_error() -> TestResult {
    let server = Server::start().await?;
    let error = server
        .client
        .provision_publisher(
            &Secret::new("private slt"),
            &Mutation::with_key("publisher-invalid")?,
        )
        .await
        .expect_err("SLTs use visible ASCII without whitespace");
    assert!(matches!(&error, Error::Invalid(_)));
    assert!(!error.to_string().contains("private slt"));
    assert!(server.fixture.calls.lock().await.is_empty());
    Ok(())
}
