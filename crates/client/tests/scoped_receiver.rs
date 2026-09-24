//! Scoped receiver acquisition never creates a general Ting session or ACK.

use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use silicon_hook_client::{
    Client, Error, Mutation,
    delivery::{DeliveryMode, PublicationStatus, ReceiverScope, RecipientRegistration},
};
use std::sync::{
    Arc,
    atomic::{AtomicU16, Ordering},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Mutex;
use uuid::Uuid;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type CapturedRequest = (String, HeaderMap, Vec<u8>);
const ENV: &str = "0198c21a-6330-7000-8000-000000000001";
const ORG: &str = "0198c21a-6330-7000-8000-000000000002";

fn scope_json() -> Value {
    json!({"app_id":"hook","for":"si:worker","kind":"silicon","org_id":ORG,"hook_org_id":"tos",
        "environment":{"kind":"testing","id":ENV,"generation":7}})
}

fn capability(expiry: OffsetDateTime) -> Value {
    let mut value = scope_json();
    value["receiver_id"] = json!("recv_fixture");
    value["receiver_token"] = json!(format!("ting_recv_{}", "a".repeat(64)));
    value["expires_at"] = json!(expiry.format(&Rfc3339).unwrap());
    value
}

#[derive(Clone)]
struct Fixture {
    calls: Arc<Mutex<Vec<CapturedRequest>>>,
    scope: Arc<Mutex<Value>>,
    response: Arc<Mutex<Value>>,
    status: Arc<AtomicU16>,
}

struct Server {
    client: Client,
    fixture: Fixture,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Server {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let fixture = Fixture {
            calls: Arc::default(),
            scope: Arc::new(Mutex::new(scope_json())),
            response: Arc::new(Mutex::new(capability(
                OffsetDateTime::now_utc() + time::Duration::seconds(20),
            ))),
            status: Arc::new(AtomicU16::new(200)),
        };
        let app = Router::new().fallback(handle).with_state(fixture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let client = Client::new(&format!("http://{}", listener.local_addr()?))?
            .with_test_app_secret(format!("ask_{}", "a".repeat(43)))?
            .with_token("test-actor-access")
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

async fn handle(State(fixture): State<Fixture>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, 65536).await.unwrap();
    let path = parts.uri.path();
    fixture.calls.lock().await.push((
        format!("{} {path}", parts.method),
        parts.headers,
        bytes.to_vec(),
    ));
    let response = match (parts.method.as_str(), path) {
        ("GET", "/api/version") => json!({"service":"silicon-hook","selected_api_version":"v2"}),
        ("GET", "/api/v2/auth/iam") => {
            json!({"app_id":"hook","iam_url":"https://iam.example","testing":true,"login_method":"slt"})
        }
        ("GET", "/api/v2/auth/status") => {
            json!({"authenticated":true,"actor":{"id":"si:worker","type":"silicon"},"org_id":"tos"})
        }
        ("GET", "/api/v2/testing-session") => {
            json!({"id":ENV,"org_id":"tos","creator_kind":"carbon","creator_id":"owner:tos","name":"fixture","description":null,"generation":99,"created_at":"2026-09-22T12:00:00Z","last_activity_at":"2026-09-22T12:00:00Z","deleted_at":null})
        }
        ("GET", "/api/v2/delivery/receiver") => fixture.scope.lock().await.clone(),
        ("POST", "/api/v2/delivery/receiver") => {
            let status = StatusCode::from_u16(fixture.status.load(Ordering::SeqCst)).unwrap();
            if status != StatusCode::OK {
                return (status,Json(json!({"error":{"code":"receiver_environment_changed","message":"Receiver unavailable"}}))).into_response();
            }
            fixture.response.lock().await.clone()
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    Json(response).into_response()
}

#[tokio::test]
async fn recovery_preserves_scope_bytes_key_and_expiry_then_renewal_is_explicit() -> TestResult {
    let server = Server::start().await?;
    let scope = server.client.receiver_scope().await?;
    assert_eq!(
        scope.environment.generation, 7,
        "not Hook's internal credential generation 99"
    );
    assert_eq!(scope.org_id.to_string(), ORG);
    assert_eq!(scope.delivery_context().org_id, "tos");
    let mutation = Mutation::with_key("bootstrap-recovery")?;
    server.fixture.status.store(503, Ordering::SeqCst);
    assert!(matches!(
        server.client.bootstrap_receiver(&scope, &mutation).await,
        Err(Error::Api { status: 503, .. })
    ));
    server.fixture.status.store(200, Ordering::SeqCst);
    let historical = OffsetDateTime::now_utc() - time::Duration::minutes(5);
    *server.fixture.response.lock().await = capability(historical);
    let recovered = server.client.bootstrap_receiver(&scope, &mutation).await?;
    assert_eq!(recovered.expires_at, historical);
    assert!(!format!("{recovered:?}").contains("ting_recv_"));
    let new_key = Mutation::with_key("explicit-renewal")?;
    *server.fixture.response.lock().await =
        capability(OffsetDateTime::now_utc() + time::Duration::seconds(20));
    let renewed = server
        .client
        .renew_receiver(&scope, &recovered.receiver_id, &new_key)
        .await?;
    assert_eq!(renewed.receiver_id, recovered.receiver_id);
    assert!(renewed.expires_at > recovered.expires_at);
    let calls = server.fixture.calls.lock().await;
    let posts: Vec<_> = calls
        .iter()
        .filter(|(path, _, _)| path.starts_with("POST"))
        .collect();
    assert_eq!(posts.len(), 3);
    assert_eq!(posts[0].2, posts[1].2);
    for (_, headers, _) in &posts {
        assert_eq!(headers["authorization"], "Bearer test-actor-access");
        assert_eq!(headers["x-org-id"], "tos");
        assert_eq!(headers["silicon-hook-api-version"], "v2");
        assert_eq!(
            headers["x-hook-test-app-secret"],
            format!("ask_{}", "a".repeat(43))
        );
        assert!(!headers.contains_key("iam_test_app_secret"));
        assert!(!headers.contains_key("x-testing-environment-key"));
    }
    assert_eq!(posts[0].1["idempotency-key"], mutation.key());
    assert_eq!(posts[1].1["idempotency-key"], mutation.key());
    assert_eq!(posts[2].1["idempotency-key"], new_key.key());
    assert_eq!(
        serde_json::from_slice::<Value>(&posts[2].2)?,
        json!({"environment_id":ENV,"generation":7,"receiver_id":"recv_fixture"})
    );
    Ok(())
}

#[tokio::test]
async fn capability_requires_exact_scope_token_and_bounded_expiry() -> TestResult {
    let server = Server::start().await?;
    let scope: ReceiverScope = serde_json::from_value(scope_json())?;
    let mutation = Mutation::with_key("wrong-response")?;
    let valid = capability(OffsetDateTime::now_utc() + time::Duration::seconds(20));
    for (field, value) in [
        ("app_id", json!("other")),
        ("for", json!("si:other")),
        ("kind", json!("carbon")),
        ("kind", json!("unexpected-upstream-secret")),
        ("org_id", json!(Uuid::new_v4())),
        ("hook_org_id", json!("other")),
        ("receiver_token", json!("general-session-secret")),
        (
            "environment",
            json!({"kind":"production","id":ENV,"generation":7}),
        ),
        (
            "environment",
            json!({"kind":"testing","id":Uuid::new_v4(),"generation":7}),
        ),
        (
            "environment",
            json!({"kind":"testing","id":ENV,"generation":8}),
        ),
        (
            "expires_at",
            json!((OffsetDateTime::now_utc() + time::Duration::seconds(60)).format(&Rfc3339)?),
        ),
    ] {
        let mut bad = valid.clone();
        bad[field] = value;
        *server.fixture.response.lock().await = bad;
        let error = server
            .client
            .bootstrap_receiver(&scope, &mutation)
            .await
            .expect_err(field);
        assert!(!error.to_string().contains("general-session-secret"));
        assert!(!error.to_string().contains("unexpected-upstream-secret"));
    }
    *server.fixture.response.lock().await = valid;
    assert!(
        server
            .client
            .renew_receiver(&scope, "another-receiver", &mutation)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn scope_attestation_matches_live_actor_app_and_selected_environment() -> TestResult {
    let server = Server::start().await?;
    for (field, value) in [
        ("app_id", json!("other")),
        ("for", json!("si:other")),
        ("kind", json!("carbon")),
        ("org_id", json!(Uuid::nil())),
        ("hook_org_id", json!("other")),
        (
            "environment",
            json!({"kind":"testing","id":Uuid::new_v4(),"generation":7}),
        ),
        (
            "environment",
            json!({"kind":"testing","id":ENV,"generation":0}),
        ),
        (
            "environment",
            json!({"kind":"production","id":ENV,"generation":7}),
        ),
    ] {
        let mut bad = scope_json();
        bad[field] = value;
        *server.fixture.scope.lock().await = bad;
        assert!(server.client.receiver_scope().await.is_err(), "{field}");
    }
    assert!(
        server
            .fixture
            .calls
            .lock()
            .await
            .iter()
            .all(|(path, _, _)| !path.starts_with("POST"))
    );
    Ok(())
}

#[tokio::test]
async fn production_and_unbound_context_fail_before_network_or_mutation() -> TestResult {
    let server = Server::start().await?;
    let scope: ReceiverScope = serde_json::from_value(scope_json())?;
    let mutation = Mutation::with_key("production-denied")?;
    let production = server
        .client
        .without_test_environment()
        .with_token("prod-access")
        .with_organization("tos");
    assert!(production.receiver_scope().await.is_err());
    assert!(
        production
            .bootstrap_receiver(&scope, &mutation)
            .await
            .is_err()
    );
    assert!(
        server
            .client
            .with_token("")
            .bootstrap_receiver(&scope, &mutation)
            .await
            .is_err()
    );
    assert!(
        server
            .client
            .with_organization("other")
            .bootstrap_receiver(&scope, &mutation)
            .await
            .is_err()
    );
    let mut invalid = scope;
    invalid.environment.generation = 0;
    assert!(
        server
            .client
            .bootstrap_receiver(&invalid, &mutation)
            .await
            .is_err()
    );
    assert!(server.fixture.calls.lock().await.is_empty());
    Ok(())
}

#[test]
fn publication_models_keep_required_delivery_separate_from_muting_and_receipts() -> TestResult {
    let mut value = json!({"event_id":Uuid::new_v4(),"recipient_id":"si:worker","state":"accepted_by_ting","delivery":"required","silent":true,
        "attempts":1,"ting_id":"ting_fixture","last_error_code":null,"accepted_at":"2026-09-22T12:00:00Z","next_attempt_at":"2026-09-22T12:00:00Z",
        "expires_at":"2026-10-06T12:00:00Z","recipient_receipt":{"id":"ting_fixture","read":false,"silent":true,"delivery":"required","deliveries":[],"more_destinations":false},"recipient_status_error":null});
    let status: PublicationStatus = serde_json::from_value(value.clone())?;
    assert_eq!(status.delivery, DeliveryMode::Required);
    assert_eq!(status.silent, Some(true));
    assert!(!status.recipient_receipt.ok_or("missing receipt")?.read);
    value["silent"] = Value::Null;
    assert!(
        serde_json::from_value::<PublicationStatus>(value.clone())?
            .silent
            .is_none()
    );
    for mode in [Value::Null, json!("forced"), json!(true)] {
        value["delivery"] = mode;
        assert!(serde_json::from_value::<PublicationStatus>(value.clone()).is_err());
    }
    let grant: RecipientRegistration = serde_json::from_value(
        json!({"id":"sub_fixture","app_id":"hook","for":"si:worker","active":true,"required_delivery":false}),
    )?;
    assert!(!grant.required_delivery);
    Ok(())
}
