//! Exercises the internal Ting callback boundary and authorized raw-event hydration.
//! The fixture implements Hook HTTP only: no Ting receipt or ACK is manufactured.

use axum::{
    Json, Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use silicon_hook_client::{
    Client, Error, Secret,
    delivery::{DeliveryContext, DeliveryOutcome, Receiver, TingNotification},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const EVENT_ID: &str = "0198c21a-6330-7000-8000-000000000001";
const HOOK_ID: &str = "0198c21a-6330-7000-8000-000000000002";
const TING_ID: &str = "0198c21a-6330-7000-8000-000000000003";
const WEBHOOK_ID: &str = "0198c21a-6330-7000-8000-000000000004";
const SECOND_EVENT_ID: &str = "0198c21a-6330-7000-8000-000000000005";
const SECOND_TING_ID: &str = "0198c21a-6330-7000-8000-000000000006";
const ENVIRONMENT_ID: &str = "0198c21a-6330-7000-8000-000000000007";
const OTHER_ID: &str = "0198c21a-6330-7000-8000-000000000008";
const CALLBACK_SECRET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB";
const TEST_KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWX12345678";
const RECEIVED_AT: &str = "2026-09-22T10:00:00Z";
const SUMMARY: &str = "stripe triggered at 10:00:00 22-09-2026 UTC";

fn context() -> DeliveryContext {
    DeliveryContext {
        app_id: "hook".into(),
        org_id: "tos".into(),
        recipient_id: "si:cos".into(),
        environment_id: Uuid::nil(),
    }
}

fn receiver(context: DeliveryContext) -> silicon_hook_client::Result<Receiver> {
    Receiver::new(context, WEBHOOK_ID, Secret::new(CALLBACK_SECRET))
}

fn callback_authorization() -> String {
    format!("Bearer {CALLBACK_SECRET}")
}

fn producer_key(event_id: &str) -> String {
    format!("hook:{event_id}:{}", hex::encode(Sha256::digest(b"si:cos")))
}

/// Native Ting callback items intentionally have no `for` field.
fn notification_value(event_id: &str, ting_id: &str, sequence: i64) -> Value {
    json!({
        "id": ting_id,
        "created_at": "2026-09-22T10:00:01Z",
        "type": "hook.webhook.received",
        "data": {
            "type": "new_event",
            "data": {
                "sender": "stripe",
                "metadata": {
                    "id": event_id,
                    "org_id": "tos",
                    "silicon_id": "si:cos",
                    "hook_id": HOOK_ID,
                    "delivery_sequence": sequence,
                    "received_at": RECEIVED_AT,
                    "summary": SUMMARY,
                    "environment_id": Uuid::nil(),
                    "environment_generation": 0
                }
            }
        },
        "metadata": {},
        "key": producer_key(event_id)
    })
}

fn event_value(event_id: &str, sequence: i64, body: &str) -> Value {
    json!({
        "id": event_id,
        "org_id": "tos",
        "silicon_id": "si:cos",
        "hook_id": HOOK_ID,
        "provider": "stripe",
        "delivery_sequence": sequence,
        "received_at": RECEIVED_AT,
        "summary": SUMMARY,
        "request": {
            "method": "POST",
            "url": "https://hook.example.test/silicon/si:cos/ABCDEFGH?a=one%20two&a=three",
            "path": "/silicon/si:cos/ABCDEFGH",
            "query_string": "a=one%20two&a=three",
            "headers": [["X-Provider-Value", "first"], ["X-Provider-Value", "second"]],
            "content_type": "application/json; charset=utf-8",
            "body": body,
            "body_base64": null,
            "remote_ip": "192.0.2.42"
        }
    })
}

fn batch(items: &[Value]) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&json!({"tings": items}))
}

#[derive(Clone, Debug)]
struct RequestRecord {
    method: String,
    path: String,
    query: Option<String>,
    headers: HeaderMap,
}

#[derive(Default)]
struct FixtureState {
    requests: Mutex<Vec<RequestRecord>>,
    responses: Mutex<HashMap<String, (StatusCode, Value)>>,
}

struct Fixture {
    client: Client,
    state: Arc<FixtureState>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let state = Arc::new(FixtureState::default());
        let router = Router::new().fallback(handle).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let client = Client::new(&format!("http://{}", listener.local_addr()?))?
            .with_token("hook-recipient-token")
            .with_organization("tos")
            .with_telemetry(false);
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("fixture server");
        });
        Ok(Self {
            client,
            state,
            server,
        })
    }

    fn respond(&self, event_id: &str, status: StatusCode, body: Value) {
        self.state
            .responses
            .lock()
            .unwrap()
            .insert(event_id.into(), (status, body));
    }

    fn requests(&self) -> Vec<RequestRecord> {
        self.state.requests.lock().unwrap().clone()
    }

    fn assert_no_acknowledgment(&self) {
        for request in self.requests() {
            assert_eq!(
                request.method, "GET",
                "hydration must not mutate delivery state"
            );
            assert!(
                request.path == "/api/version" || request.path.starts_with("/api/v2/silicons/"),
                "unexpected transport operation: {}",
                request.path
            );
            assert!(!request.path.contains("/ack"));
            assert!(!request.path.contains("/deliveries"));
        }
    }
}

async fn handle(State(state): State<Arc<FixtureState>>, request: Request<Body>) -> Response {
    let path = request.uri().path().to_owned();
    let method = request.method().as_str().to_owned();
    state.requests.lock().unwrap().push(RequestRecord {
        method: method.clone(),
        path: path.clone(),
        query: request.uri().query().map(str::to_owned),
        headers: request.headers().clone(),
    });
    if method == "GET" && path == "/api/version" {
        return (
            [("silicon-hook-api-version", "v2")],
            Json(json!({
                "service": "silicon-hook",
                "selected_api_version": "v2",
                "supported_api_versions": ["v2", "v1"],
                "build": "fixture",
                "commit": "fixture"
            })),
        )
            .into_response();
    }
    if method == "GET" && path.starts_with("/api/v2/silicons/si:cos/events/") {
        let event_id = path.rsplit('/').next().unwrap();
        if let Some((status, body)) = state.responses.lock().unwrap().get(event_id).cloned() {
            return (status, Json(body)).into_response();
        }
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": {"code": "not_found", "message": "event unavailable"}})),
        )
            .into_response();
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": {"code": "unexpected_operation", "message": "fixture does not acknowledge deliveries"}})),
    ).into_response()
}

#[test]
fn native_callback_requires_both_destination_authentication_and_correct_webhook() -> TestResult {
    let receiving = receiver(context())?;
    let native = notification_value(EVENT_ID, TING_ID, 42);
    assert!(native.get("for").is_none());
    let body = batch(std::slice::from_ref(&native))?;
    assert_eq!(
        receiving
            .decode(&callback_authorization(), WEBHOOK_ID, &body)?
            .len(),
        1
    );
    for authorization in ["", "Bearer wrong-secret", "Basic wrong-secret"] {
        assert!(receiving.decode(authorization, WEBHOOK_ID, &body).is_err());
    }
    assert!(
        receiving
            .decode(&callback_authorization(), OTHER_ID, &body)
            .is_err()
    );
    let mut addressed = native.clone();
    addressed["for"] = json!("si:cos");
    assert_eq!(
        receiving
            .decode(&callback_authorization(), WEBHOOK_ID, &batch(&[addressed])?)?
            .len(),
        1
    );
    let mut foreign = native;
    foreign["for"] = json!("si:another");
    assert!(
        receiving
            .decode(&callback_authorization(), WEBHOOK_ID, &batch(&[foreign])?)
            .is_err()
    );
    Ok(())
}

#[test]
fn callback_rejects_malformed_or_incomplete_items_and_enforces_batch_bounds() -> TestResult {
    let receiving = receiver(context())?;
    let valid = notification_value(EVENT_ID, TING_ID, 42);
    for malformed in [
        b"not-json".as_slice(),
        b"[]".as_slice(),
        b"{}".as_slice(),
        &[0xff, 0xfe],
    ] {
        assert!(
            receiving
                .decode(&callback_authorization(), WEBHOOK_ID, malformed)
                .is_err()
        );
    }
    assert!(
        receiving
            .decode(&callback_authorization(), WEBHOOK_ID, &batch(&[])?)
            .is_err()
    );
    for field in ["id", "created_at", "type", "data", "metadata", "key"] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            receiving
                .decode(&callback_authorization(), WEBHOOK_ID, &batch(&[missing])?)
                .is_err(),
            "missing required native Ting field {field}"
        );
    }
    let hundred = vec![valid.clone(); 100];
    assert_eq!(
        receiving
            .decode(&callback_authorization(), WEBHOOK_ID, &batch(&hundred)?)?
            .len(),
        100
    );
    assert!(
        receiving
            .decode(
                &callback_authorization(),
                WEBHOOK_ID,
                &batch(&vec![valid.clone(); 101])?
            )
            .is_err()
    );
    let mut oversized = valid;
    oversized["metadata"] = json!({"padding": "x".repeat(2 * 1024 * 1024)});
    let body = batch(&[oversized])?;
    assert!(body.len() > 2 * 1024 * 1024);
    assert!(
        receiving
            .decode(&callback_authorization(), WEBHOOK_ID, &body)
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn hydration_fetches_original_large_request_and_summary_using_v2_without_ack() -> TestResult {
    let fixture = Fixture::start().await?;
    let body = format!(
        "{{\"payload\":\"{}\",\"unicode\":\"☃\"}}",
        "x".repeat(512 * 1024)
    );
    let original = event_value(EVENT_ID, 42, &body);
    fixture.respond(EVENT_ID, StatusCode::OK, original.clone());
    let receiving = receiver(context())?;
    let compact = batch(&[notification_value(EVENT_ID, TING_ID, 42)])?;
    assert!(
        compact.len() < 4096,
        "Ting carries only the compact reference"
    );
    let decoded = receiving.decode(&callback_authorization(), WEBHOOK_ID, &compact)?;
    let received = receiving.hydrate(&fixture.client, &decoded).await?;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].ting_id, TING_ID);
    assert_eq!(received[0].key, producer_key(EVENT_ID));
    assert_eq!(serde_json::to_value(&received[0].event)?, original);
    let calls = fixture.requests();
    let negotiation = calls
        .iter()
        .find(|r| r.path == "/api/version")
        .expect("version negotiation");
    assert_eq!(
        negotiation.headers["silicon-hook-supported-api-versions"],
        "v2"
    );
    let fetched = calls
        .iter()
        .find(|r| r.path.ends_with(EVENT_ID))
        .expect("original event fetch");
    assert_eq!(
        fetched.path,
        format!("/api/v2/silicons/si:cos/events/{EVENT_ID}")
    );
    assert_eq!(fetched.headers["silicon-hook-api-version"], "v2");
    assert_eq!(
        fetched.headers["authorization"],
        "Bearer hook-recipient-token"
    );
    assert_eq!(fetched.headers["x-org-id"], "tos");
    assert!(!fetched.headers.contains_key("x-hook-test-key"));
    assert!(!fetched.headers.contains_key("x-hook-test-app-secret"));
    let query: HashMap<_, _> =
        url::form_urlencoded::parse(fetched.query.as_deref().unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    assert_eq!(query.get("environment_id"), Some(&Uuid::nil().to_string()));
    assert_eq!(
        query.get("environment_generation").map(String::as_str),
        Some("0")
    );
    fixture.assert_no_acknowledgment();
    Ok(())
}

#[tokio::test]
async fn test_hydration_keeps_the_events_original_generation_and_current_test_selector()
-> TestResult {
    let fixture = Fixture::start().await?;
    let mut selected = context();
    selected.environment_id = ENVIRONMENT_ID.parse()?;
    let mut value = notification_value(EVENT_ID, TING_ID, 42);
    value["data"]["data"]["metadata"]["environment_id"] = json!(ENVIRONMENT_ID);
    value["data"]["data"]["metadata"]["environment_generation"] = json!(7);
    fixture.respond(
        EVENT_ID,
        StatusCode::OK,
        event_value(EVENT_ID, 42, "original test body"),
    );
    let client = fixture
        .client
        .with_test_key(TEST_KEY)?
        .with_token("current-test-token")
        .with_organization("tos");
    let notification: TingNotification = serde_json::from_value(value)?;
    let received = client
        .hydrate_notification(&selected, &notification)
        .await?;
    assert_eq!(
        received.event.request.body.as_deref(),
        Some("original test body")
    );
    let request = fixture
        .requests()
        .into_iter()
        .find(|r| r.path.ends_with(EVENT_ID))
        .expect("test event fetch");
    assert_eq!(request.headers["x-hook-test-key"], TEST_KEY);
    assert_eq!(
        request.headers["authorization"],
        "Bearer current-test-token"
    );
    let query: HashMap<_, _> =
        url::form_urlencoded::parse(request.query.as_deref().unwrap_or_default().as_bytes())
            .into_owned()
            .collect();
    assert_eq!(
        query.get("environment_id").map(String::as_str),
        Some(ENVIRONMENT_ID)
    );
    assert_eq!(
        query.get("environment_generation").map(String::as_str),
        Some("7")
    );
    fixture.assert_no_acknowledgment();
    Ok(())
}

#[tokio::test]
async fn foreign_reference_authority_or_ting_identity_is_rejected_before_http() -> TestResult {
    let fixture = Fixture::start().await?;
    let valid = notification_value(EVENT_ID, TING_ID, 42);
    let changes = [
        ("/type", json!("hook.webhook.received")),
        ("/data/type", json!("another_event")),
        ("/data/data/metadata/org_id", json!("foreign-org")),
        ("/data/data/metadata/environment_id", json!(ENVIRONMENT_ID)),
        ("/data/data/metadata/environment_generation", json!(-1)),
        ("/data/data/metadata/environment_generation", json!(1)),
        ("/key", json!("a-different-recipient-or-producer-key")),
    ];
    for (pointer, replacement) in changes {
        let mut foreign = valid.clone();
        *foreign
            .pointer_mut(pointer)
            .expect("fixture reference field") = replacement;
        let notification: TingNotification = serde_json::from_value(foreign)?;
        assert!(
            fixture
                .client
                .hydrate_notification(&context(), &notification)
                .await
                .is_err(),
            "accepted foreign reference at {pointer}"
        );
    }
    let mut foreign_recipient = valid;
    foreign_recipient["for"] = json!("si:another");
    let notification: TingNotification = serde_json::from_value(foreign_recipient)?;
    assert!(
        fixture
            .client
            .hydrate_notification(&context(), &notification)
            .await
            .is_err()
    );
    let mut foreign_context = context();
    foreign_context.recipient_id = "si:another".into();
    let native: TingNotification =
        serde_json::from_value(notification_value(EVENT_ID, TING_ID, 42))?;
    assert!(
        fixture
            .client
            .hydrate_notification(&foreign_context, &native)
            .await
            .is_err(),
        "native notifications without for must still bind the producer key to the recipient"
    );
    assert!(
        fixture.requests().is_empty(),
        "foreign reference must not cause an authenticated fetch"
    );
    Ok(())
}

#[tokio::test]
async fn receiver_refuses_a_differently_scoped_client_before_sending_credentials() -> TestResult {
    let fixture = Fixture::start().await?;
    let receiving = receiver(context())?;
    let decoded = receiving.decode(
        &callback_authorization(),
        WEBHOOK_ID,
        &batch(&[notification_value(EVENT_ID, TING_ID, 42)])?,
    )?;
    assert!(
        receiving
            .hydrate(&fixture.client.with_organization("another-org"), &decoded)
            .await
            .is_err()
    );
    let test_client = fixture
        .client
        .with_test_key(TEST_KEY)?
        .with_token("test-token")
        .with_organization("tos");
    assert!(receiving.hydrate(&test_client, &decoded).await.is_err());
    assert!(fixture.requests().is_empty());
    Ok(())
}

#[tokio::test]
async fn every_reference_is_validated_before_any_payload_in_the_batch_is_fetched() -> TestResult {
    let fixture = Fixture::start().await?;
    fixture.respond(
        EVENT_ID,
        StatusCode::OK,
        event_value(EVENT_ID, 42, "do not fetch before validating the batch"),
    );
    let valid = notification_value(EVENT_ID, TING_ID, 42);
    let mut foreign = notification_value(SECOND_EVENT_ID, SECOND_TING_ID, 43);
    foreign["data"]["data"]["metadata"]["org_id"] = json!("another-org");
    let notifications = vec![
        serde_json::from_value::<TingNotification>(valid)?,
        serde_json::from_value::<TingNotification>(foreign)?,
    ];
    assert!(
        receiver(context())?
            .hydrate(&fixture.client, &notifications)
            .await
            .is_err()
    );
    assert!(
        receiver(context())?
            .resolve(&fixture.client, &notifications)
            .await
            .is_err()
    );
    assert!(fixture.requests().is_empty());
    Ok(())
}

#[tokio::test]
async fn unavailable_reference_is_explicit_and_does_not_hide_the_next_event() -> TestResult {
    let fixture = Fixture::start().await?;
    let original = event_value(SECOND_EVENT_ID, 43, "still available");
    fixture.respond(SECOND_EVENT_ID, StatusCode::OK, original.clone());
    let receiving = receiver(context())?;
    let records = receiving.decode(
        &callback_authorization(),
        WEBHOOK_ID,
        &batch(&[
            notification_value(EVENT_ID, TING_ID, 42),
            notification_value(SECOND_EVENT_ID, SECOND_TING_ID, 43),
        ])?,
    )?;
    let outcomes = receiving.resolve(&fixture.client, &records).await?;
    assert_eq!(outcomes.len(), 2);
    let DeliveryOutcome::Unavailable(unavailable) = &outcomes[0] else {
        panic!("a missing payload must have an explicit terminal outcome");
    };
    assert_eq!(unavailable.ting_id, TING_ID);
    assert_eq!(unavailable.key, producer_key(EVENT_ID));
    assert_eq!(unavailable.reference.id.to_string(), EVENT_ID);
    let DeliveryOutcome::Event(received) = &outcomes[1] else {
        panic!("the subsequent available event must still be returned");
    };
    assert_eq!(serde_json::to_value(&received.event)?, original);
    fixture.assert_no_acknowledgment();
    Ok(())
}

#[tokio::test]
async fn resolution_never_terminally_accepts_authority_protocol_or_service_failures() -> TestResult
{
    let fixture = Fixture::start().await?;
    let receiving = receiver(context())?;
    let records = receiving.decode(
        &callback_authorization(),
        WEBHOOK_ID,
        &batch(&[notification_value(EVENT_ID, TING_ID, 42)])?,
    )?;
    for (status, code) in [
        (StatusCode::UNAUTHORIZED, "invalid_credential"),
        (StatusCode::FORBIDDEN, "permission_denied"),
        (StatusCode::NOT_FOUND, "unexpected_route"),
        (StatusCode::GONE, "environment_disabled"),
        (StatusCode::SERVICE_UNAVAILABLE, "upstream_unavailable"),
    ] {
        fixture.respond(
            EVENT_ID,
            status,
            json!({"error":{"code":code,"message":"unavailable"}}),
        );
        assert!(matches!(
            receiving.resolve(&fixture.client, &records).await,
            Err(Error::Api { .. })
        ));
    }
    let mut mismatch = event_value(EVENT_ID, 42, "wrong original");
    mismatch["org_id"] = json!("another-org");
    fixture.respond(EVENT_ID, StatusCode::OK, mismatch);
    assert!(matches!(
        receiving.resolve(&fixture.client, &records).await,
        Err(Error::Protocol(_))
    ));
    fixture.assert_no_acknowledgment();
    Ok(())
}

#[tokio::test]
async fn an_observer_hydrates_the_visible_silicon_without_changing_event_ownership() -> TestResult {
    let fixture = Fixture::start().await?;
    let mut observer = context();
    observer.recipient_id = "c:alice".into();
    let mut notification = notification_value(EVENT_ID, TING_ID, 42);
    notification["key"] = json!(format!(
        "hook:{EVENT_ID}:{}",
        hex::encode(Sha256::digest(b"c:alice"))
    ));
    let original = event_value(EVENT_ID, 42, "shared with an authorized observer");
    fixture.respond(EVENT_ID, StatusCode::OK, original.clone());
    let receiving = receiver(observer)?;
    let decoded = receiving.decode(
        &callback_authorization(),
        WEBHOOK_ID,
        &batch(&[notification])?,
    )?;
    let received = receiving.hydrate(&fixture.client, &decoded).await?;
    assert_eq!(received.len(), 1);
    assert_eq!(serde_json::to_value(&received[0].event)?, original);
    assert_eq!(received[0].event.silicon_id, "si:cos");
    fixture.assert_no_acknowledgment();
    Ok(())
}

#[tokio::test]
async fn unavailable_hook_leaves_the_callback_unaccepted() -> TestResult {
    let mut fixture = Fixture::start().await?;
    let receiving = receiver(context())?;
    let decoded = receiving.decode(
        &callback_authorization(),
        WEBHOOK_ID,
        &batch(&[notification_value(EVENT_ID, TING_ID, 42)])?,
    )?;
    fixture.server.abort();
    let _ = (&mut fixture.server).await;
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        receiving.hydrate(&fixture.client, &decoded),
    )
    .await?
    .expect_err("a missing original must not become accepted recipient work");
    assert!(matches!(error, Error::Transport(_)));
    assert!(fixture.requests().is_empty());
    Ok(())
}

#[tokio::test]
async fn hydration_rejects_original_details_that_do_not_match_the_reference() -> TestResult {
    let fixture = Fixture::start().await?;
    let notification: TingNotification =
        serde_json::from_value(notification_value(EVENT_ID, TING_ID, 42))?;
    let original = event_value(EVENT_ID, 42, "provider payload");
    let changes = [
        ("id", json!(SECOND_EVENT_ID)),
        ("org_id", json!("another-org")),
        ("silicon_id", json!("si:another")),
        ("hook_id", json!(OTHER_ID)),
        ("provider", json!("different-provider")),
        ("delivery_sequence", json!(43)),
        ("received_at", json!("2026-09-22T10:01:00Z")),
        ("summary", json!("different provider or receipt time")),
    ];
    for (field, replacement) in changes {
        let mut mismatched = original.clone();
        mismatched[field] = replacement;
        fixture.respond(EVENT_ID, StatusCode::OK, mismatched);
        assert!(
            fixture
                .client
                .hydrate_notification(&context(), &notification)
                .await
                .is_err(),
            "accepted mismatched original {field}"
        );
    }
    fixture.assert_no_acknowledgment();
    Ok(())
}

#[tokio::test]
async fn expired_or_invisible_events_fail_the_whole_batch_without_acknowledging() -> TestResult {
    let fixture = Fixture::start().await?;
    fixture.respond(
        EVENT_ID,
        StatusCode::OK,
        event_value(EVENT_ID, 42, "visible event"),
    );
    let receiving = receiver(context())?;
    let decoded = receiving.decode(
        &callback_authorization(),
        WEBHOOK_ID,
        &batch(&[
            notification_value(EVENT_ID, TING_ID, 42),
            notification_value(SECOND_EVENT_ID, SECOND_TING_ID, 43),
        ])?,
    )?;
    for (status, code) in [
        (StatusCode::NOT_FOUND, "not_found"),
        (StatusCode::FORBIDDEN, "forbidden"),
        (StatusCode::UNAUTHORIZED, "unauthenticated"),
    ] {
        fixture.respond(
            SECOND_EVENT_ID,
            status,
            json!({"error":{"code":code,"message":"event cannot be read"}}),
        );
        let error = receiving
            .hydrate(&fixture.client, &decoded)
            .await
            .expect_err("partial batch must not be accepted");
        assert!(matches!(error, Error::Api { status: actual, .. } if actual == status.as_u16()));
    }
    fixture.assert_no_acknowledgment();
    Ok(())
}

#[tokio::test]
async fn replayed_and_reordered_notifications_keep_identity_for_host_deduplication() -> TestResult {
    let fixture = Fixture::start().await?;
    fixture.respond(
        EVENT_ID,
        StatusCode::OK,
        event_value(EVENT_ID, 42, "first original"),
    );
    fixture.respond(
        SECOND_EVENT_ID,
        StatusCode::OK,
        event_value(SECOND_EVENT_ID, 43, "second original"),
    );
    let later = notification_value(SECOND_EVENT_ID, SECOND_TING_ID, 43);
    let receiving = receiver(context())?;
    let decoded = receiving.decode(
        &callback_authorization(),
        WEBHOOK_ID,
        &batch(&[
            later.clone(),
            notification_value(EVENT_ID, TING_ID, 42),
            later,
        ])?,
    )?;
    let received = receiving.hydrate(&fixture.client, &decoded).await?;
    assert_eq!(
        received
            .iter()
            .map(|event| event.event.delivery_sequence)
            .collect::<Vec<_>>(),
        vec![43, 42, 43]
    );
    assert_eq!(
        received
            .iter()
            .map(|event| event.ting_id.as_str())
            .collect::<Vec<_>>(),
        vec![SECOND_TING_ID, TING_ID, SECOND_TING_ID]
    );
    assert_eq!(received[0].event.id, received[2].event.id);
    assert_eq!(received[0].key, received[2].key);
    assert_eq!(
        received[0].event.request.body,
        received[2].event.request.body
    );
    fixture.assert_no_acknowledgment();
    Ok(())
}
