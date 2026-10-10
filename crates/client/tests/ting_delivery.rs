//! The Ting callback boundary and hydration of event references through Hook
//! API v3. The fixture implements Hook HTTP only: nothing is acknowledged.

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

type TestResult = Result<(), Box<dyn std::error::Error>>;

const EVENT_ID: &str = "0198c21a-6330-7000-8000-000000000001";
const HOOK_ID: &str = "0198c21a-6330-7000-8000-000000000002";
const TING_ID: &str = "0198c21a-6330-7000-8000-000000000003";
const WEBHOOK_ID: &str = "0198c21a-6330-7000-8000-000000000004";
const SECOND_EVENT_ID: &str = "0198c21a-6330-7000-8000-000000000005";
const SECOND_TING_ID: &str = "0198c21a-6330-7000-8000-000000000006";
const OTHER_ID: &str = "0198c21a-6330-7000-8000-000000000008";
const CALLBACK_SECRET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB";
const RECEIVED_AT: &str = "2026-09-22T10:00:00Z";
const SUMMARY: &str = "stripe triggered at 10:00:00 22-09-2026 UTC";
/// The Silicon's permanent uuid and its id when the event arrived.
const SILICON_UUID: &str = "Sx1";
const SILICON_ID: &str = "si:cos";

fn context() -> DeliveryContext {
    DeliveryContext {
        app_id: "hook".into(),
        recipient_uuid: SILICON_UUID.into(),
        recipient_id: Some(SILICON_ID.into()),
    }
}

fn receiver(context: DeliveryContext) -> silicon_hook_client::Result<Receiver> {
    Receiver::new(context, WEBHOOK_ID, Secret::new(CALLBACK_SECRET))
}

fn callback_authorization() -> String {
    format!("Bearer {CALLBACK_SECRET}")
}

fn producer_key_for(event_id: &str, recipient_uuid: &str) -> String {
    format!(
        "hook:{event_id}:{}",
        hex::encode(Sha256::digest(recipient_uuid.as_bytes()))
    )
}

fn producer_key(event_id: &str) -> String {
    producer_key_for(event_id, SILICON_UUID)
}

/// Native Ting callback items have no `for` field.
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
                    "silicon": {"uuid": SILICON_UUID, "id": SILICON_ID},
                    "hook_id": HOOK_ID,
                    "delivery_sequence": sequence,
                    "received_at": RECEIVED_AT,
                    "summary": SUMMARY
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
        "silicon": {"uuid": SILICON_UUID, "id": SILICON_ID},
        "hook_id": HOOK_ID,
        "provider": "stripe",
        "delivery_sequence": sequence,
        "summary": SUMMARY,
        "received_at": RECEIVED_AT,
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
            assert_eq!(request.method, "GET", "hydration must not change anything");
            assert!(
                request.path == "/api/version" || request.path.starts_with("/api/v3/silicons/"),
                "unexpected operation: {}",
                request.path
            );
            assert!(!request.path.contains("/ack"));
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
            [("silicon-hook-api-version", "v3")],
            Json(json!({
                "service": "silicon-hook",
                "selected_api_version": "v3",
                "supported_api_versions": ["v3"],
                "build": "fixture",
                "commit": "fixture"
            })),
        )
            .into_response();
    }
    if method == "GET" && path.starts_with(&format!("/api/v3/silicons/{SILICON_UUID}/events/")) {
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
        Json(json!({"error": {"code": "unexpected_operation", "message": "the fixture serves events only"}})),
    )
        .into_response()
}

#[test]
fn native_callback_requires_destination_authentication_and_the_right_webhook() -> TestResult {
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
    // `for` may name the recipient by uuid, by id, or as {uuid, id}.
    for addressed in [
        json!(SILICON_UUID),
        json!(SILICON_ID),
        json!({"uuid": SILICON_UUID, "id": SILICON_ID}),
        json!({"uuid": SILICON_UUID}),
    ] {
        let mut item = native.clone();
        item["for"] = addressed.clone();
        assert_eq!(
            receiving
                .decode(&callback_authorization(), WEBHOOK_ID, &batch(&[item])?)?
                .len(),
            1,
            "for = {addressed}"
        );
    }
    for foreign in [
        json!("si:another"),
        json!("Zz9"),
        json!({"uuid": "Zz9", "id": SILICON_ID}),
        json!(42),
    ] {
        let mut item = native.clone();
        item["for"] = foreign.clone();
        assert!(
            receiving
                .decode(&callback_authorization(), WEBHOOK_ID, &batch(&[item])?)
                .is_err(),
            "for = {foreign}"
        );
    }
    Ok(())
}

#[test]
fn callback_rejects_malformed_items_and_enforces_batch_bounds() -> TestResult {
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
            "missing Ting field {field}"
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
async fn hydration_fetches_the_original_request_through_v3_by_uuid_without_ack() -> TestResult {
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
        "v3"
    );
    let fetched = calls
        .iter()
        .find(|r| r.path.ends_with(EVENT_ID))
        .expect("original event fetch");
    assert_eq!(
        fetched.path,
        format!("/api/v3/silicons/{SILICON_UUID}/events/{EVENT_ID}")
    );
    assert_eq!(fetched.query, None);
    assert_eq!(fetched.headers["silicon-hook-api-version"], "v3");
    assert_eq!(
        fetched.headers["authorization"],
        "Bearer hook-recipient-token"
    );
    for retired in ["x-org-id", "x-hook-test-key", "x-hook-test-app-secret"] {
        assert!(
            !fetched.headers.contains_key(retired),
            "{retired} must not be sent"
        );
    }
    fixture.assert_no_acknowledgment();
    Ok(())
}

#[tokio::test]
async fn a_renamed_silicon_still_hydrates_because_references_match_by_uuid() -> TestResult {
    let fixture = Fixture::start().await?;
    let mut renamed = event_value(EVENT_ID, 42, "body");
    renamed["silicon"]["id"] = json!("si:cosmo");
    fixture.respond(EVENT_ID, StatusCode::OK, renamed);
    let notification: TingNotification =
        serde_json::from_value(notification_value(EVENT_ID, TING_ID, 42))?;
    let received = fixture
        .client
        .hydrate_notification(&context(), &notification)
        .await?;
    assert_eq!(received.event.silicon.id.as_deref(), Some("si:cosmo"));
    assert_eq!(received.event.silicon.uuid, SILICON_UUID);
    Ok(())
}

#[tokio::test]
async fn foreign_or_pre_1_0_references_are_rejected_before_any_http() -> TestResult {
    let fixture = Fixture::start().await?;
    let valid = notification_value(EVENT_ID, TING_ID, 42);
    let changes = [
        ("/type", json!("foreign-hook.webhook.received")),
        ("/data/type", json!("another_event")),
        ("/data/data/metadata/delivery_sequence", json!(-1)),
        ("/data/data/metadata/silicon/uuid", json!("")),
        ("/data/data/metadata/received_at", json!("yesterday")),
        ("/key", json!("a-different-recipient-or-producer-key")),
    ];
    for (pointer, replacement) in changes {
        let mut foreign = valid.clone();
        *foreign.pointer_mut(pointer).expect("fixture field") = replacement;
        let notification: TingNotification = serde_json::from_value(foreign)?;
        assert!(
            fixture
                .client
                .hydrate_notification(&context(), &notification)
                .await
                .is_err(),
            "accepted a foreign reference at {pointer}"
        );
    }
    // References from before Silicon Accounts carried tenant and environment fields.
    for (field, value) in [
        ("org_id", json!("tos")),
        (
            "environment_id",
            json!("00000000-0000-0000-0000-000000000000"),
        ),
        ("silicon_id", json!(SILICON_ID)),
    ] {
        let mut legacy = valid.clone();
        legacy["data"]["data"]["metadata"][field] = value;
        let notification: TingNotification = serde_json::from_value(legacy)?;
        assert!(
            fixture
                .client
                .hydrate_notification(&context(), &notification)
                .await
                .is_err(),
            "accepted a legacy reference with {field}"
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
    let mut other_recipient = context();
    other_recipient.recipient_uuid = "Zz9".into();
    let native: TingNotification =
        serde_json::from_value(notification_value(EVENT_ID, TING_ID, 42))?;
    assert!(
        fixture
            .client
            .hydrate_notification(&other_recipient, &native)
            .await
            .is_err(),
        "without `for`, the producer key still binds the notification to its recipient"
    );
    assert!(
        fixture.requests().is_empty(),
        "nothing may be fetched for a foreign reference"
    );
    Ok(())
}

#[tokio::test]
async fn every_reference_is_validated_before_any_payload_is_fetched() -> TestResult {
    let fixture = Fixture::start().await?;
    fixture.respond(
        EVENT_ID,
        StatusCode::OK,
        event_value(EVENT_ID, 42, "do not fetch before validating the batch"),
    );
    let valid = notification_value(EVENT_ID, TING_ID, 42);
    let mut foreign = notification_value(SECOND_EVENT_ID, SECOND_TING_ID, 43);
    foreign["data"]["data"]["metadata"]["org_id"] = json!("another");
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
async fn an_unavailable_reference_is_explicit_and_does_not_hide_the_next_event() -> TestResult {
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
        panic!("a missing event must have an explicit outcome");
    };
    assert_eq!(unavailable.ting_id, TING_ID);
    assert_eq!(unavailable.key, producer_key(EVENT_ID));
    assert_eq!(unavailable.reference.id.to_string(), EVENT_ID);
    assert_eq!(unavailable.reference.silicon.uuid, SILICON_UUID);
    let DeliveryOutcome::Event(received) = &outcomes[1] else {
        panic!("the next available event must still be returned");
    };
    assert_eq!(serde_json::to_value(&received.event)?, original);
    fixture.assert_no_acknowledgment();
    Ok(())
}

#[tokio::test]
async fn resolution_never_turns_authority_protocol_or_service_failures_into_results() -> TestResult
{
    let fixture = Fixture::start().await?;
    let receiving = receiver(context())?;
    let records = receiving.decode(
        &callback_authorization(),
        WEBHOOK_ID,
        &batch(&[notification_value(EVENT_ID, TING_ID, 42)])?,
    )?;
    for (status, code) in [
        (StatusCode::UNAUTHORIZED, "session_ended"),
        (StatusCode::FORBIDDEN, "forbidden"),
        (StatusCode::NOT_FOUND, "silicon_not_found"),
        (StatusCode::GONE, "account_deleted"),
        (StatusCode::SERVICE_UNAVAILABLE, "accounts_unavailable"),
    ] {
        fixture.respond(
            EVENT_ID,
            status,
            json!({"error":{"code":code,"message":"unavailable","request_id":"req-1"}}),
        );
        let error = receiving
            .resolve(&fixture.client, &records)
            .await
            .expect_err("not a terminal result");
        assert!(
            matches!(&error, Error::Api(api) if api.code == code && api.status == status.as_u16())
        );
        assert_eq!(error.code(), Some(code));
    }
    let mut mismatch = event_value(EVENT_ID, 42, "wrong original");
    mismatch["silicon"]["uuid"] = json!("Zz9");
    fixture.respond(EVENT_ID, StatusCode::OK, mismatch);
    assert!(matches!(
        receiving.resolve(&fixture.client, &records).await,
        Err(Error::Protocol(_))
    ));
    fixture.assert_no_acknowledgment();
    Ok(())
}

#[tokio::test]
async fn a_carbon_observer_hydrates_the_silicons_event() -> TestResult {
    let fixture = Fixture::start().await?;
    let observer = DeliveryContext {
        app_id: "hook".into(),
        recipient_uuid: "Cz9".into(),
        recipient_id: Some("c:alice".into()),
    };
    let mut notification = notification_value(EVENT_ID, TING_ID, 42);
    notification["key"] = json!(producer_key_for(EVENT_ID, "Cz9"));
    notification["for"] = json!({"uuid": "Cz9", "id": "c:alice"});
    let original = event_value(EVENT_ID, 42, "seen by the custodian");
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
    assert_eq!(received[0].event.silicon.uuid, SILICON_UUID);
    fixture.assert_no_acknowledgment();
    Ok(())
}

#[tokio::test]
async fn an_unreachable_hook_leaves_the_callback_unaccepted() -> TestResult {
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
    .expect_err("a missing original must not become accepted work");
    assert!(matches!(error, Error::Transport(_)));
    assert!(fixture.requests().is_empty());
    Ok(())
}

#[tokio::test]
async fn hydration_rejects_originals_that_differ_from_the_reference() -> TestResult {
    let fixture = Fixture::start().await?;
    let notification: TingNotification =
        serde_json::from_value(notification_value(EVENT_ID, TING_ID, 42))?;
    let original = event_value(EVENT_ID, 42, "provider payload");
    let changes = [
        ("/id", json!(SECOND_EVENT_ID)),
        ("/silicon/uuid", json!("Zz9")),
        ("/hook_id", json!(OTHER_ID)),
        ("/provider", json!("different-provider")),
        ("/delivery_sequence", json!(43)),
        ("/received_at", json!("2026-09-22T10:01:00Z")),
        ("/summary", json!("different provider or receipt time")),
    ];
    for (pointer, replacement) in changes {
        let mut mismatched = original.clone();
        *mismatched.pointer_mut(pointer).expect("event field") = replacement;
        fixture.respond(EVENT_ID, StatusCode::OK, mismatched);
        assert!(
            fixture
                .client
                .hydrate_notification(&context(), &notification)
                .await
                .is_err(),
            "accepted a mismatched original at {pointer}"
        );
    }
    fixture.assert_no_acknowledgment();
    Ok(())
}

#[tokio::test]
async fn expired_or_hidden_events_fail_the_whole_batch_without_acknowledging() -> TestResult {
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
            .expect_err("a partial batch must not be accepted");
        assert_eq!(error.status(), Some(status.as_u16()));
    }
    fixture.assert_no_acknowledgment();
    Ok(())
}

#[tokio::test]
async fn replayed_and_reordered_notifications_keep_identity_for_deduplication() -> TestResult {
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
            .map(|e| e.event.delivery_sequence)
            .collect::<Vec<_>>(),
        vec![43, 42, 43]
    );
    assert_eq!(
        received
            .iter()
            .map(|e| e.ting_id.as_str())
            .collect::<Vec<_>>(),
        vec![SECOND_TING_ID, TING_ID, SECOND_TING_ID]
    );
    assert_eq!(received[0].event.id, received[2].event.id);
    assert_eq!(received[0].key, received[2].key);
    fixture.assert_no_acknowledgment();
    Ok(())
}
