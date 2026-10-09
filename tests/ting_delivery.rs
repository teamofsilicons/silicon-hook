//! Delivery through Ting in the Silicon Accounts era: with `HOOK_TING_URL`
//! set, every accepted event is queued for its Silicon (and observing
//! Carbons) and sent with a Silicon Accounts proof; without it nothing is
//! queued and the API says delivery is off.

mod support;

use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result};
use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use http::{Method, StatusCode};
use serde_json::{Value, json};
use silicon_hook::delivery::publisher::Publisher;
use support::api::{TestApi, event};

type Calls = Arc<Mutex<Vec<(String, String, Value)>>>;

/// A stub Ting that accepts every send and records what it received.
struct StubTing {
    url: String,
    calls: Calls,
}

impl StubTing {
    async fn start() -> Result<Self> {
        let calls = Calls::default();
        let app = Router::new()
            .route("/v1/tings", post(send))
            .route("/v1/subscriptions", post(subscribe))
            .route("/v1/sent/query", post(query))
            .with_state(calls.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/", listener.local_addr()?);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { url, calls })
    }

    fn calls(&self, path: &str) -> Vec<(String, Value)> {
        self.calls
            .lock()
            .map(|calls| {
                calls
                    .iter()
                    .filter(|(called, _, _)| called == path)
                    .map(|(_, authorization, body)| (authorization.clone(), body.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Records a call and returns its number among calls to the same path.
fn record(calls: &Calls, path: &str, headers: &HeaderMap, body: &Value) -> usize {
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    calls.lock().map_or(0, |mut calls| {
        calls.push((path.to_owned(), authorization, body.clone()));
        calls.iter().filter(|(called, _, _)| called == path).count()
    })
}

async fn send(
    State(calls): State<Calls>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let serial = record(&calls, "send", &headers, &body);
    let mut accepted = json!({"id": format!("msg_{serial}"), "key": body["key"], "status": "accepted",
        "silent": false, "created_at": "2026-10-10T00:00:00Z"});
    if body["delivery"] == "required" {
        accepted["delivery"] = json!("required");
    }
    (StatusCode::ACCEPTED, Json(accepted))
}

async fn subscribe(
    State(calls): State<Calls>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    record(&calls, "subscribe", &headers, &body);
    (
        StatusCode::CREATED,
        Json(
            json!({"id": "sub_1", "app_id": body["app_id"], "for": body["for"],
        "active": true, "required_delivery": false}),
        ),
    )
}

async fn query(
    State(calls): State<Calls>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    record(&calls, "query", &headers, &body);
    let sent = calls.lock().ok().and_then(|calls| {
        calls
            .iter()
            .filter(|(path, _, _)| path == "send")
            .enumerate()
            .find(|(index, _)| body["id"] == format!("msg_{}", index + 1))
            .map(|(_, (_, _, sent))| sent.clone())
    });
    let sent = sent.unwrap_or_default();
    let mut detail = json!({"id": body["id"], "type": "hook.webhook.received", "for": sent["for"],
        "read": true, "silent": false,
        "deliveries": [{"webhook_id": "wh_1", "delivery_acked": true, "read_acked": true}]});
    if sent["delivery"] == "required" {
        detail["delivery"] = json!("required");
    }
    Json(detail)
}

fn setup(api: &TestApi) -> (String, String, String) {
    let stub = &api.accounts;
    stub.add_carbon("CAlice1", "c:alice");
    stub.add_carbon("CBob2", "c:bob");
    stub.add_carbon("CDave4", "c:dave");
    stub.add_silicon("SCos1", "si:cos", Some(("CAlice1", "c:alice")));
    (
        stub.token("SCos1", "silicon", "si:cos"),
        stub.token("CAlice1", "carbon", "c:alice"),
        stub.token("CBob2", "carbon", "c:bob"),
    )
}

async fn open_hook(api: &TestApi, cos: &str) -> Result<String> {
    let body = json!({"name": "Open", "signature": {"required": false}});
    let (status, hook) = api
        .call(
            Method::POST,
            "/api/v3/silicons/si:cos/hooks",
            Some(cos),
            Some(&body),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{hook}");
    Ok(format!(
        "/silicon/si:cos/{}",
        hook["endpoint_key"].as_str().unwrap_or_default()
    ))
}

async fn queued(api: &TestApi) -> Result<Vec<(String, bool)>> {
    Ok(sqlx::query_as(
        "SELECT recipient_id, observer_subscription_id IS NOT NULL FROM hook_private.ting_outbox
         WHERE accepted_at IS NULL ORDER BY recipient_id",
    )
    .fetch_all(api.owner.pool())
    .await?)
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one delivery scenario, step by step")]
async fn accepted_events_reach_the_silicon_and_its_observers_with_accounts_proofs() -> Result<()> {
    let ting = StubTing::start().await?;
    let Some(api) = TestApi::start_with_ting(Some(&ting.url)).await? else {
        return Ok(());
    };
    let (cos, alice, bob) = setup(&api);
    let (_, status) = api
        .call(Method::GET, "/api/v3/delivery", Some(&cos), None)
        .await?;
    assert_eq!(status, json!({"enabled": true, "transport": "ting"}));

    let subscription = "/api/v3/silicons/si:cos/delivery/subscription";
    let (status, observed) = api
        .call(Method::POST, subscription, Some(&alice), None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{observed}");
    assert_eq!(observed["receiving"], true);
    let enrolment = ting.calls("subscribe");
    assert_eq!(enrolment.len(), 1);
    assert!(
        enrolment[0].0.starts_with("Proof sap_stub_"),
        "{enrolment:?}"
    );
    assert_eq!(
        enrolment[0].1["for"],
        json!({"uuid": "CAlice1", "id": "c:alice"})
    );
    assert_eq!(
        api.call(Method::POST, subscription, Some(&bob), None)
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        api.call(Method::POST, subscription, Some(&cos), None)
            .await?
            .0,
        StatusCode::FORBIDDEN
    );

    let endpoint = open_hook(&api, &cos).await?;
    assert_eq!(
        api.deliver(&endpoint, &[], b"{\"n\":1}").await?.0,
        StatusCode::OK
    );
    assert_eq!(
        queued(&api).await?,
        vec![("CAlice1".to_owned(), true), ("SCos1".to_owned(), false)]
    );

    let ting_adapter = api
        .application
        .delivery()
        .cloned()
        .context("delivery is on")?;
    let publisher = Publisher::new(api.application.store().clone(), ting_adapter);
    while publisher.publish_one().await? {}
    assert_eq!(queued(&api).await?, vec![]);
    let sends = ting.calls("send");
    assert_eq!(sends.len(), 2);
    for (authorization, body) in &sends {
        assert!(
            authorization.starts_with("Proof sap_stub_"),
            "{authorization}"
        );
        assert_eq!(body["type"], "hook.webhook.received");
        assert_eq!(
            body["data"]["data"]["metadata"]["silicon"],
            json!({"uuid": "SCos1", "id": "si:cos"})
        );
    }
    let to_silicon = sends
        .iter()
        .find(|(_, body)| body["for"]["uuid"] == "SCos1")
        .context("send to Cos")?;
    assert_eq!(
        (
            to_silicon.1["for"]["id"].clone(),
            to_silicon.1["delivery"].clone()
        ),
        (json!("si:cos"), json!("required"))
    );
    let to_alice = sends
        .iter()
        .find(|(_, body)| body["for"]["uuid"] == "CAlice1")
        .context("copy for Alice")?;
    assert!(
        to_alice.1.get("delivery").is_none(),
        "observer copies are ordinary notifications"
    );
    let proofs = api.accounts.proofs();
    assert!(
        proofs
            .iter()
            .any(|proof| proof["kind"] == "app_verification"
                && proof["receiving_app"] == "ting"
                && proof["scopes"] == json!(["tings.send"])),
        "{proofs:?}"
    );
    assert!(
        proofs
            .iter()
            .any(|proof| proof["kind"] == "user_verification"
                && proof["subject_token"] == alice.as_str()
                && proof["scopes"] == json!(["tings.subscribe"])),
        "{proofs:?}"
    );

    let event_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM hook.events")
        .fetch_one(api.owner.pool())
        .await?;
    let path = format!("/api/v3/silicons/si:cos/events/{event_id}/publication");
    let (status, publication) = api.call(Method::GET, &path, Some(&cos), None).await?;
    assert_eq!(status, StatusCode::OK, "{publication}");
    assert_eq!(
        (
            publication["state"].clone(),
            publication["recipient"].clone()
        ),
        (json!("accepted_by_ting"), json!("SCos1"))
    );
    assert_eq!(
        publication["recipient_receipt"]["read"], true,
        "{publication}"
    );

    // A custodian that hands the Silicon over stops receiving its events.
    api.accounts
        .set_custodian("SCos1", Some(("CDave4", "c:dave")));
    let moved = event(
        "evt_move",
        "silicon.custodian_changed",
        &json!({"uuid": "SCos1",
        "from": {"uuid": "CAlice1", "id": "c:alice"}, "to": {"uuid": "CDave4", "id": "c:dave"}}),
    );
    assert_eq!(api.webhook(&moved).await?.0, StatusCode::NO_CONTENT);
    assert_eq!(
        api.deliver(&endpoint, &[], b"{\"n\":2}").await?.0,
        StatusCode::OK
    );
    assert_eq!(queued(&api).await?, vec![("SCos1".to_owned(), false)]);
    Ok(())
}

#[tokio::test]
async fn without_ting_nothing_is_queued_and_the_api_says_delivery_is_off() -> Result<()> {
    let Some(api) = TestApi::start().await? else {
        return Ok(());
    };
    let (cos, alice, _) = setup(&api);
    let (_, status) = api
        .call(Method::GET, "/api/v3/delivery", Some(&cos), None)
        .await?;
    assert_eq!(status["enabled"], false);
    assert!(
        status["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("HOOK_TING_URL"))
    );
    let (_, ready) = api.call(Method::GET, "/readyz", None, None).await?;
    assert_eq!(ready["delivery"]["ting"], "disabled");
    for (path, token) in [
        ("/api/v3/delivery/recipient", &cos),
        ("/api/v3/silicons/si:cos/delivery/subscription", &alice),
    ] {
        let (status, refused) = api.call(Method::POST, path, Some(token), None).await?;
        assert_eq!(
            (status, refused["error"]["code"].clone()),
            (StatusCode::CONFLICT, json!("delivery_disabled")),
            "{path}"
        );
    }

    let endpoint = open_hook(&api, &cos).await?;
    assert_eq!(api.deliver(&endpoint, &[], b"{}").await?.0, StatusCode::OK);
    assert_eq!(queued(&api).await?, vec![]);
    let event_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM hook.events")
        .fetch_one(api.owner.pool())
        .await?;
    let (status, publication) = api
        .call(
            Method::GET,
            &format!("/api/v3/silicons/si:cos/events/{event_id}/publication"),
            Some(&cos),
            None,
        )
        .await?;
    assert_eq!(
        (status, publication["state"].clone()),
        (StatusCode::OK, json!("delivery_disabled"))
    );
    let (status, events) = api
        .call(
            Method::GET,
            "/api/v3/silicons/si:cos/events",
            Some(&cos),
            None,
        )
        .await?;
    assert_eq!(
        (status, events["items"].as_array().map(Vec::len)),
        (StatusCode::OK, Some(1)),
        "events are still kept"
    );
    Ok(())
}
