use axum::{
    Json, Router,
    extract::{State, WebSocketUpgrade, ws::Message},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use silicon_hook_client::{Client, LoginOptions, Mutation};
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, mpsc};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone)]
struct Fixture {
    notices: mpsc::UnboundedSender<String>,
    login_bodies: Arc<Mutex<Vec<Value>>>,
}

async fn server(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, task)
}

async fn notice(rx: &mut mpsc::UnboundedReceiver<String>, expected: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let message = rx.recv().await.expect("fixture closed");
            if message == expected {
                break;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("missing {expected}"));
}

async fn stream(ws: WebSocketUpgrade, State(f): State<Fixture>) -> impl IntoResponse {
    ws.on_upgrade(move |mut socket| async move {
        let _ = f.notices.send("connected".into());
        let ping = json!({"type":"ping","ping_id":"heartbeat-1"});
        let event = json!({"type":"new_event", "data":{"sender":"demo",
            "metadata":{"id":"00000000-0000-4000-8000-000000000001", "org_id":"tos",
                "silicon_id":"cos:tos","hook_id":"00000000-0000-4000-8000-000000000002",
                "provider":"demo","summary":"demo triggered", "delivery_sequence":1,
                "received_at":"2026-09-09T00:00:00Z", "request":{"method":"POST",
                    "url":"https://hook.example.test/silicon/cos:tos/ABCDEFGH", "path":"/silicon/cos:tos/ABCDEFGH",
                    "query_string":"","headers":[],"content_type":"application/json",
                    "body":"{\"example\":true}","body_base64":null,"remote_ip":"127.0.0.1"}}}});
        for frame in [ping, event] {
            if socket.send(Message::Text(frame.to_string().into())).await.is_err() { return; }
        }
        while let Some(Ok(message)) = socket.recv().await {
            if let Message::Text(text) = message {
                let value: Value = serde_json::from_str(&text).unwrap();
                let kind = value["type"].as_str().unwrap();
                if kind == "pong" { assert_eq!(value["ping_id"], "heartbeat-1"); }
                if kind == "ack" {
                    assert_eq!(value["silicon_id"], "cos:tos");
                    assert_eq!(value["through_sequence"], 1);
                }
                let _ = f.notices.send(kind.into());
            }
        }
        let _ = f.notices.send("disconnected".into());
    })
}

#[tokio::test]
async fn authenticate_then_attach_detach_and_replay_without_leaking_destination() -> TestResult {
    let (tx, mut notices) = mpsc::unbounded_channel();
    let fixture = Fixture {
        notices: tx,
        login_bodies: Arc::default(),
    };
    let app = Router::new()
        .route("/api/version", get(|| async { Json(json!({"service":"silicon-hook", "selected_api_version":"v1"})) }))
        .route("/api/v1/auth/login", post(|State(f): State<Fixture>, Json(body): Json<Value>| async move {
            f.login_bodies.lock().await.push(body);
            Json(json!({"access_token":"oat_test", "refresh_token":"ort_test", "token_type":"Bearer",
                "expires_in":3600, "scopes":[], "actor":{"type":"silicon","id":"cos:tos"}, "org_id":"tos"}))
        }))
        .route("/api/v1/auth/iam", get(|headers: HeaderMap| async move {
            assert_eq!(headers["x-hook-test-key"], "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
            Json(json!({"app_id":"test>hook", "iam_url":"https://iam.example.test", "testing":true, "login_method":"short_lived_token"}))
        }))
        .route("/api/v1/auth/status", get(|headers: HeaderMap| async move {
            assert_eq!(headers["x-org-id"], "tos");
            if headers["authorization"] == "Bearer revoked" {
                return (StatusCode::UNAUTHORIZED, Json(json!({"error":{"code":"unauthenticated","message":"revoked"}}))).into_response();
            }
            Json(json!({"authenticated":true,"actor":{"type":"silicon","id":"cos:tos"},"org_id":"tos"})).into_response()
        }))
        .route("/api/v1/ws", get(stream))
        .route("/failing", post(|State(f): State<Fixture>| async move {
            let _ = f.notices.send("failed_delivery".into());
            StatusCode::SERVICE_UNAVAILABLE
        }))
        .route("/recipient", post(|State(f): State<Fixture>, headers: HeaderMap, Json(body): Json<Value>| async move {
            assert_eq!(body.as_object().map(serde_json::Map::len), Some(3));
            assert_eq!(body["metadata"]["app"], "tos>hook");
            assert_eq!(body["metadata"]["event_id"], body["data"]["metadata"]["id"]);
            assert_eq!(body["metadata"]["delivery_sequence"], 1);
            assert_eq!(body["type"], "new_event");
            assert_eq!(body["data"].as_object().map(serde_json::Map::len), Some(2));
            assert_eq!(body["data"]["sender"], "demo");
            let event = &body["data"]["metadata"];
            assert_eq!(event["silicon_id"], "cos:tos");
            assert_eq!(event["delivery_sequence"], 1);
            assert_eq!(event["summary"], "demo triggered");
            assert_eq!(event["request"]["body"], "{\"example\":true}");
            assert_eq!(headers["silicon-hook-event-id"], event["id"].as_str().unwrap());
            assert_eq!(headers["silicon-hook-delivery-sequence"], "1");
            let _ = f.notices.send("delivered".into());
            StatusCode::NO_CONTENT
        }))
        .route("/silicon-recipient", post(|State(f): State<Fixture>, headers: HeaderMap, Json(body): Json<Value>| async move {
            assert!(headers["host"].to_str().unwrap().starts_with("cos.tos.localhost:"));
            assert_eq!(body["type"], "new_event");
            assert!(body["data"].is_object());
            assert_eq!(body["metadata"]["app"], "tos>hook");
            assert_eq!(body["metadata"]["event_id"], body["data"]["metadata"]["id"]);
            let _ = f.notices.send("silicon-delivered".into());
            Json(json!({"status":"ok", "event_id":"00000000-0000-4000-8000-000000000099"}))
        }))
        .with_state(fixture.clone());
    let (url, server_task) = server(app).await;
    let base = Client::new(&url)?.with_auto_update(false);
    let test = base.with_test_key("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")?;
    assert_eq!(test.iam().await?.app_id.as_deref(), Some("test>hook"));
    assert!(!base.login_status().await?.authenticated);
    assert!(
        !base
            .with_token("revoked")
            .with_organization("tos")
            .login_status()
            .await?
            .authenticated
    );
    let port = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await?
        .local_addr()?
        .port();
    let options = LoginOptions {
        port,
        ..LoginOptions::default()
    };
    let session = base
        .login_with_options("opaque-slt", &options, &Mutation::new())
        .await?;
    assert!(session.recipient().is_none());
    assert!(session.health().await.is_ok());
    assert!(session.client().login_status().await?.authenticated);
    assert!(
        notices.try_recv().is_err(),
        "no stream before recipient configuration"
    );
    assert_eq!(
        *fixture.login_bodies.lock().await,
        vec![json!({"slt":"opaque-slt"})]
    );
    session.webhook(&format!("{url}/failing"))?;
    notice(&mut notices, "failed_delivery").await;
    session.unhook();
    assert!(session.recipient().is_none());
    notice(&mut notices, "disconnected").await;
    assert!(session.health().await.is_ok());
    assert!(
        session
            .webhook("https://user:password@example.com/events")
            .is_err()
    );
    session.webhook(&format!("{url}/recipient"))?;
    notice(&mut notices, "delivered").await;
    notice(&mut notices, "ack").await;
    session.unhook();
    notice(&mut notices, "disconnected").await;
    let port = url::Url::parse(&url)?.port().unwrap();
    session.webhook(&format!(
        "http://cos.tos.localhost:{port}/silicon-recipient"
    ))?;
    notice(&mut notices, "silicon-delivered").await;
    notice(&mut notices, "ack").await;
    session.shutdown().await?;
    server_task.abort();
    Ok(())
}
