//! Exercise the actual CLI JSON contract with isolated Silicon homes.
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    process::Output,
    sync::{Arc, Mutex},
};
use tokio::process::Command;

const ENVIRONMENT: &str = "01900000-0000-7000-8000-000000000001";

struct Home(PathBuf);
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn session(actor: &str, kind: &str, org: Option<&str>, token: &str) -> Value {
    json!({"tokens":{"access_token":token,"refresh_token":match token {"revoked"=>"revoked-refresh", "repeat"=>"repeat-refresh", _=>"ort_fixture"},"token_type":"Bearer",
        "expires_in":3600,"scopes":[],"actor":{"type":kind,"id":actor},"org_id":org},
        "expires_at":4_000_000_000u64})
}

type Requests = Arc<Mutex<Vec<(String, Option<String>, Option<String>)>>>;

async fn status(State(requests): State<Requests>, headers: HeaderMap) -> axum::response::Response {
    assert_eq!(headers["silicon-hook-api-version"], "v2");
    let org = headers.get("x-org-id").and_then(|v| v.to_str().ok());
    requests.lock().unwrap().push((
        "status".into(),
        org.map(str::to_owned),
        headers
            .get("x-hook-test-key")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
    ));
    let status = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some("Bearer revoked" | "Bearer early" | "Bearer repeat") => StatusCode::UNAUTHORIZED,
        Some("Bearer forbidden") => StatusCode::FORBIDDEN,
        Some("Bearer unavailable") => StatusCode::SERVICE_UNAVAILABLE,
        _ if org.is_none() => StatusCode::BAD_REQUEST,
        _ => StatusCode::OK,
    };
    if status != StatusCode::OK {
        return (
            status,
            Json(json!({"error":{"code":"fixture_error","message":"status failed"}})),
        )
            .into_response();
    }
    Json(json!({"authenticated":true,"actor":{"type":"silicon","id":"si:testsi"},"org_id":org}))
        .into_response()
}

async fn run(
    profile: Value,
    args: &[&str],
) -> (Output, Vec<(String, Option<String>, Option<String>)>) {
    let mut command = vec!["login", "status", "--json"];
    command.extend_from_slice(args);
    run_command(profile, &command).await
}

async fn run_command(
    profile: Value,
    args: &[&str],
) -> (Output, Vec<(String, Option<String>, Option<String>)>) {
    let (output, requests, _, _) = run_details(profile, args).await;
    (output, requests)
}

async fn run_details(
    mut profile: Value,
    args: &[&str],
) -> (
    Output,
    Vec<(String, Option<String>, Option<String>)>,
    Value,
    Vec<String>,
) {
    let requests: Requests = Arc::default();
    let app =
        Router::new()
            .route(
                "/api/version",
                get(|| async {
                    Json(json!({"service":"silicon-hook","selected_api_version":"v2"}))
                }),
            )
            .route("/api/v2/auth/status", get(status))
            .route("/api/v2/auth/login", post(|State(requests): State<Requests>, headers: HeaderMap, Json(body): Json<Value>| async move {
                assert_eq!(headers["silicon-hook-api-version"], "v2");
                assert_eq!(body, json!({"slt":"fixture-slt"}));
                requests.lock().unwrap().push(("login".into(), None, None));
                Json(session("si:testsi", "silicon", Some("tos"), "oat_login")["tokens"].clone())
            }))
            .route("/api/v2/delivery/recipient", post(|State(requests): State<Requests>, body: axum::body::Bytes| async move {
                assert!(body.is_empty());
                requests.lock().unwrap().push(("register".into(), Some("tos".into()), None));
                Json(json!({"id":"sub_recipient", "app_id":"hook", "for":"si:testsi", "active":true,"required_delivery":false}))
            }))
            .route("/api/v2/silicons/si:testsi/delivery/subscription", get(|State(requests): State<Requests>| async move {
                requests.lock().unwrap().push(("receiving_status".into(), Some("tos".into()), None));
                Json(json!({"receiving":false,"subscription":null}))
            }).post(|State(requests): State<Requests>, body: axum::body::Bytes| async move {
                assert!(body.is_empty());
                requests.lock().unwrap().push(("subscribe".into(), Some("tos".into()), None));
                Json(json!({"receiving":true,"subscription":{"id":ENVIRONMENT,"org_id":"tos","silicon_id":"si:testsi","recipient_id":"c:alice","created_at":"2026-09-22T12:00:00Z"}}))
            }).delete(|State(requests): State<Requests>, body: axum::body::Bytes| async move {
                assert!(body.is_empty());
                requests.lock().unwrap().push(("unsubscribe".into(), Some("tos".into()), None));
                StatusCode::NO_CONTENT
            }))
            .route("/api/v2/silicons/si:testsi/events/{id}", get(|State(requests): State<Requests>, axum::extract::Path(id): axum::extract::Path<String>| async move {
                requests.lock().unwrap().push(("event".into(), Some("tos".into()), None));
                Json(json!({"id":id,"org_id":"tos","silicon_id":"si:testsi","hook_id":ENVIRONMENT,"provider":"Provider","summary":"Provider triggered","delivery_sequence":4,"received_at":"2026-09-22T12:00:00Z","request":{"method":"POST","url":"https://hook.example.test/provider","path":"/provider","query_string":"","headers":[],"content_type":"application/json","body":"original body","body_base64":null,"remote_ip":"127.0.0.1"}}))
            }))
            .route("/api/v2/silicons/si:testsi/events/{id}/publication", get(|State(requests): State<Requests>, axum::extract::Path(id): axum::extract::Path<String>| async move {
                requests.lock().unwrap().push(("publication".into(), Some("tos".into()), None));
                Json(json!({"event_id":id,"recipient_id":"si:testsi","state":"accepted_by_ting","delivery":"required","silent":false,"attempts":2,"ting_id":"msg_fixture","last_error_code":null,"accepted_at":"2026-09-22T12:00:00Z","next_attempt_at":"2026-09-22T12:00:00Z","expires_at":"2026-10-06T12:00:00Z","recipient_receipt":{"id":"msg_fixture","read":true,"silent":false,"delivery":"required","deliveries":[{"webhook_id":"receiver","delivery_acked":true,"read_acked":true}],"more_destinations":false},"recipient_status_error":null}))
            }))
            .route("/api/v2/silicons/si:testsi/hooks", get(|State(requests): State<Requests>, headers: HeaderMap| async move {
                assert_eq!(headers["authorization"], "Bearer oat_refreshed");
                requests.lock().unwrap().push(("list".into(), Some("tos".into()), None));
                Json(json!({"items":[]}))
            }))
            .route(
                "/api/v2/auth/refresh",
                post(
                    |State(requests): State<Requests>,
                     headers: HeaderMap,
                     Json(body): Json<Value>| async move {
                        requests.lock().unwrap().push((
                            "refresh".into(),
                            headers
                                .get("x-org-id")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned),
                            None,
                        ));
                        if body["refresh_token"] == "revoked-refresh" {
                            return (StatusCode::UNAUTHORIZED, Json(json!({"error":{"code":"invalid_token","message":"family revoked"}}))).into_response();
                        }
                        let mut tokens =
                            session("si:testsi", "silicon", None, "oat_refreshed")["tokens"]
                                .clone();
                        if body["refresh_token"] == "repeat-refresh" { tokens["access_token"] = json!("repeat"); }
                        tokens["refresh_token"] =
                            json!(format!("{}_next", body["refresh_token"].as_str().unwrap()));
                        Json(tokens).into_response()
                    },
                ),
            )
            .with_state(requests.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    profile["url"] = json!(format!("http://{}", listener.local_addr().unwrap()));
    profile["telemetry"] = json!(false);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let home = Home(std::env::temp_dir().join(format!("hook-status-{}", uuid::Uuid::new_v4())));
    let state = home.0.join(".silicon-hook");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(
        state.join("state.json"),
        json!({"profiles":{"default":profile}}).to_string(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hook"))
        .env("SILICON_HOME", &home.0)
        .env_remove("SILICON_HOOK_HOME")
        .env_remove("SILICON_HOOK_URL")
        .env_remove("SILICON_HOOK_ORG")
        .env("SILICON_HOOK_TELEMETRY", "off")
        .args(args)
        .output()
        .await
        .unwrap();
    server.abort();
    let requests = requests.lock().unwrap().clone();
    let saved = serde_json::from_slice(&std::fs::read(state.join("state.json")).unwrap()).unwrap();
    let files = std::fs::read_dir(&state)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    (output, requests, saved, files)
}

fn authenticated(output: &Output, expected: bool) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["authenticated"], expected);
    assert!(body.get("access_token").is_none());
    assert!(body.get("webhook_url").is_none());
    assert!(body.get("hooked").is_none());
}

#[tokio::test]
async fn unscoped_silicon_status_requires_explicit_organization() {
    let profile = json!({"session":session("si:testsi","silicon",None,"oat_fixture")});
    let (output, requests) = run(profile.clone(), &[]).await;
    assert!(!output.status.success());
    assert_eq!(requests, vec![("status".into(), None, None)]);
    let (output, requests) = run(profile, &["--org", "chosen"]).await;
    authenticated(&output, true);
    assert_eq!(requests[0].1.as_deref(), Some("chosen"));
}

#[tokio::test]
async fn token_org_and_profile_selection_take_precedence_over_identity() {
    let profile = json!({"session":session("c:alice","carbon",Some("token-org"),"oat_fixture")});
    let (output, requests) = run(profile.clone(), &[]).await;
    authenticated(&output, true);
    assert_eq!(requests[0].1.as_deref(), Some("token-org"));
    let mut profile = profile;
    profile["org"] = json!("selected-org");
    let (output, requests) = run(profile, &[]).await;
    authenticated(&output, true);
    assert_eq!(requests[0].1.as_deref(), Some("selected-org"));
}

#[tokio::test]
async fn test_status_uses_only_the_selected_test_sessions_context() {
    let profile = json!({"org":"production-org","session":session("si:live","silicon",Some("production-org"),"oat_production"),
        "selected_test":ENVIRONMENT,"test_keys":{ENVIRONMENT:"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"},
        "test_sessions":{ENVIRONMENT:session("si:testsi","silicon",Some("testing-org"),"oat_test")}});
    let (output, requests) = run(profile, &[]).await;
    authenticated(&output, true);
    assert_eq!(
        requests,
        vec![(
            "status".into(),
            Some("testing-org".into()),
            Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456".into())
        )]
    );
}

#[tokio::test]
async fn refresh_keeps_the_session_organization_for_the_following_status() {
    let mut saved = session("si:testsi", "silicon", Some("tos"), "oat_expired");
    saved["expires_at"] = json!(0);
    let (output, requests) = run(json!({"session":saved}), &[]).await;
    authenticated(&output, true);
    assert_eq!(
        requests,
        vec![
            ("refresh".into(), Some("tos".into()), None),
            ("status".into(), Some("tos".into()), None)
        ]
    );
}

#[tokio::test]
async fn old_or_delayed_pending_refresh_is_replayed_then_renewed_before_status() {
    for started in [Value::Null, json!(1)] {
        let mut saved = session("si:testsi", "silicon", Some("tos"), "oat_expired");
        saved["expires_at"] = json!(0);
        saved["pending_refresh_key"] = json!("original-refresh-attempt");
        saved["refresh_started_at"] = started;
        let (output, requests) = run(json!({"session":saved}), &[]).await;
        authenticated(&output, true);
        assert_eq!(
            requests
                .iter()
                .map(|request| request.0.as_str())
                .collect::<Vec<_>>(),
            ["refresh", "refresh", "status"]
        );
    }
}

#[tokio::test]
async fn absent_and_revoked_sessions_are_false_but_permission_and_service_errors_fail() {
    let (output, requests) = run(json!({}), &[]).await;
    authenticated(&output, false);
    assert!(requests.is_empty());
    let (output, requests) = run(
        json!({"session":session("si:testsi","silicon",Some("tos"),"revoked")}),
        &[],
    )
    .await;
    authenticated(&output, false);
    assert_eq!(requests.len(), 2);
    for token in ["forbidden", "unavailable"] {
        let (output, requests) = run(
            json!({"session":session("si:testsi","silicon",Some("tos"),token)}),
            &[],
        )
        .await;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(requests.len(), 1);
    }
}

#[tokio::test]
async fn early_access_rejection_renews_the_still_active_family_once() {
    let (output, requests) = run(
        json!({"session":session("si:testsi","silicon",Some("tos"),"early")}),
        &[],
    )
    .await;
    authenticated(&output, true);
    assert_eq!(
        requests.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
        ["status", "refresh", "status"]
    );
    assert!(requests.iter().all(|r| r.1.as_deref() == Some("tos")));
}

#[tokio::test]
async fn ordinary_reads_recover_before_dispatch_and_repeated_rejection_is_bounded() {
    let (output, requests) = run_command(
        json!({"session":session("si:testsi","silicon",Some("tos"),"early")}),
        &["list", "--json"],
    )
    .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        requests.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
        ["status", "refresh", "status", "list"]
    );
    let (output, requests) = run(
        json!({"session":session("si:testsi","silicon",Some("tos"),"repeat")}),
        &[],
    )
    .await;
    authenticated(&output, false);
    assert_eq!(
        requests.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
        ["status", "refresh", "status"]
    );
}

#[tokio::test]
async fn login_saves_only_session_state_and_never_creates_a_relay() {
    let (output, requests, state, files) = run_details(
        json!({}),
        &["--silicon", "si:chosen", "login", "fixture-slt", "--json"],
    )
    .await;
    authenticated(&output, true);
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["signed_in"], true);
    assert!(body.get("relay").is_none());
    assert_eq!(
        requests
            .iter()
            .map(|request| request.0.as_str())
            .collect::<Vec<_>>(),
        ["login"]
    );
    assert_eq!(state["profiles"]["default"]["silicon"], "si:chosen");
    let session = &state["profiles"]["default"]["session"];
    assert_eq!(session["tokens"]["access_token"], "oat_login");
    for field in [
        "webhook_url",
        "webhook_secret",
        "relay_token",
        "silicons",
        "isi",
        "test_destination",
    ] {
        assert!(session.get(field).is_none(), "retired field {field}");
    }
    assert!(
        files
            .iter()
            .all(|name| matches!(name.as_str(), "state.json" | "state.lock")),
        "{files:?}"
    );
}

#[tokio::test]
async fn saving_legacy_state_drops_transport_fields_but_preserves_both_session_planes() {
    let mut old = session("si:testsi", "silicon", Some("tos"), "production-access");
    for (key, value) in [
        ("webhook_url", json!("http://127.0.0.1/retired")),
        ("webhook_secret", json!("old-secret")),
        ("relay_token", json!("old-local-token")),
        ("isi", json!("old-isi")),
        ("silicons", json!(["si:testsi"])),
        ("test_destination", json!(true)),
    ] {
        old[key] = value;
    }
    let mut test = old.clone();
    test["tokens"]["access_token"] = json!("test-access");
    let profile = json!({"session":old,"test_sessions":{ENVIRONMENT:test},"test_keys":{ENVIRONMENT:"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"}});
    let (output, requests, saved, _) =
        run_details(profile, &["config", "set", "telemetry", "off", "--json"]).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(requests.is_empty());
    let profile = &saved["profiles"]["default"];
    assert_eq!(
        profile["session"]["tokens"]["access_token"],
        "production-access"
    );
    assert_eq!(
        profile["test_sessions"][ENVIRONMENT]["tokens"]["access_token"],
        "test-access"
    );
    for session in [&profile["session"], &profile["test_sessions"][ENVIRONMENT]] {
        for field in [
            "webhook_url",
            "webhook_secret",
            "relay_token",
            "silicons",
            "isi",
            "test_destination",
        ] {
            assert!(session.get(field).is_none(), "retired field {field}");
        }
    }
    assert_eq!(
        profile["test_keys"][ENVIRONMENT],
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    );
}

#[tokio::test]
async fn internal_receiving_commands_use_stateless_sdk_operations() {
    let profile = json!({"session":session("c:alice","carbon",Some("tos"),"oat_fixture")});
    for (action, recorded) in [
        ("register", "register"),
        ("status", "receiving_status"),
        ("subscribe", "subscribe"),
        ("unsubscribe", "unsubscribe"),
    ] {
        let (output, requests, _, files) = run_details(
            profile.clone(),
            &["--silicon", "si:testsi", "receiving", action, "--json"],
        )
        .await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            requests
                .iter()
                .map(|request| request.0.as_str())
                .collect::<Vec<_>>(),
            ["status", recorded]
        );
        let body: Value = serde_json::from_slice(&output.stdout).unwrap();
        match action {
            "register" => assert_eq!(body["active"], true),
            "subscribe" => assert_eq!(body["recipient_id"], "c:alice"),
            _ => assert_eq!(body["receiving"], false),
        }
        assert!(!files.iter().any(|name| name.starts_with("relay")));
    }
}

#[tokio::test]
async fn event_and_publication_inspection_preserve_original_data_and_receipt_levels() {
    let profile = json!({"session":session("si:testsi","silicon",Some("tos"),"oat_fixture")});
    for command in ["event", "publication"] {
        let (output, requests) =
            run_command(profile.clone(), &[command, ENVIRONMENT, "--json"]).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            requests
                .iter()
                .map(|request| request.0.as_str())
                .collect::<Vec<_>>(),
            ["status", command]
        );
        let body: Value = serde_json::from_slice(&output.stdout).unwrap();
        if command == "event" {
            assert_eq!(body["request"]["body"], "original body");
            assert_eq!(body["summary"], "Provider triggered");
        } else {
            assert_eq!(body["state"], "accepted_by_ting");
            assert_eq!(body["recipient_receipt"]["read"], true);
            assert_eq!(
                body["recipient_receipt"]["deliveries"][0]["read_acked"],
                true
            );
        }
    }
}
