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
    json!({"tokens":{"access_token":token,"refresh_token":"ort_fixture","token_type":"Bearer",
        "expires_in":3600,"scopes":[],"actor":{"type":kind,"id":actor},"org_id":org},
        "expires_at":4_000_000_000u64})
}

type Requests = Arc<Mutex<Vec<(String, Option<String>, Option<String>)>>>;

async fn status(State(requests): State<Requests>, headers: HeaderMap) -> axum::response::Response {
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
        Some("Bearer revoked") => StatusCode::UNAUTHORIZED,
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
    Json(json!({"authenticated":true,"actor":{"type":"silicon","id":"testsi:tos"},"org_id":org}))
        .into_response()
}

async fn run(
    mut profile: Value,
    args: &[&str],
) -> (Output, Vec<(String, Option<String>, Option<String>)>) {
    let requests: Requests = Arc::default();
    let app = Router::new()
        .route(
            "/api/version",
            get(|| async { Json(json!({"service":"silicon-hook","selected_api_version":"v1"})) }),
        )
        .route("/api/v1/auth/status", get(status))
        .route(
            "/api/v1/auth/refresh",
            post(
                |State(requests): State<Requests>, headers: HeaderMap| async move {
                    requests.lock().unwrap().push((
                        "refresh".into(),
                        headers
                            .get("x-org-id")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned),
                        None,
                    ));
                    Json(session("testsi:tos", "silicon", None, "oat_refreshed")["tokens"].clone())
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
        .args(["login", "status", "--json"])
        .args(args)
        .output()
        .await
        .unwrap();
    server.abort();
    let requests = requests.lock().unwrap().clone();
    (output, requests)
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
}

#[tokio::test]
async fn unscoped_silicon_status_resolves_its_organization_and_checks_online() {
    let profile = json!({"session":session("testsi:tos","silicon",None,"oat_fixture")});
    let (output, requests) = run(profile.clone(), &[]).await;
    authenticated(&output, true);
    assert_eq!(requests, vec![("status".into(), Some("tos".into()), None)]);
    let (output, requests) = run(profile, &["--org", "chosen"]).await;
    authenticated(&output, true);
    assert_eq!(requests[0].1.as_deref(), Some("chosen"));
}

#[tokio::test]
async fn token_org_and_profile_selection_take_precedence_over_identity() {
    let profile = json!({"session":session("alice","carbon",Some("token-org"),"oat_fixture")});
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
    let profile = json!({"org":"production-org","session":session("live:production-org","silicon",None,"oat_production"),
        "selected_test":ENVIRONMENT,"test_keys":{ENVIRONMENT:"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"},
        "test_sessions":{ENVIRONMENT:session("testsi:testing-org","silicon",None,"oat_test")}});
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
async fn refresh_keeps_the_inferred_organization_for_the_following_status() {
    let mut saved = session("testsi:tos", "silicon", None, "oat_expired");
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
async fn absent_and_revoked_sessions_are_false_but_permission_and_service_errors_fail() {
    let (output, requests) = run(json!({}), &[]).await;
    authenticated(&output, false);
    assert!(requests.is_empty());
    let (output, requests) = run(
        json!({"session":session("testsi:tos","silicon",None,"revoked")}),
        &[],
    )
    .await;
    authenticated(&output, false);
    assert_eq!(requests.len(), 1);
    for token in ["forbidden", "unavailable"] {
        let (output, requests) = run(
            json!({"session":session("testsi:tos","silicon",None,token)}),
            &[],
        )
        .await;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(requests.len(), 1);
    }
}
