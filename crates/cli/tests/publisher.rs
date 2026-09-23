//! Exercise org-scoped publisher provisioning through the real CLI binary.

use std::{
    path::PathBuf,
    process::{Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse as _,
    routing::{get, post},
};
use serde_json::{Value, json};
use tokio::{io::AsyncWriteExt as _, process::Command, sync::Mutex};

const SLT: &str = "fixture-dedicated-publisher-slt";

#[derive(Clone, Default)]
struct Fixture {
    calls: Arc<Mutex<Vec<(HeaderMap, Value)>>>,
    status: Arc<AtomicU16>,
}

struct Server {
    home: PathBuf,
    fixture: Fixture,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Server {
    async fn start() -> Self {
        let fixture = Fixture::default();
        fixture.status.store(200, Ordering::SeqCst);
        let app = Router::new()
            .route(
                "/api/version",
                get(|| async {
                    Json(json!({"service":"silicon-hook","selected_api_version":"v2"}))
                }),
            )
            .route(
                "/api/v2/auth/status",
                get(|headers: HeaderMap| async move {
                    assert_eq!(headers["authorization"], "Bearer admin-access");
                    assert_eq!(headers["x-org-id"], "tos");
                    Json(json!({"authenticated":true,"actor":{"type":"carbon","id":"admin"},"org_id":"tos"}))
                }),
            )
            .route(
                "/api/v2/delivery/publisher",
                post(|State(fixture): State<Fixture>, headers: HeaderMap, Json(body): Json<Value>| async move {
                    fixture.calls.lock().await.push((headers, body));
                    let status = StatusCode::from_u16(fixture.status.load(Ordering::SeqCst)).unwrap();
                    if status != StatusCode::OK {
                        return (status, Json(json!({"error":{"code":"forbidden","message":"Carbon owner/admin required"}}))).into_response();
                    }
                    Json(json!({"org_id":"tos","actor_id":"si:hook-publisher","expires_at":"2026-09-24T00:00:00Z",
                        "access_token":"unexpected-server-secret"})).into_response()
                }),
            )
            .with_state(fixture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        let home = std::env::temp_dir().join(format!("hook-publisher-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(home.join(".silicon-hook")).unwrap();
        let session = json!({"tokens":{"access_token":"admin-access","refresh_token":"admin-refresh",
            "token_type":"Bearer","expires_in":3600,"scopes":[],"actor":{"type":"carbon","id":"admin"},"org_id":"tos"},
            "expires_at":4_000_000_000u64});
        std::fs::write(
            home.join(".silicon-hook/state.json"),
            json!({"profiles":{"default":{"url":url,"org":"tos","telemetry":false,"session":session}}}).to_string(),
        ).unwrap();
        std::fs::write(home.join("publisher.slt"), format!("{SLT}\n")).unwrap();
        Self {
            home,
            fixture,
            task,
        }
    }

    async fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hook"));
        command
            .env("SILICON_HOME", &self.home)
            .env_remove("SILICON_HOOK_HOME")
            .env_remove("SILICON_HOOK_URL")
            .env_remove("SILICON_HOOK_ORG")
            .env("SILICON_HOOK_TELEMETRY", "off")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(args);
        let mut child = command.spawn().unwrap();
        if let Some(input) = stdin {
            let mut writer = child.stdin.take().unwrap();
            writer.write_all(input).await.unwrap();
            writer.shutdown().await.unwrap();
        }
        child.wait_with_output().await.unwrap()
    }

    fn saved(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.home.join(".silicon-hook/state.json")).unwrap())
            .unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn assert_safe_metadata(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({"org_id":"tos","actor_id":"si:hook-publisher","expires_at":"2026-09-24T00:00:00Z"})
    );
    for secret in [
        SLT,
        "admin-access",
        "admin-refresh",
        "unexpected-server-secret",
    ] {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
    }
}

#[tokio::test]
async fn admin_can_provision_and_retry_from_file_without_silicon_selection() {
    let server = Server::start().await;
    let path = server.home.join("publisher.slt");
    let args = [
        "--json",
        "--idempotency-key",
        "publisher-fixture-retry",
        "publisher",
        "provision",
        "--slt-file",
        path.to_str().unwrap(),
    ];
    let session_before = server.saved()["profiles"]["default"]["session"].clone();
    for _ in 0..2 {
        assert_safe_metadata(&server.run(&args, None).await);
    }
    let calls = server.fixture.calls.lock().await;
    assert_eq!(calls.len(), 2);
    for (headers, body) in calls.iter() {
        assert_eq!(headers["authorization"], "Bearer admin-access");
        assert_eq!(headers["x-org-id"], "tos");
        assert_eq!(headers["idempotency-key"], "publisher-fixture-retry");
        assert_eq!(headers["silicon-hook-api-version"], "v2");
        assert_eq!(body, &json!({"slt":SLT,"replace_rejected":false}));
    }
    let saved = server.saved();
    assert_eq!(saved["profiles"]["default"]["session"], session_before);
    assert!(!saved.to_string().contains(SLT));
    assert!(!saved.to_string().contains("unexpected-server-secret"));
}

#[tokio::test]
async fn explicit_recovery_reads_slt_from_stdin() {
    let server = Server::start().await;
    let output = server
        .run(
            &[
                "publisher",
                "provision",
                "--slt-file",
                "-",
                "--replace-rejected",
                "--idempotency-key",
                "publisher-recovery",
                "--json",
            ],
            Some(format!("{SLT}\r\n").as_bytes()),
        )
        .await;
    assert_safe_metadata(&output);
    let calls = server.fixture.calls.lock().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0["idempotency-key"], "publisher-recovery");
    assert_eq!(calls[0].1, json!({"slt":SLT,"replace_rejected":true}));
}

#[tokio::test]
async fn provisioning_requires_explicit_retry_key_before_reading_slt() {
    let server = Server::start().await;
    let output = server
        .run(
            &[
                "publisher",
                "provision",
                "--slt-file",
                "/missing/publisher.slt",
            ],
            None,
        )
        .await;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--idempotency-key"));
    assert!(!stderr.contains("could not read"));
    assert!(server.fixture.calls.lock().await.is_empty());
}

#[tokio::test]
async fn insufficient_org_authority_is_reported_without_recovery_or_secret_output() {
    let server = Server::start().await;
    server.fixture.status.store(403, Ordering::SeqCst);
    let path = server.home.join("publisher.slt");
    let output = server
        .run(
            &[
                "--json",
                "--idempotency-key",
                "publisher-denied",
                "publisher",
                "provision",
                "--slt-file",
                path.to_str().unwrap(),
            ],
            None,
        )
        .await;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("forbidden"));
    assert!(stderr.contains("Carbon owner/admin required"));
    assert!(!stderr.contains(SLT));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SLT));
    let calls = server.fixture.calls.lock().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1["replace_rejected"], false);
}
