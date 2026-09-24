//! CLI file handoff preserves explicit receiver operations and never prints tokens.

use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response},
};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    process::Output,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};
use tokio::{process::Command, sync::Mutex};

const ENVIRONMENT: &str = "01900000-0000-7000-8000-000000000001";
const ORGANIZATION: &str = "01900000-0000-7000-8000-000000000002";
type CapturedRequest = (String, HeaderMap, Vec<u8>);

fn scope() -> Value {
    json!({"app_id":"hook","for":"si:worker","kind":"silicon","org_id":ORGANIZATION,"hook_org_id":"tos","environment":{"kind":"testing","id":ENVIRONMENT,"generation":7}})
}
fn token() -> String {
    format!("ting_recv_{}", "a".repeat(64))
}
fn capability() -> Value {
    let mut value = scope();
    value["receiver_id"] = json!("recv_fixture");
    value["receiver_token"] = json!(token());
    value["expires_at"] = json!("2026-09-22T12:00:00Z");
    value
}

#[derive(Clone)]
struct Fixture {
    calls: Arc<Mutex<Vec<CapturedRequest>>>,
    status: Arc<AtomicU16>,
    scope: Arc<Mutex<Value>>,
}
struct Server {
    home: PathBuf,
    fixture: Fixture,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl Server {
    async fn start() -> Self {
        let fixture = Fixture {
            calls: Arc::default(),
            status: Arc::new(AtomicU16::new(200)),
            scope: Arc::new(Mutex::new(scope())),
        };
        let app = Router::new().fallback(handle).with_state(fixture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        let home = std::env::temp_dir().join(format!("hook-receiving-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(home.join(".silicon-hook")).unwrap();
        let session = json!({"tokens":{"access_token":"test-actor-access","refresh_token":"test-actor-refresh","token_type":"Bearer","expires_in":3600,"scopes":[],"actor":{"type":"silicon","id":"si:worker"},"org_id":"tos"},"expires_at":4_000_000_000u64});
        std::fs::write(home.join(".silicon-hook/state.json"),json!({"profiles":{"default":{"url":url,"telemetry":false,"selected_test":ENVIRONMENT,
            "test_app_secrets":{ENVIRONMENT:format!("ask_{}","b".repeat(43))},"test_orgs":{ENVIRONMENT:"tos"},"test_names":{ENVIRONMENT:"Receiver sandbox"},
            "test_sessions":{ENVIRONMENT:session}}}}).to_string()).unwrap();
        std::fs::write(home.join("scope.json"), scope().to_string()).unwrap();
        Self {
            home,
            fixture,
            task,
        }
    }
    async fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hook"))
            .env("SILICON_HOME", &self.home)
            .env_remove("SILICON_HOOK_HOME")
            .env_remove("SILICON_HOOK_URL")
            .env_remove("SILICON_HOOK_ORG")
            .env("SILICON_HOOK_TELEMETRY", "off")
            .args(args)
            .output()
            .await
            .unwrap()
    }
    async fn bootstrap(
        &self,
        path: &std::path::Path,
        key: Option<&str>,
        receiver: Option<&str>,
        production: bool,
    ) -> Output {
        let scope = self.home.join("scope.json");
        let mut args = vec!["--json"];
        if production {
            args.push("--production");
        }
        if let Some(key) = key {
            args.extend(["--idempotency-key", key]);
        }
        args.extend([
            "receiving",
            "bootstrap",
            "--scope-file",
            scope.to_str().unwrap(),
            "--output",
            path.to_str().unwrap(),
        ]);
        if let Some(id) = receiver {
            args.extend(["--receiver-id", id]);
        }
        self.run(&args).await
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.home);
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
    let value = match (parts.method.as_str(), path) {
        ("GET", "/api/version") => json!({"service":"silicon-hook","selected_api_version":"v2"}),
        ("GET", "/api/v2/auth/status") => {
            json!({"authenticated":true,"actor":{"type":"silicon","id":"si:worker"},"org_id":"tos"})
        }
        ("POST", "/api/v2/auth/login") => {
            json!({"access_token":"test-actor-access","refresh_token":"test-actor-refresh","token_type":"Bearer","expires_in":3600,"scopes":[],"actor":{"type":"silicon","id":"si:worker"},"org_id":"tos"})
        }
        ("GET", "/api/v2/auth/iam") => {
            json!({"app_id":"hook","iam_url":"https://iam.example","testing":true,"login_method":"slt"})
        }
        ("GET", "/api/v2/testing-session") => {
            json!({"id":ENVIRONMENT,"org_id":"tos","name":"Receiver sandbox","creator_kind":"carbon","creator_id":"admin","description":null,"generation":99,"created_at":"2026-09-22T10:00:00Z","last_activity_at":"2026-09-22T10:00:00Z","deleted_at":null})
        }
        ("GET", "/api/v2/delivery/receiver") => fixture.scope.lock().await.clone(),
        ("POST", "/api/v2/delivery/receiver") => {
            let status = StatusCode::from_u16(fixture.status.load(Ordering::SeqCst)).unwrap();
            if status != StatusCode::OK {
                return (status,Json(json!({"error":{"code":"receiver_unavailable","message":"Receiver unavailable"}}))).into_response();
            }
            capability()
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    Json(value).into_response()
}

fn assert_redacted(output: &Output) {
    for secret in [
        token(),
        "test-actor-access".into(),
        "test-actor-refresh".into(),
        format!("ask_{}", "b".repeat(43)),
    ] {
        assert!(!String::from_utf8_lossy(&output.stdout).contains(&secret));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(&secret));
    }
    assert!(String::from_utf8_lossy(&output.stderr).contains("TEST ENVIRONMENT: Receiver sandbox"));
}

#[tokio::test]
async fn env_use_binds_a_fresh_profile_to_the_verified_backend_and_preserves_binding() {
    let server = Server::start().await;
    let state = server.home.join(".silicon-hook/state.json");
    let existing: Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    let url = existing["profiles"]["default"]["url"]
        .as_str()
        .unwrap()
        .to_owned();
    std::fs::write(&state, br#"{"profiles":{}}"#).unwrap();
    let secret = server.home.join("test-app.secret");
    std::fs::write(&secret, format!("ask_{}", "b".repeat(43))).unwrap();
    let selected = server
        .run(&[
            "--url",
            &url,
            "--json",
            "env",
            "use",
            "--app-secret-file",
            secret.to_str().unwrap(),
        ])
        .await;
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    assert_redacted(&selected);
    let saved: Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    assert_eq!(saved["profiles"]["default"]["url"], format!("{url}/"));
    assert_eq!(
        saved["profiles"]["default"]["test_orgs"][ENVIRONMENT],
        "tos"
    );
    assert!(
        saved["profiles"]["default"]["org"].is_null(),
        "test selection must not replace production org context"
    );

    let login = server
        .run(&[
            "--url",
            &url,
            "--json",
            "login",
            "fixture-slt",
            "--org",
            "tos",
        ])
        .await;
    assert!(
        login.status.success(),
        "{}",
        String::from_utf8_lossy(&login.stderr)
    );
    assert_redacted(&login);
    let status = server.run(&["--json", "login", "status"]).await;
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert_redacted(&status);
    assert_eq!(
        serde_json::from_slice::<Value>(&status.stdout).unwrap()["authenticated"],
        true
    );

    let before = std::fs::read(&state).unwrap();
    let calls_before = server.fixture.calls.lock().await.len();
    let refused = server
        .run(&[
            "--url",
            "http://127.0.0.1:1",
            "--json",
            "env",
            "use",
            "--app-secret-file",
            secret.to_str().unwrap(),
        ])
        .await;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("bound to a different backend"));
    assert_redacted(&refused);
    assert_eq!(server.fixture.calls.lock().await.len(), calls_before);
    assert_eq!(std::fs::read(&state).unwrap(), before);
}

#[tokio::test]
async fn scope_prints_only_validated_authority_with_the_test_footer() {
    let server = Server::start().await;
    let output = server.run(&["--json", "receiving", "scope"]).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        scope()
    );
    assert_redacted(&output);
    assert!(
        server
            .fixture
            .calls
            .lock()
            .await
            .iter()
            .all(|(path, _, _)| !path.starts_with("POST"))
    );
}

#[tokio::test]
async fn retry_keeps_pinned_body_and_key_and_writes_only_a_private_file() {
    let server = Server::start().await;
    let failed_path = server.home.join("failed.json");
    server.fixture.status.store(503, Ordering::SeqCst);
    let failed = server
        .bootstrap(&failed_path, Some("receiver-original-key"), None, false)
        .await;
    assert!(!failed.status.success());
    assert_redacted(&failed);
    #[cfg(unix)]
    assert!(!failed_path.exists());
    #[cfg(windows)]
    assert_eq!(std::fs::metadata(&failed_path).unwrap().len(), 0);
    server.fixture.status.store(200, Ordering::SeqCst);
    server.fixture.scope.lock().await["environment"]["generation"] = json!(8);
    let output_path = server.home.join("capability.json");
    let output = server
        .bootstrap(&output_path, Some("receiver-original-key"), None, false)
        .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_redacted(&output);
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(&output_path).unwrap()).unwrap(),
        capability()
    );
    let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        metadata,
        json!({"scope":scope(),"receiver_id":"recv_fixture","expires_at":"2026-09-22T12:00:00Z","output":output_path})
    );
    assert!(metadata.get("ready").is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&output_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let calls = server.fixture.calls.lock().await;
    assert!(
        calls
            .iter()
            .all(|(path, _, _)| path != "GET /api/v2/delivery/receiver"),
        "bootstrap must not fetch a different scope"
    );
    let posts: Vec<_> = calls
        .iter()
        .filter(|(path, _, _)| path.starts_with("POST"))
        .collect();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[0].2, posts[1].2);
    for (_, headers, body) in posts {
        assert_eq!(headers["idempotency-key"], "receiver-original-key");
        assert_eq!(headers["authorization"], "Bearer test-actor-access");
        assert_eq!(
            headers["x-hook-test-app-secret"],
            format!("ask_{}", "b".repeat(43))
        );
        assert_eq!(
            serde_json::from_slice::<Value>(body).unwrap(),
            json!({"environment_id":ENVIRONMENT,"generation":7})
        );
    }
    let profile = std::fs::read_to_string(server.home.join(".silicon-hook/state.json")).unwrap();
    assert!(!profile.contains("ting_recv_"));
    assert!(!profile.contains("recv_fixture"));
}

#[tokio::test]
async fn explicit_renewal_keeps_receiver_identity_and_uses_the_supplied_new_key() {
    let server = Server::start().await;
    for (file, key, id) in [
        ("first.json", "create-operation", None),
        ("renewal.json", "renew-operation", Some("recv_fixture")),
    ] {
        let output = server
            .bootstrap(&server.home.join(file), Some(key), id, false)
            .await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_redacted(&output);
    }
    let calls = server.fixture.calls.lock().await;
    let posts: Vec<_> = calls
        .iter()
        .filter(|(path, _, _)| path.starts_with("POST"))
        .collect();
    assert_eq!(posts.len(), 2);
    assert_eq!(posts[1].1["idempotency-key"], "renew-operation");
    assert_eq!(
        serde_json::from_slice::<Value>(&posts[1].2).unwrap(),
        json!({"environment_id":ENVIRONMENT,"generation":7,"receiver_id":"recv_fixture"})
    );
}

#[tokio::test]
async fn missing_key_production_and_existing_output_fail_before_bootstrap() {
    let server = Server::start().await;
    let path = server.home.join("reserved.json");
    let output = server.bootstrap(&path, None, None, false).await;
    assert!(!output.status.success());
    assert_redacted(&output);
    assert!(!path.exists());
    let production = server
        .bootstrap(&path, Some("production-denied"), None, true)
        .await;
    assert!(!production.status.success());
    assert!(!path.exists());
    assert!(!String::from_utf8_lossy(&production.stdout).contains("ting_recv_"));
    std::fs::write(&path, b"existing-content").unwrap();
    let output = server
        .bootstrap(&path, Some("existing-output"), None, false)
        .await;
    assert!(!output.status.success());
    assert_redacted(&output);
    assert_eq!(std::fs::read(&path).unwrap(), b"existing-content");
    assert!(server.fixture.calls.lock().await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_output_is_never_followed_or_overwritten() {
    let server = Server::start().await;
    let original = server.home.join("original.json");
    std::fs::write(&original, b"keep-me").unwrap();
    let link = server.home.join("link.json");
    std::os::unix::fs::symlink(&original, &link).unwrap();
    let output = server
        .bootstrap(&link, Some("symlink-denied"), None, false)
        .await;
    assert!(!output.status.success());
    assert_redacted(&output);
    assert_eq!(std::fs::read(&original).unwrap(), b"keep-me");
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(server.fixture.calls.lock().await.is_empty());
}
