//! A stub Silicon Accounts and a stub Hook API on one local port, and helpers
//! to run the real `hook` binary in a throwaway home.
#![allow(dead_code, reason = "each test file uses part of the support")]

use axum::{
    Form, Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    process::Output,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::AsyncWriteExt as _;

pub const SILICON: (&str, &str) = ("Sx1", "si:scout");
pub const CARBON: (&str, &str) = ("Cz9", "c:ada");

#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub authorization: Option<String>,
    pub idempotency_key: Option<String>,
    pub body: Value,
}

#[derive(Default)]
pub struct Stub {
    counter: Mutex<u64>,
    /// access token -> (uuid, id, kind)
    access: Mutex<HashMap<String, (String, String, String)>>,
    /// refresh token -> (uuid, id, kind)
    refresh: Mutex<HashMap<String, (String, String, String)>>,
    used_refresh: Mutex<HashSet<String>>,
    pub refresh_calls: Mutex<u64>,
    pub reuse_detected: Mutex<bool>,
    pub revoked: Mutex<Vec<String>>,
    pub device_script: Mutex<Vec<&'static str>>,
    pub device_polls: Mutex<u64>,
    /// access tokens Hook refuses once with 401 session_ended
    pub refuse_once: Mutex<HashSet<String>>,
    pub hook_requests: Mutex<Vec<Seen>>,
    pub slts: Mutex<Vec<String>>,
    pub refresh_delay_ms: Mutex<u64>,
}

impl Stub {
    fn issue(&self, account: (&str, &str, &str)) -> Value {
        let n = {
            let mut counter = self.counter.lock().unwrap();
            *counter += 1;
            *counter
        };
        let access = format!("at-{n}");
        let refresh = format!("sar_{n}");
        let owned = (
            account.0.to_owned(),
            account.1.to_owned(),
            account.2.to_owned(),
        );
        self.access
            .lock()
            .unwrap()
            .insert(access.clone(), owned.clone());
        self.refresh.lock().unwrap().insert(refresh.clone(), owned);
        json!({
            "access_token": access, "token_type": "Bearer", "expires_in": 1800,
            "refresh_token": refresh, "refresh_token_expires_at": "2029-03-28T02:28:25.000Z",
            "scope": "profile",
            "account": {"uuid": account.0, "membership_id": format!("hook:{}", account.0), "kind": account.2,
                "id": account.1, "display_name": "", "pfp_url": "", "version": 1}
        })
    }

    /// Registers a refresh token as valid for `account` (for sessions written by tests).
    pub fn register_refresh(&self, refresh: &str, account: (&str, &str, &str)) {
        self.refresh.lock().unwrap().insert(
            refresh.into(),
            (account.0.into(), account.1.into(), account.2.into()),
        );
    }

    pub fn register_access(&self, access: &str, account: (&str, &str, &str)) {
        self.access.lock().unwrap().insert(
            access.into(),
            (account.0.into(), account.1.into(), account.2.into()),
        );
    }

    pub fn hook_requests(&self) -> Vec<Seen> {
        self.hook_requests.lock().unwrap().clone()
    }
}

fn oauth(error: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": error, "error_description": description})),
    )
        .into_response()
}

fn hook_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({"error": {"code": code, "message": message, "request_id": "req-stub"}})),
    )
        .into_response()
}

async fn token(
    State(stub): State<Arc<Stub>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if form.get("client_id").map(String::as_str) != Some("hook") {
        return oauth("invalid_client", "Hook's CLI must send client_id=hook");
    }
    match form.get("grant_type").map(String::as_str) {
        Some("urn:ietf:params:oauth:grant-type:device_code") => {
            *stub.device_polls.lock().unwrap() += 1;
            let next = {
                let mut script = stub.device_script.lock().unwrap();
                if script.is_empty() {
                    "pending"
                } else {
                    script.remove(0)
                }
            };
            match next {
                "ok" => Json(stub.issue((CARBON.0, CARBON.1, "carbon"))).into_response(),
                "slow_down" => oauth("slow_down", "polling too fast"),
                "denied" => oauth("access_denied", "The sign-in request was denied."),
                "expired" => oauth("expired_token", "The device code expired."),
                _ => oauth("authorization_pending", "pending"),
            }
        }
        Some("urn:silicon:params:oauth:grant-type:slt") => {
            let slt = form["slt"].clone();
            stub.slts.lock().unwrap().push(slt.clone());
            if slt.starts_with("slt_ok") {
                Json(stub.issue((SILICON.0, SILICON.1, "silicon"))).into_response()
            } else if slt.starts_with("slt_used") {
                oauth(
                    "invalid_grant",
                    "The short-lived token was already used; each one works once. Get a new one.",
                )
            } else if slt.starts_with("slt_expired") {
                oauth(
                    "invalid_grant",
                    "The short-lived token expired at 2026-10-10T00:00:00.000Z (they last 120 seconds); get a new one with `silicon-accounts login --app hook`.",
                )
            } else if slt.starts_with("slt_wrong") {
                oauth(
                    "invalid_grant",
                    "The short-lived token was issued for the app 'dm', not for 'hook'; get one for 'hook' with `silicon-accounts login --app hook`.",
                )
            } else {
                oauth(
                    "invalid_grant",
                    "The short-lived token is not known: it is mistyped or was never issued.",
                )
            }
        }
        Some("refresh_token") => {
            let presented = form["refresh_token"].clone();
            let delay = *stub.refresh_delay_ms.lock().unwrap();
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            if presented == "sar_dead" {
                return oauth(
                    "invalid_grant",
                    "The sign-in this refresh token belongs to was revoked at 2026-10-07T02:35:29.652Z (access_removed); sign in again.",
                );
            }
            if stub.used_refresh.lock().unwrap().contains(&presented) {
                *stub.reuse_detected.lock().unwrap() = true;
                return oauth(
                    "invalid_grant",
                    "This refresh token was already used once. Presenting a used refresh token revokes the whole sign-in to protect the account, so this sign-in is now revoked; sign in again.",
                );
            }
            let Some(account) = stub.refresh.lock().unwrap().remove(&presented) else {
                return oauth(
                    "invalid_grant",
                    "The refresh token is not known to Silicon Accounts.",
                );
            };
            stub.used_refresh.lock().unwrap().insert(presented);
            *stub.refresh_calls.lock().unwrap() += 1;
            Json(stub.issue((&account.0, &account.1, &account.2))).into_response()
        }
        _ => oauth("unsupported_grant_type", "?"),
    }
}

async fn revoke(
    State(stub): State<Arc<Stub>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    assert_eq!(form.get("client_id").map(String::as_str), Some("hook"));
    stub.revoked.lock().unwrap().push(form["token"].clone());
    StatusCode::OK.into_response()
}

async fn device(Json(body): Json<Value>) -> Response {
    assert_eq!(body["client_id"], "hook");
    Json(json!({"device_code": "sad_device", "user_code": "WDJB-MJHT",
        "verification_uri": "http://localhost/device", "verification_uri_complete": "http://localhost/device?code=WDJB-MJHT",
        "expires_in": 600, "interval": 1}))
    .into_response()
}

fn silicon_ref() -> Value {
    json!({"uuid": SILICON.0, "id": SILICON.1})
}

pub fn hook_json(id: &str, has_secret: bool) -> Value {
    json!({
        "id": id, "silicon": silicon_ref(), "name": "GitHub", "description": null,
        "endpoint_url": format!("http://127.0.0.1/silicon/{}/ABCDEFGH", SILICON.1),
        "endpoint_key": "ABCDEFGH", "status": "active",
        "signature": {"required": true, "algorithm": "hmac-sha256", "payload": "request.raw_body",
            "signature": "request.headers[\"x-signature\"]", "signature_encoding": "hex",
            "secret_encoding": "utf8", "public_key": null, "has_secret": has_secret},
        "time_zone": "UTC", "created_by": {"uuid": SILICON.0, "kind": "silicon", "id": SILICON.1},
        "created_at": "2026-10-10T00:00:00Z", "disabled_at": null, "deleted_at": null,
        "recoverable_until": null, "last_received_at": null, "last_blocked_at": null, "endpoint_rotated_at": null
    })
}

pub const HOOK_ID: &str = "0198c21a-6330-7000-8000-000000000002";

/// Hook API v3, as much as the CLI tests need.
async fn hook_api(State(stub): State<Arc<Stub>>, request: Request<Body>) -> Response {
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().map(str::to_owned);
    let headers = request.headers().clone();
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let authorization = header("authorization");
    let idempotency_key = header("idempotency-key");
    let bytes = to_bytes(request.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if path == "/api/version" {
        return Json(json!({"service": "silicon-hook", "selected_api_version": "v3", "supported_api_versions": ["v3"], "build": "stub"})).into_response();
    }
    if path == "/api/v3/version" {
        return Json(json!({"service": "silicon-hook", "version": "1.0.0"})).into_response();
    }
    if path == "/readyz" {
        return Json(json!({"status": "ready"})).into_response();
    }
    stub.hook_requests.lock().unwrap().push(Seen {
        method: method.clone(),
        path: path.clone(),
        query,
        authorization: authorization.clone(),
        idempotency_key,
        body: body.clone(),
    });
    let token = authorization
        .as_deref()
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if stub.refuse_once.lock().unwrap().remove(token) {
        return hook_error(
            StatusCode::UNAUTHORIZED,
            "session_ended",
            "This sign-in ended at 2026-10-10T00:00:00Z.",
        );
    }
    let Some(account) = stub.access.lock().unwrap().get(token).cloned() else {
        return hook_error(
            StatusCode::UNAUTHORIZED,
            "token_expired",
            "The access token expired.",
        );
    };
    let silicon_path = |rest: &str| {
        path == format!("/api/v3/silicons/{}{rest}", SILICON.0)
            || path == format!("/api/v3/silicons/{}{rest}", SILICON.1)
    };
    match method.as_str() {
        "GET" if path == "/api/v3/auth/status" => Json(json!({"authenticated": true, "app_id": "hook", "uuid": account.0, "id": account.1, "kind": account.2})).into_response(),
        "POST" if path == "/api/v3/telemetry" => StatusCode::ACCEPTED.into_response(),
        "GET" if path == "/api/v3/silicons" => Json(json!({"items": [{"silicon": silicon_ref(), "access": if account.2 == "carbon" {"custodian"} else {"self"}, "custodian": CARBON.0}]})).into_response(),
        "GET" if path == "/api/v3/delivery" => Json(json!({"enabled": false, "reason": "Delivery through Ting is turned off on this Hook (HOOK_TING_URL is not set)."})).into_response(),
        "POST" if path == "/api/v3/delivery/recipient" => hook_error(StatusCode::CONFLICT, "delivery_disabled", "Delivery through Ting is turned off on this Hook."),
        _ if !path.starts_with(&format!("/api/v3/silicons/{}", SILICON.0)) && !path.starts_with(&format!("/api/v3/silicons/{}", SILICON.1)) => {
            hook_error(StatusCode::NOT_FOUND, "silicon_not_found", "No Silicon with that id or uuid.")
        }
        "GET" if silicon_path("/hooks") => Json(json!({"items": [hook_json(HOOK_ID, true)]})).into_response(),
        "POST" if silicon_path("/hooks") => {
            let mut created = hook_json(HOOK_ID, true);
            created["signing_secret"] = if body["signature"]["secret"].is_string() { Value::Null } else { json!("whsec_generated") };
            (StatusCode::CREATED, Json(created)).into_response()
        }
        "POST" if silicon_path("/hooks/accounts") => Json(json!({"hook": hook_json(HOOK_ID, false), "next_steps": {
            "set_webhook": format!("silicon-accounts webhook set http://127.0.0.1/silicon/{}/ABCDEFGH", SILICON.1),
            "store_secret": "PATCH ...", "explanation": "..."}})).into_response(),
        "PATCH" if silicon_path(&format!("/hooks/{HOOK_ID}")) => Json(hook_json(HOOK_ID, true)).into_response(),
        "DELETE" if silicon_path(&format!("/hooks/{HOOK_ID}")) => StatusCode::NO_CONTENT.into_response(),
        "GET" if silicon_path("/events") || silicon_path(&format!("/hooks/{HOOK_ID}/events")) => Json(json!({"items": [], "next_cursor": null})).into_response(),
        "GET" if silicon_path("/access") => Json(json!({"silicon": silicon_ref(),
            "you": {"account": {"uuid": account.0, "kind": account.2, "id": account.1}, "access": "custodian"},
            "custodian": {"uuid": CARBON.0, "kind": "carbon", "id": CARBON.1}, "grants": []})).into_response(),
        "PUT" if path.contains("/access/") => Json(json!({"silicon": silicon_ref(), "grant": {
            "account": {"uuid": "Bb2", "kind": "carbon", "id": "c:bob"}, "level": body["level"],
            "granted_by": {"uuid": account.0, "kind": account.2, "id": account.1},
            "created_at": "2026-10-10T00:00:00Z", "updated_at": "2026-10-10T00:00:00Z"}})).into_response(),
        "DELETE" if path.contains("/access/") || path.contains("/allow-list/") => StatusCode::NO_CONTENT.into_response(),
        "GET" if silicon_path("/allow-list") => Json(json!({"silicon": silicon_ref(), "items": []})).into_response(),
        "GET" if silicon_path("/delivery/subscription") => Json(json!({"receiving": false, "subscription": null})).into_response(),
        _ => hook_error(StatusCode::NOT_FOUND, "not_found", "The requested resource was not found."),
    }
}

pub struct Server {
    pub url: String,
    pub stub: Arc<Stub>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn start() -> Server {
    let stub = Arc::new(Stub::default());
    let router = Router::new()
        .route("/v1/oauth/token", axum::routing::post(token))
        .route("/v1/oauth/revoke", axum::routing::post(revoke))
        .route("/v1/device/authorize", axum::routing::post(device))
        .fallback(hook_api)
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("address"));
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("stub");
    });
    Server { url, stub, task }
}

/// A throwaway home directory (HOME and SILICON_HOME).
pub struct Home(pub PathBuf);

impl Home {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("hook-cli-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("home");
        Self(dir)
    }

    pub fn state_dir(&self) -> PathBuf {
        self.0.join(".silicon-hook")
    }

    pub fn state(&self) -> Value {
        serde_json::from_slice(
            &std::fs::read(self.state_dir().join("profiles.json")).expect("state"),
        )
        .expect("json")
    }

    pub fn write_state(&self, value: &Value) {
        std::fs::create_dir_all(self.state_dir()).expect("dir");
        std::fs::write(
            self.state_dir().join("profiles.json"),
            serde_json::to_vec_pretty(value).expect("json"),
        )
        .expect("write");
    }

    /// A saved session for `account` with the given tokens and expiry offset.
    pub fn write_session(
        &self,
        server: &Server,
        account: (&str, &str, &str),
        access: &str,
        refresh: &str,
        expires_in: i64,
    ) {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_secs(),
        )
        .expect("i64");
        self.write_state(
            &json!({"schema": 1, "profiles": {"default": {"telemetry": true, "session": {
                "app_id": "hook", "accounts_url": server.url, "url": server.url,
                "access_token": access, "refresh_token": refresh, "expires_at": now + expires_in,
                "refresh_expires_at": now + 86_400, "scope": "profile",
                "account": {"uuid": account.0, "kind": account.2, "id": account.1},
                "method": "slt", "signed_in_at": now
            }}}}),
        );
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub struct Run {
    pub output: Output,
}

impl Run {
    pub fn code(&self) -> i32 {
        self.output.status.code().unwrap_or(-1)
    }
    pub fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.output.stdout).into_owned()
    }
    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr).into_owned()
    }
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.output.stdout).unwrap_or_else(|e| {
            panic!(
                "stdout is not JSON ({e}): {}\nstderr: {}",
                self.stdout(),
                self.stderr()
            )
        })
    }
    pub fn error(&self) -> Value {
        let line = self
            .stderr()
            .lines()
            .find(|l| l.starts_with('{'))
            .map(str::to_owned)
            .unwrap_or_default();
        serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("stderr has no JSON error ({e}): {}", self.stderr()))
    }
}

pub async fn hook_env(
    home: Option<&Path>,
    env: &[(&str, &str)],
    args: &[&str],
    stdin: Option<&str>,
) -> Run {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_hook"));
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("SILICON_HOOK_TELEMETRY", "off");
    if let Some(home) = home {
        command
            .env("HOME", home)
            .env("SILICON_HOME", home)
            .current_dir(home);
    }
    for (name, value) in env {
        command.env(name, value);
    }
    command
        .stdin(if stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().expect("spawn hook");
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(input.as_bytes()).await.expect("write stdin");
        drop(pipe);
    }
    let output = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .expect("hook finished in time")
        .expect("hook output");
    Run { output }
}

/// Runs `hook` against the stub in `home`.
pub async fn hook(home: &Home, server: &Server, args: &[&str], stdin: Option<&str>) -> Run {
    hook_env(
        Some(&home.0),
        &[
            ("ACCOUNTS_URL", &server.url),
            ("SILICON_HOOK_URL", &server.url),
        ],
        args,
        stdin,
    )
    .await
}
