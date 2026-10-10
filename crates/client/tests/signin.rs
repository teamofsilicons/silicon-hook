//! Signing in as Hook's public client against a stub Silicon Accounts:
//! device flow, short-lived token exchange, refresh rotation and revoke.

use axum::{
    Form, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use serde_json::{Value, json};
use silicon_hook_client::{
    Error,
    models::AccountKind,
    signin::{DeviceEvent, SignIn, SignInErrorKind, SltRefusal},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct Accounts {
    /// Every form posted to the token and revoke endpoints.
    forms: Mutex<Vec<(String, HashMap<String, String>)>>,
    /// Scripted answers for each device code, consumed in order.
    device_script: Mutex<HashMap<String, Vec<&'static str>>>,
    poll_times: Mutex<Vec<Instant>>,
    device_expires_in: Mutex<u64>,
    authorization_headers: Mutex<Vec<String>>,
}

fn tokens(refresh: &str) -> Value {
    json!({
        "access_token": format!("at-for-{refresh}"),
        "token_type": "Bearer",
        "expires_in": 1800,
        "refresh_token": refresh,
        "refresh_token_expires_at": "2029-03-28T02:28:25.000Z",
        "scope": "profile",
        "membership_id": "hook:Sx1",
        "account": {"uuid": "Sx1", "membership_id": "hook:Sx1", "kind": "silicon", "id": "si:scout",
            "display_name": "Scout", "pfp_url": "", "custodian": {"uuid": "Cz9", "id": "c:ada"}, "version": 3}
    })
}

fn oauth(error: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": error, "error_description": description})),
    )
        .into_response()
}

async fn device_authorize(State(state): State<Arc<Accounts>>, Json(body): Json<Value>) -> Response {
    assert_eq!(body["client_id"], "hook");
    let code = body["client_label"]
        .as_str()
        .unwrap_or("dc_default")
        .to_owned();
    Json(json!({
        "device_code": code,
        "user_code": "WDJB-MJHT",
        "verification_uri": "http://localhost/device",
        "verification_uri_complete": "http://localhost/device?code=WDJB-MJHT",
        "expires_in": *state.device_expires_in.lock().unwrap(),
        "interval": 1
    }))
    .into_response()
}

async fn token(
    State(state): State<Arc<Accounts>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Some(value) = headers.get("authorization") {
        state
            .authorization_headers
            .lock()
            .unwrap()
            .push(value.to_str().unwrap_or("?").into());
    }
    state
        .forms
        .lock()
        .unwrap()
        .push(("token".into(), form.clone()));
    if form.get("client_id").map(String::as_str) != Some("hook") {
        return oauth("invalid_client", "unknown client");
    }
    match form.get("grant_type").map(String::as_str) {
        Some("urn:ietf:params:oauth:grant-type:device_code") => {
            state.poll_times.lock().unwrap().push(Instant::now());
            let code = form["device_code"].clone();
            let next = state
                .device_script
                .lock()
                .unwrap()
                .get_mut(&code)
                .and_then(|script| (!script.is_empty()).then(|| script.remove(0)))
                .unwrap_or("pending");
            match next {
                "ok" => Json(tokens("sar_device")).into_response(),
                "slow_down" => oauth("slow_down", "polling too fast"),
                "denied" => oauth("access_denied", "denied"),
                "expired" => oauth("expired_token", "expired"),
                "unavailable" => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": {"code": "unavailable", "message": "busy"}}))).into_response(),
                _ => oauth("authorization_pending", "pending"),
            }
        }
        Some("urn:silicon:params:oauth:grant-type:slt") => match form["slt"].as_str() {
            "slt_ok" => Json(tokens("sar_slt")).into_response(),
            "slt_used" => oauth("invalid_grant", "The short-lived token was already used; each one works once. Get a new one."),
            "slt_expired" => oauth("invalid_grant", "The short-lived token expired at 2026-10-10T00:00:00.000Z (they last 120 seconds); get a new one with `silicon-accounts login --app hook`."),
            "slt_wrong_app" => oauth("invalid_grant", "The short-lived token was issued for the app 'dm', not for 'hook'; get one for 'hook' with `silicon-accounts login --app hook`."),
            "slt_unknown" => oauth("invalid_grant", "The short-lived token is not known: it is mistyped or was never issued."),
            "slt_rotated" => oauth("invalid_grant", "The short-lived token was issued at 2026-10-10T00:00:00Z by a sign-in of si:scout that ended when its custodian rotated its STK at 2026-10-10T00:00:01Z."),
            "slt_disabled" => (StatusCode::BAD_REQUEST, Json(json!({"error": "unauthorized_client", "error_description": "public_client is off"}))).into_response(),
            _ => oauth("invalid_request", "unexpected"),
        },
        Some("refresh_token") => match form["refresh_token"].as_str() {
            "sar_1" => Json(tokens("sar_2")).into_response(),
            "sar_dead" => oauth("invalid_grant", "The sign-in this refresh token belongs to was revoked at 2026-10-07T02:35:29.652Z (refresh_token_reuse); sign in again."),
            _ => oauth("invalid_grant", "The refresh token is not known to Silicon Accounts."),
        },
        _ => oauth("unsupported_grant_type", "?"),
    }
}

async fn revoke(
    State(state): State<Arc<Accounts>>,
    Form(form): Form<HashMap<String, String>>,
) -> StatusCode {
    state.forms.lock().unwrap().push(("revoke".into(), form));
    StatusCode::OK
}

struct Fixture {
    sign_in: SignIn,
    state: Arc<Accounts>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn start() -> Result<Fixture, Box<dyn std::error::Error>> {
    let state = Arc::new(Accounts::default());
    *state.device_expires_in.lock().unwrap() = 600;
    let router = Router::new()
        .route("/v1/device/authorize", post(device_authorize))
        .route("/v1/oauth/token", post(token))
        .route("/v1/oauth/revoke", post(revoke))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let sign_in = SignIn::new(&format!("http://{}", listener.local_addr()?))?;
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("stub accounts");
    });
    Ok(Fixture {
        sign_in,
        state,
        server,
    })
}

fn kind(error: &Error) -> SignInErrorKind {
    match error {
        Error::SignIn(sign_in) => sign_in.kind,
        other => panic!("not a sign-in error: {other}"),
    }
}

#[tokio::test]
async fn device_flow_waits_through_pending_and_slow_down_then_returns_hook_tokens() -> TestResult {
    let fixture = start().await?;
    fixture
        .state
        .device_script
        .lock()
        .unwrap()
        .insert("dc_happy".into(), vec!["pending", "slow_down", "ok"]);
    let device = fixture.sign_in.start_device(Some("dc_happy"), None).await?;
    assert_eq!(device.user_code, "WDJB-MJHT");
    assert!(
        !format!("{device:?}").contains("dc_happy"),
        "the device code never shows"
    );
    let mut events = Vec::new();
    let started = Instant::now();
    let tokens = fixture
        .sign_in
        .wait_for_device(&device, |event| {
            events.push(match event {
                DeviceEvent::Pending => "pending".to_owned(),
                DeviceEvent::SlowDown(interval) => format!("slow_down {}", interval.as_secs()),
                _ => "other".to_owned(),
            });
        })
        .await?;
    assert_eq!(events, vec!["pending", "slow_down 6"]);
    let account = tokens.account.expect("account");
    assert_eq!(
        (account.uuid.as_str(), account.kind),
        ("Sx1", AccountKind::Silicon)
    );
    assert_eq!(
        tokens.refresh_token.expect("refresh").expose(),
        "sar_device"
    );
    let polls = fixture.state.poll_times.lock().unwrap().clone();
    assert_eq!(polls.len(), 3);
    assert!(
        polls[0] - started >= Duration::from_millis(950),
        "the first poll waits one interval"
    );
    assert!(
        polls[2] - polls[1] >= Duration::from_millis(5900),
        "slow_down adds five seconds"
    );
    assert!(
        fixture
            .state
            .authorization_headers
            .lock()
            .unwrap()
            .is_empty(),
        "a public client sends no secret"
    );
    Ok(())
}

#[tokio::test]
async fn device_flow_reports_denial_expiry_and_retries_transient_failures() -> TestResult {
    let fixture = start().await?;
    {
        let mut script = fixture.state.device_script.lock().unwrap();
        script.insert("dc_denied".into(), vec!["denied"]);
        script.insert("dc_expired".into(), vec!["expired"]);
        script.insert("dc_flaky".into(), vec!["unavailable", "ok"]);
    }
    let device = fixture
        .sign_in
        .start_device(Some("dc_denied"), None)
        .await?;
    let error = fixture
        .sign_in
        .wait_for_device(&device, |_| {})
        .await
        .expect_err("denied");
    assert_eq!(kind(&error), SignInErrorKind::Denied);
    assert_eq!(error.code(), Some("access_denied"));
    let device = fixture
        .sign_in
        .start_device(Some("dc_expired"), None)
        .await?;
    let error = fixture
        .sign_in
        .wait_for_device(&device, |_| {})
        .await
        .expect_err("expired");
    assert_eq!(kind(&error), SignInErrorKind::Expired);
    let device = fixture.sign_in.start_device(Some("dc_flaky"), None).await?;
    let mut retried = 0;
    fixture
        .sign_in
        .wait_for_device(&device, |event| {
            if matches!(event, DeviceEvent::Retrying { .. }) {
                retried += 1;
            }
        })
        .await?;
    assert_eq!(retried, 1);
    // A code that outlives its expiry ends the wait even while still pending.
    *fixture.state.device_expires_in.lock().unwrap() = 1;
    let device = fixture.sign_in.start_device(Some("dc_never"), None).await?;
    let started = Instant::now();
    let error = fixture
        .sign_in
        .wait_for_device(&device, |_| {})
        .await
        .expect_err("deadline");
    assert_eq!(kind(&error), SignInErrorKind::Expired);
    assert!(started.elapsed() < Duration::from_secs(5));
    Ok(())
}

#[tokio::test]
async fn short_lived_tokens_are_exchanged_with_the_client_id_only() -> TestResult {
    let fixture = start().await?;
    let tokens = fixture.sign_in.exchange_slt("  slt_ok\n").await?;
    assert_eq!(tokens.access_token.expose(), "at-for-sar_slt");
    assert_eq!(tokens.expires_in, 1800);
    assert!(tokens.refresh_expires_at.is_some());
    let account = tokens.account.expect("account");
    assert_eq!(account.custodian.expect("custodian").id, "c:ada");
    let forms = fixture.state.forms.lock().unwrap().clone();
    let (_, form) = forms.last().expect("exchange");
    assert_eq!(
        form["grant_type"],
        "urn:silicon:params:oauth:grant-type:slt"
    );
    assert_eq!(form["slt"], "slt_ok");
    assert_eq!(form["client_id"], "hook");
    assert!(!form.contains_key("client_secret"));
    assert!(
        fixture
            .state
            .authorization_headers
            .lock()
            .unwrap()
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn each_refused_short_lived_token_says_exactly_why() -> TestResult {
    let fixture = start().await?;
    for (slt, reason) in [
        ("slt_used", SltRefusal::AlreadyUsed),
        ("slt_expired", SltRefusal::Expired),
        ("slt_wrong_app", SltRefusal::WrongApp),
        ("slt_unknown", SltRefusal::Unknown),
        ("slt_rotated", SltRefusal::Ended),
    ] {
        let error = fixture.sign_in.exchange_slt(slt).await.expect_err(slt);
        assert_eq!(kind(&error), SignInErrorKind::SltRefused(reason), "{slt}");
        assert_eq!(error.code(), Some("invalid_grant"));
        assert!(
            error
                .hint()
                .unwrap_or_default()
                .contains("silicon-accounts login --app hook -q"),
            "{slt}: the hint tells the Silicon how to mint a fresh one"
        );
        assert_eq!(error.status(), Some(400));
    }
    let error = fixture
        .sign_in
        .exchange_slt("slt_disabled")
        .await
        .expect_err("disabled");
    assert_eq!(kind(&error), SignInErrorKind::NotEnabled);
    let sent = fixture.state.forms.lock().unwrap().len();
    let error = fixture
        .sign_in
        .exchange_slt("oat_iam_token")
        .await
        .expect_err("not an slt");
    assert_eq!(
        kind(&error),
        SignInErrorKind::SltRefused(SltRefusal::NotAnSlt)
    );
    assert_eq!(
        fixture.state.forms.lock().unwrap().len(),
        sent,
        "nothing is sent for a non-SLT"
    );
    Ok(())
}

#[tokio::test]
async fn refresh_rotates_and_an_ended_sign_in_is_reported_as_ended() -> TestResult {
    let fixture = start().await?;
    let tokens = fixture.sign_in.refresh("sar_1").await?;
    assert_eq!(tokens.refresh_token.expect("rotated").expose(), "sar_2");
    let error = fixture
        .sign_in
        .refresh("sar_dead")
        .await
        .expect_err("reused");
    assert_eq!(kind(&error), SignInErrorKind::SessionEnded);
    assert!(error.to_string().contains("refresh_token_reuse"));
    let forms = fixture.state.forms.lock().unwrap().clone();
    assert_eq!(forms[0].1["grant_type"], "refresh_token");
    assert_eq!(forms[0].1["client_id"], "hook");
    Ok(())
}

#[tokio::test]
async fn revoke_posts_the_refresh_token_as_hooks_public_client() -> TestResult {
    let fixture = start().await?;
    fixture.sign_in.revoke("sar_9").await?;
    let forms = fixture.state.forms.lock().unwrap().clone();
    let (endpoint, form) = forms.last().expect("revoke");
    assert_eq!(endpoint, "revoke");
    assert_eq!(form["token"], "sar_9");
    assert_eq!(form["token_type_hint"], "refresh_token");
    assert_eq!(form["client_id"], "hook");
    Ok(())
}

#[tokio::test]
async fn an_unreachable_accounts_is_unavailable_and_nothing_was_processed() -> TestResult {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    let sign_in = SignIn::new(&format!("http://{address}"))?;
    let error = sign_in.exchange_slt("slt_ok").await.expect_err("down");
    assert_eq!(
        kind(&error),
        SignInErrorKind::Unavailable {
            maybe_processed: false
        }
    );
    let error = sign_in.refresh("sar_1").await.expect_err("down");
    assert_eq!(
        kind(&error),
        SignInErrorKind::Unavailable {
            maybe_processed: false
        }
    );
    Ok(())
}

#[test]
fn accounts_urls_must_be_https_or_this_machine() {
    for good in [
        "https://accounts.teamofsilicons.com",
        "http://localhost:9590",
        "http://127.0.0.1:9589/",
    ] {
        assert!(SignIn::new(good).is_ok(), "{good}");
    }
    for bad in [
        "http://accounts.example.com",
        "https://a.example.com?x=1",
        "https://u:p@a.example.com",
        "nope",
    ] {
        assert!(SignIn::new(bad).is_err(), "{bad}");
    }
    assert_eq!(
        SignIn::production()
            .map(|s| s.app_id().to_owned())
            .ok()
            .as_deref(),
        Some("hook")
    );
}
