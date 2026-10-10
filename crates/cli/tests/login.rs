//! Signing in, staying signed in and signing out, against a stub Silicon
//! Accounts and a stub Hook API, with the real binary.

mod support;

use serde_json::{Value, json};
use support::{CARBON, Home, SILICON, hook, start};

fn silicon() -> (&'static str, &'static str, &'static str) {
    (SILICON.0, SILICON.1, "silicon")
}

#[tokio::test]
async fn a_carbon_signs_in_with_the_device_flow_and_json_progress_lines() {
    let server = start().await;
    let home = Home::new();
    *server.stub.device_script.lock().unwrap() = vec!["pending", "ok"];
    let run = hook(&home, &server, &["login", "--json"], None).await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    let lines: Vec<Value> = run
        .stdout()
        .lines()
        .map(|line| serde_json::from_str(line).expect("each line is JSON"))
        .collect();
    assert_eq!(lines.len(), 2, "{}", run.stdout());
    assert_eq!(lines[0]["event"], "device_code");
    assert_eq!(lines[0]["user_code"], "WDJB-MJHT");
    assert_eq!(lines[0]["verification_uri"], "http://localhost/device");
    assert_eq!(
        lines[0]["browser_opened"], false,
        "nothing opens without --open"
    );
    assert!(
        lines[0].get("device_code").is_none(),
        "the device code is never printed"
    );
    assert_eq!(lines[1]["authenticated"], true);
    assert_eq!(lines[1]["uuid"], CARBON.0);
    assert_eq!(lines[1]["kind"], "carbon");
    assert_eq!(lines[1]["method"], "device");
    assert_eq!(*server.stub.device_polls.lock().unwrap(), 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(home.state_dir().join("profiles.json"))
            .expect("saved")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Verified online by Hook.
    let status = hook(&home, &server, &["login", "status", "--json"], None).await;
    assert_eq!(status.code(), 0);
    let value = status.json();
    assert_eq!(
        (
            value["authenticated"].clone(),
            value["verified"].clone(),
            value["id"].clone()
        ),
        (json!(true), json!(true), json!(CARBON.1))
    );
    for field in ["uuid", "kind", "expires_at", "refresh_expires_at"] {
        assert!(value.get(field).is_some(), "{field}");
    }
}

#[tokio::test]
async fn a_denied_or_expired_device_sign_in_fails_with_its_reason() {
    let server = start().await;
    let home = Home::new();
    *server.stub.device_script.lock().unwrap() = vec!["denied"];
    let run = hook(&home, &server, &["login", "--json"], None).await;
    assert_eq!(run.code(), 3);
    assert_eq!(run.error()["error"]["code"], "access_denied");
    *server.stub.device_script.lock().unwrap() = vec!["slow_down", "expired"];
    let run = hook(&home, &server, &["login", "--json"], None).await;
    assert_eq!(run.code(), 3);
    assert_eq!(run.error()["error"]["code"], "expired_token");
    assert!(
        run.stdout().contains("\"event\":\"slow_down\""),
        "slow_down is reported: {}",
        run.stdout()
    );
    assert!(
        !home.state_dir().join("profiles.json").exists(),
        "nothing saved"
    );
}

#[tokio::test]
async fn a_silicon_signs_in_with_a_short_lived_token_that_is_never_echoed() {
    let server = start().await;
    let home = Home::new();
    let secret = "slt_ok_DO_NOT_PRINT";
    let run = hook(
        &home,
        &server,
        &["login", "--slt-stdin"],
        Some(&format!("{secret}\n")),
    )
    .await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(run.json()["uuid"], SILICON.0);
    assert_eq!(run.json()["kind"], "silicon");
    assert!(!run.stdout().contains(secret) && !run.stderr().contains(secret));
    let saved = std::fs::read_to_string(home.state_dir().join("profiles.json")).expect("state");
    assert!(
        !saved.contains(secret),
        "the short-lived token is not stored"
    );
    assert_eq!(server.stub.slts.lock().unwrap().as_slice(), [secret]);
    // The positional form the Silicon runtime uses also works, and replaces
    // (and signs out) the previous sign-in.
    let first_refresh = home.state()["profiles"]["default"]["session"]["refresh_token"].clone();
    let run = hook(&home, &server, &["login", "slt_ok_again"], None).await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(
        server.stub.revoked.lock().unwrap().as_slice(),
        [first_refresh.as_str().expect("refresh")]
    );
}

#[tokio::test]
async fn refused_short_lived_tokens_say_exactly_why_and_how_to_get_a_fresh_one() {
    let server = start().await;
    let home = Home::new();
    for (slt, reason) in [
        ("slt_used_1", "already_used"),
        ("slt_expired_1", "expired"),
        ("slt_wrong_1", "wrong_app"),
        ("slt_unknown_1", "unknown"),
    ] {
        let run = hook(&home, &server, &["--json", "login", "--slt", slt], None).await;
        assert_eq!(run.code(), 3, "{slt}");
        let error = run.error();
        assert_eq!(error["error"]["code"], "invalid_grant");
        assert_eq!(error["error"]["details"]["reason"], reason, "{slt}");
        assert!(
            error["error"]["hint"]
                .as_str()
                .unwrap_or_default()
                .contains("silicon-accounts login --app hook -q")
        );
        assert!(
            !run.stderr().contains(slt),
            "the token itself is never echoed"
        );
    }
    let run = hook(
        &home,
        &server,
        &["--json", "login", "--slt", "not-a-token"],
        None,
    )
    .await;
    assert_eq!(run.code(), 3);
    assert_eq!(run.error()["error"]["details"]["reason"], "not_an_slt");
}

#[tokio::test]
async fn an_expiring_token_is_refreshed_once_and_the_rotated_pair_is_saved_first() {
    let server = start().await;
    let home = Home::new();
    server.stub.register_refresh("sar_saved", silicon());
    home.write_session(&server, silicon(), "at-stale", "sar_saved", 30);
    let run = hook(&home, &server, &["list"], None).await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(*server.stub.refresh_calls.lock().unwrap(), 1);
    let session = home.state()["profiles"]["default"]["session"].clone();
    assert_ne!(
        session["refresh_token"], "sar_saved",
        "the rotated refresh token is saved"
    );
    assert!(session.get("refresh_started_at").is_none());
    let requests = server.stub.hook_requests();
    let list = requests
        .iter()
        .find(|r| r.path.ends_with("/hooks"))
        .expect("list");
    assert_eq!(
        list.path,
        format!("/api/v3/silicons/{}/hooks", SILICON.0),
        "a Silicon's own hooks, by uuid"
    );
    assert_eq!(
        list.authorization.as_deref(),
        Some(
            format!(
                "Bearer {}",
                session["access_token"].as_str().unwrap_or_default()
            )
            .as_str()
        )
    );
}

#[tokio::test]
async fn concurrent_commands_share_one_refresh_under_the_lock() {
    let server = start().await;
    let home = Home::new();
    *server.stub.refresh_delay_ms.lock().unwrap() = 400;
    server.stub.register_refresh("sar_shared", silicon());
    home.write_session(&server, silicon(), "at-stale", "sar_shared", 10);
    let runs = futures_join(&home, &server, 5).await;
    for run in &runs {
        assert_eq!(run.code(), 0, "{}", run.stderr());
        assert_eq!(run.json()["authenticated"], true);
        assert_eq!(run.json()["verified"], true);
    }
    assert_eq!(
        *server.stub.refresh_calls.lock().unwrap(),
        1,
        "exactly one refresh"
    );
    assert!(
        !*server.stub.reuse_detected.lock().unwrap(),
        "no spent token was presented twice"
    );
}

async fn futures_join(home: &Home, server: &support::Server, n: usize) -> Vec<support::Run> {
    assert_eq!(n, 5);
    let args = ["login", "status", "--json"];
    // Polled together, so the five processes start at the same time.
    let (a, b, c, d, e) = tokio::join!(
        hook(home, server, &args, None),
        hook(home, server, &args, None),
        hook(home, server, &args, None),
        hook(home, server, &args, None),
        hook(home, server, &args, None),
    );
    vec![a, b, c, d, e]
}

#[tokio::test]
async fn an_ended_sign_in_reads_as_signed_out_and_is_forgotten() {
    let server = start().await;
    let home = Home::new();
    home.write_session(&server, silicon(), "at-stale", "sar_dead", 5);
    let run = hook(&home, &server, &["login", "status", "--json"], None).await;
    assert_eq!(run.code(), 0);
    let value = run.json();
    assert_eq!(value["authenticated"], false);
    assert_eq!(value["reason"], "session_ended");
    assert!(
        value["message"]
            .as_str()
            .unwrap_or_default()
            .contains("access_removed")
    );
    assert!(home.state()["profiles"]["default"].get("session").is_none());
    let run = hook(&home, &server, &["--json", "list"], None).await;
    assert_eq!(run.code(), 3);
    assert_eq!(run.error()["error"]["code"], "not_signed_in");
}

#[tokio::test]
async fn an_interrupted_refresh_never_presents_the_possibly_spent_token_again() {
    let server = start().await;
    let home = Home::new();
    server.stub.register_refresh("sar_maybe_spent", silicon());
    home.write_session(&server, silicon(), "at-stale", "sar_maybe_spent", 5);
    let mut state = home.state();
    state["profiles"]["default"]["session"]["refresh_started_at"] = json!(1_760_000_000);
    home.write_state(&state);
    let run = hook(&home, &server, &["--json", "list"], None).await;
    assert_eq!(run.code(), 3);
    assert_eq!(run.error()["error"]["code"], "refresh_interrupted");
    assert_eq!(
        *server.stub.refresh_calls.lock().unwrap(),
        0,
        "never presented to the token endpoint"
    );
    assert_eq!(
        server.stub.revoked.lock().unwrap().as_slice(),
        ["sar_maybe_spent"],
        "revoked instead"
    );
    assert!(home.state()["profiles"]["default"].get("session").is_none());
}

#[tokio::test]
async fn a_token_hook_refuses_is_refreshed_once_and_the_command_retried() {
    let server = start().await;
    let home = Home::new();
    server.stub.register_refresh("sar_fresh", silicon());
    server.stub.register_access("at-refused", silicon());
    server
        .stub
        .refuse_once
        .lock()
        .unwrap()
        .insert("at-refused".into());
    home.write_session(&server, silicon(), "at-refused", "sar_fresh", 1500);
    let run = hook(&home, &server, &["list"], None).await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(*server.stub.refresh_calls.lock().unwrap(), 1);
    let lists = server
        .stub
        .hook_requests()
        .into_iter()
        .filter(|r| r.path.ends_with("/hooks"))
        .count();
    assert_eq!(lists, 2, "refused once, then retried with the new token");
}

#[tokio::test]
async fn logout_revokes_the_refresh_token_and_forgets_the_sign_in() {
    let server = start().await;
    let home = Home::new();
    let run = hook(&home, &server, &["login", "--slt", "slt_ok_logout"], None).await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    let refresh = home.state()["profiles"]["default"]["session"]["refresh_token"]
        .as_str()
        .expect("refresh")
        .to_owned();
    let run = hook(&home, &server, &["logout"], None).await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(run.json()["signed_out"], true);
    assert_eq!(run.json()["revoked"], true);
    assert_eq!(
        server.stub.revoked.lock().unwrap().as_slice(),
        [refresh.as_str()]
    );
    assert!(home.state()["profiles"]["default"].get("session").is_none());
    let status = hook(&home, &server, &["login", "status", "--json"], None).await;
    assert_eq!(status.json(), json!({"authenticated": false}));
    let again = hook(&home, &server, &["logout"], None).await;
    assert_eq!(
        (again.code(), again.json()["signed_out"].clone()),
        (0, json!(false))
    );
}

#[tokio::test]
async fn a_pre_1_0_sign_in_is_not_carried_over_and_says_so() {
    let server = start().await;
    let home = Home::new();
    std::fs::create_dir_all(home.state_dir()).expect("dir");
    let legacy = json!({"profiles": {"default": {"url": server.url, "org": "tos", "silicon": null,
        "telemetry": false, "session": {"tokens": {"access_token": "oat_old", "refresh_token": "ort_old",
        "token_type": "Bearer", "expires_in": 3600, "scopes": [], "actor": {"type": "silicon", "id": "si:scout"}, "org_id": "tos"},
        "expires_at": 4000000000u64}}}});
    let bytes = serde_json::to_vec(&legacy).expect("json");
    std::fs::write(home.state_dir().join("state.json"), &bytes).expect("legacy");
    let status = hook(&home, &server, &["login", "status", "--json"], None).await;
    assert_eq!(status.code(), 0);
    assert_eq!(status.json()["authenticated"], false);
    assert_eq!(status.json()["reason"], "previous_version_session");
    let list = hook(&home, &server, &["--json", "list"], None).await;
    assert_eq!(list.code(), 3);
    assert_eq!(list.error()["error"]["code"], "previous_version_session");
    assert!(
        server
            .stub
            .hook_requests()
            .iter()
            .all(|r| r.authorization.as_deref() != Some("Bearer oat_old")),
        "old tokens are never sent"
    );
    let login = hook(
        &home,
        &server,
        &["login", "--slt-stdin"],
        Some("slt_ok_upgrade"),
    )
    .await;
    assert_eq!(login.code(), 0, "{}", login.stderr());
    let state = home.state();
    assert_eq!(
        state["profiles"]["default"]["telemetry"], false,
        "the opt-out survived"
    );
    assert!(
        state["profiles"]["default"]
            .get("previous_version_session")
            .is_none()
    );
    assert_eq!(
        std::fs::read(home.state_dir().join("state.json")).expect("legacy"),
        bytes,
        "state.json untouched"
    );
}

#[tokio::test]
async fn an_unreadable_state_file_is_reported_and_a_new_sign_in_recovers() {
    let server = start().await;
    let home = Home::new();
    std::fs::create_dir_all(home.state_dir()).expect("dir");
    std::fs::write(home.state_dir().join("profiles.json"), b"{broken").expect("write");
    let status = hook(&home, &server, &["login", "status", "--json"], None).await;
    assert_eq!(status.code(), 0);
    assert_eq!(status.json()["reason"], "state_unreadable");
    let list = hook(&home, &server, &["--json", "list"], None).await;
    assert_eq!(
        (list.code(), list.error()["error"]["code"].clone()),
        (1, json!("state_unreadable"))
    );
    let login = hook(&home, &server, &["login", "slt_ok_recover"], None).await;
    assert_eq!(login.code(), 0, "{}", login.stderr());
    assert!(login.stderr().contains("moved to"));
    assert_eq!(
        hook(&home, &server, &["login", "status", "--json"], None)
            .await
            .json()["authenticated"],
        true
    );
}

#[tokio::test]
async fn a_session_is_only_used_with_the_services_it_signed_in_with() {
    let server = start().await;
    let home = Home::new();
    assert_eq!(
        hook(&home, &server, &["login", "slt_ok_bound"], None)
            .await
            .code(),
        0
    );
    let elsewhere = support::hook_env(
        Some(&home.0),
        &[
            ("ACCOUNTS_URL", "https://accounts.teamofsilicons.com"),
            ("SILICON_HOOK_URL", &server.url),
        ],
        &["login", "status", "--json"],
        None,
    )
    .await;
    assert_eq!(elsewhere.code(), 0);
    assert_eq!(elsewhere.json()["reason"], "signed_in_elsewhere");
    let other_hook = support::hook_env(
        Some(&home.0),
        &[
            ("ACCOUNTS_URL", &server.url),
            ("SILICON_HOOK_URL", "http://127.0.0.1:9"),
        ],
        &["--json", "list"],
        None,
    )
    .await;
    assert_eq!(other_hook.code(), 3);
    assert_eq!(other_hook.error()["error"]["code"], "signed_in_elsewhere");
    let offline = hook(
        &home,
        &server,
        &["login", "status", "--json", "--offline"],
        None,
    )
    .await;
    assert_eq!(
        (
            offline.json()["authenticated"].clone(),
            offline.json()["verified"].clone()
        ),
        (json!(true), json!(false))
    );
    let removed = hook(&home, &server, &["--json", "--org", "tos", "list"], None).await;
    assert_eq!(removed.code(), 2);
    assert!(
        removed.error()["error"]["hint"]
            .as_str()
            .unwrap_or_default()
            .contains("--silicon")
    );
}

#[tokio::test]
async fn telemetry_is_sent_only_when_signed_in_and_not_turned_off() {
    let server = start().await;
    let home = Home::new();
    assert_eq!(
        hook(&home, &server, &["login", "slt_ok_telemetry"], None)
            .await
            .code(),
        0
    );
    let on = support::hook_env(
        Some(&home.0),
        &[
            ("ACCOUNTS_URL", &server.url),
            ("SILICON_HOOK_URL", &server.url),
            ("SILICON_HOOK_TELEMETRY", "on"),
        ],
        &["list"],
        None,
    )
    .await;
    assert_eq!(on.code(), 0);
    let sent = server
        .stub
        .hook_requests()
        .into_iter()
        .filter(|r| r.path == "/api/v3/telemetry")
        .collect::<Vec<_>>();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].body["operation"], "list");
    assert_eq!(sent[0].body["source"], "cli");
    assert!(
        !sent[0].body.to_string().contains("at-"),
        "no token in the event"
    );
    assert_eq!(hook(&home, &server, &["list"], None).await.code(), 0);
    let after = server
        .stub
        .hook_requests()
        .into_iter()
        .filter(|r| r.path == "/api/v3/telemetry")
        .count();
    assert_eq!(after, 1, "SILICON_HOOK_TELEMETRY=off sends nothing");
}

#[tokio::test]
async fn refreshing_waits_for_the_state_lock_and_then_happens_once() {
    use fs2::FileExt as _;
    let server = start().await;
    let home = Home::new();
    server.stub.register_refresh("sar_locked", silicon());
    home.write_session(&server, silicon(), "at-stale", "sar_locked", 10);
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(home.state_dir().join("profiles.lock"))
        .expect("lock file");
    lock.lock_exclusive().expect("hold the lock");
    let children: Vec<_> = (0..3)
        .map(|_| {
            std::process::Command::new(env!("CARGO_BIN_EXE_hook"))
                .args(["login", "status", "--json"])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &home.0)
                .env("SILICON_HOME", &home.0)
                .env("ACCOUNTS_URL", &server.url)
                .env("SILICON_HOOK_URL", &server.url)
                .env("SILICON_HOOK_TELEMETRY", "off")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn")
        })
        .collect();
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    assert_eq!(
        *server.stub.refresh_calls.lock().unwrap(),
        0,
        "nobody refreshes while another holds the lock"
    );
    fs2::FileExt::unlock(&lock).expect("release");
    for child in children {
        let output = tokio::task::spawn_blocking(move || child.wait_with_output())
            .await
            .expect("join")
            .expect("output");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).expect("json");
        assert_eq!(value["authenticated"], true);
    }
    assert_eq!(
        *server.stub.refresh_calls.lock().unwrap(),
        1,
        "exactly one refresh after the lock is released"
    );
    assert!(!*server.stub.reuse_detected.lock().unwrap());
}
