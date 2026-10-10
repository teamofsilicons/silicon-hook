//! The management commands against the stub Hook API: paths, bodies, the
//! default Silicon, and how refusals are shown.

mod support;

use serde_json::json;
use support::{CARBON, HOOK_ID, Home, SILICON, Server, hook, start};

async fn signed_in_silicon() -> (Server, Home) {
    let server = start().await;
    let home = Home::new();
    let run = hook(&home, &server, &["login", "slt_ok_commands"], None).await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    (server, home)
}

async fn signed_in_carbon() -> (Server, Home) {
    let server = start().await;
    let home = Home::new();
    *server.stub.device_script.lock().unwrap() = vec!["ok"];
    let run = hook(&home, &server, &["login", "--json"], None).await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    (server, home)
}

fn last(server: &Server) -> support::Seen {
    server
        .stub
        .hook_requests()
        .into_iter()
        .rfind(|r| r.path != "/api/v3/telemetry")
        .expect("a request")
}

#[tokio::test]
async fn a_silicon_creates_and_manages_its_own_hooks_by_uuid() {
    let (server, home) = signed_in_silicon().await;
    let secret = home.0.join("secret.txt");
    std::fs::write(&secret, " provider secret \n").expect("secret");
    let run = hook(
        &home,
        &server,
        &[
            "create",
            "Stripe",
            "--secret-file",
            secret.to_str().expect("path"),
            "--time-zone",
            "Asia/Kolkata",
        ],
        None,
    )
    .await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    let request = last(&server);
    assert_eq!(
        (request.method.as_str(), request.path.as_str()),
        ("POST", &*format!("/api/v3/silicons/{}/hooks", SILICON.0))
    );
    assert_eq!(request.body["signature"]["secret"], " provider secret ");
    assert_eq!(request.body["time_zone"], "Asia/Kolkata");
    assert!(request.idempotency_key.is_some());
    let run = hook(
        &home,
        &server,
        &[
            "--idempotency-key",
            "same-key-123",
            "update",
            HOOK_ID,
            "--patch",
            "{\"description\":null}",
        ],
        None,
    )
    .await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    let request = last(&server);
    assert_eq!(request.method, "PATCH");
    assert_eq!(request.body, json!({"description": null}));
    assert_eq!(request.idempotency_key.as_deref(), Some("same-key-123"));
    let run = hook(&home, &server, &["delete", HOOK_ID], None).await;
    assert_eq!(run.code(), 0);
    assert_eq!(
        run.json(),
        json!({"deleted": HOOK_ID, "recoverable_days": 45})
    );
    let run = hook(
        &home,
        &server,
        &[
            "events", "--hook", HOOK_ID, "--limit", "5", "--cursor", "abc",
        ],
        None,
    )
    .await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    let request = last(&server);
    assert_eq!(
        request.path,
        format!("/api/v3/silicons/{}/hooks/{HOOK_ID}/events", SILICON.0)
    );
    assert_eq!(request.query.as_deref(), Some("limit=5&cursor=abc"));
}

#[tokio::test]
async fn a_carbon_must_choose_the_silicon_and_can_save_a_default() {
    let (server, home) = signed_in_carbon().await;
    let run = hook(&home, &server, &["--json", "list"], None).await;
    assert_eq!(run.code(), 2);
    let error = run.error();
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Which Silicon?")
    );
    assert!(
        error["error"]["hint"]
            .as_str()
            .unwrap_or_default()
            .contains("hook silicons")
    );
    let run = hook(&home, &server, &["silicons"], None).await;
    assert_eq!(run.code(), 0);
    assert_eq!(run.json()["items"][0]["access"], "custodian");
    let run = hook(&home, &server, &["--silicon", SILICON.1, "list"], None).await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(
        last(&server).path,
        format!("/api/v3/silicons/{}/hooks", SILICON.1)
    );
    assert_eq!(
        hook(
            &home,
            &server,
            &["config", "set", "silicon", SILICON.1],
            None
        )
        .await
        .code(),
        0
    );
    assert_eq!(hook(&home, &server, &["list"], None).await.code(), 0);
    let shown = hook(&home, &server, &["config", "show"], None).await.json();
    assert_eq!(shown["silicon"], SILICON.1);
    assert_eq!(
        shown["signed_in_as"],
        format!("{} ({})", CARBON.1, CARBON.0)
    );
    assert!(
        !shown.to_string().contains("at-"),
        "no token in config show"
    );
    let refused = hook(
        &home,
        &server,
        &["config", "set", "url", "http://127.0.0.1:9"],
        None,
    )
    .await;
    assert_eq!(refused.code(), 2, "a signed-in profile keeps its Hook URL");
}

#[tokio::test]
async fn access_and_allow_list_commands() {
    let (server, home) = signed_in_carbon().await;
    let base = ["--silicon", SILICON.1];
    let run = hook(
        &home,
        &server,
        &[
            &base[..],
            &["access", "grant", "c:bob", "--level", "manage"],
        ]
        .concat(),
        None,
    )
    .await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    let request = last(&server);
    assert_eq!(
        (request.method.as_str(), request.path.as_str()),
        (
            "PUT",
            &*format!("/api/v3/silicons/{}/access/c:bob", SILICON.1)
        )
    );
    assert_eq!(request.body, json!({"level": "manage"}));
    assert_eq!(
        hook(
            &home,
            &server,
            &[&base[..], &["access", "revoke", "c:bob"]].concat(),
            None
        )
        .await
        .code(),
        0
    );
    assert_eq!(last(&server).method, "DELETE");
    assert_eq!(
        hook(
            &home,
            &server,
            &[&base[..], &["access", "leave"]].concat(),
            None
        )
        .await
        .code(),
        0
    );
    assert_eq!(
        last(&server).path,
        format!("/api/v3/silicons/{}/access/me", SILICON.1)
    );
    let run = hook(
        &home,
        &server,
        &[&base[..], &["access", "list"]].concat(),
        None,
    )
    .await;
    assert_eq!(run.json()["you"]["access"], "custodian");
    assert_eq!(
        hook(
            &home,
            &server,
            &[&base[..], &["allow-list", "list"]].concat(),
            None
        )
        .await
        .code(),
        0
    );
    assert_eq!(
        hook(
            &home,
            &server,
            &[&base[..], &["allow-list", "remove", "si:friend"]].concat(),
            None
        )
        .await
        .code(),
        0
    );
    assert_eq!(
        last(&server).path,
        format!("/api/v3/silicons/{}/allow-list/si:friend", SILICON.1)
    );
}

#[tokio::test]
async fn connect_accounts_prepares_the_hook_then_stores_the_whsec_secret() {
    let (server, home) = signed_in_silicon().await;
    let run = hook(&home, &server, &["connect-accounts"], None).await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(run.json()["secret_stored_now"], false);
    assert!(run.stderr().contains("silicon-accounts webhook set"));
    let run = hook(
        &home,
        &server,
        &["connect-accounts", "--secret-file", "-"],
        Some("whsec_from_accounts\n"),
    )
    .await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(run.json()["secret_stored_now"], true);
    let requests: Vec<_> = server
        .stub
        .hook_requests()
        .into_iter()
        .filter(|r| r.path != "/api/v3/telemetry")
        .collect();
    let tail = &requests[requests.len() - 2..];
    assert_eq!(
        (tail[0].method.as_str(), tail[0].path.as_str()),
        (
            "POST",
            &*format!("/api/v3/silicons/{}/hooks/accounts", SILICON.0)
        )
    );
    assert_eq!(tail[1].method, "PATCH");
    assert_eq!(
        tail[1].body,
        json!({"signature": {"secret": "whsec_from_accounts"}})
    );
}

#[tokio::test]
async fn delivery_and_system_commands_explain_a_hook_without_ting() {
    let (server, home) = signed_in_silicon().await;
    let run = hook(&home, &server, &["system", "delivery"], None).await;
    assert_eq!(run.code(), 0);
    assert_eq!(run.json()["enabled"], false);
    let run = hook(&home, &server, &["--json", "receiving", "register"], None).await;
    assert_eq!(run.code(), 5);
    let error = run.error();
    assert_eq!(error["error"]["code"], "delivery_disabled");
    assert_eq!(error["error"]["status"], 409);
    let run = hook(&home, &server, &["receiving", "status"], None).await;
    assert_eq!(
        run.json(),
        json!({"receiving": false, "subscription": null})
    );
    let run = hook(&home, &server, &["system", "version"], None).await;
    assert_eq!(run.code(), 0);
    assert_eq!(run.json()["cli"], env!("CARGO_PKG_VERSION"));
    let missing = hook(
        &home,
        &server,
        &["--json", "--silicon", "si:nobody", "list"],
        None,
    )
    .await;
    assert_eq!(missing.code(), 4);
    assert_eq!(missing.error()["error"]["code"], "silicon_not_found");
    assert_eq!(missing.error()["error"]["request_id"], "req-stub");
}

#[tokio::test]
async fn docs_topics_are_bundled_and_unknown_topics_list_the_choices() {
    let home = Home::new();
    for topic in [
        "overview",
        "signin",
        "cli",
        "client",
        "receiving",
        "signatures",
        "delivery",
        "contracts",
        "configuration",
        "telemetry",
        "deployment",
        "releases",
    ] {
        let run = support::hook_env(Some(&home.0), &[], &["docs", topic], None).await;
        assert_eq!(run.code(), 0, "{topic}");
        assert!(
            run.stdout().starts_with('#') || run.stdout().starts_with('>'),
            "{topic}"
        );
    }
    let run = support::hook_env(Some(&home.0), &[], &["--json", "docs", "testing"], None).await;
    assert_eq!(run.code(), 2);
    assert!(
        run.error()["error"]["hint"]
            .as_str()
            .unwrap_or_default()
            .contains("signin")
    );
}
