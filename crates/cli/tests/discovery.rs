//! The three commands every Silicon Apps app must answer signed out, offline,
//! in an empty home: `--help`, `accounts --json`, `login status --json`.

mod support;

use serde_json::json;
use support::{Home, hook_env};

#[tokio::test]
async fn help_is_non_empty_and_exits_zero_in_an_empty_home() {
    let home = Home::new();
    let run = hook_env(Some(&home.0), &[], &["--help"], None).await;
    assert_eq!(run.code(), 0);
    assert!(run.stdout().contains("hook login"));
    assert!(
        run.stdout()
            .contains("silicon-accounts login --app hook -q | hook login --slt-stdin")
    );
    assert!(!home.state_dir().exists(), "discovery creates nothing");
}

#[tokio::test]
async fn accounts_json_is_offline_and_exact() {
    let home = Home::new();
    let run = hook_env(Some(&home.0), &[], &["accounts", "--json"], None).await;
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert_eq!(run.stderr(), "", "--json prints nothing else");
    assert_eq!(
        run.json(),
        json!({
            "app_id": "hook",
            "name": "Silicon Hook",
            "version": env!("CARGO_PKG_VERSION"),
            "accounts_url": "https://accounts.teamofsilicons.com",
            "api_url": "https://backend.hook.teamofsilicons.com",
            "api_version": "v3",
            "docs": "https://docs.hook.teamofsilicons.com",
            "repository": "https://github.com/teamofsilicons/silicon-hook",
            "install": "silicon-apps install hook",
            "sign_in": {
                "carbon": "hook login",
                "silicon": "silicon-accounts login --app hook -q | hook login --slt-stdin",
                "slt_command": "silicon-accounts login --app hook -q"
            },
            "state_dir": home.state_dir().display().to_string()
        })
    );
    // The hidden alias the Silicon runtime still calls prints exactly the same.
    let alias = hook_env(Some(&home.0), &[], &["iam", "--json"], None).await;
    assert_eq!(alias.code(), 0);
    assert_eq!(alias.json(), run.json());
    // Configured URLs are reported; a bad one is a warning, still exit 0.
    let configured = hook_env(
        Some(&home.0),
        &[
            ("ACCOUNTS_URL", "http://localhost:9590"),
            ("SILICON_HOOK_URL", "http://example.com"),
        ],
        &["accounts", "--json"],
        None,
    )
    .await;
    assert_eq!(configured.code(), 0);
    let value = configured.json();
    assert_eq!(value["accounts_url"], "http://localhost:9590");
    assert_eq!(value["api_url"], "http://example.com");
    assert!(
        value["warnings"][0]
            .as_str()
            .unwrap_or_default()
            .contains("http://example.com")
    );
    assert!(!home.state_dir().exists());
}

#[tokio::test]
async fn login_status_is_false_signed_out_and_exits_zero_with_json() {
    let home = Home::new();
    let run = hook_env(Some(&home.0), &[], &["login", "status", "--json"], None).await;
    assert_eq!(run.code(), 0);
    assert_eq!(run.json(), json!({"authenticated": false}));
    assert_eq!(run.stderr(), "");
    let text = hook_env(Some(&home.0), &[], &["login", "status"], None).await;
    assert_eq!(text.code(), 1, "without --json, signed out exits 1");
    assert!(text.stderr().contains("hook login"));
    let offline = hook_env(
        Some(&home.0),
        &[],
        &["login", "status", "--json", "--offline"],
        None,
    )
    .await;
    assert_eq!(
        (offline.code(), offline.json()),
        (0, json!({"authenticated": false}))
    );
    assert!(!home.state_dir().exists(), "discovery creates nothing");
}

#[tokio::test]
async fn discovery_works_without_any_home_variable() {
    let run = hook_env(None, &[], &["login", "status", "--json"], None).await;
    assert_eq!(run.code(), 0);
    let value = run.json();
    assert_eq!(value["authenticated"], false);
    assert_eq!(value["reason"], "no_home");
    let run = hook_env(None, &[], &["accounts", "--json"], None).await;
    assert_eq!(run.code(), 0);
    assert_eq!(run.json()["app_id"], "hook");
    assert_eq!(run.json()["state_dir"], serde_json::Value::Null);
    assert_eq!(hook_env(None, &[], &["--help"], None).await.code(), 0);
}

#[tokio::test]
async fn every_command_explains_itself_without_retired_concepts() {
    let home = Home::new();
    let run = hook_env(Some(&home.0), &[], &["commands", "--json"], None).await;
    assert_eq!(run.code(), 0);
    let items = run.json();
    let items = items.as_array().expect("command list");
    assert!(items.len() > 30, "the whole tree is listed");
    for item in items {
        let help = item["help"].as_str().unwrap_or_default();
        assert!(!help.is_empty());
        let words: Vec<String> = help
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .map(str::to_ascii_lowercase)
            .collect();
        for retired in ["iam", "org", "honeycomb", "organization", "human"] {
            assert!(
                !words.iter().any(|w| w == retired),
                "`{}` help mentions {retired}",
                item["command"]
            );
        }
    }
    let paths: Vec<&str> = items.iter().filter_map(|i| i["command"].as_str()).collect();
    for expected in [
        "hook login status",
        "hook accounts",
        "hook access grant",
        "hook allow-list add",
        "hook connect-accounts",
    ] {
        assert!(paths.contains(&expected), "{expected} missing");
    }
    assert!(!paths.contains(&"hook iam"), "the alias stays hidden");
}
