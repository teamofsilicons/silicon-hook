//! The upgrade path: a database filled under origin/main's last migration
//! (0018, Silicon IAM ids) is migrated to the Silicon Accounts schema, keeps
//! every byte, keeps its provider URLs working, and is linked to Accounts
//! uuids with `hook-migrate link-identities`.

mod support;

use std::path::PathBuf;
use tokio::process::Command;

use anyhow::{Context as _, Result};
use http::{Method, StatusCode};
use serde_json::{Value, json};
use silicon_hook::domain::signature::SignatureConfig;
use sqlx::PgPool;
use support::api::{TestApi, Upgrade};
use uuid::Uuid;

const LEGACY_HOOK: Uuid = Uuid::from_u128(0xa1);
const ORPHAN_HOOK: Uuid = Uuid::from_u128(0xa2);
const EVENT: Uuid = Uuid::from_u128(0xe1);

/// IAM-era rows, written with the 0018 schema.
async fn iam_era_fixture(pool: &PgPool) -> Result<()> {
    let config = serde_json::to_value(SignatureConfig::default())?;
    for (id, silicon, key, creator_kind, creator) in [
        (LEGACY_HOOK, "si:cos", "LEGACY01", "carbon", "c:alice"),
        (ORPHAN_HOOK, "si:old", "LEGACY02", "silicon", "si:old"),
    ] {
        sqlx::query(
            "INSERT INTO hook.hooks (id, org_id, silicon_id, endpoint_key, name, signature_required,
                 signature_config, created_by_kind, created_by_id, created_at, updated_at)
             VALUES ($1, 'tos', $2, $3, 'Legacy GitHub', false, $4, $5, $6,
                 now() - INTERVAL '3 days', now() - INTERVAL '3 days')",
        )
        .bind(id)
        .bind(silicon)
        .bind(key)
        .bind(&config)
        .bind(creator_kind)
        .bind(creator)
        .execute(pool)
        .await?;
    }
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "INSERT INTO hook.events (id, hook_id, org_id, silicon_id, provider, summary, delivery_sequence,
             method, url, path, query_string, headers, body, remote_ip, received_at, expires_at, source_generation)
         VALUES ('{EVENT}', '{LEGACY_HOOK}', 'tos', 'si:cos', 'GitHub', 'GitHub at 2026-10-09', 1, 'POST',
             'https://hook.example.test/silicon/si:cos/LEGACY01', '/silicon/si:cos/LEGACY01', '',
             '[]'::jsonb, 'legacy body'::bytea, '203.0.113.10'::inet,
             date_trunc('second', now()) - INTERVAL '1 day',
             date_trunc('second', now()) - INTERVAL '1 day' + INTERVAL '14 days', 0);
         INSERT INTO hook.blocked_requests (id, hook_id, org_id, silicon_id, provider, reason_code,
             reason_detail, method, url, path, query_string, headers, body, remote_ip, received_at, expires_at)
         VALUES (gen_random_uuid(), '{LEGACY_HOOK}', 'tos', 'si:cos', 'GitHub', 'signature_missing', 'missing',
             'POST', 'https://hook.example.test/silicon/si:cos/LEGACY01', '/silicon/si:cos/LEGACY01', '',
             '[]'::jsonb, ''::bytea, '203.0.113.10'::inet, date_trunc('second', now()),
             date_trunc('second', now()) + INTERVAL '14 days');
         INSERT INTO hook_private.retired_endpoint_keys (silicon_id, endpoint_key, hook_id, retired_at)
         VALUES ('si:cos', 'RETIRED1', '{LEGACY_HOOK}', now() - INTERVAL '2 days');
         INSERT INTO hook_private.audit_log (id, occurred_at, action, org_id, silicon_id, hook_id, actor_kind, actor_id)
         VALUES (gen_random_uuid(), now() - INTERVAL '3 days', 'hook.created', 'tos', 'si:cos', '{LEGACY_HOOK}',
             'carbon', 'c:alice');
         INSERT INTO hook_private.delivery_sequences (silicon_id, last_sequence) VALUES ('si:cos', 1);
         INSERT INTO hook_private.ting_outbox (id, environment_generation, event_id, org_id, silicon_id,
             recipient_id, idempotency_key, request_body, expires_at, accepted_at, ting_id, silent)
         SELECT gen_random_uuid(), 0, id, org_id, silicon_id, recipient, 'hook:' || id || ':' || recipient,
             '{{}}'::bytea, expires_at, accepted, CASE WHEN accepted IS NULL THEN NULL ELSE 'msg_1' END,
             CASE WHEN accepted IS NULL THEN NULL ELSE false END
         FROM hook.events, (VALUES ('si:cos', NULL::timestamptz), ('c:alice', now())) AS sends(recipient, accepted)
         WHERE id = '{EVENT}';"
    )))
    .execute(pool)
    .await?;
    Ok(())
}

/// Runs the real `hook-migrate link-identities` binary against the test database.
async fn link(api: &TestApi, mapping: &str, dry_run: bool) -> Result<(bool, Value, String)> {
    let directory = std::env::temp_dir().join(format!("hook-link-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&directory)?;
    let file: PathBuf = directory.join("mapping.csv");
    std::fs::write(&file, mapping)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_hook-migrate"));
    command
        .current_dir(&directory)
        .env("HOOK_ENVIRONMENT", "development")
        .env("HOOK_LOG_FILTER", "error")
        .env("ACCOUNTS_API_URL", &api.accounts.url)
        .env("HOOK_APP_SECRET", support::accounts::APP_SECRET)
        .env("HOOK_MIGRATOR_DATABASE_URL", api.database_url())
        .args(["link-identities", "--file"])
        .arg(&file);
    if dry_run {
        command.arg("--dry-run");
    }
    let output = command.output().await.context("run hook-migrate")?;
    std::fs::remove_dir_all(&directory)?;
    let report = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    Ok((
        output.status.success(),
        report,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

async fn scalar(api: &TestApi, sql: &'static str) -> Result<Option<String>> {
    Ok(sqlx::query_scalar(sql).fetch_one(api.owner.pool()).await?)
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one upgrade, step by step")]
async fn an_iam_era_database_upgrades_keeps_its_urls_and_links_to_accounts() -> Result<()> {
    let Some(upgrade) = Upgrade::at(18).await? else {
        return Ok(());
    };
    iam_era_fixture(upgrade.pool()).await?;
    let api = upgrade.finish(None).await?;

    let inventory: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT iam_public_id, kind, in_hook_data FROM hook_private.identity_links ORDER BY 1",
    )
    .fetch_all(api.owner.pool())
    .await?;
    assert_eq!(
        inventory,
        vec![
            ("c:alice".to_owned(), "carbon".to_owned(), true),
            ("si:cos".to_owned(), "silicon".to_owned(), true),
            ("si:old".to_owned(), "silicon".to_owned(), true),
        ]
    );
    let outbox: Vec<(String, Option<String>, bool)> = sqlx::query_as(
        "SELECT recipient_id, last_error_code, next_attempt_at = expires_at
         FROM hook_private.ting_outbox ORDER BY recipient_id",
    )
    .fetch_all(api.owner.pool())
    .await?;
    assert_eq!(
        outbox,
        vec![
            ("c:alice".to_owned(), None, false),
            (
                "si:cos".to_owned(),
                Some("legacy_identity".to_owned()),
                true
            ),
        ],
        "unaccepted IAM-era sends are parked, accepted ones kept as they were"
    );
    let kept: (String, String, Option<String>, Vec<u8>) = sqlx::query_as(
        "SELECT hook.org_id, hook.silicon_id, hook.silicon_uuid, event.body
         FROM hook.hooks AS hook JOIN hook.events AS event ON event.hook_id = hook.id WHERE hook.id = $1",
    )
    .bind(LEGACY_HOOK)
    .fetch_one(api.owner.pool())
    .await?;
    assert_eq!(
        kept,
        (
            "tos".to_owned(),
            "si:cos".to_owned(),
            None,
            b"legacy body".to_vec()
        )
    );

    // Provider URLs keep working before anything is linked.
    for path in [
        "/silicon/si:cos/LEGACY01",
        "/api/v1/silicon/si:cos/LEGACY01",
    ] {
        assert_eq!(
            api.deliver(path, &[], b"{}").await?.0,
            StatusCode::OK,
            "{path}"
        );
    }
    let (status, retired) = api.deliver("/silicon/si:cos/RETIRED1", &[], b"{}").await?;
    assert_eq!(
        (status, retired["error"]["code"].clone()),
        (StatusCode::GONE, json!("endpoint_retired"))
    );
    api.accounts.add_carbon("CAlice1", "c:alice");
    api.accounts
        .add_silicon("8HV", "si:cos", Some(("CAlice1", "c:alice")));
    let cos = api.accounts.token("8HV", "silicon", "si:cos");
    let (_, before) = api
        .call(
            Method::GET,
            "/api/v3/silicons/si:cos/hooks",
            Some(&cos),
            None,
        )
        .await?;
    assert_eq!(
        before["items"],
        json!([]),
        "unlinked IAM-era hooks have no Accounts owner yet"
    );

    // A cached Carbon must never receive a Silicon namespace, even in a dry run.
    let alice = api.accounts.token("CAlice1", "carbon", "c:alice");
    api.call(Method::GET, "/api/v3/auth/status", Some(&alice), None)
        .await?;
    let (ok, _, stderr) = link(&api, "iam_public_id,accounts_uuid\nsi:cos,CAlice1\n", true).await?;
    assert!(!ok, "kind mismatch was accepted");
    assert!(stderr.contains("that account is a carbon"), "{stderr}");

    api.accounts
        .add_silicon("Gh0st", "si:ghost", Some(("CAlice1", "c:alice")));
    let mapping =
        "# reviewed\niam_principal_id,accounts_uuid\nsi:cos,8HV\nc:alice,CAlice1\nsi:ghost,Gh0st\n";
    let (ok, dry, stderr) = link(&api, mapping, true).await?;
    assert!(ok, "{stderr}");
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["linked"], 3);
    assert_eq!(dry["rekeyed"]["hooks"], 1);
    assert_eq!(dry["rekeyed"]["hook_creators"], 1);
    assert_eq!(
        dry["rekeyed"]["events"], 3,
        "the fixture event and the two received above"
    );
    assert_eq!(dry["not_in_hook_data"], json!(["si:ghost"]));
    assert_eq!(dry["unmatched_in_hook_data"], json!(["si:old"]));
    assert_eq!(dry["hooks_without_owner"], 1);
    let unchanged = scalar(
        &api,
        "SELECT silicon_uuid FROM hook.hooks WHERE endpoint_key = 'LEGACY01'",
    )
    .await?;
    assert_eq!(unchanged, None, "a dry run changes nothing");

    let (ok, real, stderr) = link(&api, mapping, false).await?;
    assert!(ok, "{stderr}");
    assert_eq!(
        (real["dry_run"].clone(), real["rekeyed"].clone()),
        (json!(false), dry["rekeyed"].clone())
    );
    let again = link(&api, mapping, false).await?.1;
    assert!(
        again["rekeyed"]
            .as_object()
            .is_some_and(|rows| rows.values().all(|count| count == 0)),
        "{again}"
    );
    for (sql, expected) in [
        (
            "SELECT silicon_uuid FROM hook.hooks WHERE endpoint_key = 'LEGACY01'",
            "8HV",
        ),
        (
            "SELECT created_by_uuid FROM hook.hooks WHERE endpoint_key = 'LEGACY01'",
            "CAlice1",
        ),
        ("SELECT max(silicon_uuid) FROM hook.blocked_requests", "8HV"),
        (
            "SELECT max(silicon_uuid) FROM hook_private.retired_endpoint_keys",
            "8HV",
        ),
        (
            "SELECT max(actor_uuid) FROM hook_private.audit_log WHERE actor_id = 'c:alice'",
            "CAlice1",
        ),
        (
            "SELECT org_id || ' ' || silicon_id FROM hook.hooks WHERE endpoint_key = 'LEGACY01'",
            "tos si:cos",
        ),
    ] {
        assert_eq!(scalar(&api, sql).await?.as_deref(), Some(expected), "{sql}");
    }

    // The Silicon now manages its IAM-era hook and reads its history; every URL works.
    let (status, hooks) = api
        .call(Method::GET, "/api/v3/silicons/8HV/hooks", Some(&cos), None)
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        hooks["items"][0]["endpoint_url"],
        "https://hook.example.test/silicon/si:cos/LEGACY01"
    );
    assert_eq!(hooks["items"][0]["created_by"]["uuid"], "CAlice1");
    let (_, events) = api
        .call(
            Method::GET,
            "/api/v3/silicons/si:cos/events",
            Some(&cos),
            None,
        )
        .await?;
    assert_eq!(events["items"].as_array().map(Vec::len), Some(3));
    for path in ["/silicon/8HV/LEGACY01", "/silicon/si:cos/LEGACY01"] {
        assert_eq!(
            api.deliver(path, &[], b"{}").await?.0,
            StatusCode::OK,
            "{path}"
        );
    }
    let alice = api.accounts.token("CAlice1", "carbon", "c:alice");
    let (status, _) = api
        .call(
            Method::PATCH,
            &format!("/api/v3/silicons/si:cos/hooks/{LEGACY_HOOK}"),
            Some(&alice),
            Some(&json!({"name": "GitHub (renamed)"})),
        )
        .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "the custodian manages the linked hook"
    );

    // A uuid already linked elsewhere is refused; an empty uuid unlinks.
    let (ok, _, stderr) = link(&api, "iam_public_id,accounts_uuid\nsi:old,8HV\n", false).await?;
    assert!(
        !ok && stderr.contains("8HV is linked to si:cos"),
        "{stderr}"
    );
    let (ok, unlinked, stderr) =
        link(&api, "iam_public_id,accounts_uuid\nsi:cos,\n", false).await?;
    assert!(ok, "{stderr}");
    assert_eq!(unlinked["unlinked"], 1);
    let (_, after) = api
        .call(
            Method::GET,
            "/api/v3/silicons/si:cos/hooks",
            Some(&cos),
            None,
        )
        .await?;
    assert_eq!(after["items"], json!([]));
    let (ok, _, stderr) = link(
        &api,
        "iam_public_id,accounts_uuid\nsi:cos,8HV\nsi:cos,8HV\n",
        false,
    )
    .await?;
    assert!(
        !ok && stderr.contains("already mapped on line 2"),
        "{stderr}"
    );
    Ok(())
}
