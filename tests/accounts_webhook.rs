//! Hook's Silicon Accounts app webhook over HTTP: signature checks, dedupe,
//! unknown types, and what each of the six account events does to sign-ins,
//! access and provider URLs.

mod support;

use anyhow::Result;
use http::{Method, StatusCode};
use serde_json::{Value, json};
use support::{
    accounts::{self, WEBHOOK_SECRET},
    api::{TestApi, event},
};

fn setup(api: &TestApi) {
    let stub = &api.accounts;
    stub.add_carbon("CAlice1", "c:alice");
    stub.add_carbon("CBob2", "c:bob");
    stub.add_carbon("CDave4", "c:dave");
    stub.add_silicon("SCos1", "si:cos", Some(("CAlice1", "c:alice")));
    stub.add_silicon("SDev2", "si:dev", Some(("CAlice1", "c:alice")));
}

/// Creates an unsigned hook for Cos and returns its endpoint key.
async fn open_hook(api: &TestApi) -> Result<String> {
    let cos = api.accounts.token("SCos1", "silicon", "si:cos");
    let (status, hook) = api
        .call(
            Method::POST,
            "/api/v3/silicons/si:cos/hooks",
            Some(&cos),
            Some(&json!({"name": "Open", "signature": {"required": false}})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{hook}");
    Ok(hook["endpoint_key"].as_str().unwrap_or_default().to_owned())
}

async fn status_of(api: &TestApi, token: &str) -> Result<(StatusCode, Value)> {
    api.call(Method::GET, "/api/v3/auth/status", Some(token), None)
        .await
}

async fn hooks_as(api: &TestApi, silicon: &str, token: &str) -> Result<StatusCode> {
    let path = format!("/api/v3/silicons/{silicon}/hooks");
    Ok(api.call(Method::GET, &path, Some(token), None).await?.0)
}

#[tokio::test]
async fn deliveries_are_verified_deduplicated_and_unknown_types_acknowledged() -> Result<()> {
    let Some(api) = TestApi::start().await? else {
        return Ok(());
    };
    setup(&api);
    let ping = event("evt_ping", "ping", &json!({}));
    let body = ping.to_string().into_bytes();
    let now = accounts::now();

    let forged = silicon_accounts_client::sign_webhook("whsec_wrong", now, &body);
    let (status, refused) = api
        .raw_webhook(&now.to_string(), &forged, body.clone())
        .await?;
    assert_eq!(
        (status, refused["error"]["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("webhook_signature_invalid"))
    );
    let stale = now - 6 * 60;
    let old = silicon_accounts_client::sign_webhook(WEBHOOK_SECRET, stale, &body);
    let (status, _) = api
        .raw_webhook(&stale.to_string(), &old, body.clone())
        .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "older than five minutes");
    let (status, _) = api.raw_webhook("", "", body.clone()).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "unsigned");
    let not_event = b"not json".to_vec();
    let signed = silicon_accounts_client::sign_webhook(WEBHOOK_SECRET, now, &not_event);
    let (status, bad) = api
        .raw_webhook(&now.to_string(), &signed, not_event)
        .await?;
    assert_eq!(
        (status, bad["error"]["code"].clone()),
        (StatusCode::BAD_REQUEST, json!("invalid_event"))
    );

    assert_eq!(api.webhook(&ping).await?.0, StatusCode::NO_CONTENT);
    let future = event(
        "evt_future",
        "account.something_new",
        &json!({"uuid": "SCos1"}),
    );
    assert_eq!(
        api.webhook(&future).await?.0,
        StatusCode::NO_CONTENT,
        "unknown types are acknowledged"
    );

    // The same event id applies once, whatever a repeat says.
    let renamed = event(
        "evt_rename",
        "account.id_changed",
        &json!({"uuid": "SCos1", "kind": "silicon", "old_id": "si:cos", "new_id": "si:cosmo"}),
    );
    assert_eq!(api.webhook(&renamed).await?.0, StatusCode::NO_CONTENT);
    let replay = event(
        "evt_rename",
        "account.id_changed",
        &json!({"uuid": "SCos1", "kind": "silicon", "old_id": "si:cosmo", "new_id": "si:other"}),
    );
    assert_eq!(api.webhook(&replay).await?.0, StatusCode::NO_CONTENT);
    let current: Option<String> =
        sqlx::query_scalar("SELECT public_id FROM hook_private.accounts WHERE uuid = 'SCos1'")
            .fetch_one(api.owner.pool())
            .await?;
    assert_eq!(current.as_deref(), Some("si:cosmo"));
    let handled: i64 = sqlx::query_scalar("SELECT count(*) FROM hook_private.accounts_events")
        .fetch_one(api.owner.pool())
        .await?;
    assert_eq!(
        handled, 3,
        "ping, the unknown type and the rename are recorded once each"
    );
    Ok(())
}

#[tokio::test]
async fn provider_urls_keep_working_after_the_silicon_changes_its_id() -> Result<()> {
    let Some(api) = TestApi::start().await? else {
        return Ok(());
    };
    setup(&api);
    let key = open_hook(&api).await?;
    for segment in ["si:cos", "SCos1"] {
        let (status, body) = api
            .deliver(&format!("/silicon/{segment}/{key}"), &[], b"{}")
            .await?;
        assert_eq!(status, StatusCode::OK, "{segment}: {body}");
    }

    api.accounts.rename("SCos1", "si:cosmo");
    let renamed = event(
        "evt_1",
        "account.id_changed",
        &json!({"uuid": "SCos1", "kind": "silicon", "old_id": "si:cos", "new_id": "si:cosmo"}),
    );
    assert_eq!(api.webhook(&renamed).await?.0, StatusCode::NO_CONTENT);
    for segment in ["si:cosmo", "si:cos", "SCos1", "api/v2/silicon/si:cos"] {
        let path = if segment.starts_with("api/") {
            format!("/{segment}/{key}")
        } else {
            format!("/silicon/{segment}/{key}")
        };
        let (status, body) = api.deliver(&path, &[], b"{}").await?;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
    }
    // Another Silicon's id never routes to Cos's hook.
    let (status, _) = api
        .deliver(&format!("/silicon/si:dev/{key}"), &[], b"{}")
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let cos = api.accounts.token("SCos1", "silicon", "si:cosmo");
    let (status, listed) = api
        .call(
            Method::GET,
            "/api/v3/silicons/si:cosmo/hooks",
            Some(&cos),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        listed["items"][0]["endpoint_url"],
        format!("https://hook.example.test/silicon/si:cosmo/{key}")
    );
    let (_, events) = api
        .call(
            Method::GET,
            "/api/v3/silicons/si:cosmo/events",
            Some(&cos),
            None,
        )
        .await?;
    assert_eq!(
        events["items"].as_array().map(Vec::len),
        Some(6),
        "{events}"
    );
    Ok(())
}

#[tokio::test]
async fn custodian_changes_move_control_at_once_and_stale_events_change_nothing() -> Result<()> {
    let Some(api) = TestApi::start().await? else {
        return Ok(());
    };
    setup(&api);
    let alice = api.accounts.token("CAlice1", "carbon", "c:alice");
    let dave = api.accounts.token("CDave4", "carbon", "c:dave");
    assert_eq!(hooks_as(&api, "si:cos", &alice).await?, StatusCode::OK);
    assert_eq!(
        hooks_as(&api, "si:cos", &dave).await?,
        StatusCode::FORBIDDEN
    );

    api.accounts
        .set_custodian("SCos1", Some(("CDave4", "c:dave")));
    let moved = event(
        "evt_c1",
        "silicon.custodian_changed",
        &json!({"uuid": "SCos1",
        "from": {"uuid": "CAlice1", "id": "c:alice"}, "to": {"uuid": "CDave4", "id": "c:dave"}}),
    );
    assert_eq!(api.webhook(&moved).await?.0, StatusCode::NO_CONTENT);
    assert_eq!(
        hooks_as(&api, "si:cos", &alice).await?,
        StatusCode::FORBIDDEN
    );
    assert_eq!(hooks_as(&api, "si:cos", &dave).await?, StatusCode::OK);

    // An older event arriving late does not move the Silicon back.
    let mut late = event(
        "evt_c0",
        "silicon.custodian_changed",
        &json!({"uuid": "SCos1",
        "from": null, "to": {"uuid": "CAlice1", "id": "c:alice"}}),
    );
    late["occurred_at"] = json!("2026-01-01T00:00:00.000Z");
    assert_eq!(api.webhook(&late).await?.0, StatusCode::NO_CONTENT);
    assert_eq!(
        hooks_as(&api, "si:cos", &alice).await?,
        StatusCode::FORBIDDEN
    );

    // account.updated: only a higher version changes the stored profile.
    for (event_id, version, name) in [("evt_u2", 2, "Cos Two"), ("evt_u1", 1, "Cos One")] {
        let updated = event(
            event_id,
            "account.updated",
            &json!({"uuid": "SCos1", "changed": ["display_name"],
            "account": {"uuid": "SCos1", "kind": "silicon", "id": "si:cos", "display_name": name,
                "custodian": {"uuid": "CDave4", "id": "c:dave"}, "version": version}}),
        );
        assert_eq!(api.webhook(&updated).await?.0, StatusCode::NO_CONTENT);
    }
    let profile: (Option<String>, i64) = sqlx::query_as(
        "SELECT display_name, profile_version FROM hook_private.accounts WHERE uuid = 'SCos1'",
    )
    .fetch_one(api.owner.pool())
    .await?;
    assert_eq!(profile, (Some("Cos Two".to_owned()), 2));
    Ok(())
}

#[tokio::test]
async fn sign_outs_end_sessions_except_the_ones_hook_revoked_itself() -> Result<()> {
    let Some(api) = TestApi::start().await? else {
        return Ok(());
    };
    setup(&api);
    let bob = api.accounts.token("CBob2", "carbon", "c:bob");
    assert_eq!(status_of(&api, &bob).await?.0, StatusCode::OK);

    let own_logout = event(
        "evt_s1",
        "membership.signed_out",
        &json!({"uuid": "CBob2", "reason": "app_revoked"}),
    );
    assert_eq!(api.webhook(&own_logout).await?.0, StatusCode::NO_CONTENT);
    assert_eq!(
        status_of(&api, &bob).await?.0,
        StatusCode::OK,
        "Hook ended one sign-in itself; others continue"
    );

    // Silicon Accounts revokes every token of the account, then tells Hook.
    api.accounts.deactivate(&bob);
    let everywhere = event(
        "evt_s2",
        "membership.signed_out",
        &json!({"uuid": "CBob2", "reason": "signed_out_everywhere"}),
    );
    assert_eq!(api.webhook(&everywhere).await?.0, StatusCode::NO_CONTENT);
    let (status, refused) = status_of(&api, &bob).await?;
    assert_eq!(
        (status, refused["error"]["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("session_ended"))
    );
    let later = accounts::now() + 2;
    let fresh = api.accounts.sign(
        &json!({"iss": api.accounts.url, "sub": "CBob2", "aud": "hook",
        "exp": later + 600, "iat": later, "kind": "carbon", "id": "c:bob"}),
    );
    assert_eq!(
        status_of(&api, &fresh).await?.0,
        StatusCode::OK,
        "signing in again works"
    );

    let alice = api.accounts.token("CAlice1", "carbon", "c:alice");
    api.accounts.deactivate(&alice);
    let removed = event(
        "evt_s3",
        "membership.access_removed",
        &json!({"uuid": "CAlice1"}),
    );
    assert_eq!(api.webhook(&removed).await?.0, StatusCode::NO_CONTENT);
    assert_eq!(status_of(&api, &alice).await?.0, StatusCode::UNAUTHORIZED);
    Ok(())
}

/// `iat` counts whole seconds while a sign-out keeps milliseconds: a Silicon
/// that signs in again right after its STK was rotated holds a token from the
/// sign-out's own second, which only Silicon Accounts can place.
#[tokio::test]
async fn a_token_from_the_sign_out_second_is_settled_by_silicon_accounts() -> Result<()> {
    let Some(api) = TestApi::start().await? else {
        return Ok(());
    };
    setup(&api);
    let second = accounts::now();
    let signed_out_at =
        time::OffsetDateTime::from_unix_timestamp(second)? + time::Duration::milliseconds(500);
    let stamp = signed_out_at.format(&time::format_description::well_known::Rfc3339)?;
    let sign_out = json!({
        "event_id": "evt_same_second", "type": "membership.signed_out", "occurred_at": stamp,
        "data": {"uuid": "CBob2", "reason": "stk_rotated"},
    });
    assert_eq!(api.webhook(&sign_out).await?.0, StatusCode::NO_CONTENT);
    let token = |iat: i64, lifetime: i64| {
        api.accounts.sign(
            &json!({"iss": api.accounts.url, "sub": "CBob2", "aud": "hook",
            "exp": iat + lifetime, "iat": iat, "kind": "carbon", "id": "c:bob"}),
        )
    };

    let asked = api.accounts.introspections();
    let older = token(second - 1, 600);
    assert_eq!(status_of(&api, &older).await?.0, StatusCode::UNAUTHORIZED);
    let newer = token(second + 1, 600);
    assert_eq!(status_of(&api, &newer).await?.0, StatusCode::OK);
    assert_eq!(
        api.accounts.introspections(),
        asked,
        "other seconds are settled locally"
    );

    let after_it = token(second, 601);
    assert_eq!(
        status_of(&api, &after_it).await?.0,
        StatusCode::OK,
        "issued after the sign-out"
    );
    assert_eq!(status_of(&api, &after_it).await?.0, StatusCode::OK);
    assert_eq!(
        api.accounts.introspections(),
        asked + 1,
        "asked once, then remembered"
    );

    let before_it = token(second, 602);
    api.accounts.deactivate(&before_it);
    let (status, refused) = status_of(&api, &before_it).await?;
    assert_eq!(
        (status, refused["error"]["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("session_ended")),
        "issued before the sign-out in the same second"
    );
    let message = refused["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&stamp),
        "the time reads as RFC 3339: {message}"
    );
    Ok(())
}

#[tokio::test]
async fn deleting_an_account_retires_its_hooks_tokens_and_grants() -> Result<()> {
    let Some(api) = TestApi::start().await? else {
        return Ok(());
    };
    setup(&api);
    let key = open_hook(&api).await?;
    let alice = api.accounts.token("CAlice1", "carbon", "c:alice");
    let bob = api.accounts.token("CBob2", "carbon", "c:bob");
    let cos = api.accounts.token("SCos1", "silicon", "si:cos");
    for silicon in ["si:cos", "si:dev"] {
        let (status, body) = api
            .call(
                Method::PUT,
                &format!("/api/v3/silicons/{silicon}/access/c:bob"),
                Some(&alice),
                Some(&json!({"level": "view"})),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    api.accounts.delete("SCos1");
    assert_eq!(
        api.webhook(&event(
            "evt_d1",
            "account.deleted",
            &json!({"uuid": "SCos1"})
        ))
        .await?
        .0,
        StatusCode::NO_CONTENT
    );
    let (status, gone) = api
        .deliver(&format!("/silicon/si:cos/{key}"), &[], b"{}")
        .await?;
    assert_eq!(
        (status, gone["error"]["code"].clone()),
        (StatusCode::GONE, json!("account_deleted"))
    );
    let (status, refused) = status_of(&api, &cos).await?;
    assert_eq!(
        (status, refused["error"]["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("account_deleted"))
    );
    let (status, body) = api
        .call(
            Method::GET,
            "/api/v3/silicons/SCos1/hooks",
            Some(&alice),
            None,
        )
        .await?;
    assert_eq!(
        (status, body["error"]["code"].clone()),
        (StatusCode::GONE, json!("account_deleted"))
    );
    let hooks: (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE deleted_at IS NOT NULL) FROM hook.hooks WHERE silicon_uuid = 'SCos1'",
    )
    .fetch_one(api.owner.pool())
    .await?;
    assert_eq!(hooks, (1, 1), "the hook is soft-deleted, not destroyed");

    // A deleted Carbon loses every grant it held; other Silicons are untouched.
    assert_eq!(hooks_as(&api, "si:dev", &bob).await?, StatusCode::OK);
    assert_eq!(
        api.webhook(&event(
            "evt_d2",
            "account.deleted",
            &json!({"uuid": "CBob2"})
        ))
        .await?
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(status_of(&api, &bob).await?.0, StatusCode::UNAUTHORIZED);
    let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM hook_private.silicon_grants")
        .fetch_one(api.owner.pool())
        .await?;
    assert_eq!(grants, 0);
    assert_eq!(hooks_as(&api, "si:dev", &alice).await?, StatusCode::OK);
    Ok(())
}
