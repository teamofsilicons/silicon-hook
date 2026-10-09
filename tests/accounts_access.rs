//! Who may do what with a Silicon's hooks, over HTTP with Silicon Accounts
//! tokens: the Silicon, its custodian, view and manage grants, the allow-list
//! that keeps Silicons from being open to the world, and introspection on
//! the routes that reveal secrets or change access.

mod support;

use anyhow::Result;
use http::{Method, StatusCode};
use serde_json::{Value, json};
use support::api::TestApi;

/// Alice looks after Cos and Dev; Dave looks after Ext; Bob and Carol are
/// other Carbons.
struct People {
    cos: String,
    dev: String,
    ext: String,
    alice: String,
    bob: String,
    carol: String,
    dave: String,
}

fn people(api: &TestApi) -> People {
    let stub = &api.accounts;
    stub.add_carbon("CAlice1", "c:alice");
    stub.add_carbon("CBob2", "c:bob");
    stub.add_carbon("CCarol3", "c:carol");
    stub.add_carbon("CDave4", "c:dave");
    stub.add_silicon("SCos1", "si:cos", Some(("CAlice1", "c:alice")));
    stub.add_silicon("SDev2", "si:dev", Some(("CAlice1", "c:alice")));
    stub.add_silicon("SExt3", "si:ext", Some(("CDave4", "c:dave")));
    People {
        cos: stub.token("SCos1", "silicon", "si:cos"),
        dev: stub.token("SDev2", "silicon", "si:dev"),
        ext: stub.token("SExt3", "silicon", "si:ext"),
        alice: stub.token("CAlice1", "carbon", "c:alice"),
        bob: stub.token("CBob2", "carbon", "c:bob"),
        carol: stub.token("CCarol3", "carbon", "c:carol"),
        dave: stub.token("CDave4", "carbon", "c:dave"),
    }
}

async fn create_hook(
    api: &TestApi,
    silicon: &str,
    token: &str,
    name: &str,
) -> Result<(StatusCode, Value)> {
    api.call(
        Method::POST,
        &format!("/api/v3/silicons/{silicon}/hooks"),
        Some(token),
        Some(&json!({"name": name})),
    )
    .await
}

async fn list_hooks(api: &TestApi, silicon: &str, token: &str) -> Result<(StatusCode, Value)> {
    api.call(
        Method::GET,
        &format!("/api/v3/silicons/{silicon}/hooks"),
        Some(token),
        None,
    )
    .await
}

async fn grant(
    api: &TestApi,
    token: &str,
    grantee: &str,
    level: &str,
) -> Result<(StatusCode, Value)> {
    api.call(
        Method::PUT,
        &format!("/api/v3/silicons/si:cos/access/{grantee}"),
        Some(token),
        Some(&json!({"level": level})),
    )
    .await
}

#[tokio::test]
async fn the_silicon_and_its_custodian_have_full_control_and_nobody_else_has_any() -> Result<()> {
    let Some(api) = TestApi::start().await? else {
        return Ok(());
    };
    let p = people(&api);

    let (status, own) = create_hook(&api, "si:cos", &p.cos, "GitHub").await?;
    assert_eq!(status, StatusCode::CREATED, "{own}");
    assert_eq!(own["silicon"], json!({"uuid": "SCos1", "id": "si:cos"}));
    assert_eq!(own["created_by"]["uuid"], "SCos1");
    assert!(
        own["endpoint_url"]
            .as_str()
            .is_some_and(|url| url.starts_with("https://hook.example.test/silicon/si:cos/"))
    );
    assert!(
        own["signing_secret"]
            .as_str()
            .is_some_and(|secret| !secret.is_empty())
    );

    // The custodian acts on the Silicon's hooks as itself, never as the Silicon.
    let (status, by_custodian) = create_hook(&api, "si:cos", &p.alice, "Stripe").await?;
    assert_eq!(status, StatusCode::CREATED, "{by_custodian}");
    assert_eq!(
        by_custodian["created_by"],
        json!({"uuid": "CAlice1", "kind": "carbon", "id": "c:alice"})
    );
    let (status, listed) = list_hooks(&api, "SCos1", &p.alice).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["items"].as_array().map(Vec::len), Some(2));

    // A sibling Silicon (same custodian), another Silicon and other Carbons see nothing.
    for (who, token) in [
        ("sibling", &p.dev),
        ("outside Silicon", &p.ext),
        ("Carbon", &p.bob),
        ("another Carbon", &p.carol),
        ("custodian of another", &p.dave),
    ] {
        let (status, body) = list_hooks(&api, "si:cos", token).await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{who}: {body}");
        assert_eq!(body["error"]["code"], "no_access", "{who}");
        let (status, _) = create_hook(&api, "si:cos", token, "Nope").await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{who}");
    }

    // Exact errors for Silicons that do not exist and for Carbons.
    let (status, body) = list_hooks(&api, "si:nobody", &p.alice).await?;
    assert_eq!(
        (status, body["error"]["code"].clone()),
        (StatusCode::NOT_FOUND, json!("silicon_not_found"))
    );
    let (status, body) = list_hooks(&api, "c:bob", &p.alice).await?;
    assert_eq!(
        (status, body["error"]["code"].clone()),
        (StatusCode::NOT_FOUND, json!("not_a_silicon"))
    );
    let (status, body) = list_hooks(&api, "not%20an%20id", &p.alice).await?;
    assert_eq!(
        (status, body["error"]["code"].clone()),
        (StatusCode::UNPROCESSABLE_ENTITY, json!("invalid_account"))
    );
    let (status, body) = api
        .call(Method::GET, "/api/v3/silicons/si:cos/hooks", None, None)
        .await?;
    assert_eq!(
        (status, body["error"]["code"].clone()),
        (StatusCode::UNAUTHORIZED, json!("unauthenticated"))
    );

    // The custodian sees both Silicons it looks after once Hook has met them.
    list_hooks(&api, "si:dev", &p.dev).await?;
    let (status, silicons) = api
        .call(Method::GET, "/api/v3/silicons", Some(&p.alice), None)
        .await?;
    assert_eq!(status, StatusCode::OK);
    let mut seen = silicons["items"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|item| (item["silicon"]["id"].clone(), item["access"].clone()))
        .collect::<Vec<_>>();
    seen.sort_by_key(|(id, _)| id.to_string());
    assert_eq!(
        seen,
        vec![
            (json!("si:cos"), json!("custodian")),
            (json!("si:dev"), json!("custodian"))
        ]
    );
    let (_, own_list) = api
        .call(Method::GET, "/api/v3/silicons", Some(&p.cos), None)
        .await?;
    assert_eq!(own_list["items"][0]["access"], "self");
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one sharing scenario, step by step")]
async fn grants_give_view_or_manage_and_a_grantee_can_leave() -> Result<()> {
    let Some(api) = TestApi::start().await? else {
        return Ok(());
    };
    let p = people(&api);
    let (_, hook) = create_hook(&api, "si:cos", &p.cos, "GitHub").await?;
    let hook_path = format!(
        "/api/v3/silicons/si:cos/hooks/{}",
        hook["id"].as_str().unwrap_or_default()
    );

    let (status, granted) = grant(&api, &p.alice, "c:bob", "view").await?;
    assert_eq!(status, StatusCode::OK, "{granted}");
    assert_eq!(granted["grant"]["level"], "view");
    assert_eq!(granted["grant"]["granted_by"]["uuid"], "CAlice1");
    assert_eq!(list_hooks(&api, "si:cos", &p.bob).await?.0, StatusCode::OK);
    assert_eq!(
        api.call(
            Method::GET,
            "/api/v3/silicons/si:cos/events",
            Some(&p.bob),
            None
        )
        .await?
        .0,
        StatusCode::OK
    );
    let (status, body) = create_hook(&api, "si:cos", &p.bob, "Viewer").await?;
    assert_eq!(
        (status, body["error"]["code"].clone()),
        (StatusCode::FORBIDDEN, json!("forbidden"))
    );
    assert_eq!(
        api.call(Method::DELETE, &hook_path, Some(&p.bob), None)
            .await?
            .0,
        StatusCode::FORBIDDEN
    );

    // Only the Silicon and its custodian decide who has access.
    let (status, _) = grant(&api, &p.bob, "c:carol", "view").await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = api
        .call(
            Method::POST,
            "/api/v3/silicons/si:cos/hooks/accounts",
            Some(&p.bob),
            None,
        )
        .await?;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "only the Silicon or its custodian connects its Accounts updates"
    );
    let (status, body) = grant(&api, &p.cos, "c:alice", "view").await?;
    assert_eq!(
        (status, body["error"]["code"].clone()),
        (StatusCode::CONFLICT, json!("already_has_access"))
    );
    let (status, body) = grant(&api, &p.cos, "c:bob", "admin").await?;
    assert_eq!(
        (status, body["error"]["code"].clone()),
        (StatusCode::UNPROCESSABLE_ENTITY, json!("invalid_level"))
    );

    // The Silicon itself raises Bob to manage; Bob can now change hooks.
    assert_eq!(
        grant(&api, &p.cos, "c:bob", "manage").await?.0,
        StatusCode::OK
    );
    let (status, managed) = create_hook(&api, "si:cos", &p.bob, "Manager").await?;
    assert_eq!(status, StatusCode::CREATED, "{managed}");
    assert_eq!(managed["created_by"]["uuid"], "CBob2");
    assert_eq!(
        api.call(Method::DELETE, &hook_path, Some(&p.bob), None)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );

    let (status, access) = api
        .call(
            Method::GET,
            "/api/v3/silicons/si:cos/access",
            Some(&p.alice),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(access["you"]["access"], "custodian");
    assert_eq!(access["custodian"]["uuid"], "CAlice1");
    assert_eq!(access["grants"].as_array().map(Vec::len), Some(1));

    // A grantee leaves; afterwards it has no access at all.
    let (status, _) = api
        .call(
            Method::DELETE,
            "/api/v3/silicons/si:cos/access/me",
            Some(&p.bob),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        list_hooks(&api, "si:cos", &p.bob).await?.0,
        StatusCode::FORBIDDEN
    );
    let (status, body) = api
        .call(
            Method::DELETE,
            "/api/v3/silicons/si:cos/access/c:bob",
            Some(&p.alice),
            None,
        )
        .await?;
    assert_eq!(
        (status, body["error"]["code"].clone()),
        (StatusCode::NOT_FOUND, json!("grant_not_found"))
    );
    Ok(())
}

#[tokio::test]
async fn a_silicon_outside_the_circle_receives_access_only_after_allowing_the_sharer() -> Result<()>
{
    let Some(api) = TestApi::start().await? else {
        return Ok(());
    };
    let p = people(&api);
    create_hook(&api, "si:cos", &p.cos, "GitHub").await?;

    let (status, body) = grant(&api, &p.alice, "si:ext", "view").await?;
    assert_eq!(
        (status, body["error"]["code"].clone()),
        (StatusCode::FORBIDDEN, json!("silicon_not_reachable")),
        "{body}"
    );
    // A sibling (same custodian) is inside the circle and needs no allow-list.
    assert_eq!(
        grant(&api, &p.alice, "si:dev", "view").await?.0,
        StatusCode::OK
    );
    assert_eq!(list_hooks(&api, "si:cos", &p.dev).await?.0, StatusCode::OK);

    // Only Ext and its custodian manage Ext's allow-list.
    let allow = "/api/v3/silicons/si:ext/allow-list/c:alice";
    assert_eq!(
        api.call(Method::PUT, allow, Some(&p.alice), None).await?.0,
        StatusCode::FORBIDDEN
    );
    let (status, entry) = api.call(Method::PUT, allow, Some(&p.dave), None).await?;
    assert_eq!(status, StatusCode::OK, "{entry}");
    assert_eq!(entry["account"]["uuid"], "CAlice1");
    let (status, listed) = api
        .call(
            Method::GET,
            "/api/v3/silicons/si:ext/allow-list",
            Some(&p.ext),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["items"].as_array().map(Vec::len), Some(1));

    assert_eq!(
        grant(&api, &p.alice, "si:ext", "view").await?.0,
        StatusCode::OK
    );
    assert_eq!(list_hooks(&api, "si:cos", &p.ext).await?.0, StatusCode::OK);
    assert_eq!(
        create_hook(&api, "si:cos", &p.ext, "Nope").await?.0,
        StatusCode::FORBIDDEN
    );

    // Removing the allowance stops new grants, not the existing one.
    assert_eq!(
        api.call(Method::DELETE, allow, Some(&p.ext), None).await?.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        api.call(Method::DELETE, allow, Some(&p.ext), None).await?.0,
        StatusCode::NOT_FOUND
    );
    let (status, _) = grant(&api, &p.alice, "si:ext", "manage").await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn routes_that_reveal_secrets_or_change_access_confirm_the_token_is_still_active()
-> Result<()> {
    let Some(api) = TestApi::start().await? else {
        return Ok(());
    };
    let p = people(&api);
    let (_, hook) = create_hook(&api, "si:cos", &p.cos, "GitHub").await?;
    let hook_id = hook["id"].as_str().unwrap_or_default().to_owned();
    api.accounts.deactivate(&p.cos);

    // Local checks still pass: the token is valid until it expires.
    assert_eq!(list_hooks(&api, "si:cos", &p.cos).await?.0, StatusCode::OK);
    for (method, path, body) in [
        (
            Method::POST,
            "/api/v3/silicons/si:cos/hooks".to_owned(),
            Some(json!({"name": "Late"})),
        ),
        (
            Method::POST,
            format!("/api/v3/silicons/si:cos/hooks/{hook_id}/secret/rotate"),
            None,
        ),
        (
            Method::POST,
            format!("/api/v3/silicons/si:cos/hooks/{hook_id}/endpoint/rotate"),
            None,
        ),
        (
            Method::DELETE,
            format!("/api/v3/silicons/si:cos/hooks/{hook_id}"),
            None,
        ),
        (
            Method::PUT,
            "/api/v3/silicons/si:cos/access/c:bob".to_owned(),
            Some(json!({"level": "view"})),
        ),
        (
            Method::PUT,
            "/api/v3/silicons/si:cos/allow-list/c:bob".to_owned(),
            None,
        ),
        (
            Method::POST,
            "/api/v3/silicons/si:cos/hooks/accounts".to_owned(),
            None,
        ),
    ] {
        let (status, response) = api
            .call(method.clone(), &path, Some(&p.cos), body.as_ref())
            .await?;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {path}: {response}"
        );
        assert_eq!(
            response["error"]["code"], "session_ended",
            "{method} {path}"
        );
    }
    Ok(())
}
