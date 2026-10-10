//! Silicon Accounts at the HTTP boundary: sign-in discovery, status, the app
//! webhook, the Silicons a caller can open, who has access to them, and the
//! hook that receives a Silicon's own Accounts events.

use axum::{Extension, Json, body::Bytes, extract::Path};
use http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{
    auth::{self, Check},
    dto::{AccountResponse, HookResponse, SiliconResponse},
    extractors,
    handlers::{
        hook_response, management_context, map_application_error, parse_json, require_empty_body,
        secret_response_headers,
    },
    state::ApiState,
};
use crate::{
    application::{AccessibleSilicon, ConnectAccountsHookCommand},
    domain::{AccountUuid, Actor, ActorKind, GrantLevel, PublicId, SiliconRef},
    error::AppError,
    infrastructure::postgres::{AccountRecord, AllowRecord, GrantRecord},
    request_context,
};

/// `GET /api/v3/auth/accounts`: how to sign in to Hook. Public.
pub(super) async fn sign_in_information(
    Extension(state): Extension<ApiState>,
) -> (HeaderMap, Json<serde_json::Value>) {
    let accounts = state.application.accounts();
    (
        secret_response_headers(),
        Json(serde_json::json!({
            "app_id": accounts.app_id(),
            "accounts_url": accounts.issuer(),
            "token": {
                "type": "Bearer",
                "format": "Silicon Accounts access token (EdDSA JWT)",
                "audience": accounts.app_id(),
                "issuer": accounts.issuer(),
                "jwks_url": format!("{}/.well-known/jwks.json", accounts.issuer()),
            },
            "sign_in": {
                "carbons": "device flow with client_id hook (hook login), or the web console",
                "silicons": format!(
                    "a short-lived token from `silicon-accounts login --app {} -q`, exchanged with grant_type urn:silicon:params:oauth:grant-type:slt and client_id {} (hook login --slt)",
                    accounts.app_id(),
                    accounts.app_id()
                ),
            },
            "delivery": if state.application.delivery().is_some() { "ting" } else { "disabled" },
        })),
    )
}

/// `GET /api/v3/auth/status`: who the bearer token belongs to.
pub(super) async fn status(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<serde_json::Value>), AppError> {
    let caller = auth::authenticate(&state, &headers, Check::Local).await?;
    Ok((
        secret_response_headers(),
        Json(serde_json::json!({
            "authenticated": true,
            "app_id": state.application.accounts().app_id(),
            "uuid": caller.actor.uuid(),
            "id": caller.actor.id(),
            "kind": caller.actor.kind(),
        })),
    ))
}

/// `POST /webhook/` and `/webhook`: Hook's Silicon Accounts app webhook.
///
/// The signature is verified over the raw body before anything is parsed;
/// repeated deliveries (same `event_id`) change nothing. Unknown event types
/// are acknowledged and logged.
pub(super) async fn receive_webhook(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
    state
        .application
        .receive_accounts_webhook(
            header(silicon_accounts_client::TIMESTAMP_HEADER),
            header(silicon_accounts_client::SIGNATURE_HEADER),
            &body,
        )
        .await
        .map_err(map_application_error)?;
    Ok(StatusCode::NO_CONTENT)
}

/// One Silicon the caller can open.
#[derive(Serialize)]
struct SiliconItem {
    silicon: SiliconResponse,
    access: &'static str,
    custodian: Option<String>,
}

/// `GET /api/v3/silicons`: the Silicons the caller can open.
pub(super) async fn list_silicons(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let caller = auth::authenticate(&state, &headers, Check::Local).await?;
    let silicons = state
        .application
        .accessible_silicons(&caller.actor)
        .await
        .map_err(map_application_error)?;
    let items = silicons
        .iter()
        .map(|AccessibleSilicon { silicon, access }| SiliconItem {
            silicon: SiliconResponse {
                uuid: silicon.uuid.as_str().to_owned(),
                id: silicon.public_id.as_ref().map(|id| id.as_str().to_owned()),
            },
            access: access.as_str(),
            custodian: silicon
                .custodian_uuid
                .as_ref()
                .map(|uuid| uuid.as_str().to_owned()),
        })
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({ "items": items })))
}

fn account_response(uuid: &AccountUuid, accounts: &[AccountRecord]) -> AccountResponse {
    accounts
        .iter()
        .find(|record| &record.uuid == uuid)
        .map_or_else(
            || AccountResponse::of(uuid, ActorKind::Carbon, None),
            |record| {
                AccountResponse::of(
                    uuid,
                    record.kind,
                    record.public_id.as_ref().map(PublicId::as_str),
                )
            },
        )
}

#[derive(Serialize)]
struct GrantItem {
    account: AccountResponse,
    level: GrantLevel,
    granted_by: AccountResponse,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

fn grant_item(grant: &GrantRecord, accounts: &[AccountRecord]) -> GrantItem {
    GrantItem {
        account: account_response(&grant.grantee_uuid, accounts),
        level: grant.level,
        granted_by: account_response(&grant.granted_by_uuid, accounts),
        created_at: grant.created_at,
        updated_at: grant.updated_at,
    }
}

/// `GET /api/v3/silicons/{s}/access`: who has access to the Silicon's hooks.
pub(super) async fn access(
    Extension(state): Extension<ApiState>,
    Path(silicon): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let (_, context) = auth::authorize(&state, &headers, &silicon, Check::Local).await?;
    let summary = state
        .application
        .access_summary(&context)
        .await
        .map_err(map_application_error)?;
    Ok(Json(serde_json::json!({
        "silicon": SiliconResponse::from(context.silicon()),
        "you": {
            "account": AccountResponse::of(
                context.actor().uuid(),
                context.actor().kind(),
                context.actor().id().map(PublicId::as_str),
            ),
            "access": context.access().as_str(),
        },
        "custodian": summary.custodian.as_ref().map(|custodian| AccountResponse::of(
            &custodian.uuid,
            ActorKind::Carbon,
            custodian.public_id.as_ref().map(PublicId::as_str),
        )),
        "grants": summary
            .grants
            .iter()
            .map(|grant| grant_item(grant, &summary.accounts))
            .collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GrantRequest {
    level: String,
}

/// `PUT /api/v3/silicons/{s}/access/{account}`: grant or change access.
pub(super) async fn grant(
    Extension(state): Extension<ApiState>,
    Path((silicon, account)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    extractors::require_json(&headers)?;
    let request: GrantRequest = parse_json(&body)?;
    let level = GrantLevel::parse(&request.level).ok_or_else(|| {
        AppError::validation_with_details(
            "invalid_level",
            "level must be `view` (read hooks, events and blocked requests) or `manage` (also create and change hooks)",
        )
    })?;
    let (_, context) = auth::authorize(&state, &headers, &silicon, Check::Introspect).await?;
    let request_id = request_context::current_request_id();
    let (grant, grantee) = state
        .application
        .grant_access(&context, &account, level, request_id.as_deref())
        .await
        .map_err(map_application_error)?;
    let mut item = grant_item(&grant, &[grantee]);
    item.granted_by = AccountResponse::of(
        context.actor().uuid(),
        context.actor().kind(),
        context.actor().id().map(PublicId::as_str),
    );
    Ok(Json(serde_json::json!({
        "silicon": SiliconResponse::from(context.silicon()),
        "grant": item,
    })))
}

/// `DELETE /api/v3/silicons/{s}/access/{account}`: revoke a grant, or leave
/// one's own (`{account}` = `me`).
pub(super) async fn revoke(
    Extension(state): Extension<ApiState>,
    Path((silicon, account)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    require_empty_body(&body)?;
    let caller = auth::authenticate(&state, &headers, Check::Introspect).await?;
    let request_id = request_context::current_request_id();
    state
        .application
        .revoke_access(&caller.actor, &silicon, &account, request_id.as_deref())
        .await
        .map_err(map_application_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn allow_item(entry: &AllowRecord, accounts: &[AccountRecord]) -> serde_json::Value {
    serde_json::json!({
        "account": account_response(&entry.allowed_uuid, accounts),
        "added_by": entry.added_by_uuid,
        "created_at": entry.created_at.format(&time::format_description::well_known::Rfc3339).ok(),
    })
}

/// `GET /api/v3/silicons/{s}/allow-list`.
pub(super) async fn allow_list(
    Extension(state): Extension<ApiState>,
    Path(silicon): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let (_, context) = auth::authorize(&state, &headers, &silicon, Check::Local).await?;
    let (entries, accounts) = state
        .application
        .allow_list(&context)
        .await
        .map_err(map_application_error)?;
    Ok(Json(serde_json::json!({
        "silicon": SiliconResponse::from(context.silicon()),
        "items": entries.iter().map(|entry| allow_item(entry, &accounts)).collect::<Vec<_>>(),
    })))
}

/// `PUT /api/v3/silicons/{s}/allow-list/{account}`.
pub(super) async fn allow(
    Extension(state): Extension<ApiState>,
    Path((silicon, account)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    require_empty_body(&body)?;
    let (_, context) = auth::authorize(&state, &headers, &silicon, Check::Introspect).await?;
    let request_id = request_context::current_request_id();
    let (entry, record) = state
        .application
        .allow(&context, &account, request_id.as_deref())
        .await
        .map_err(map_application_error)?;
    Ok(Json(allow_item(&entry, &[record])))
}

/// `DELETE /api/v3/silicons/{s}/allow-list/{account}`.
pub(super) async fn disallow(
    Extension(state): Extension<ApiState>,
    Path((silicon, account)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    require_empty_body(&body)?;
    let (_, context) = auth::authorize(&state, &headers, &silicon, Check::Introspect).await?;
    let request_id = request_context::current_request_id();
    state
        .application
        .disallow(&context, &account, request_id.as_deref())
        .await
        .map_err(map_application_error)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v3/silicons/{s}/hooks/accounts`: prepare the hook that receives
/// the Silicon's own Silicon Accounts events, and say how to finish.
pub(super) async fn connect_accounts_hook(
    Extension(state): Extension<ApiState>,
    Path(silicon): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    require_empty_body(&body)?;
    let idempotency_key = extractors::idempotency_key(&headers)?;
    let (_, context) = auth::authorize(&state, &headers, &silicon, Check::Introspect).await?;
    let hook = state
        .application
        .prepare_accounts_hook(ConnectAccountsHookCommand {
            context: management_context(context.clone(), idempotency_key),
        })
        .await
        .map_err(map_application_error)?;
    let response: HookResponse = hook_response(&state, &context, &hook).await?;
    let url = super::handlers::endpoint_url(&state, &context, &hook)?;
    Ok(Json(serde_json::json!({
        "hook": response,
        "next_steps": next_steps(context.actor(), context.silicon(), &hook.id().to_string(), url.as_str()),
    })))
}

fn next_steps(actor: &Actor, silicon: &SiliconRef, hook_id: &str, url: &str) -> serde_json::Value {
    let silicon_id = silicon.display();
    let set_command = if actor.uuid() == silicon.uuid() {
        format!("silicon-accounts webhook set {url}")
    } else {
        format!("silicon-accounts silicon webhook set {silicon_id} {url}")
    };
    serde_json::json!({
        "set_webhook": set_command,
        "store_secret": format!(
            "PATCH /api/v3/silicons/{silicon_id}/hooks/{hook_id} with {{\"signature\": {{\"secret\": \"<the whsec_ secret Silicon Accounts printed>\"}}}} (the Hook CLI's set-secret command does this)"
        ),
        "explanation": "Silicon Accounts creates the signing secret when the webhook is set and prints it once. Until Hook stores it on this hook, deliveries are withheld as unverified.",
    })
}
