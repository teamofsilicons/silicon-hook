//! HTTP handlers that translate between transport and application contracts.

use std::collections::HashMap;

use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, Query, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
};
use serde::de::DeserializeOwned;

use super::{
    auth::{self, Check},
    dto::{
        AccountResponse, BlockedRequestResponse, CreateHookRequest, EventResponse, HealthResponse,
        HistoryPageResponse, HistoryQuery, HookPageResponse, HookResponse, HookWithSecretResponse,
        ListHooksQuery, OneTimeSecret, ReceiptResponse, SetHooksEnabledRequest,
        SigningSecretResponse, UpdateHookRequest, VersionResponse,
    },
    extractors::{self, PeerAddress},
    state::ApiState,
};
use crate::{
    application::{
        ApplicationError, CreateHookCommand, DeleteHookCommand, HookMutationCommand, HookPatch,
        ListHistoryCommand, ManagementContext, ReceiveRequestCommand, SetHooksEnabledCommand,
        UpdateHookCommand,
    },
    domain::{
        AccountUuid, AuthorizationContext, EndpointKey, EventId, Hook, HookDescription, HookId,
        HookName, HookTimeZone,
    },
    error::AppError,
    infrastructure::postgres::RuntimeDatabaseRole,
    request_context,
};

pub(super) async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

pub(super) async fn readiness(
    Extension(state): Extension<ApiState>,
) -> Result<Json<serde_json::Value>, AppError> {
    state
        .application
        .store()
        .ready_for(RuntimeDatabaseRole::Api)
        .await
        .map_err(|error| {
            tracing::warn!(
                error_code = error.diagnostic_code(),
                "readiness database probe failed"
            );
            AppError::ProviderUnavailable
        })?;
    let delivery = if state.application.delivery().is_some() {
        serde_json::json!({"ting": "enabled"})
    } else {
        serde_json::json!({
            "ting": "disabled",
            "detail": "HOOK_TING_URL is not set: Hook receives, verifies and stores events, and delivers none through Ting."
        })
    };
    Ok(Json(
        serde_json::json!({"status": "ready", "delivery": delivery}),
    ))
}

pub(super) async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        service: "silicon-hook",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Unversioned handshake: selects the API major shared with the client.
pub(super) async fn negotiate_api_version(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<serde_json::Value>), AppError> {
    super::contracts::negotiate(&state, &headers).await
}

pub(super) async fn list_hooks(
    Extension(state): Extension<ApiState>,
    Path(silicon): Path<String>,
    query: Result<Query<ListHooksQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<Json<HookPageResponse>, AppError> {
    let Query(query) = query.map_err(|_| AppError::validation("invalid_query"))?;
    let (_, authorization) = auth::authorize(&state, &headers, &silicon, Check::Local).await?;
    let hooks = state
        .application
        .list_hooks(&authorization, query.include_deleted)
        .await
        .map_err(map_application_error)?;
    Ok(Json(HookPageResponse {
        items: hook_responses(&state, &authorization, &hooks).await?,
    }))
}

pub(super) async fn create_hook(
    Extension(state): Extension<ApiState>,
    Path(silicon): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Json<HookWithSecretResponse>), AppError> {
    extractors::require_json(&headers)?;
    let idempotency_key = extractors::idempotency_key(&headers)?;
    let request: CreateHookRequest = parse_json(&body)?;
    let name = HookName::new(request.name).map_err(|_| AppError::validation("invalid_name"))?;
    let description = HookDescription::optional(request.description)
        .map_err(|_| AppError::validation("invalid_description"))?;
    let time_zone = parse_time_zone(request.time_zone)?.unwrap_or_default();
    let signing = request
        .signature
        .map(super::dto::SignatureRequest::into_patch)
        .transpose()?
        .unwrap_or_default();
    // Creation returns a signing secret once: confirm the session is live.
    let (_, authorization) = auth::authorize(&state, &headers, &silicon, Check::Introspect).await?;
    let result = state
        .application
        .create_hook(CreateHookCommand {
            context: management_context(authorization.clone(), idempotency_key),
            name,
            description,
            time_zone,
            signing,
        })
        .await
        .map_err(map_application_error)?;
    let hook = hook_response(&state, &authorization, &result.hook).await?;
    Ok((
        StatusCode::CREATED,
        secret_response_headers(),
        Json(HookWithSecretResponse::from_result(&result, hook)),
    ))
}

pub(super) async fn get_hook(
    Extension(state): Extension<ApiState>,
    Path((silicon, hook_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<HookResponse>, AppError> {
    let hook_id = parse_hook_id(&hook_id)?;
    let (_, authorization) = auth::authorize(&state, &headers, &silicon, Check::Local).await?;
    let hook = state
        .application
        .get_hook(&authorization, hook_id)
        .await
        .map_err(map_application_error)?;
    Ok(Json(hook_response(&state, &authorization, &hook).await?))
}

pub(super) async fn update_hook(
    Extension(state): Extension<ApiState>,
    Path((silicon, hook_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<HookResponse>, AppError> {
    extractors::require_json(&headers)?;
    let hook_id = parse_hook_id(&hook_id)?;
    let request: UpdateHookRequest = parse_json(&body)?;
    let patch = HookPatch {
        name: request
            .name
            .map(HookName::new)
            .transpose()
            .map_err(|_| AppError::validation("invalid_name"))?,
        description: request
            .description
            .map(HookDescription::optional)
            .transpose()
            .map_err(|_| AppError::validation("invalid_description"))?,
        time_zone: parse_time_zone(request.time_zone)?,
        enabled: request.enabled,
        signing: request
            .signature
            .map(super::dto::SignatureRequest::into_patch)
            .transpose()?,
    };
    if patch.enabled.is_none() && !patch.changes_metadata() {
        return Err(AppError::validation("empty_update"));
    }
    // Replacing a signing secret is a credential change: confirm the session.
    let check = if patch
        .signing
        .as_ref()
        .is_some_and(|signing| signing.secret.is_some())
    {
        Check::Introspect
    } else {
        Check::Local
    };
    let (_, authorization) = auth::authorize(&state, &headers, &silicon, check).await?;
    let hook = state
        .application
        .update_hook(UpdateHookCommand {
            authorization: authorization.clone(),
            hook_id,
            patch,
            request_id: request_context::current_request_id(),
        })
        .await
        .map_err(map_application_error)?;
    Ok(Json(hook_response(&state, &authorization, &hook).await?))
}

pub(super) async fn delete_hook(
    Extension(state): Extension<ApiState>,
    Path((silicon, hook_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    require_empty_body(&body)?;
    let hook_id = parse_hook_id(&hook_id)?;
    let (_, authorization) = auth::authorize(&state, &headers, &silicon, Check::Introspect).await?;
    state
        .application
        .delete_hook(DeleteHookCommand {
            authorization,
            hook_id,
            request_id: request_context::current_request_id(),
        })
        .await
        .map_err(map_application_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn set_hooks_enabled(
    Extension(state): Extension<ApiState>,
    Path(silicon): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<HookPageResponse>, AppError> {
    extractors::require_json(&headers)?;
    let request: SetHooksEnabledRequest = parse_json(&body)?;
    let (_, authorization) = auth::authorize(&state, &headers, &silicon, Check::Local).await?;
    let hooks = state
        .application
        .set_hooks_enabled(SetHooksEnabledCommand {
            authorization: authorization.clone(),
            hook_ids: request.hook_ids,
            enabled: request.enabled,
            request_id: request_context::current_request_id(),
        })
        .await
        .map_err(map_application_error)?;
    Ok(Json(HookPageResponse {
        items: hook_responses(&state, &authorization, &hooks).await?,
    }))
}

pub(super) async fn restore_hook(
    Extension(state): Extension<ApiState>,
    Path((silicon, hook_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<HookResponse>, AppError> {
    require_empty_body(&body)?;
    let hook_id = parse_hook_id(&hook_id)?;
    let idempotency_key = extractors::idempotency_key(&headers)?;
    let (_, authorization) = auth::authorize(&state, &headers, &silicon, Check::Introspect).await?;
    let hook = state
        .application
        .restore_hook(HookMutationCommand {
            context: management_context(authorization.clone(), idempotency_key),
            hook_id,
        })
        .await
        .map_err(map_application_error)?;
    Ok(Json(hook_response(&state, &authorization, &hook).await?))
}

pub(super) async fn rotate_hook_secret(
    Extension(state): Extension<ApiState>,
    Path((silicon, hook_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, Json<SigningSecretResponse>), AppError> {
    require_empty_body(&body)?;
    let hook_id = parse_hook_id(&hook_id)?;
    let idempotency_key = extractors::idempotency_key(&headers)?;
    let (_, authorization) = auth::authorize(&state, &headers, &silicon, Check::Introspect).await?;
    let result = state
        .application
        .rotate_hook_secret(HookMutationCommand {
            context: management_context(authorization, idempotency_key),
            hook_id,
        })
        .await
        .map_err(map_application_error)?;
    let signing_secret = result
        .signing_secret
        .ok_or_else(|| AppError::internal(anyhow::anyhow!("secret rotation returned no secret")))?;
    Ok((
        secret_response_headers(),
        Json(SigningSecretResponse {
            signing_secret: OneTimeSecret::new(signing_secret.to_exposed()),
        }),
    ))
}

pub(super) async fn rotate_hook_endpoint(
    Extension(state): Extension<ApiState>,
    Path((silicon, hook_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<HookResponse>, AppError> {
    require_empty_body(&body)?;
    let hook_id = parse_hook_id(&hook_id)?;
    let idempotency_key = extractors::idempotency_key(&headers)?;
    // Rotation retires a URL providers may hold: confirm the session.
    let (_, authorization) = auth::authorize(&state, &headers, &silicon, Check::Introspect).await?;
    let hook = state
        .application
        .rotate_hook_endpoint(HookMutationCommand {
            context: management_context(authorization.clone(), idempotency_key),
            hook_id,
        })
        .await
        .map_err(map_application_error)?;
    Ok(Json(hook_response(&state, &authorization, &hook).await?))
}

pub(super) async fn list_events(
    Extension(state): Extension<ApiState>,
    Path(silicon): Path<String>,
    query: Result<Query<HistoryQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<Json<HistoryPageResponse<EventResponse>>, AppError> {
    let command = history_command(&state, &silicon, None, query, &headers).await?;
    let silicon = command.authorization.silicon().clone();
    let page = state
        .application
        .list_events(command)
        .await
        .map_err(map_application_error)?;
    Ok(Json(HistoryPageResponse {
        items: page
            .items
            .iter()
            .map(|event| EventResponse::new(event, &silicon))
            .collect(),
        next_cursor: page.next_cursor,
    }))
}

pub(super) async fn list_hook_events(
    Extension(state): Extension<ApiState>,
    Path((silicon, hook_id)): Path<(String, String)>,
    query: Result<Query<HistoryQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<Json<HistoryPageResponse<EventResponse>>, AppError> {
    let hook_id = parse_hook_id(&hook_id)?;
    let command = history_command(&state, &silicon, Some(hook_id), query, &headers).await?;
    let silicon = command.authorization.silicon().clone();
    let page = state
        .application
        .list_events(command)
        .await
        .map_err(map_application_error)?;
    Ok(Json(HistoryPageResponse {
        items: page
            .items
            .iter()
            .map(|event| EventResponse::new(event, &silicon))
            .collect(),
        next_cursor: page.next_cursor,
    }))
}

pub(super) async fn list_blocked_requests(
    Extension(state): Extension<ApiState>,
    Path(silicon): Path<String>,
    query: Result<Query<HistoryQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<Json<HistoryPageResponse<BlockedRequestResponse>>, AppError> {
    let command = history_command(&state, &silicon, None, query, &headers).await?;
    let silicon = command.authorization.silicon().clone();
    let page = state
        .application
        .list_blocked_requests(command)
        .await
        .map_err(map_application_error)?;
    Ok(Json(HistoryPageResponse {
        items: page
            .items
            .iter()
            .map(|blocked| BlockedRequestResponse::new(blocked, &silicon))
            .collect(),
        next_cursor: page.next_cursor,
    }))
}

pub(super) async fn list_hook_blocked_requests(
    Extension(state): Extension<ApiState>,
    Path((silicon, hook_id)): Path<(String, String)>,
    query: Result<Query<HistoryQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<Json<HistoryPageResponse<BlockedRequestResponse>>, AppError> {
    let hook_id = parse_hook_id(&hook_id)?;
    let command = history_command(&state, &silicon, Some(hook_id), query, &headers).await?;
    let silicon = command.authorization.silicon().clone();
    let page = state
        .application
        .list_blocked_requests(command)
        .await
        .map_err(map_application_error)?;
    Ok(Json(HistoryPageResponse {
        items: page
            .items
            .iter()
            .map(|blocked| BlockedRequestResponse::new(blocked, &silicon))
            .collect(),
        next_cursor: page.next_cursor,
    }))
}

/// Hydrates one delivered event reference with the caller's own access.
pub(super) async fn get_event(
    Extension(state): Extension<ApiState>,
    Path((silicon, event_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<EventResponse>), AppError> {
    let event_id: EventId = event_id
        .parse()
        .map_err(|_| AppError::validation("invalid_event_id"))?;
    let (_, authorization) = auth::authorize(&state, &headers, &silicon, Check::Local).await?;
    let event = state
        .application
        .get_event(&authorization, event_id)
        .await
        .map_err(map_application_error)?;
    Ok((
        secret_response_headers(),
        Json(EventResponse::new(&event, authorization.silicon())),
    ))
}

async fn history_command(
    state: &ApiState,
    silicon: &str,
    hook_id: Option<HookId>,
    query: Result<Query<HistoryQuery>, QueryRejection>,
    headers: &HeaderMap,
) -> Result<ListHistoryCommand, AppError> {
    let Query(query) = query.map_err(|_| AppError::validation("invalid_query"))?;
    if hook_id.is_some() && query.hook_id.is_some_and(|filter| Some(filter) != hook_id) {
        return Err(AppError::validation("invalid_hook_id"));
    }
    let (_, authorization) = auth::authorize(state, headers, silicon, Check::Local).await?;
    Ok(ListHistoryCommand {
        authorization,
        hook_id: hook_id.or(query.hook_id),
        limit: query.limit,
        cursor: query.cursor,
    })
}

pub(super) async fn receive(
    Extension(state): Extension<ApiState>,
    Path((silicon_segment, endpoint_key)): Path<(String, String)>,
    peer: PeerAddress,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<ReceiptResponse>), AppError> {
    if silicon_segment.is_empty() || silicon_segment.len() > 255 {
        return Err(AppError::NotFound);
    }
    let endpoint_key = EndpointKey::parse(&endpoint_key)
        .map_err(|_| AppError::validation("invalid_endpoint_key"))?;
    let remote_ip = extractors::client_ip(&headers, peer, state.trusted_proxy_hops)?;
    let outcome = state
        .application
        .receive_request(ReceiveRequestCommand {
            silicon_segment,
            endpoint_key,
            method: method.as_str().to_owned(),
            path: uri.path().to_owned(),
            query: uri.query().map(ToOwned::to_owned),
            headers: extractors::capture_headers(&headers),
            body,
            remote_ip,
        })
        .await
        .map_err(map_application_error)?;
    Ok((
        StatusCode::OK,
        Json(ReceiptResponse::ok(outcome.receipt_id())),
    ))
}

pub(super) fn management_context(
    authorization: AuthorizationContext,
    idempotency_key: String,
) -> ManagementContext {
    ManagementContext {
        authorization,
        idempotency_key,
        request_id: request_context::current_request_id(),
    }
}

/// The URL providers should call: the Silicon's current id, or its uuid when
/// no id is known (both route to the hook).
pub(super) fn endpoint_url(
    state: &ApiState,
    authorization: &AuthorizationContext,
    hook: &Hook,
) -> Result<url::Url, AppError> {
    state
        .application
        .endpoint_url(authorization.silicon().display(), hook.endpoint_key())
        .map_err(map_application_error)
}

async fn creator_ids(
    state: &ApiState,
    hooks: &[Hook],
) -> Result<HashMap<AccountUuid, Option<String>>, AppError> {
    let mut uuids = hooks
        .iter()
        .filter_map(|hook| hook.created_by().uuid().cloned())
        .collect::<Vec<_>>();
    uuids.sort();
    uuids.dedup();
    Ok(state
        .application
        .store()
        .accounts(&uuids)
        .await
        .map_err(|error| map_application_error(ApplicationError::Internal(error.into())))?
        .into_iter()
        .map(|record| {
            (
                record.uuid,
                record.public_id.map(|id| id.as_str().to_owned()),
            )
        })
        .collect())
}

fn hook_response_with(
    state: &ApiState,
    authorization: &AuthorizationContext,
    hook: &Hook,
    creators: &HashMap<AccountUuid, Option<String>>,
) -> Result<HookResponse, AppError> {
    let creator_id = hook
        .created_by()
        .uuid()
        .and_then(|uuid| creators.get(uuid))
        .and_then(Option::as_deref);
    Ok(HookResponse::from_domain(
        hook,
        endpoint_url(state, authorization, hook)?,
        authorization.silicon(),
        AccountResponse::from_attribution(hook.created_by(), creator_id),
    ))
}

pub(super) async fn hook_response(
    state: &ApiState,
    authorization: &AuthorizationContext,
    hook: &Hook,
) -> Result<HookResponse, AppError> {
    let creators = creator_ids(state, std::slice::from_ref(hook)).await?;
    hook_response_with(state, authorization, hook, &creators)
}

async fn hook_responses(
    state: &ApiState,
    authorization: &AuthorizationContext,
    hooks: &[Hook],
) -> Result<Vec<HookResponse>, AppError> {
    let creators = creator_ids(state, hooks).await?;
    hooks
        .iter()
        .map(|hook| hook_response_with(state, authorization, hook, &creators))
        .collect()
}

fn parse_hook_id(value: &str) -> Result<HookId, AppError> {
    value
        .parse()
        .map_err(|_| AppError::validation("invalid_hook_id"))
}

fn parse_time_zone(value: Option<String>) -> Result<Option<HookTimeZone>, AppError> {
    value
        .map(HookTimeZone::new)
        .transpose()
        .map_err(|error| AppError::validation_with_details("invalid_time_zone", error.to_string()))
}

pub(super) fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, AppError> {
    serde_json::from_slice(body).map_err(|error| match error.classify() {
        serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
            AppError::bad_request("invalid_json")
        }
        serde_json::error::Category::Data => {
            AppError::validation_with_details("validation_failed", error.to_string())
        }
        serde_json::error::Category::Io => AppError::internal(error),
    })
}

pub(super) fn require_empty_body(body: &[u8]) -> Result<(), AppError> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(AppError::bad_request("unexpected_request_body"))
    }
}

pub(super) fn secret_response_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers
}

pub(super) fn map_application_error(error: ApplicationError) -> AppError {
    match error {
        ApplicationError::Validation { field } => AppError::validation(format!("invalid_{field}")),
        ApplicationError::ValidationDetailed { field, detail } => {
            AppError::validation_with_details(format!("invalid_{field}"), detail)
        }
        ApplicationError::Forbidden => AppError::Forbidden,
        ApplicationError::NotFound => AppError::NotFound,
        ApplicationError::RecoveryExpired => AppError::gone("recovery_expired"),
        ApplicationError::EndpointRetired => AppError::gone("endpoint_retired"),
        ApplicationError::IpBlocked { until } => AppError::Blocked {
            retry_after: std::time::Duration::try_from(until - time::OffsetDateTime::now_utc())
                .unwrap_or_default(),
        },
        ApplicationError::IdempotencyConflict => AppError::conflict("idempotency_conflict"),
        ApplicationError::StateConflict => AppError::conflict("state_conflict"),
        ApplicationError::SecretUnavailable => AppError::gone("secret_unavailable"),
        ApplicationError::HookLimitReached => AppError::conflict("hook_limit_reached"),
        ApplicationError::PayloadTooLarge => AppError::PayloadTooLarge,
        ApplicationError::Refused {
            status,
            code,
            message,
        } => AppError::refused(
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
            code,
            message,
        ),
        ApplicationError::Unavailable(source) => {
            tracing::warn!(error = %source, "application dependency is unavailable");
            AppError::ProviderUnavailable
        }
        ApplicationError::Internal(source) => AppError::internal(source),
    }
}

pub(super) async fn not_found() -> AppError {
    AppError::NotFound
}

pub(super) async fn method_not_allowed() -> AppError {
    AppError::MethodNotAllowed
}

#[cfg(test)]
mod tests {
    use super::{map_application_error, parse_json, require_empty_body, secret_response_headers};
    use crate::api::dto::CreateHookRequest;
    use crate::application::ApplicationError;

    #[test]
    fn malformed_json_and_invalid_shape_have_distinct_statuses() {
        let syntax = parse_json::<CreateHookRequest>(br#"{"name":"#);
        let shape = parse_json::<CreateHookRequest>(br#"{"unknown":true}"#);

        assert_eq!(
            syntax.err().map(|error| error.status()),
            Some(http::StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            shape.err().map(|error| error.status()),
            Some(http::StatusCode::UNPROCESSABLE_ENTITY)
        );
    }

    #[test]
    fn bodyless_operations_reject_unexpected_content() {
        assert!(require_empty_body(&[]).is_ok());
        assert!(require_empty_body(b"{}").is_err());
    }

    #[test]
    fn one_time_secret_responses_are_never_cacheable() {
        let headers = secret_response_headers();
        assert_eq!(
            headers
                .get(http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
    }

    #[test]
    fn application_failures_map_to_their_statuses() {
        assert_eq!(
            map_application_error(ApplicationError::EndpointRetired).status(),
            http::StatusCode::GONE
        );
        assert_eq!(
            map_application_error(ApplicationError::IpBlocked {
                until: time::OffsetDateTime::now_utc() + time::Duration::days(1),
            })
            .status(),
            http::StatusCode::FORBIDDEN
        );
        assert_eq!(
            map_application_error(ApplicationError::Unavailable(anyhow::anyhow!("detail")))
                .status(),
            http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            map_application_error(ApplicationError::Refused {
                status: 403,
                code: "no_access",
                message: "c:bob has no access to si:cos's hooks.".to_owned(),
            })
            .status(),
            http::StatusCode::FORBIDDEN
        );
    }
}
