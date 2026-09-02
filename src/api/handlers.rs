//! HTTP handlers that translate between transport and application contracts.

use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
};
use serde::de::DeserializeOwned;

use super::{
    dto::{
        AcknowledgeRequest, BlockedRequestResponse, CreateHookRequest, DeliveriesQuery,
        DeliveryBatchResponse, DeliveryCursorResponse, EventResponse, HealthResponse,
        HistoryPageResponse, HistoryQuery, HookPageResponse, HookResponse, HookWithSecretResponse,
        ListHooksQuery, OneTimeSecret, ProvisionIamHookRequest, ReceiptResponse,
        SetHooksEnabledRequest, SigningSecretResponse, UpdateHookRequest, VersionResponse,
    },
    extractors::{self, PeerAddress},
    state::ApiState,
};
use crate::{
    application::{
        AcknowledgeDeliveriesCommand, ApplicationError, CreateHookCommand, DeleteHookCommand,
        HookMutationCommand, HookPatch, ListHistoryCommand, ManagementContext,
        ProvisionIamHookCommand, PullDeliveriesCommand, ReceiveRequestCommand,
        SetHooksEnabledCommand, UpdateHookCommand,
    },
    domain::{
        AuthorizationContext, EndpointKey, Hook, HookDescription, HookId, HookName, HookTimeZone,
        OrganizationId, SiliconId,
    },
    error::AppError,
    infrastructure::iam::AuthorizationRequest,
    infrastructure::postgres::RuntimeDatabaseRole,
    request_context,
};

pub(super) const ACTION_LIST_HOOKS: &str = "hook.hooks.list";
pub(super) const ACTION_READ_HOOK: &str = "hook.hooks.read";
pub(super) const ACTION_CREATE_HOOK: &str = "hook.hooks.create";
pub(super) const ACTION_UPDATE_HOOK: &str = "hook.hooks.update";
pub(super) const ACTION_DELETE_HOOK: &str = "hook.hooks.delete";
pub(super) const ACTION_SET_HOOK_ENABLED: &str = "hook.hooks.enabled.update";
pub(super) const ACTION_RESTORE_HOOK: &str = "hook.hooks.restore";
pub(super) const ACTION_ROTATE_SECRET: &str = "hook.hooks.secret.rotate";
pub(super) const ACTION_ROTATE_ENDPOINT: &str = "hook.hooks.endpoint.rotate";
pub(super) const ACTION_READ_EVENTS: &str = "hook.events.read";

pub(super) async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

pub(super) async fn readiness(
    State(state): State<ApiState>,
) -> Result<Json<HealthResponse>, AppError> {
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
    Ok(Json(HealthResponse { status: "ready" }))
}

pub(super) async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        service: "silicon-hook",
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub(super) async fn list_hooks(
    State(state): State<ApiState>,
    Path(silicon_id): Path<String>,
    query: Result<Query<ListHooksQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<Json<HookPageResponse>, AppError> {
    let silicon_id = parse_silicon_id(silicon_id)?;
    let Query(query) = query.map_err(|_| AppError::validation("invalid_query"))?;
    let authorization =
        authorize_management(&state, &headers, ACTION_LIST_HOOKS, silicon_id.as_str()).await?;
    let hooks = state
        .application
        .list_hooks(&authorization, &silicon_id, query.include_deleted)
        .await
        .map_err(map_application_error)?;
    Ok(Json(HookPageResponse {
        items: hook_responses(&state, &hooks)?,
    }))
}

pub(super) async fn create_hook(
    State(state): State<ApiState>,
    Path(silicon_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Json<HookWithSecretResponse>), AppError> {
    extractors::require_json(&headers)?;
    let silicon_id = parse_silicon_id(silicon_id)?;
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
    let authorization =
        authorize_management(&state, &headers, ACTION_CREATE_HOOK, silicon_id.as_str()).await?;
    let result = state
        .application
        .create_hook(CreateHookCommand {
            context: management_context(authorization, idempotency_key),
            silicon_id,
            name,
            description,
            time_zone,
            signing,
        })
        .await
        .map_err(map_application_error)?;
    let response =
        HookWithSecretResponse::from_result(&result, endpoint_url(&state, &result.hook)?);
    Ok((
        StatusCode::CREATED,
        secret_response_headers(),
        Json(response),
    ))
}

pub(super) async fn get_hook(
    State(state): State<ApiState>,
    Path((silicon_id, hook_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<HookResponse>, AppError> {
    let silicon_id = parse_silicon_id(silicon_id)?;
    let hook_id = parse_hook_id(&hook_id)?;
    let authorization =
        authorize_management(&state, &headers, ACTION_READ_HOOK, &hook_id.to_string()).await?;
    let hook = state
        .application
        .get_hook(&authorization, &silicon_id, hook_id)
        .await
        .map_err(map_application_error)?;
    Ok(Json(hook_response(&state, &hook)?))
}

pub(super) async fn update_hook(
    State(state): State<ApiState>,
    Path((silicon_id, hook_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<HookResponse>, AppError> {
    extractors::require_json(&headers)?;
    let silicon_id = parse_silicon_id(silicon_id)?;
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
    // A pure activation change keeps its dedicated IAM action; anything else
    // is authorized as an update.
    let action = if patch.changes_metadata() {
        ACTION_UPDATE_HOOK
    } else {
        ACTION_SET_HOOK_ENABLED
    };
    let authorization =
        authorize_management(&state, &headers, action, &hook_id.to_string()).await?;
    let hook = state
        .application
        .update_hook(UpdateHookCommand {
            authorization,
            silicon_id,
            hook_id,
            patch,
            request_id: request_context::current_request_id(),
        })
        .await
        .map_err(map_application_error)?;
    Ok(Json(hook_response(&state, &hook)?))
}

pub(super) async fn delete_hook(
    State(state): State<ApiState>,
    Path((silicon_id, hook_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    require_empty_body(&body)?;
    let silicon_id = parse_silicon_id(silicon_id)?;
    let hook_id = parse_hook_id(&hook_id)?;
    let authorization =
        authorize_management(&state, &headers, ACTION_DELETE_HOOK, &hook_id.to_string()).await?;
    state
        .application
        .delete_hook(DeleteHookCommand {
            authorization,
            silicon_id,
            hook_id,
            request_id: request_context::current_request_id(),
        })
        .await
        .map_err(map_application_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn set_hooks_enabled(
    State(state): State<ApiState>,
    Path(silicon_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<HookPageResponse>, AppError> {
    extractors::require_json(&headers)?;
    let silicon_id = parse_silicon_id(silicon_id)?;
    let request: SetHooksEnabledRequest = parse_json(&body)?;
    let authorization = authorize_management(
        &state,
        &headers,
        ACTION_SET_HOOK_ENABLED,
        silicon_id.as_str(),
    )
    .await?;
    let hooks = state
        .application
        .set_hooks_enabled(SetHooksEnabledCommand {
            authorization,
            silicon_id,
            hook_ids: request.hook_ids,
            enabled: request.enabled,
            request_id: request_context::current_request_id(),
        })
        .await
        .map_err(map_application_error)?;
    Ok(Json(HookPageResponse {
        items: hook_responses(&state, &hooks)?,
    }))
}

pub(super) async fn restore_hook(
    State(state): State<ApiState>,
    Path((silicon_id, hook_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<HookResponse>, AppError> {
    require_empty_body(&body)?;
    let silicon_id = parse_silicon_id(silicon_id)?;
    let hook_id = parse_hook_id(&hook_id)?;
    let idempotency_key = extractors::idempotency_key(&headers)?;
    let authorization =
        authorize_management(&state, &headers, ACTION_RESTORE_HOOK, &hook_id.to_string()).await?;
    let hook = state
        .application
        .restore_hook(HookMutationCommand {
            context: management_context(authorization, idempotency_key),
            silicon_id,
            hook_id,
        })
        .await
        .map_err(map_application_error)?;
    Ok(Json(hook_response(&state, &hook)?))
}

pub(super) async fn rotate_hook_secret(
    State(state): State<ApiState>,
    Path((silicon_id, hook_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, Json<SigningSecretResponse>), AppError> {
    require_empty_body(&body)?;
    let silicon_id = parse_silicon_id(silicon_id)?;
    let hook_id = parse_hook_id(&hook_id)?;
    let idempotency_key = extractors::idempotency_key(&headers)?;
    let authorization =
        authorize_management(&state, &headers, ACTION_ROTATE_SECRET, &hook_id.to_string()).await?;
    let result = state
        .application
        .rotate_hook_secret(HookMutationCommand {
            context: management_context(authorization, idempotency_key),
            silicon_id,
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
    State(state): State<ApiState>,
    Path((silicon_id, hook_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<HookResponse>, AppError> {
    require_empty_body(&body)?;
    let silicon_id = parse_silicon_id(silicon_id)?;
    let hook_id = parse_hook_id(&hook_id)?;
    let idempotency_key = extractors::idempotency_key(&headers)?;
    let authorization = authorize_management(
        &state,
        &headers,
        ACTION_ROTATE_ENDPOINT,
        &hook_id.to_string(),
    )
    .await?;
    let hook = state
        .application
        .rotate_hook_endpoint(HookMutationCommand {
            context: management_context(authorization, idempotency_key),
            silicon_id,
            hook_id,
        })
        .await
        .map_err(map_application_error)?;
    Ok(Json(hook_response(&state, &hook)?))
}

pub(super) async fn list_events(
    State(state): State<ApiState>,
    Path(silicon_id): Path<String>,
    query: Result<Query<HistoryQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<Json<HistoryPageResponse<EventResponse>>, AppError> {
    let command = history_command(&state, silicon_id, None, query, &headers).await?;
    let page = state
        .application
        .list_events(command)
        .await
        .map_err(map_application_error)?;
    Ok(Json(HistoryPageResponse {
        items: page.items.iter().map(EventResponse::from).collect(),
        next_cursor: page.next_cursor,
    }))
}

pub(super) async fn list_hook_events(
    State(state): State<ApiState>,
    Path((silicon_id, hook_id)): Path<(String, String)>,
    query: Result<Query<HistoryQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<Json<HistoryPageResponse<EventResponse>>, AppError> {
    let hook_id = parse_hook_id(&hook_id)?;
    let command = history_command(&state, silicon_id, Some(hook_id), query, &headers).await?;
    let page = state
        .application
        .list_events(command)
        .await
        .map_err(map_application_error)?;
    Ok(Json(HistoryPageResponse {
        items: page.items.iter().map(EventResponse::from).collect(),
        next_cursor: page.next_cursor,
    }))
}

pub(super) async fn list_blocked_requests(
    State(state): State<ApiState>,
    Path(silicon_id): Path<String>,
    query: Result<Query<HistoryQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<Json<HistoryPageResponse<BlockedRequestResponse>>, AppError> {
    let command = history_command(&state, silicon_id, None, query, &headers).await?;
    let page = state
        .application
        .list_blocked_requests(command)
        .await
        .map_err(map_application_error)?;
    Ok(Json(HistoryPageResponse {
        items: page
            .items
            .iter()
            .map(BlockedRequestResponse::from)
            .collect(),
        next_cursor: page.next_cursor,
    }))
}

pub(super) async fn list_hook_blocked_requests(
    State(state): State<ApiState>,
    Path((silicon_id, hook_id)): Path<(String, String)>,
    query: Result<Query<HistoryQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<Json<HistoryPageResponse<BlockedRequestResponse>>, AppError> {
    let hook_id = parse_hook_id(&hook_id)?;
    let command = history_command(&state, silicon_id, Some(hook_id), query, &headers).await?;
    let page = state
        .application
        .list_blocked_requests(command)
        .await
        .map_err(map_application_error)?;
    Ok(Json(HistoryPageResponse {
        items: page
            .items
            .iter()
            .map(BlockedRequestResponse::from)
            .collect(),
        next_cursor: page.next_cursor,
    }))
}

async fn history_command(
    state: &ApiState,
    silicon_id: String,
    hook_id: Option<HookId>,
    query: Result<Query<HistoryQuery>, QueryRejection>,
    headers: &HeaderMap,
) -> Result<ListHistoryCommand, AppError> {
    let silicon_id = parse_silicon_id(silicon_id)?;
    let Query(query) = query.map_err(|_| AppError::validation("invalid_query"))?;
    if hook_id.is_some() && query.hook_id.is_some_and(|filter| Some(filter) != hook_id) {
        return Err(AppError::validation("invalid_hook_id"));
    }
    let resource = hook_id.map_or_else(|| silicon_id.as_str().to_owned(), |id| id.to_string());
    let authorization = authorize_management(state, headers, ACTION_READ_EVENTS, &resource).await?;
    Ok(ListHistoryCommand {
        authorization,
        silicon_id,
        hook_id: hook_id.or(query.hook_id),
        limit: query.limit,
        cursor: query.cursor,
    })
}

pub(super) async fn pull_deliveries(
    State(state): State<ApiState>,
    Path(silicon_id): Path<String>,
    query: Result<Query<DeliveriesQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<Json<DeliveryBatchResponse>, AppError> {
    let silicon_id = parse_silicon_id(silicon_id)?;
    let Query(query) = query.map_err(|_| AppError::validation("invalid_query"))?;
    let authorization =
        authorize_management(&state, &headers, ACTION_READ_EVENTS, silicon_id.as_str()).await?;
    let batch = state
        .application
        .pull_deliveries(PullDeliveriesCommand {
            authorization,
            silicon_id,
            after_sequence: query.after_sequence,
            limit: query.limit,
        })
        .await
        .map_err(map_application_error)?;
    Ok(Json(DeliveryBatchResponse {
        items: batch.items.iter().map(EventResponse::from).collect(),
        cursor: DeliveryCursorResponse::from(&batch.cursor),
        latest_sequence: batch.latest_sequence,
    }))
}

pub(super) async fn acknowledge_deliveries(
    State(state): State<ApiState>,
    Path(silicon_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<DeliveryCursorResponse>, AppError> {
    extractors::require_json(&headers)?;
    let silicon_id = parse_silicon_id(silicon_id)?;
    let request: AcknowledgeRequest = parse_json(&body)?;
    let authorization =
        authorize_management(&state, &headers, ACTION_READ_EVENTS, silicon_id.as_str()).await?;
    let cursor = state
        .application
        .acknowledge_deliveries(AcknowledgeDeliveriesCommand {
            authorization,
            silicon_id,
            through_sequence: request.through_sequence,
        })
        .await
        .map_err(map_application_error)?;
    Ok(Json(DeliveryCursorResponse::from(&cursor)))
}

pub(super) async fn delivery_cursor(
    State(state): State<ApiState>,
    Path(silicon_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<DeliveryCursorResponse>, AppError> {
    let silicon_id = parse_silicon_id(silicon_id)?;
    let authorization =
        authorize_management(&state, &headers, ACTION_READ_EVENTS, silicon_id.as_str()).await?;
    let access = state
        .application
        .authorize_stream(&authorization, &silicon_id)
        .map_err(map_application_error)?;
    let cursor = state
        .application
        .stream_cursor(&access)
        .await
        .map_err(map_application_error)?;
    Ok(Json(DeliveryCursorResponse::from(&cursor)))
}

pub(super) async fn receive(
    State(state): State<ApiState>,
    Path((silicon_id, endpoint_key)): Path<(String, String)>,
    peer: PeerAddress,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<ReceiptResponse>), AppError> {
    let silicon_id = parse_silicon_id(silicon_id)?;
    let endpoint_key = EndpointKey::parse(&endpoint_key)
        .map_err(|_| AppError::validation("invalid_endpoint_key"))?;
    let remote_ip = extractors::client_ip(&headers, peer, state.trusted_proxy_hops)?;
    let outcome = state
        .application
        .receive_request(ReceiveRequestCommand {
            silicon_id,
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

pub(super) async fn provision_iam_hook(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Json<HookWithSecretResponse>), AppError> {
    extractors::require_json(&headers)?;
    let token = extractors::service_bearer(&headers)?;
    let idempotency_key = extractors::idempotency_key(&headers)?;
    let request: ProvisionIamHookRequest = parse_json(&body)?;
    let organization_id =
        OrganizationId::new(request.org_id).map_err(|_| AppError::validation("invalid_org_id"))?;
    let silicon_id = SiliconId::new(request.silicon_id)
        .map_err(|_| AppError::validation("invalid_silicon_id"))?;
    let actor = state
        .iam
        .authenticate_iam_service(&token)
        .await
        .map_err(AppError::from)?;
    let result = state
        .application
        .provision_iam_hook(ProvisionIamHookCommand {
            actor,
            organization_id,
            silicon_id,
            idempotency_key,
            request_id: request_context::current_request_id(),
        })
        .await
        .map_err(map_application_error)?;
    let response =
        HookWithSecretResponse::from_result(&result, endpoint_url(&state, &result.hook)?);
    Ok((
        StatusCode::CREATED,
        secret_response_headers(),
        Json(response),
    ))
}

pub(super) async fn authorize_management(
    state: &ApiState,
    headers: &HeaderMap,
    action: &'static str,
    resource: &str,
) -> Result<AuthorizationContext, AppError> {
    let credential = extractors::management_credential(headers, state.allow_local_credentials)?;
    let org_id = extractors::organization_id(headers)?;
    state
        .iam
        .authorize(&AuthorizationRequest {
            credential,
            org_id,
            action: action.to_owned(),
            resource: Some(resource.to_owned()),
        })
        .await
        .map_err(AppError::from)
}

fn management_context(
    authorization: AuthorizationContext,
    idempotency_key: String,
) -> ManagementContext {
    ManagementContext {
        authorization,
        idempotency_key,
        request_id: request_context::current_request_id(),
    }
}

fn hook_response(state: &ApiState, hook: &Hook) -> Result<HookResponse, AppError> {
    Ok(HookResponse::from_domain(hook, endpoint_url(state, hook)?))
}

fn hook_responses(state: &ApiState, hooks: &[Hook]) -> Result<Vec<HookResponse>, AppError> {
    hooks
        .iter()
        .map(|hook| hook_response(state, hook))
        .collect()
}

fn endpoint_url(state: &ApiState, hook: &Hook) -> Result<url::Url, AppError> {
    state
        .application
        .endpoint_url(hook.silicon_id(), hook.endpoint_key())
        .map_err(map_application_error)
}

pub(super) fn parse_silicon_id(value: String) -> Result<SiliconId, AppError> {
    SiliconId::new(value).map_err(|_| AppError::validation("invalid_silicon_id"))
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

fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, AppError> {
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

fn require_empty_body(body: &[u8]) -> Result<(), AppError> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(AppError::bad_request("unexpected_request_body"))
    }
}

fn secret_response_headers() -> HeaderMap {
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
            retry_after: until.map(|until| {
                let remaining = until - time::OffsetDateTime::now_utc();
                std::time::Duration::try_from(remaining).unwrap_or_default()
            }),
        },
        ApplicationError::IdempotencyConflict => AppError::conflict("idempotency_conflict"),
        ApplicationError::StateConflict => AppError::conflict("state_conflict"),
        ApplicationError::SecretUnavailable => AppError::gone("secret_unavailable"),
        ApplicationError::IamHookAlreadyExists => AppError::conflict("iam_hook_already_exists"),
        ApplicationError::HookLimitReached => AppError::conflict("hook_limit_reached"),
        ApplicationError::PayloadTooLarge => AppError::PayloadTooLarge,
        ApplicationError::Unavailable(_source) => {
            tracing::warn!("application dependency is unavailable");
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
    fn retired_endpoints_and_blocked_addresses_map_to_their_statuses() {
        assert_eq!(
            map_application_error(ApplicationError::EndpointRetired).status(),
            http::StatusCode::GONE
        );
        assert_eq!(
            map_application_error(ApplicationError::IpBlocked { until: None }).status(),
            http::StatusCode::FORBIDDEN
        );
        assert_eq!(
            map_application_error(ApplicationError::Unavailable(anyhow::anyhow!("detail")))
                .status(),
            http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            map_application_error(ApplicationError::PayloadTooLarge).status(),
            http::StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}
