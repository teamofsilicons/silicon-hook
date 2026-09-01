//! HTTP handlers that translate between transport and application contracts.

use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
};
use serde::de::DeserializeOwned;

use super::{
    dto::{
        CreateHookRequest, EventAcceptedResponse, EventPageResponse, EventRecordResponse,
        HealthResponse, HookPageResponse, HookResponse, HookWithSecretResponse, ListEventsQuery,
        ListHooksQuery, OneTimeSecret, ProvisionIamHookRequest, SetHookEnabledRequest,
        SetHooksEnabledRequest, SigningSecretResponse, VersionResponse,
    },
    extractors,
    state::ApiState,
};
use crate::{
    application::{
        AcceptEventCommand, ApplicationError, CreateHookCommand, DeleteHookCommand,
        HookMutationCommand, ListEventsCommand, ManagementContext, ProvisionIamHookCommand,
        SetHooksEnabledCommand,
    },
    domain::{
        AuthorizationContext, EndpointKey, HookDescription, HookId, HookName, OrganizationId,
        SiliconId,
    },
    error::AppError,
    infrastructure::iam::AuthorizationRequest,
    infrastructure::postgres::RuntimeDatabaseRole,
    request_context,
};

const ACTION_LIST_HOOKS: &str = "hook.hooks.list";
const ACTION_READ_HOOK: &str = "hook.hooks.read";
const ACTION_CREATE_HOOK: &str = "hook.hooks.create";
const ACTION_DELETE_HOOK: &str = "hook.hooks.delete";
const ACTION_SET_HOOK_ENABLED: &str = "hook.hooks.enabled.update";
const ACTION_RESTORE_HOOK: &str = "hook.hooks.restore";
const ACTION_ROTATE_SECRET: &str = "hook.hooks.secret.rotate";
const ACTION_READ_EVENTS: &str = "hook.events.read";

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
    let items = hooks
        .iter()
        .map(|hook| HookResponse::from_domain(hook, &state.public_base_url))
        .collect::<anyhow::Result<Vec<_>>>()
        .map_err(AppError::internal)?;
    Ok(Json(HookPageResponse { items }))
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
    let authorization =
        authorize_management(&state, &headers, ACTION_CREATE_HOOK, silicon_id.as_str()).await?;
    let result = state
        .application
        .create_hook(CreateHookCommand {
            context: management_context(authorization, idempotency_key),
            silicon_id,
            name,
            description,
        })
        .await
        .map_err(map_application_error)?;
    let response = HookWithSecretResponse {
        hook: HookResponse::from_domain(&result.hook, &state.public_base_url)
            .map_err(AppError::internal)?,
        signing_secret: OneTimeSecret::new(result.signing_secret.to_encoded()),
    };
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
    Ok(Json(
        HookResponse::from_domain(&hook, &state.public_base_url).map_err(AppError::internal)?,
    ))
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

pub(super) async fn set_hook_enabled(
    State(state): State<ApiState>,
    Path((silicon_id, hook_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<HookResponse>, AppError> {
    extractors::require_json(&headers)?;
    let silicon_id = parse_silicon_id(silicon_id)?;
    let hook_id = parse_hook_id(&hook_id)?;
    let request: SetHookEnabledRequest = parse_json(&body)?;
    let authorization = authorize_management(
        &state,
        &headers,
        ACTION_SET_HOOK_ENABLED,
        &hook_id.to_string(),
    )
    .await?;
    let mut hooks = state
        .application
        .set_hooks_enabled(SetHooksEnabledCommand {
            authorization,
            silicon_id,
            hook_ids: vec![hook_id],
            enabled: request.enabled,
            request_id: request_context::current_request_id(),
        })
        .await
        .map_err(map_application_error)?;
    let hook = hooks.pop().ok_or_else(|| {
        AppError::internal(anyhow::anyhow!("single-hook activation returned no hook"))
    })?;
    Ok(Json(
        HookResponse::from_domain(&hook, &state.public_base_url).map_err(AppError::internal)?,
    ))
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
    let items = hooks
        .iter()
        .map(|hook| HookResponse::from_domain(hook, &state.public_base_url))
        .collect::<anyhow::Result<Vec<_>>>()
        .map_err(AppError::internal)?;
    Ok(Json(HookPageResponse { items }))
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
    Ok(Json(
        HookResponse::from_domain(&hook, &state.public_base_url).map_err(AppError::internal)?,
    ))
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
    Ok((
        secret_response_headers(),
        Json(SigningSecretResponse {
            signing_secret: OneTimeSecret::new(result.signing_secret.to_encoded()),
        }),
    ))
}

pub(super) async fn list_events(
    State(state): State<ApiState>,
    Path(silicon_id): Path<String>,
    query: Result<Query<ListEventsQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<Json<EventPageResponse>, AppError> {
    let silicon_id = parse_silicon_id(silicon_id)?;
    let Query(query) = query.map_err(|_| AppError::validation("invalid_query"))?;
    let authorization =
        authorize_management(&state, &headers, ACTION_READ_EVENTS, silicon_id.as_str()).await?;
    let page = state
        .application
        .list_events(ListEventsCommand {
            authorization,
            silicon_id,
            hook_id: query.hook_id,
            event_type: query.event_type,
            limit: query.limit,
            cursor: query.cursor,
        })
        .await
        .map_err(map_application_error)?;
    Ok(Json(EventPageResponse {
        items: page
            .items
            .into_iter()
            .map(EventRecordResponse::from)
            .collect(),
        next_cursor: page.next_cursor,
    }))
}

pub(super) async fn receive_event(
    State(state): State<ApiState>,
    Path((silicon_id, endpoint_key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<EventAcceptedResponse>), AppError> {
    extractors::require_json(&headers)?;
    let silicon_id = parse_silicon_id(silicon_id)?;
    let endpoint_key = EndpointKey::parse(&endpoint_key)
        .map_err(|_| AppError::validation("invalid_endpoint_key"))?;
    let ingress = extractors::ingress_headers(&headers)?;
    let request_id = request_context::current_request_id()
        .ok_or_else(|| AppError::internal(anyhow::anyhow!("request scope is unavailable")))?;
    let event_id = state
        .application
        .accept_event(AcceptEventCommand {
            silicon_id,
            endpoint_key,
            timestamp: ingress.timestamp,
            signature: ingress.signature,
            idempotency_key: ingress.idempotency_key,
            body,
            request_id,
        })
        .await
        .map_err(map_application_error)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(EventAcceptedResponse::new(event_id)),
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
    let response = HookWithSecretResponse {
        hook: HookResponse::from_domain(&result.hook, &state.public_base_url)
            .map_err(AppError::internal)?,
        signing_secret: OneTimeSecret::new(result.signing_secret.to_encoded()),
    };
    Ok((
        StatusCode::CREATED,
        secret_response_headers(),
        Json(response),
    ))
}

async fn authorize_management(
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

fn parse_silicon_id(value: String) -> Result<SiliconId, AppError> {
    SiliconId::new(value).map_err(|_| AppError::validation("invalid_silicon_id"))
}

fn parse_hook_id(value: &str) -> Result<HookId, AppError> {
    value
        .parse()
        .map_err(|_| AppError::validation("invalid_hook_id"))
}

fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, AppError> {
    serde_json::from_slice(body).map_err(|error| match error.classify() {
        serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
            AppError::bad_request("invalid_json")
        }
        serde_json::error::Category::Data => AppError::validation("validation_failed"),
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

fn map_application_error(error: ApplicationError) -> AppError {
    match error {
        ApplicationError::Validation { field } => AppError::validation(format!("invalid_{field}")),
        ApplicationError::MalformedJson => AppError::bad_request("invalid_json"),
        ApplicationError::Forbidden => AppError::Forbidden,
        ApplicationError::NotFound => AppError::NotFound,
        ApplicationError::RecoveryExpired => AppError::gone("recovery_expired"),
        ApplicationError::IdempotencyConflict => AppError::conflict("idempotency_conflict"),
        ApplicationError::StateConflict => AppError::conflict("state_conflict"),
        ApplicationError::SecretUnavailable => AppError::gone("secret_unavailable"),
        ApplicationError::IamHookAlreadyExists => AppError::conflict("iam_hook_already_exists"),
        ApplicationError::HookLimitReached => AppError::conflict("hook_limit_reached"),
        ApplicationError::InvalidSignature => AppError::Unauthenticated,
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
        assert_eq!(
            headers
                .get(http::header::PRAGMA)
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );
    }

    #[test]
    fn dependency_failures_map_to_service_unavailable() {
        let error = map_application_error(ApplicationError::Unavailable(anyhow::anyhow!(
            "dependency detail"
        )));

        assert_eq!(error.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn normalized_delivery_overflow_maps_to_payload_too_large() {
        let error = map_application_error(ApplicationError::PayloadTooLarge);

        assert_eq!(error.status(), http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn malformed_application_json_maps_to_bad_request() {
        let error = map_application_error(ApplicationError::MalformedJson);

        assert_eq!(error.status(), http::StatusCode::BAD_REQUEST);
    }
}
