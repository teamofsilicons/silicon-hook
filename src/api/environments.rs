//! HTTP boundary for test environment administration and request scoping.

use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, Query, Request, State},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use http::{HeaderMap, StatusCode};
use serde::Deserialize;
use uuid::Uuid;

use super::{
    dto::OneTimeSecret,
    extractors,
    handlers::{authorize_management, parse_json, require_empty_body, secret_response_headers},
    state::ApiState,
};
use crate::{
    application::environments::{
        CreateEnvironment, EnvironmentService, TestEnvironment, TestIamConfiguration,
    },
    error::AppError,
};

pub(super) const TEST_KEY_HEADER: &str = "x-hook-test-key";

pub(super) fn test_key(headers: &HeaderMap) -> Result<Option<&str>, AppError> {
    let mut values = headers.get_all(TEST_KEY_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AppError::bad_request("duplicate_header"));
    }
    let key = value.to_str().map_err(|_| AppError::Unauthenticated)?;
    if key.len() != 32 || !key.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(AppError::Unauthenticated);
    }
    Ok(Some(key))
}

fn service(state: &ApiState) -> Result<&EnvironmentService, AppError> {
    state
        .environments
        .as_ref()
        .ok_or_else(|| AppError::conflict("testing_not_configured"))
}

fn required_key(headers: &HeaderMap) -> Result<&str, AppError> {
    test_key(headers)?.ok_or_else(|| {
        AppError::validation_with_details(
            "test_environment_required",
            "This action is only possible in a test environment. Use hook --test <id>.",
        )
    })
}

/// Chooses immutable dependencies before a handler can touch its data plane.
pub(super) async fn scope(
    State(mut state): State<ApiState>,
    mut request: Request,
    next: Next,
) -> Response {
    match resolve(&mut state, request.uri().path(), request.headers()).await {
        Ok(()) => {
            let identity = state.application.environment_identity();
            let environments = state.environments.clone();
            request.extensions_mut().insert(state);
            let response = next.run(request).await;
            if (response.status().is_success()
                || response.status() == StatusCode::SWITCHING_PROTOCOLS)
                && let Some((id, generation)) = identity
                && let Some(service) = environments
                && let Err(error) = service.touch(id, generation).await
            {
                tracing::warn!(%error, "could not record test request activity");
            }
            response
        }
        Err(error) => error.into_response(),
    }
}

async fn resolve(state: &mut ApiState, path: &str, headers: &HeaderMap) -> Result<(), AppError> {
    let key = test_key(headers)?;
    // Root administration must work before IAM application bootstrap. Its
    // handlers validate the test key directly without creating an actor session.
    if path.starts_with("/api/v1/testing-environment/") || path == "/api/v1/testing-environment" {
        return Ok(());
    }
    if path.starts_with("/api/v1/testing-environments") {
        if key.is_some() {
            return Err(AppError::validation("production_identity_required"));
        }
        return Ok(());
    }
    let context = if let Some(endpoint) = path.strip_prefix("/test/silicon/") {
        if key.is_some() {
            return Err(AppError::bad_request("test_key_not_allowed_on_ingress"));
        }
        let parts: Vec<_> = endpoint.trim_end_matches('/').split('/').collect();
        if parts.len() != 2 {
            return Err(AppError::NotFound);
        }
        let silicon = percent_encoding::percent_decode_str(parts[0])
            .decode_utf8()
            .map_err(|_| AppError::NotFound)?;
        Some(
            service(state)?
                .resolve_endpoint(&silicon, &parts[1].to_ascii_uppercase())
                .await?,
        )
    } else if let Some(key) = key {
        if !path.starts_with("/api/v1/") {
            return Err(AppError::bad_request("test_key_not_allowed_on_ingress"));
        }
        Some(service(state)?.resolve_key(key).await?)
    } else {
        None
    };
    if let Some(context) = context {
        state.application = state.application.for_test_environment(
            context.store,
            context.environment.id,
            context.environment.generation,
        );
        state.iam = context.iam;
    }
    Ok(())
}

#[derive(serde::Serialize)]
pub(super) struct WithKey {
    #[serde(flatten)]
    environment: TestEnvironment,
    key: OneTimeSecret,
    max_hooks: u8,
}

impl WithKey {
    fn new((environment, key): (TestEnvironment, zeroize::Zeroizing<String>)) -> Self {
        Self {
            environment,
            key: OneTimeSecret::new(key),
            max_hooks: 10,
        }
    }
}

pub(super) async fn create(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, Json<WithKey>), AppError> {
    extractors::require_json(&headers)?;
    let actor = authorize_management(&state, &headers, &[]).await?;
    let input: CreateEnvironment = parse_json(&body)?;
    let result = service(&state)?
        .create(&actor, input, &extractors::idempotency_key(&headers)?)
        .await?;
    Ok((secret_response_headers(), Json(WithKey::new(result))))
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListQuery {
    status: Option<String>,
    limit: Option<u32>,
    after: Option<Uuid>,
}

pub(super) async fn list(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let actor = authorize_management(&state, &headers, &[]).await?;
    let items = service(&state)?
        .list(
            &actor,
            query.status.as_deref().unwrap_or("active"),
            query.limit.unwrap_or(100),
            query.after,
        )
        .await?;
    Ok(Json(serde_json::json!({"items": items})))
}

pub(super) async fn get(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<TestEnvironment>, AppError> {
    let actor = authorize_management(&state, &headers, &[]).await?;
    Ok(Json(service(&state)?.get(&actor, id).await?))
}

pub(super) async fn key(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<(HeaderMap, Json<WithKey>), AppError> {
    let actor = authorize_management(&state, &headers, &[]).await?;
    Ok((
        secret_response_headers(),
        Json(WithKey::new(service(&state)?.key(&actor, id).await?)),
    ))
}

pub(super) async fn rotate(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<(HeaderMap, Json<WithKey>), AppError> {
    require_empty_body(&body)?;
    let actor = authorize_management(&state, &headers, &[]).await?;
    Ok((
        secret_response_headers(),
        Json(WithKey::new(
            service(&state)?
                .rotate_key(&actor, id, &extractors::idempotency_key(&headers)?)
                .await?,
        )),
    ))
}

pub(super) async fn delete(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<Json<TestEnvironment>, AppError> {
    require_empty_body(&body)?;
    let actor = authorize_management(&state, &headers, &[]).await?;
    Ok(Json(
        service(&state)?
            .set_deleted(&actor, id, true, &extractors::idempotency_key(&headers)?)
            .await?,
    ))
}

pub(super) async fn restore(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<Json<TestEnvironment>, AppError> {
    require_empty_body(&body)?;
    let actor = authorize_management(&state, &headers, &[]).await?;
    Ok(Json(
        service(&state)?
            .set_deleted(&actor, id, false, &extractors::idempotency_key(&headers)?)
            .await?,
    ))
}

pub(super) async fn current(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> Result<Json<TestEnvironment>, AppError> {
    Ok(Json(
        service(&state)?.current(required_key(&headers)?).await?,
    ))
}

pub(super) async fn clean(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<TestEnvironment>, AppError> {
    require_empty_body(&body)?;
    Ok(Json(
        service(&state)?
            .clean(
                required_key(&headers)?,
                &extractors::idempotency_key(&headers)?,
            )
            .await?,
    ))
}

pub(super) async fn configure_iam(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<TestEnvironment>), AppError> {
    extractors::require_json(&headers)?;
    let config: TestIamConfiguration = parse_json(&body)?;
    Ok((
        StatusCode::OK,
        Json(
            service(&state)?
                .configure_iam(
                    required_key(&headers)?,
                    config,
                    &extractors::idempotency_key(&headers)?,
                )
                .await?,
        ),
    ))
}
