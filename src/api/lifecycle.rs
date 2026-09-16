//! Control-plane routes deliberately bypass test-session scoping.
use super::state::ApiState;
use crate::{
    application::environments::{EnvironmentService, lifecycle::LifecycleOperation},
    error::AppError,
};
use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
};
use http::HeaderMap;
use serde_json::Value;
use uuid::Uuid;

fn authorize<'a>(
    state: &'a ApiState,
    headers: &HeaderMap,
) -> Result<&'a EnvironmentService, AppError> {
    let service = state
        .environments
        .as_ref()
        .ok_or(AppError::ProviderUnavailable)?;
    let mut values = headers.get_all(http::header::AUTHORIZATION).iter();
    let token = values
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthenticated)?;
    if values.next().is_some() {
        return Err(AppError::Unauthenticated);
    }
    service.authorize_honeycomb(token)?;
    Ok(service)
}

pub(super) async fn apply(
    State(state): State<ApiState>,
    Path((org, environment, operation)): Path<(String, Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, AppError> {
    let service = authorize(&state, &headers)?;
    let input: LifecycleOperation = serde_json::from_slice(&body)
        .map_err(|_| AppError::validation("invalid_lifecycle_operation"))?;
    if input.org_id != org || input.environment_id != environment || input.operation_id != operation
    {
        return Err(AppError::validation("lifecycle_path_mismatch"));
    }
    Ok(Json(service.lifecycle(&input).await?))
}

pub(super) async fn status(
    State(state): State<ApiState>,
    Path((org, environment, operation)): Path<(String, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    Ok(Json(
        authorize(&state, &headers)?
            .lifecycle_status(&org, environment, operation)
            .await?,
    ))
}
