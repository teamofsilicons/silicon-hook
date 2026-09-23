//! Authenticated app adapters acquire scoped testing receivers through Hook.

use axum::{Extension, Json, body::Bytes};
use http::HeaderMap;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    dto::OneTimeSecret,
    extractors,
    handlers::{authorize_management, map_application_error, parse_json, secret_response_headers},
    state::ApiState,
};
use crate::{
    domain::AuthorizationContext,
    error::AppError,
    infrastructure::ting::{
        TingError,
        receiver::{ReceiverEnvironment, ReceiverScope},
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapRequest {
    environment_id: Uuid,
    generation: i64,
    receiver_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct BootstrapResponse {
    #[serde(flatten)]
    scope: ReceiverScope,
    receiver_id: String,
    receiver_token: OneTimeSecret,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

async fn scope(
    state: &ApiState,
    headers: &HeaderMap,
    authorization: &AuthorizationContext,
    environment: (Uuid, i64),
) -> Result<ReceiverScope, AppError> {
    // delivery_guard holds this row across the network call, preventing an
    // overlapping clean/rotation from minting a stale capability afterward.
    let generation: Option<i64> = sqlx::query_scalar(
        "SELECT honeycomb_generation FROM hook_control.environments
         WHERE id=$1 AND generation=$2 AND org_id=$3 AND deleted_at IS NULL
           AND honeycomb_state='ready' AND honeycomb_generation>0",
    )
    .bind(environment.0)
    .bind(environment.1)
    .bind(authorization.organization_id().as_str())
    .fetch_optional(state.application.store().pool())
    .await
    .map_err(|_| AppError::ProviderUnavailable)?
    .flatten();
    let generation =
        generation.ok_or_else(|| AppError::conflict("receiver_environment_unavailable"))?;
    let org_id = state
        .iam
        .ting_receiver_organization(
            &extractors::bearer_token(headers)?,
            authorization.organization_id(),
            authorization.actor(),
            environment.0,
        )
        .await
        .map_err(AppError::from)?;
    Ok(ReceiverScope {
        app_id: state
            .iam
            .application_id()
            .ok_or(AppError::ProviderUnavailable)?
            .to_owned(),
        recipient: authorization.actor().id().as_str().to_owned(),
        kind: match authorization.actor().kind() {
            crate::domain::ActorKind::Carbon => "carbon",
            crate::domain::ActorKind::Silicon => "silicon",
        }
        .to_owned(),
        org_id,
        hook_org_id: authorization.organization_id().as_str().to_owned(),
        environment: ReceiverEnvironment {
            kind: "testing".into(),
            id: environment.0,
            generation,
        },
    })
}

fn testing(state: &ApiState) -> Result<(Uuid, i64), AppError> {
    state
        .application
        .environment_identity()
        .filter(|(id, _)| !id.is_nil() && state.iam.is_testing())
        .ok_or_else(|| AppError::validation("test_environment_required"))
}

pub(super) async fn get(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<ReceiverScope>), AppError> {
    let environment = testing(&state)?;
    let authorization = authorize_management(&state, &headers, &[]).await?;
    let _guard = state
        .application
        .delivery_guard()
        .await
        .map_err(map_application_error)?;
    let scope = scope(&state, &headers, &authorization, environment).await?;
    Ok((secret_response_headers(), Json(scope)))
}

pub(super) async fn bootstrap(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, Json<BootstrapResponse>), AppError> {
    extractors::require_json(&headers)?;
    let key = extractors::idempotency_key(&headers)?;
    let input: BootstrapRequest = parse_json(&body)?;
    let environment = testing(&state)?;
    if input.environment_id != environment.0 || input.generation <= 0 {
        return Err(AppError::conflict("receiver_environment_changed"));
    }
    let authorization = authorize_management(&state, &headers, &[]).await?;
    let _guard = state
        .application
        .delivery_guard()
        .await
        .map_err(map_application_error)?;
    let scope = scope(&state, &headers, &authorization, environment).await?;
    if input.generation != scope.environment.generation {
        return Err(AppError::conflict("receiver_environment_changed"));
    }
    let capability = state
        .ting
        .bootstrap_receiver(
            &state.iam,
            &extractors::bearer_token(&headers)?,
            &scope,
            &key,
            input.receiver_id.as_deref(),
        )
        .await
        .map_err(|error| match error {
            TingError::InvalidInput(code) => AppError::validation(code),
            TingError::Rejected { status: 409, .. } => {
                AppError::conflict("receiver_operation_conflict")
            }
            _ => super::delivery::ting_error(&error),
        })?;
    Ok((
        secret_response_headers(),
        Json(BootstrapResponse {
            scope,
            receiver_id: capability.receiver_id,
            receiver_token: OneTimeSecret::new(Zeroizing::new(
                capability.receiver_token.expose_secret().to_owned(),
            )),
            expires_at: capability.expires_at,
        }),
    ))
}
