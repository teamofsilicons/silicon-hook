//! Persistent contract governance, independent of optional telemetry systems.
use crate::{api::state::ApiState, error::AppError};
use axum::{Extension, Json};
use http::{HeaderMap, HeaderValue};

#[derive(sqlx::FromRow, serde::Serialize)]
pub(super) struct Contract {
    pub(super) status: String,
    #[serde(with = "time::serde::rfc3339::option")]
    deprecated_at: Option<time::OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    last_requested_at: Option<time::OffsetDateTime>,
    request_count: i64,
    #[serde(with = "time::serde::rfc3339::option")]
    sunset_at: Option<time::OffsetDateTime>,
}

pub(super) async fn status(state: &ApiState, record: bool) -> Result<Contract, AppError> {
    sqlx::query_as("SELECT * FROM hook_private.contract_status('v1', $1)")
        .bind(record)
        .fetch_optional(state.application.store().pool())
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::ProviderUnavailable)
}

pub(super) async fn admit(state: &ApiState) -> Result<HeaderMap, AppError> {
    let contract = status(state, true).await?;
    if contract.status == "sunset" {
        return Err(AppError::gone("api_version_sunset"));
    }
    let mut headers = HeaderMap::new();
    if let Some(at) = contract.deprecated_at {
        headers.insert(
            "deprecation",
            HeaderValue::from_str(&format!("@{}", at.unix_timestamp()))
                .map_err(AppError::internal)?,
        );
        headers.insert("link", HeaderValue::from_static("<https://docs.hook.teamofsilicons.com/contracts/>; rel=\"deprecation\"; type=\"text/html\""));
    }
    Ok(headers)
}

pub(super) async fn catalog(
    Extension(state): Extension<ApiState>,
) -> Result<(HeaderMap, Json<serde_json::Value>), AppError> {
    let contract = status(&state, false).await?;
    // Public discovery exposes lifecycle policy, never request counters or actor activity.
    Ok((
        super::handlers::secret_response_headers(),
        Json(serde_json::json!({
            "service":"silicon-hook", "contracts":[{"api_version":"v1","status":contract.status,"deprecated_at":contract.deprecated_at.map(time::OffsetDateTime::unix_timestamp),"sunset_at":contract.sunset_at.map(time::OffsetDateTime::unix_timestamp),"websocket_protocols":[1],"relay_protocols":[1]}],
            "policy":{"breaking_changes":"new_major","sunset_after_idle_days":7,"sunset_requires_deprecation":true},
            "compatibility_matrix":"https://docs.hook.teamofsilicons.com/contracts/"
        })),
    ))
}
