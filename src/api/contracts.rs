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
    status_major(state, "v1", record).await
}

pub(super) async fn status_major(
    state: &ApiState,
    major: &str,
    record: bool,
) -> Result<Contract, AppError> {
    sqlx::query_as("SELECT * FROM hook_private.contract_status($1, $2)")
        .bind(major)
        .bind(record)
        .fetch_optional(state.application.store().pool())
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::ProviderUnavailable)
}

pub(super) async fn admit(state: &ApiState) -> Result<HeaderMap, AppError> {
    let contract = status(state, true).await?;
    admission_headers(&contract)
}

pub(super) async fn admit_major(state: &ApiState, major: &str) -> Result<HeaderMap, AppError> {
    admission_headers(&status_major(state, major, true).await?)
}

fn admission_headers(contract: &Contract) -> Result<HeaderMap, AppError> {
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

pub(super) async fn negotiate(
    state: &ApiState,
    headers: &HeaderMap,
) -> Result<(HeaderMap, Json<serde_json::Value>), AppError> {
    let mut available = Vec::new();
    for &major in super::version::SUPPORTED_API_VERSIONS {
        if status_major(state, major, false).await?.status != "sunset" {
            available.push(major);
        }
    }
    let advertised = super::version::advertised_versions(headers)?;
    let selected = if available.len() == super::version::SUPPORTED_API_VERSIONS.len() {
        super::version::negotiate(advertised)?
    } else {
        super::version::negotiate_available(advertised, &available)?
    };
    Ok((
        super::version::response_headers(selected),
        Json(serde_json::json!({
            "service": "silicon-hook",
            "selected_api_version": selected,
            "supported_api_versions": available,
            "build": env!("CARGO_PKG_VERSION"),
            "commit": option_env!("HOOK_BUILD_COMMIT").unwrap_or("unknown"),
        })),
    ))
}

pub(super) async fn catalog(
    Extension(state): Extension<ApiState>,
) -> Result<(HeaderMap, Json<serde_json::Value>), AppError> {
    let mut contracts = Vec::new();
    for &major in super::version::SUPPORTED_API_VERSIONS {
        let contract = status_major(&state, major, false).await?;
        let legacy = major == "v1";
        contracts.push(serde_json::json!({
            "api_version": major,
            "status": contract.status,
            "deprecated_at": contract.deprecated_at.map(time::OffsetDateTime::unix_timestamp),
            "sunset_at": contract.sunset_at.map(time::OffsetDateTime::unix_timestamp),
            "websocket_protocols": if legacy { vec![1] } else { Vec::<u8>::new() },
            "relay_protocols": if legacy { vec![1] } else { Vec::<u8>::new() },
            "delivery_transport": if legacy { "hook" } else { "ting" },
        }));
    }
    // Public discovery exposes lifecycle policy, never request counters or actor activity.
    Ok((
        super::handlers::secret_response_headers(),
        Json(serde_json::json!({
            "service":"silicon-hook", "contracts":contracts,
            "policy":{"breaking_changes":"new_major","sunset_after_idle_days":7,"sunset_requires_deprecation":true},
            "compatibility_matrix":"https://docs.hook.teamofsilicons.com/contracts/"
        })),
    ))
}
