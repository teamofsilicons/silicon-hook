//! Structured, bounded, private operational events with explicit consent.
use super::{handlers::authorize_management, state::ApiState};
use crate::{
    error::AppError,
    telemetry::events::{Event, enabled, record},
};
use axum::{
    Extension, Json,
    extract::{MatchedPath, Request},
};
use http::{HeaderMap, StatusCode};
use sha2::{Digest as _, Sha256};
use std::time::Instant;

pub(super) struct RequestEvent {
    pool: sqlx::PgPool,
    started: Instant,
    event: Option<Event>,
}
impl RequestEvent {
    pub(super) fn start(state: &ApiState, request: &Request) -> Self {
        let opted_in = enabled()
            && request
                .headers()
                .get("x-hook-telemetry")
                .is_none_or(|v| v != "off");
        let path = request.uri().path();
        let collect = opted_in
            && !matches!(
                path,
                "/healthz" | "/readyz" | "/api/v1/telemetry" | "/api/v1/relay/ws"
            );
        let mut event = Event::new("backend", "request", "started");
        // Only route templates are collected; never paths, queries, headers or bodies.
        event.route = request
            .extensions()
            .get::<MatchedPath>()
            .map(|p| p.as_str().to_owned());
        event.method = Some(request.method().as_str().to_owned());
        if let Some(id) =
            crate::request_context::current_request_id().and_then(|id| id.parse().ok())
        {
            event.trace_id = id;
        }
        Self {
            pool: state.application.store().pool().clone(),
            started: Instant::now(),
            event: collect.then_some(event),
        }
    }
    pub(super) fn finish(self, status: StatusCode) {
        if let Some(mut event) = self.event {
            event.outcome = if status.is_success() || status.is_informational() {
                "succeeded"
            } else {
                "failed"
            }
            .into();
            event.duration_ms =
                Some(u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX));
            event.status = Some(status.as_u16());
            record(self.pool, event, None);
        }
    }
}

pub(super) async fn ingest(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    Json(event): Json<Event>,
) -> Result<StatusCode, AppError> {
    if !enabled() || headers.get("x-hook-telemetry").is_some_and(|v| v == "off") {
        return Ok(StatusCode::NO_CONTENT);
    }
    event
        .validate_external()
        .map_err(|()| AppError::validation("invalid_telemetry_event"))?;
    let actor = authorize_management(&state, &headers, &[]).await?;
    let subject = hex::encode(Sha256::digest(
        serde_json::to_vec(&(actor.organization_id(), actor.actor()))
            .map_err(AppError::internal)?,
    ));
    record(
        state.application.store().pool().clone(),
        event,
        Some(subject),
    );
    Ok(StatusCode::ACCEPTED)
}
