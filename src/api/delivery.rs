//! Delivery through Ting at the HTTP boundary: whether it is on, enrolling the
//! caller as a recipient, and one event's publication status.
//!
//! When `HOOK_TING_URL` is unset these routes say so explicitly
//! (`delivery_disabled`) instead of failing: Hook still receives, verifies and
//! stores every event.

use axum::{Extension, Json, body::Bytes, extract::Path};
use http::{HeaderMap, StatusCode};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    auth::{self, Check},
    handlers::{map_application_error, require_empty_body, secret_response_headers},
    state::ApiState,
};
use crate::{
    delivery::adapter::{DeliveryError, TingAdapter},
    domain::{Action, EventId, authorize},
    error::AppError,
    infrastructure::ting::{TingDeliveryMode, TingError, TingReceipt, TingRecipient},
};

pub(super) const DELIVERY_DISABLED: &str = "Delivery through Ting is turned off on this Hook (HOOK_TING_URL is not set). Hook still receives, verifies and stores every event; read them with the events API.";

pub(super) fn delivery(state: &ApiState) -> Result<&TingAdapter, AppError> {
    state.application.delivery().ok_or_else(|| {
        AppError::refused(StatusCode::CONFLICT, "delivery_disabled", DELIVERY_DISABLED)
    })
}

pub(super) fn delivery_error(error: &DeliveryError) -> AppError {
    match error {
        DeliveryError::Proof(error) => {
            tracing::warn!(%error, "no Silicon Accounts proof for Ting");
            AppError::refused(
                StatusCode::SERVICE_UNAVAILABLE,
                "proof_unavailable",
                "Silicon Accounts could not issue the proof Hook needs to talk to Ting. Retry shortly.",
            )
        }
        DeliveryError::Ting(error) => ting_error(error),
    }
}

fn ting_error(error: &TingError) -> AppError {
    match error {
        TingError::Rejected {
            status: 429,
            retry_after,
            ..
        } => AppError::RateLimited {
            retry_after: retry_after.unwrap_or(std::time::Duration::from_secs(1)),
        },
        TingError::Rejected { code, .. } => AppError::refused(
            StatusCode::BAD_GATEWAY,
            "ting_rejected",
            format!("Ting refused the request ({code})."),
        ),
        _ => AppError::ProviderUnavailable,
    }
}

/// `GET /api/v3/delivery`: whether Hook delivers through Ting.
pub(super) async fn status(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    auth::authenticate(&state, &headers, Check::Local).await?;
    Ok(Json(match state.application.delivery() {
        Some(_) => serde_json::json!({"enabled": true, "transport": "ting"}),
        None => serde_json::json!({"enabled": false, "reason": DELIVERY_DISABLED}),
    }))
}

/// `POST /api/v3/delivery/recipient`: enrol the caller with Ting so it can
/// receive Hook's notifications, with a User verification proof issued from
/// the caller's own access token.
pub(super) async fn register_recipient(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    require_empty_body(&body)?;
    let ting = delivery(&state)?;
    let caller = auth::authenticate(&state, &headers, Check::Introspect).await?;
    let recipient = TingRecipient {
        uuid: caller.actor.uuid().as_str().to_owned(),
        id: caller.actor.id().map(|id| id.as_str().to_owned()),
    };
    let subscription = ting
        .enrol(&caller.token, &recipient)
        .await
        .map_err(|error| delivery_error(&error))?;
    Ok(Json(serde_json::json!({
        "recipient": recipient,
        "ting_subscription_id": subscription.id,
        "required_delivery": subscription.required_delivery,
    })))
}

#[derive(Serialize)]
pub(super) struct PublicationStatus {
    event_id: Uuid,
    recipient: String,
    state: &'static str,
    delivery: TingDeliveryMode,
    silent: Option<bool>,
    attempts: i64,
    ting_id: Option<String>,
    last_error_code: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    accepted_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    next_attempt_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    recipient_receipt: Option<TingReceipt>,
    recipient_status_error: Option<&'static str>,
}

/// `GET /api/v3/silicons/{s}/events/{e}/publication`: the Silicon's own send.
pub(super) async fn publication_status(
    Extension(state): Extension<ApiState>,
    Path((silicon, event_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<serde_json::Value>), AppError> {
    let event_id: EventId = event_id
        .parse()
        .map_err(|_| AppError::validation("invalid_event_id"))?;
    let (_, context) = auth::authorize(&state, &headers, &silicon, Check::Local).await?;
    if !authorize(&context, Action::ReadEvents).is_allowed() {
        return Err(AppError::Forbidden);
    }
    let Some(ting) = state.application.delivery() else {
        // The event exists (or not) regardless of delivery; say both.
        state
            .application
            .get_event(&context, event_id)
            .await
            .map_err(map_application_error)?;
        return Ok((
            secret_response_headers(),
            Json(serde_json::json!({
                "event_id": event_id,
                "state": "delivery_disabled",
                "detail": DELIVERY_DISABLED,
            })),
        ));
    };
    let silicon_uuid = context.silicon().uuid();
    let status = state
        .application
        .store()
        .ting_status(silicon_uuid, event_id, silicon_uuid.as_str())
        .await
        .map_err(|_| AppError::ProviderUnavailable)?;
    let Some(status) = status else {
        state
            .application
            .get_event(&context, event_id)
            .await
            .map_err(map_application_error)?;
        return Ok((
            secret_response_headers(),
            Json(serde_json::json!({
                "event_id": event_id,
                "state": "not_queued",
                "detail": "This event was received while delivery was off, or before the Silicon was linked to its Silicon Accounts account, so nothing was queued for Ting.",
            })),
        ));
    };
    let (recipient_receipt, recipient_status_error) = match &status.ting_id {
        Some(id) => match ting
            .receipt(id, &status.recipient_id, status.delivery)
            .await
        {
            Ok(receipt) => (Some(receipt), None),
            Err(_) => (None, Some("recipient_status_unavailable")),
        },
        None => (None, None),
    };
    let state_name = if status.last_error_code.as_deref() == Some("legacy_identity") {
        "not_delivered_legacy"
    } else if status.accepted_at.is_none() {
        "pending"
    } else if status.silent == Some(true) && status.delivery == TingDeliveryMode::Ordinary {
        "accepted_silently"
    } else {
        "accepted_by_ting"
    };
    let response = PublicationStatus {
        event_id: status.event_id,
        recipient: status.recipient_id,
        state: state_name,
        delivery: status.delivery,
        silent: status.silent,
        attempts: status.attempts,
        ting_id: status.ting_id,
        last_error_code: status.last_error_code,
        accepted_at: status.accepted_at,
        next_attempt_at: status.next_attempt_at,
        expires_at: status.expires_at,
        recipient_receipt,
        recipient_status_error,
    };
    Ok((
        secret_response_headers(),
        Json(serde_json::to_value(response).map_err(AppError::internal)?),
    ))
}
