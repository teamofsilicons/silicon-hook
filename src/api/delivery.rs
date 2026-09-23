//! Authenticated management of internal Ting delivery and event hydration.

use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, Query, rejection::QueryRejection},
};
use http::HeaderMap;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    extractors,
    handlers::{authorize_management, map_application_error, parse_json},
    state::ApiState,
};
use crate::{
    api::EventResponse,
    delivery::credentials::{PublisherCredentialError, PublisherMetadata},
    domain::{Action, ActorKind, EventId, OrganizationId, OrganizationRole, SiliconId, authorize},
    error::AppError,
    infrastructure::{
        iam::IamError,
        ting::{TingDeliveryMode, TingError},
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProvisionPublisherRequest {
    slt: SecretString,
    #[serde(default)]
    replace_rejected: bool,
}

pub(super) async fn provision_publisher(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, Json<PublisherMetadata>), AppError> {
    extractors::require_json(&headers)?;
    let key = extractors::idempotency_key(&headers)?;
    let request: ProvisionPublisherRequest = parse_json(&body)?;
    let authorization = authorize_management(&state, &headers, &[]).await?;
    if authorization.actor().kind() != ActorKind::Carbon
        || !matches!(
            authorization.organization_role(),
            OrganizationRole::Owner | OrganizationRole::Admin
        )
    {
        return Err(AppError::Forbidden);
    }
    let credentials = state.application.publisher_credentials(state.iam.clone());
    let result = if request.replace_rejected {
        credentials
            .reprovision(
                authorization.organization_id(),
                request.slt.expose_secret(),
                &key,
            )
            .await
    } else {
        credentials
            .provision(
                authorization.organization_id(),
                request.slt.expose_secret(),
                &key,
            )
            .await
    }
    .map_err(publisher_error)?;
    Ok((super::handlers::secret_response_headers(), Json(result)))
}

pub(super) async fn register_recipient(
    Extension(state): Extension<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, Json<serde_json::Value>), AppError> {
    if !body.is_empty() {
        return Err(AppError::bad_request("unexpected_body"));
    }
    let authorization = authorize_management(&state, &headers, &[]).await?;
    let token = extractors::bearer_token(&headers)?;
    let app_id = state
        .iam
        .application_id()
        .ok_or(AppError::ProviderUnavailable)?;
    let prepared = serde_json::to_vec(&serde_json::json!({
        "org_id": authorization.organization_id(), "app_id": app_id,
        "for": authorization.actor().id(),
    }))
    .map_err(AppError::internal)?;
    let _guard = state
        .application
        .delivery_guard()
        .await
        .map_err(map_application_error)?;
    let subscription = state
        .ting
        .register_recipient(&state.iam, &token, &prepared)
        .await
        .map_err(|error| ting_error(&error))?;
    Ok((
        super::handlers::secret_response_headers(),
        Json(serde_json::json!({
            "id": subscription.id, "app_id": subscription.app_id,
            "for": subscription.recipient, "active": subscription.active,
            "required_delivery": subscription.required_delivery,
        })),
    ))
}

#[derive(Serialize)]
pub(super) struct PublicationStatus {
    event_id: Uuid,
    recipient_id: String,
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
    recipient_receipt: Option<crate::infrastructure::ting::TingReceipt>,
    recipient_status_error: Option<&'static str>,
}

pub(super) async fn publication_status(
    Extension(state): Extension<ApiState>,
    Path((silicon_id, event_id)): Path<(SiliconId, EventId)>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<PublicationStatus>), AppError> {
    let authorization =
        authorize_management(&state, &headers, std::slice::from_ref(&silicon_id)).await?;
    if !authorize(&authorization, Action::ReadEvents, &silicon_id).is_allowed() {
        return Err(AppError::NotFound);
    }
    let guard = state
        .application
        .delivery_guard()
        .await
        .map_err(map_application_error)?;
    let status = state
        .application
        .store()
        .ting_status(
            authorization.organization_id(),
            &silicon_id,
            event_id,
            silicon_id.as_str(),
        )
        .await
        .map_err(|_| AppError::ProviderUnavailable)?
        .ok_or(AppError::NotFound)?;
    drop(guard);
    let (recipient_receipt, recipient_status_error) = if let Some(id) = &status.ting_id {
        match recipient_receipt(
            &state,
            authorization.organization_id(),
            &silicon_id,
            id,
            status.delivery,
        )
        .await
        {
            Ok(receipt) => (Some(receipt), None),
            Err(code) => (None, Some(code)),
        }
    } else {
        (None, None)
    };
    let response = PublicationStatus {
        event_id: status.event_id,
        recipient_id: status.recipient_id,
        state: if status.accepted_at.is_none() {
            "pending"
        } else if status.silent == Some(true) && status.delivery == TingDeliveryMode::Ordinary {
            "accepted_silently"
        } else {
            "accepted_by_ting"
        },
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
    Ok((super::handlers::secret_response_headers(), Json(response)))
}

async fn recipient_receipt(
    state: &ApiState,
    org: &OrganizationId,
    silicon: &SiliconId,
    id: &str,
    delivery: TingDeliveryMode,
) -> Result<crate::infrastructure::ting::TingReceipt, &'static str> {
    let credentials = state.application.publisher_credentials(state.iam.clone());
    for attempt in 0..2 {
        let token = credentials
            .access_token(org)
            .await
            .map_err(|_| "publisher_unavailable")?;
        let result = {
            let _guard = state
                .application
                .delivery_guard()
                .await
                .map_err(|_| "recipient_status_unavailable")?;
            state
                .ting
                .receipt(
                    &state.iam,
                    &token,
                    org.as_str(),
                    id,
                    silicon.as_str(),
                    delivery,
                )
                .await
        };
        match result {
            Ok(receipt) => return Ok(receipt),
            Err(TingError::Iam(IamError::InvalidCredential)) if attempt == 0 => {
                // Release the lifecycle guard before the credential write. A
                // newer token installed by another request remains untouched.
                credentials
                    .invalidate_access_token(org, &token)
                    .await
                    .map_err(|_| "publisher_unavailable")?;
            }
            Err(_) => return Err("recipient_status_unavailable"),
        }
    }
    Err("recipient_status_unavailable")
}

fn publisher_error(error: PublisherCredentialError) -> AppError {
    match error {
        PublisherCredentialError::InvalidInput => AppError::validation("invalid_publisher_slt"),
        PublisherCredentialError::Conflict => AppError::conflict("publisher_already_configured"),
        PublisherCredentialError::Busy => AppError::conflict("publisher_busy"),
        PublisherCredentialError::NotConfigured => AppError::conflict("publisher_not_configured"),
        PublisherCredentialError::Forbidden | PublisherCredentialError::SessionRejected => {
            AppError::Forbidden
        }
        _ => AppError::ProviderUnavailable,
    }
}

pub(super) fn ting_error(error: &TingError) -> AppError {
    match error {
        TingError::Iam(IamError::InvalidCredential) => AppError::Unauthenticated,
        TingError::Iam(IamError::Forbidden) | TingError::Rejected { status: 403, .. } => {
            AppError::Forbidden
        }
        TingError::Rejected {
            status: 429,
            retry_after,
            ..
        } => AppError::RateLimited {
            retry_after: retry_after.unwrap_or(std::time::Duration::from_secs(30)),
        },
        _ => AppError::ProviderUnavailable,
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EventQuery {
    environment_id: Option<Uuid>,
    environment_generation: Option<i64>,
}

pub(super) async fn event(
    Extension(state): Extension<ApiState>,
    Path((silicon_id, event_id)): Path<(SiliconId, EventId)>,
    query: Result<Query<EventQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<EventResponse>), AppError> {
    let Query(query) = query.map_err(|_| AppError::bad_request("invalid_query"))?;
    let expected = match (query.environment_id, query.environment_generation) {
        (None, None) => None,
        (Some(id), Some(generation)) if generation >= 0 => Some((id, generation)),
        _ => {
            return Err(AppError::validation(
                "environment_id_and_generation_required_together",
            ));
        }
    };
    let authorization =
        authorize_management(&state, &headers, std::slice::from_ref(&silicon_id)).await?;
    let event = state
        .application
        .get_event(&authorization, &silicon_id, event_id, expected)
        .await
        .map_err(map_application_error)?;
    Ok((
        super::handlers::secret_response_headers(),
        Json(EventResponse::from(&event)),
    ))
}
