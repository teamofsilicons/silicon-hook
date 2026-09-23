//! Current Carbon actors can request compact references for visible Silicons.

use axum::{Extension, Json, body::Bytes, extract::Path};
use http::{HeaderMap, StatusCode};
use serde::Serialize;

use super::{
    delivery::ting_error,
    extractors,
    handlers::{authorize_management, map_application_error, secret_response_headers},
    state::ApiState,
};
use crate::{
    delivery::subscriptions::{self, ReceivingSubscription, SubscriptionError},
    domain::SiliconId,
    error::AppError,
};

#[derive(Serialize)]
pub(super) struct SubscriptionResponse {
    receiving: bool,
    subscription: Option<ReceivingSubscription>,
}

pub(super) async fn get(
    Extension(state): Extension<ApiState>,
    Path(silicon): Path<SiliconId>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<SubscriptionResponse>), AppError> {
    let authorization =
        authorize_management(&state, &headers, std::slice::from_ref(&silicon)).await?;
    subscriptions::authorize_subscription(&authorization, &silicon)
        .map_err(|error| subscription_error(&error))?;
    let _guard = state
        .application
        .delivery_guard()
        .await
        .map_err(map_application_error)?;
    let subscription = subscriptions::get(state.application.store(), &authorization, &silicon)
        .await
        .map_err(|error| subscription_error(&error))?;
    Ok((
        secret_response_headers(),
        Json(SubscriptionResponse {
            receiving: subscription.is_some(),
            subscription,
        }),
    ))
}

pub(super) async fn subscribe(
    Extension(state): Extension<ApiState>,
    Path(silicon): Path<SiliconId>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, Json<SubscriptionResponse>), AppError> {
    require_empty(&body)?;
    let authorization =
        authorize_management(&state, &headers, std::slice::from_ref(&silicon)).await?;
    subscriptions::authorize_subscription(&authorization, &silicon)
        .map_err(|error| subscription_error(&error))?;
    let token = extractors::bearer_token(&headers)?;
    let app_id = state
        .iam
        .application_id()
        .ok_or(AppError::ProviderUnavailable)?;
    let prepared = serde_json::to_vec(&serde_json::json!({
        "org_id": authorization.organization_id(),
        "app_id": app_id,
        "for": authorization.actor().id(),
    }))
    .map_err(AppError::internal)?;
    let guard = state
        .application
        .delivery_guard()
        .await
        .map_err(map_application_error)?;
    state
        .ting
        .register_recipient(&state.iam, &token, &prepared)
        .await
        .map_err(|error| ting_error(&error))?;
    // The persistence transaction obtains its own exclusive lifecycle fence.
    // Holding the separate shared guard across that write would deadlock. A
    // clean or key rotation in between makes this pinned store reject the write.
    drop(guard);
    let subscription = state
        .application
        .observer_authorities(state.iam.clone())
        .subscribe(&authorization, &silicon, &token)
        .await
        .map_err(|error| subscription_error(&error))?;
    Ok((
        secret_response_headers(),
        Json(SubscriptionResponse {
            receiving: true,
            subscription: Some(subscription),
        }),
    ))
}

pub(super) async fn unsubscribe(
    Extension(state): Extension<ApiState>,
    Path(silicon): Path<SiliconId>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, StatusCode), AppError> {
    require_empty(&body)?;
    // A caller who lost access must still be able to stop its own notifications.
    // No target read is needed: deletion remains scoped to the authenticated actor.
    let authorization = authorize_management(&state, &headers, &[]).await?;
    subscriptions::unsubscribe(state.application.store(), &authorization, &silicon)
        .await
        .map_err(|error| subscription_error(&error))?;
    Ok((secret_response_headers(), StatusCode::NO_CONTENT))
}

fn require_empty(body: &Bytes) -> Result<(), AppError> {
    if !body.is_empty() {
        return Err(AppError::bad_request("unexpected_body"));
    }
    Ok(())
}

fn subscription_error(error: &SubscriptionError) -> AppError {
    match error {
        SubscriptionError::CarbonRequired => AppError::Forbidden,
        SubscriptionError::NotVisible => AppError::NotFound,
        SubscriptionError::LimitReached => AppError::conflict("receiving_subscription_limit"),
        SubscriptionError::Store(_) | SubscriptionError::AuthorityUnavailable => {
            AppError::ProviderUnavailable
        }
    }
}
