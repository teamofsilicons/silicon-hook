//! Carbons observing a Silicon's events through Ting.

use axum::{Extension, Json, body::Bytes, extract::Path};
use http::{HeaderMap, StatusCode};
use serde::Serialize;

use super::{
    auth::{self, Check},
    delivery::{delivery, delivery_error},
    handlers::{map_application_error, require_empty_body, secret_response_headers},
    state::ApiState,
};
use crate::{
    delivery::subscriptions::{self, ObserverSubscription, SubscriptionError},
    domain::{Action, authorize},
    error::AppError,
    infrastructure::ting::TingRecipient,
};

#[derive(Serialize)]
pub(super) struct SubscriptionResponse {
    receiving: bool,
    subscription: Option<ObserverSubscription>,
}

fn subscription_error(error: &SubscriptionError) -> AppError {
    match error {
        SubscriptionError::LimitReached => AppError::refused(
            StatusCode::CONFLICT,
            "observer_limit_reached",
            "This Silicon already has the maximum of 100 observers.",
        ),
        SubscriptionError::Store(_) => AppError::ProviderUnavailable,
    }
}

fn require_observer(context: &crate::domain::AuthorizationContext) -> Result<(), AppError> {
    match authorize(context, Action::Observe) {
        crate::domain::AuthorizationDecision::Allowed => Ok(()),
        crate::domain::AuthorizationDecision::Forbidden(reason) => Err(AppError::refused(
            StatusCode::FORBIDDEN,
            "forbidden",
            format!("{reason}."),
        )),
    }
}

/// `GET /api/v3/silicons/{s}/delivery/subscription`.
pub(super) async fn get(
    Extension(state): Extension<ApiState>,
    Path(silicon): Path<String>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<SubscriptionResponse>), AppError> {
    let (_, context) = auth::authorize(&state, &headers, &silicon, Check::Local).await?;
    require_observer(&context)?;
    let subscription = subscriptions::get(
        state.application.store(),
        context.silicon().uuid(),
        context.actor().uuid(),
    )
    .await
    .map_err(|error| subscription_error(&error))?;
    Ok((
        secret_response_headers(),
        Json(SubscriptionResponse {
            receiving: subscription.is_some() && state.application.delivery().is_some(),
            subscription,
        }),
    ))
}

/// `POST /api/v3/silicons/{s}/delivery/subscription`: receive copies of the
/// Silicon's future events. Enrols the caller with Ting first.
pub(super) async fn subscribe(
    Extension(state): Extension<ApiState>,
    Path(silicon): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(HeaderMap, Json<SubscriptionResponse>), AppError> {
    require_empty_body(&body)?;
    let ting = delivery(&state)?;
    let (caller, context) = auth::authorize(&state, &headers, &silicon, Check::Introspect).await?;
    require_observer(&context)?;
    let recipient = TingRecipient {
        uuid: caller.actor.uuid().as_str().to_owned(),
        id: caller.actor.id().map(|id| id.as_str().to_owned()),
    };
    ting.enrol(&caller.token, &recipient)
        .await
        .map_err(|error| delivery_error(&error))?;
    let subscription = subscriptions::subscribe(
        state.application.store(),
        context.silicon().uuid(),
        caller.actor.uuid(),
    )
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

/// `DELETE /api/v3/silicons/{s}/delivery/subscription`: stop receiving copies.
/// Works even after the caller lost access to the Silicon.
pub(super) async fn unsubscribe(
    Extension(state): Extension<ApiState>,
    Path(silicon): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    require_empty_body(&body)?;
    let caller = auth::authenticate(&state, &headers, Check::Local).await?;
    let silicon = state
        .application
        .resolve_silicon(&silicon)
        .await
        .map_err(map_application_error)?;
    subscriptions::unsubscribe(
        state.application.store(),
        &silicon.uuid,
        caller.actor.uuid(),
    )
    .await
    .map_err(|error| subscription_error(&error))?;
    Ok(StatusCode::NO_CONTENT)
}
