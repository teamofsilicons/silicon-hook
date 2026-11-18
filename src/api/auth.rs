//! Bearer authentication and per-Silicon authorization for every API route.
//!
//! Every management route takes `Authorization: Bearer <access token>`, an
//! `EdDSA` JWT Silicon Accounts issued to Hook (`aud` = Hook's app id), verified
//! against the published keys and confirmed active by Silicon Accounts.

use http::HeaderMap;
use secrecy::{ExposeSecret as _, SecretString};

use super::{extractors, handlers::map_application_error, state::ApiState};
use crate::{
    domain::{Actor, AuthorizationContext},
    error::AppError,
};

/// The authenticated caller and the token it presented.
pub(super) struct Authenticated {
    pub(super) actor: Actor,
    pub(super) token: SecretString,
}

pub(super) async fn authenticate(
    state: &ApiState,
    headers: &HeaderMap,
) -> Result<Authenticated, AppError> {
    let token = extractors::bearer_token(headers)?;
    let actor = state
        .application
        .authenticate(token.expose_secret())
        .await
        .map_err(map_application_error)?;
    Ok(Authenticated { actor, token })
}

/// Authenticates the caller and establishes its access to the hooks of the
/// Silicon named by `silicon` (its current `si:` id or its uuid).
pub(super) async fn authorize(
    state: &ApiState,
    headers: &HeaderMap,
    silicon: &str,
) -> Result<(Authenticated, AuthorizationContext), AppError> {
    let caller = authenticate(state, headers).await?;
    let context = state
        .application
        .authorize_silicon(&caller.actor, silicon)
        .await
        .map_err(map_application_error)?;
    Ok((caller, context))
}
