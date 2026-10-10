//! Bearer authentication and per-Silicon authorization for every API route.
//!
//! Every management route takes `Authorization: Bearer <access token>`, an
//! `EdDSA` JWT Silicon Accounts issued to Hook (`aud` = Hook's app id), verified
//! locally against the cached JWKS. Routes that reveal secrets or change who
//! has access also confirm with Silicon Accounts (introspection) that the
//! token is still active.

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

/// Whether a route must see revocation at once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Check {
    /// Local verification (signature, audience, issuer, expiry, sign-outs Hook was told about).
    Local,
    /// Local verification plus introspection at Silicon Accounts.
    Introspect,
}

pub(super) async fn authenticate(
    state: &ApiState,
    headers: &HeaderMap,
    check: Check,
) -> Result<Authenticated, AppError> {
    let token = extractors::bearer_token(headers)?;
    let actor = state
        .application
        .authenticate(token.expose_secret())
        .await
        .map_err(map_application_error)?;
    if check == Check::Introspect {
        state
            .application
            .require_active_token(token.expose_secret())
            .await
            .map_err(map_application_error)?;
    }
    Ok(Authenticated { actor, token })
}

/// Authenticates the caller and establishes its access to the hooks of the
/// Silicon named by `silicon` (its current `si:` id or its uuid).
pub(super) async fn authorize(
    state: &ApiState,
    headers: &HeaderMap,
    silicon: &str,
    check: Check,
) -> Result<(Authenticated, AuthorizationContext), AppError> {
    let caller = authenticate(state, headers, check).await?;
    let context = state
        .application
        .authorize_silicon(&caller.actor, silicon)
        .await
        .map_err(map_application_error)?;
    Ok((caller, context))
}
