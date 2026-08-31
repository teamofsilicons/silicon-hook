//! Fail-closed Silicon IAM authentication and authorization adapter.
//!
//! IAM's response contract is evolving. All transport-only DTOs therefore live
//! in a private wire module, and only validated domain values cross this
//! adapter boundary.

use std::fmt;

use bytes::BytesMut;
use http::{StatusCode, header};
use reqwest::{Client, Response, Url, redirect::Policy};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    config::IamSettings,
    domain::{
        ActorKind, ActorRef, ApplicationId, AuthorizationContext, Capability, OrganizationId,
        OrganizationRole, SiliconId,
    },
    error::AppError,
};

const USER_AGENT: &str = concat!("silicon-hook/", env!("CARGO_PKG_VERSION"));
const IAM_SERVICE_ID: &str = "silicon-iam";
const IAM_PROVISION_ACTION: &str = "hook.iam.provision";
const OBO_IDEMPOTENCY_DOMAIN: &[u8] = b"silicon-hook/iam-obo-verification/v1\0";

/// Credential forms accepted by Hook's management API.
#[derive(Clone)]
pub enum PresentedCredential {
    /// Opaque IAM access token from the HTTP bearer scheme.
    Bearer(SecretString),
    /// Single-use IAM proof presented by an application acting for a user.
    Obo {
        /// Calling IAM application from `X-App-ID`.
        app_id: ApplicationId,
        /// Opaque proof from `X-IAM-OBO-Access-Proof`.
        proof: SecretString,
    },
}

impl fmt::Debug for PresentedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer(_) => formatter
                .debug_tuple("Bearer")
                .field(&"[REDACTED]")
                .finish(),
            Self::Obo { app_id, .. } => formatter
                .debug_struct("Obo")
                .field("app_id", app_id)
                .field("proof", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Information IAM needs to authenticate a management request.
#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    /// Credential supplied by the caller.
    pub credential: PresentedCredential,
    /// Organization selected by `X-Org-ID`.
    pub org_id: OrganizationId,
    /// Audience-specific action bound into an OBO proof.
    pub action: String,
    /// Optional resource identifier bound into an OBO proof.
    pub resource: Option<String>,
}

/// IAM adapter failure with explicit invalid-versus-unavailable semantics.
#[derive(Debug, Error)]
pub enum IamError {
    /// Presented credentials are absent from, inactive in, or rejected by IAM.
    #[error("IAM rejected the presented credential")]
    InvalidCredential,
    /// IAM could not be reached before the configured deadline.
    #[error("IAM transport is unavailable")]
    Transport(#[source] reqwest::Error),
    /// IAM returned more data than Hook is configured to accept.
    #[error("IAM response exceeds the configured bound")]
    ResponseTooLarge,
    /// IAM returned a success body that did not satisfy the expected contract.
    #[error("IAM returned an invalid authorization response")]
    InvalidResponse,
    /// IAM returned a status that cannot authenticate the request.
    #[error("IAM returned an unexpected HTTP status {0}")]
    UnexpectedStatus(u16),
    /// Online verification is requested without IAM application credentials.
    #[error("IAM online verification is not configured")]
    OnlineVerificationNotConfigured,
}

impl IamError {
    /// Returns whether this error specifically means the caller's credential is invalid.
    #[must_use]
    pub const fn is_invalid_credential(&self) -> bool {
        matches!(self, Self::InvalidCredential)
    }

    const fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::InvalidCredential => "invalid_credential",
            Self::Transport(_) => "transport",
            Self::ResponseTooLarge => "response_too_large",
            Self::InvalidResponse => "invalid_response",
            Self::UnexpectedStatus(_) => "unexpected_status",
            Self::OnlineVerificationNotConfigured => "not_configured",
        }
    }
}

impl From<IamError> for AppError {
    fn from(error: IamError) -> Self {
        if error.is_invalid_credential() {
            Self::Unauthenticated
        } else {
            tracing::warn!(
                error_code = error.diagnostic_code(),
                "IAM authorization failed closed"
            );
            Self::ProviderUnavailable
        }
    }
}

/// Configuration-time IAM client construction failure.
#[derive(Debug, Error)]
pub enum IamClientBuildError {
    /// Reqwest rejected the bounded client policy.
    #[error("failed to construct the IAM HTTP client")]
    HttpClient(#[source] reqwest::Error),
}

/// Cloneable, redirect-free, deadline- and response-bound IAM client.
#[derive(Clone)]
pub struct IamClient {
    client: Client,
    introspection_endpoint: Url,
    obo_verification_endpoint: Url,
    app_id: Option<String>,
    app_secret: Option<SecretString>,
    audience: String,
    max_response_bytes: usize,
    local_service_token: Option<SecretString>,
}

impl fmt::Debug for IamClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IamClient")
            .field("introspection_endpoint", &self.introspection_endpoint)
            .field("obo_verification_endpoint", &self.obo_verification_endpoint)
            .field("app_id", &self.app_id)
            .field(
                "app_secret",
                &self.app_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("audience", &self.audience)
            .field("max_response_bytes", &self.max_response_bytes)
            .field(
                "local_service_token",
                &self.local_service_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish_non_exhaustive()
    }
}

impl IamClient {
    /// Builds the bounded online adapter and optional development-only local adapter.
    ///
    /// # Errors
    ///
    /// Returns an error only when the HTTP client policy itself is invalid.
    pub fn new(settings: &IamSettings) -> Result<Self, IamClientBuildError> {
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(settings.connect_timeout)
            .timeout(settings.request_timeout)
            .user_agent(USER_AGENT)
            .build()
            .map_err(IamClientBuildError::HttpClient)?;

        Ok(Self {
            client,
            introspection_endpoint: endpoint(&settings.base_url, "/api/v1/auth/tokens/introspect"),
            obo_verification_endpoint: endpoint(&settings.base_url, "/api/v1/obo-access/verify"),
            app_id: settings.app_id.clone(),
            app_secret: settings.app_secret.clone(),
            audience: settings.audience.clone(),
            max_response_bytes: settings.max_response_bytes,
            local_service_token: settings
                .local_auth
                .as_ref()
                .map(|local| local.iam_service_token.clone()),
        })
    }

    /// Authenticates a bearer or OBO credential and returns only validated IAM facts.
    ///
    /// # Errors
    ///
    /// Invalid credentials return [`IamError::InvalidCredential`]. Timeouts,
    /// malformed success responses, response overflows, and provider failures
    /// fail closed with an availability-class error.
    ///
    /// When and only when local authentication was enabled at startup, the
    /// deterministic credential `local:<carbon|silicon>:<member|admin|owner>:
    /// <actor-id>` is accepted for development and test processes.
    pub async fn authorize(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationContext, IamError> {
        match &request.credential {
            PresentedCredential::Bearer(token) => {
                if self.local_service_token.is_some() && token.expose_secret().starts_with("local:")
                {
                    return local_authorize(token, request, None);
                }
                let response = self.introspect(token, Some(&request.org_id)).await?;
                context_from_introspection(&response, request, &self.audience)
            }
            PresentedCredential::Obo { app_id, proof } => {
                if self.local_service_token.is_some() && proof.expose_secret().starts_with("local:")
                {
                    return local_authorize(proof, request, Some(app_id.clone()));
                }
                let response = self.verify_obo(proof, app_id, request).await?;
                context_from_obo(&response, request, app_id, &self.audience)
            }
        }
    }

    /// Verifies that a bearer token is the IAM provisioning service identity.
    ///
    /// # Errors
    ///
    /// Returns [`IamError::InvalidCredential`] unless the current online IAM
    /// response proves service ID `silicon-iam`, audience `silicon-hook`, and
    /// action `hook.iam.provision`. The configured local service token is
    /// accepted only when startup explicitly enabled non-production local auth.
    pub async fn authenticate_iam_service(
        &self,
        token: &SecretString,
    ) -> Result<ActorRef, IamError> {
        if let Some(local_token) = &self.local_service_token {
            if secrets_equal(local_token, token) {
                return ActorRef::try_new(ActorKind::Service, IAM_SERVICE_ID)
                    .map_err(|_| IamError::InvalidResponse);
            }
            if token.expose_secret().starts_with("local:") {
                return Err(IamError::InvalidCredential);
            }
        }

        let response = self.introspect(token, None).await?;
        if !response.active {
            return Err(IamError::InvalidCredential);
        }
        let audiences = response.audiences().ok_or(IamError::InvalidResponse)?;
        if !audiences.contains(&self.audience.as_str()) {
            return Err(IamError::InvalidCredential);
        }
        let actor = response.service_actor().ok_or(IamError::InvalidResponse)?;
        let actor = actor.try_into_domain()?;
        let authorities = response.authorities().ok_or(IamError::InvalidResponse)?;
        if response
            .bound_action()
            .is_some_and(|action| action != IAM_PROVISION_ACTION)
        {
            return Err(IamError::InvalidResponse);
        }
        if !actor.is_service_named(IAM_SERVICE_ID) || !authorities.contains(&IAM_PROVISION_ACTION) {
            return Err(IamError::InvalidCredential);
        }
        Ok(actor)
    }

    async fn introspect(
        &self,
        token: &SecretString,
        organization_id: Option<&OrganizationId>,
    ) -> Result<wire::Introspection, IamError> {
        let (app_id, app_secret) = self.online_credentials()?;
        let mut request = self
            .client
            .post(self.introspection_endpoint.clone())
            .basic_auth(app_id, Some(app_secret.expose_secret()))
            .form(&[("token", token.expose_secret())]);
        if let Some(organization_id) = organization_id {
            request = request.header("X-Org-ID", organization_id.as_str());
        }
        let response = request.send().await.map_err(IamError::Transport)?;
        ensure_authentication_status(response.status())?;
        bounded_json(response, self.max_response_bytes).await
    }

    async fn verify_obo(
        &self,
        proof: &SecretString,
        presented_app_id: &ApplicationId,
        request: &AuthorizationRequest,
    ) -> Result<wire::OboResult, IamError> {
        let (app_id, app_secret) = self.online_credentials()?;
        let body = wire::OboVerificationRequest {
            access_proof: proof.expose_secret(),
            audience: &self.audience,
            action: &request.action,
            resource: request.resource.as_deref(),
        };
        let response = self
            .client
            .post(self.obo_verification_endpoint.clone())
            .basic_auth(app_id, Some(app_secret.expose_secret()))
            .header("X-Org-ID", request.org_id.as_str())
            .header(
                "Idempotency-Key",
                obo_verification_idempotency_key(proof, presented_app_id, request),
            )
            .json(&body)
            .send()
            .await
            .map_err(IamError::Transport)?;
        ensure_authentication_status(response.status())?;
        bounded_json(response, self.max_response_bytes).await
    }

    fn online_credentials(&self) -> Result<(&str, &SecretString), IamError> {
        self.app_id
            .as_deref()
            .zip(self.app_secret.as_ref())
            .ok_or(IamError::OnlineVerificationNotConfigured)
    }
}

fn obo_verification_idempotency_key(
    proof: &SecretString,
    presented_app_id: &ApplicationId,
    request: &AuthorizationRequest,
) -> String {
    let mut digest = Sha256::new();
    digest.update(OBO_IDEMPOTENCY_DOMAIN);
    update_length_prefixed(&mut digest, proof.expose_secret().as_bytes());
    update_length_prefixed(&mut digest, presented_app_id.as_str().as_bytes());
    update_length_prefixed(&mut digest, request.org_id.as_str().as_bytes());
    update_length_prefixed(&mut digest, request.action.as_bytes());
    match request.resource.as_deref() {
        Some(resource) => {
            digest.update([1]);
            update_length_prefixed(&mut digest, resource.as_bytes());
        }
        None => digest.update([0]),
    }
    format!("obo_verify_{}", hex::encode(digest.finalize()))
}

fn update_length_prefixed(digest: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    digest.update(length.to_be_bytes());
    digest.update(value);
}

fn endpoint(base_url: &Url, path: &str) -> Url {
    let mut endpoint = base_url.clone();
    endpoint.set_path(path);
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    endpoint
}

fn ensure_authentication_status(status: StatusCode) -> Result<(), IamError> {
    if status == StatusCode::OK {
        return Ok(());
    }
    if matches!(
        status,
        StatusCode::BAD_REQUEST
            | StatusCode::UNAUTHORIZED
            | StatusCode::FORBIDDEN
            | StatusCode::CONFLICT
            | StatusCode::GONE
            | StatusCode::UNPROCESSABLE_ENTITY
    ) {
        return Err(IamError::InvalidCredential);
    }
    Err(IamError::UnexpectedStatus(status.as_u16()))
}

async fn bounded_json<T>(mut response: Response, maximum: usize) -> Result<T, IamError>
where
    T: serde::de::DeserializeOwned,
{
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !content_type.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
        return Err(IamError::InvalidResponse);
    }
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(IamError::ResponseTooLarge);
    }
    let mut body = BytesMut::new();
    while let Some(chunk) = response.chunk().await.map_err(IamError::Transport)? {
        let remaining = maximum.saturating_sub(body.len());
        if chunk.len() > remaining {
            return Err(IamError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| IamError::InvalidResponse)
}

fn context_from_introspection(
    response: &wire::Introspection,
    request: &AuthorizationRequest,
    expected_audience: &str,
) -> Result<AuthorizationContext, IamError> {
    if !response.active {
        return Err(IamError::InvalidCredential);
    }
    let audiences = response.audiences().ok_or(IamError::InvalidResponse)?;
    if !audiences.contains(&expected_audience) {
        return Err(IamError::InvalidCredential);
    }
    build_context(response.facts(), request, None)
}

fn context_from_obo(
    response: &wire::OboResult,
    request: &AuthorizationRequest,
    presented_app_id: &ApplicationId,
    expected_audience: &str,
) -> Result<AuthorizationContext, IamError> {
    if !response.valid {
        return Err(IamError::InvalidCredential);
    }
    let expires_at = response
        .expires_at
        .as_ref()
        .and_then(wire::WireTimestamp::as_datetime)
        .ok_or(IamError::InvalidResponse)?;
    let now = OffsetDateTime::now_utc();
    let audiences = response.audiences().ok_or(IamError::InvalidResponse)?;
    let application_id = response
        .application_id
        .as_deref()
        .ok_or(IamError::InvalidResponse)?;
    if response.resource.as_deref() != request.resource.as_deref()
        || response.bound_action() != Some(request.action.as_str())
    {
        return Err(IamError::InvalidResponse);
    }
    if expires_at <= now
        || expires_at > now + time::Duration::minutes(5)
        || !audiences.contains(&expected_audience)
        || application_id != presented_app_id.as_str()
    {
        return Err(IamError::InvalidCredential);
    }
    build_context(response.facts(), request, Some(presented_app_id.clone()))
}

fn build_context(
    facts: wire::AuthorizationFacts<'_>,
    request: &AuthorizationRequest,
    acting_application: Option<ApplicationId>,
) -> Result<AuthorizationContext, IamError> {
    let actor = facts
        .actor
        .ok_or(IamError::InvalidResponse)?
        .try_into_domain()?;
    if !matches!(actor.kind(), ActorKind::Carbon | ActorKind::Silicon) {
        return Err(IamError::InvalidCredential);
    }
    let org_id = facts.org_id.ok_or(IamError::InvalidResponse)?;
    if org_id != request.org_id.as_str() {
        return Err(IamError::InvalidCredential);
    }
    let organization_id = OrganizationId::new(org_id).map_err(|_| IamError::InvalidResponse)?;
    let role = facts.role.ok_or(IamError::InvalidResponse)?.into_domain();
    let capabilities = facts
        .capabilities
        .iter()
        .filter_map(|capability| capability_from_wire(capability));
    let visible_silicons = facts
        .visible_silicons
        .iter()
        .map(|id| SiliconId::new(id.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| IamError::InvalidResponse)?;

    Ok(AuthorizationContext::new(
        organization_id,
        actor,
        role,
        capabilities,
        visible_silicons,
        acting_application,
    ))
}

fn capability_from_wire(value: &str) -> Option<Capability> {
    match value {
        "list_hooks" | "hook.hooks.list" => Some(Capability::ListHooks),
        "read_hook" | "hook.hooks.read" => Some(Capability::ReadHook),
        "create_hook" | "hook.hooks.create" => Some(Capability::CreateHook),
        "delete_hook" | "hook.hooks.delete" => Some(Capability::DeleteHook),
        "restore_hook" | "hook.hooks.restore" => Some(Capability::RestoreHook),
        "rotate_secret" | "hook.hooks.secret.rotate" => Some(Capability::RotateSecret),
        "read_events" | "hook.events.read" => Some(Capability::ReadEvents),
        "administrative_override" | "hook.administrative_override" => {
            Some(Capability::AdministrativeOverride)
        }
        _ => None,
    }
}

fn local_authorize(
    token: &SecretString,
    request: &AuthorizationRequest,
    acting_application: Option<ApplicationId>,
) -> Result<AuthorizationContext, IamError> {
    let mut parts = token.expose_secret().splitn(4, ':');
    if parts.next() != Some("local") {
        return Err(IamError::InvalidCredential);
    }
    let kind = match parts.next() {
        Some("carbon") => ActorKind::Carbon,
        Some("silicon") => ActorKind::Silicon,
        _ => return Err(IamError::InvalidCredential),
    };
    let role = match parts.next() {
        Some("member") => OrganizationRole::Member,
        Some("admin") => OrganizationRole::Admin,
        Some("owner") => OrganizationRole::Owner,
        _ => return Err(IamError::InvalidCredential),
    };
    let actor_id = parts.next().ok_or(IamError::InvalidCredential)?;
    let actor = ActorRef::try_new(kind, actor_id).map_err(|_| IamError::InvalidCredential)?;
    let visible_silicons = if kind == ActorKind::Silicon {
        vec![SiliconId::new(actor_id).map_err(|_| IamError::InvalidCredential)?]
    } else {
        Vec::new()
    };
    let capabilities = if role == OrganizationRole::Admin {
        vec![
            Capability::ListHooks,
            Capability::ReadHook,
            Capability::CreateHook,
            Capability::DeleteHook,
            Capability::RestoreHook,
            Capability::RotateSecret,
            Capability::ReadEvents,
            Capability::AdministrativeOverride,
        ]
    } else {
        Vec::new()
    };
    Ok(AuthorizationContext::new(
        request.org_id.clone(),
        actor,
        role,
        capabilities,
        visible_silicons,
        acting_application,
    ))
}

fn secrets_equal(left: &SecretString, right: &SecretString) -> bool {
    let left = left.expose_secret().as_bytes();
    let right = right.expose_secret().as_bytes();
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

mod wire {
    use serde::{Deserialize, Serialize};
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
    use uuid::Uuid;

    use super::{ActorKind, ActorRef, IamError, OrganizationRole};

    #[derive(Debug, Deserialize)]
    pub(super) struct Introspection {
        pub(super) active: bool,
        #[serde(default, alias = "principal", alias = "subject")]
        actor: Option<Actor>,
        #[serde(default)]
        principal_id: Option<Uuid>,
        #[serde(default)]
        public_id: Option<String>,
        #[serde(default, alias = "subject_type")]
        actor_type: Option<ActorKindWire>,
        #[serde(default)]
        client_id: Option<String>,
        #[serde(default, alias = "organization_id")]
        org_id: Option<String>,
        #[serde(default, alias = "org_role", alias = "role")]
        organization_role: Option<OrganizationRoleWire>,
        #[serde(default)]
        capabilities: Vec<String>,
        #[serde(default, alias = "visible_silicons")]
        visible_silicon_ids: Vec<String>,
        #[serde(default, alias = "aud")]
        audience: Option<OneOrMany>,
        #[serde(default)]
        actions: Vec<String>,
        #[serde(default)]
        action: Option<String>,
        #[serde(default)]
        scope: Option<String>,
    }

    impl Introspection {
        pub(super) fn actor(&self) -> Option<Actor> {
            resolved_actor(
                self.actor.as_ref(),
                self.actor_type,
                self.public_id.as_deref(),
                self.principal_id,
            )
        }

        pub(super) fn service_actor(&self) -> Option<Actor> {
            if let Some(actor) = self.actor() {
                if actor.kind != ActorKindWire::Service
                    || self
                        .client_id
                        .as_deref()
                        .is_some_and(|client_id| client_id != actor.id)
                {
                    return None;
                }
                return Some(actor);
            }
            // An explicit but internally contradictory actor must not fall
            // through to the top-level compatibility shape.
            if self.actor.is_some() {
                return None;
            }
            if self.actor_type != Some(ActorKindWire::Service) {
                return None;
            }
            let public_id = match (self.public_id.as_deref(), self.client_id.as_deref()) {
                (Some(public_id), Some(client_id)) if public_id != client_id => return None,
                (Some(public_id), _) | (None, Some(public_id)) => public_id,
                (None, None) => return None,
            };
            resolved_actor(None, self.actor_type, Some(public_id), self.principal_id)
        }

        pub(super) fn audiences(&self) -> Option<Vec<&str>> {
            self.audience
                .as_ref()
                .map(OneOrMany::values)
                .filter(|values| !values.is_empty())
        }

        pub(super) fn authorities(&self) -> Option<Vec<&str>> {
            let values = self
                .actions
                .iter()
                .map(String::as_str)
                .chain(self.action.as_deref())
                .chain(
                    self.scope
                        .as_deref()
                        .into_iter()
                        .flat_map(str::split_ascii_whitespace),
                )
                .collect::<Vec<_>>();
            (!values.is_empty()).then_some(values)
        }

        pub(super) fn bound_action(&self) -> Option<&str> {
            self.action.as_deref()
        }

        pub(super) fn facts(&self) -> AuthorizationFacts<'_> {
            AuthorizationFacts {
                actor: self.actor(),
                org_id: self.org_id.as_deref(),
                role: self.organization_role,
                capabilities: &self.capabilities,
                visible_silicons: &self.visible_silicon_ids,
            }
        }
    }

    #[derive(Debug, Serialize)]
    pub(super) struct OboVerificationRequest<'a> {
        pub(super) access_proof: &'a str,
        pub(super) audience: &'a str,
        pub(super) action: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(super) resource: Option<&'a str>,
    }

    #[derive(Debug, Deserialize)]
    pub(super) struct OboResult {
        pub(super) valid: bool,
        #[serde(default, alias = "principal", alias = "subject")]
        actor: Option<Actor>,
        #[serde(default, alias = "subject_principal_id")]
        principal_id: Option<Uuid>,
        #[serde(default, alias = "subject_kind")]
        actor_type: Option<ActorKindWire>,
        #[serde(default)]
        public_id: Option<String>,
        #[serde(default, alias = "organization_id")]
        org_id: Option<String>,
        #[serde(default, alias = "org_role", alias = "role")]
        organization_role: Option<OrganizationRoleWire>,
        #[serde(default)]
        capabilities: Vec<String>,
        #[serde(default, alias = "visible_silicons")]
        visible_silicon_ids: Vec<String>,
        #[serde(default, alias = "aud")]
        audience: Option<OneOrMany>,
        #[serde(default)]
        action: Option<String>,
        #[serde(
            default,
            alias = "app_id",
            alias = "client_id",
            alias = "issuer_app_id",
            alias = "issuer_application_id"
        )]
        pub(super) application_id: Option<String>,
        #[serde(default)]
        pub(super) resource: Option<String>,
        #[serde(default, alias = "exp")]
        pub(super) expires_at: Option<WireTimestamp>,
    }

    impl OboResult {
        pub(super) fn audiences(&self) -> Option<Vec<&str>> {
            self.audience
                .as_ref()
                .map(OneOrMany::values)
                .filter(|values| !values.is_empty())
        }

        pub(super) fn bound_action(&self) -> Option<&str> {
            self.action.as_deref()
        }

        pub(super) fn facts(&self) -> AuthorizationFacts<'_> {
            AuthorizationFacts {
                actor: self.actor(),
                org_id: self.org_id.as_deref(),
                role: self.organization_role,
                capabilities: &self.capabilities,
                visible_silicons: &self.visible_silicon_ids,
            }
        }

        fn actor(&self) -> Option<Actor> {
            resolved_actor(
                self.actor.as_ref(),
                self.actor_type,
                self.public_id.as_deref(),
                self.principal_id,
            )
        }
    }

    fn resolved_actor(
        explicit: Option<&Actor>,
        kind: Option<ActorKindWire>,
        public_id: Option<&str>,
        principal_id: Option<Uuid>,
    ) -> Option<Actor> {
        if let Some(explicit) = explicit {
            let kind_matches = kind.is_none_or(|kind| kind == explicit.kind);
            let public_id_matches = public_id.is_none_or(|id| id == explicit.id);
            let principal_id_matches = principal_id
                .zip(explicit.principal_id)
                .is_none_or(|(left, right)| left == right);
            return (kind_matches && public_id_matches && principal_id_matches)
                .then(|| explicit.clone());
        }

        Some(Actor {
            kind: kind?,
            id: public_id?.to_owned(),
            principal_id,
        })
    }

    pub(super) struct AuthorizationFacts<'a> {
        pub(super) actor: Option<Actor>,
        pub(super) org_id: Option<&'a str>,
        pub(super) role: Option<OrganizationRoleWire>,
        pub(super) capabilities: &'a [String],
        pub(super) visible_silicons: &'a [String],
    }

    #[derive(Clone, Debug, Deserialize)]
    pub(super) struct Actor {
        #[serde(default, rename = "principal_id")]
        principal_id: Option<Uuid>,
        #[serde(rename = "type", alias = "kind", alias = "actor_type")]
        kind: ActorKindWire,
        #[serde(rename = "public_id")]
        id: String,
    }

    impl Actor {
        pub(super) fn try_into_domain(self) -> Result<ActorRef, IamError> {
            ActorRef::try_new(self.kind.into_domain(), self.id)
                .map_err(|_| IamError::InvalidResponse)
        }
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "snake_case")]
    enum ActorKindWire {
        Carbon,
        Silicon,
        Application,
        Service,
    }

    impl ActorKindWire {
        const fn into_domain(self) -> ActorKind {
            match self {
                Self::Carbon => ActorKind::Carbon,
                Self::Silicon => ActorKind::Silicon,
                Self::Application => ActorKind::Application,
                Self::Service => ActorKind::Service,
            }
        }
    }

    #[derive(Clone, Copy, Debug, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub(super) enum OrganizationRoleWire {
        Member,
        Admin,
        Owner,
    }

    impl OrganizationRoleWire {
        pub(super) const fn into_domain(self) -> OrganizationRole {
            match self {
                Self::Member => OrganizationRole::Member,
                Self::Admin => OrganizationRole::Admin,
                Self::Owner => OrganizationRole::Owner,
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    impl OneOrMany {
        fn values(&self) -> Vec<&str> {
            match self {
                Self::One(value) => vec![value.as_str()],
                Self::Many(values) => values.iter().map(String::as_str).collect(),
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    pub(super) enum WireTimestamp {
        Rfc3339(String),
        Unix(i64),
    }

    impl WireTimestamp {
        pub(super) fn as_datetime(&self) -> Option<OffsetDateTime> {
            match self {
                Self::Rfc3339(value) => OffsetDateTime::parse(value, &Rfc3339).ok(),
                Self::Unix(value) => OffsetDateTime::from_unix_timestamp(*value).ok(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use secrecy::{ExposeSecret as _, SecretString};
    use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, body_string_contains, header, method, path},
    };

    use crate::{
        config::{IamSettings, LocalAuthSettings},
        domain::{
            ActorKind, ApplicationId, Capability, OrganizationId, OrganizationRole, SiliconId,
        },
    };

    use super::{
        AuthorizationRequest, IamClient, IamError, PresentedCredential, context_from_introspection,
        context_from_obo, obo_verification_idempotency_key, wire,
    };

    fn settings(server: &MockServer) -> Result<IamSettings, Box<dyn std::error::Error>> {
        Ok(IamSettings {
            base_url: server.uri().parse()?,
            app_id: Some("silicon-hook".to_owned()),
            app_secret: Some(SecretString::from("iam-secret")),
            audience: "silicon-hook".to_owned(),
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(2),
            max_response_bytes: 4096,
            local_auth: None,
        })
    }

    fn bearer_request() -> Result<AuthorizationRequest, Box<dyn std::error::Error>> {
        Ok(AuthorizationRequest {
            credential: PresentedCredential::Bearer(SecretString::from("cat_access-token")),
            org_id: OrganizationId::new("tos")?,
            action: "hook.hooks.list".to_owned(),
            resource: Some("cos:tos".to_owned()),
        })
    }

    #[test]
    fn versioned_management_fixture_contains_every_authorization_fact()
    -> Result<(), Box<dyn std::error::Error>> {
        let response: wire::Introspection = serde_json::from_str(include_str!(
            "../../contracts/iam/v1/management-introspection.json"
        ))?;
        let request = AuthorizationRequest {
            credential: PresentedCredential::Bearer(SecretString::from("cat_access-token")),
            org_id: OrganizationId::new("acme")?,
            action: "hook.hooks.delete".to_owned(),
            resource: Some("018eb4ce-e57a-7d2c-8f9f-a35928ef91e1".to_owned()),
        };

        let context = context_from_introspection(&response, &request, "silicon-hook")?;

        assert_eq!(context.actor().kind(), ActorKind::Carbon);
        assert_eq!(context.actor().id().as_str(), "alice");
        assert_eq!(context.organization_id().as_str(), "acme");
        assert_eq!(context.organization_role(), OrganizationRole::Admin);
        assert!(context.has_capability(Capability::DeleteHook));
        assert!(context.has_silicon_visibility(&SiliconId::new("support:acme")?));
        Ok(())
    }

    #[test]
    fn versioned_obo_fixture_contains_constraints_and_authorization_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../contracts/iam/v1/obo-verification.json"))?;
        fixture["expires_at"] = serde_json::Value::String(
            (OffsetDateTime::now_utc() + TimeDuration::minutes(1)).format(&Rfc3339)?,
        );
        let response: wire::OboResult = serde_json::from_value(fixture)?;
        let application_id = ApplicationId::new("silicon-console")?;
        let request = AuthorizationRequest {
            credential: PresentedCredential::Obo {
                app_id: application_id.clone(),
                proof: SecretString::from("obo-proof"),
            },
            org_id: OrganizationId::new("acme")?,
            action: "hook.hooks.delete".to_owned(),
            resource: Some("018eb4ce-e57a-7d2c-8f9f-a35928ef91e1".to_owned()),
        };

        let context = context_from_obo(&response, &request, &application_id, "silicon-hook")?;

        assert_eq!(context.actor().id().as_str(), "alice");
        assert_eq!(context.organization_role(), OrganizationRole::Admin);
        assert!(context.has_capability(Capability::DeleteHook));
        assert!(context.has_silicon_visibility(&SiliconId::new("support:acme")?));
        assert_eq!(
            context.acting_application().map(ApplicationId::as_str),
            Some("silicon-console")
        );
        Ok(())
    }

    #[tokio::test]
    async fn bearer_introspection_returns_validated_domain_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/tokens/introspect"))
            .and(header(
                "authorization",
                "Basic c2lsaWNvbi1ob29rOmlhbS1zZWNyZXQ=",
            ))
            .and(header("x-org-id", "tos"))
            .and(body_string_contains("token=cat_access-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "active": true,
                "principal_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91c2",
                "client_id": "silicon-console",
                "actor_type": "carbon",
                "actor": {
                    "principal_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91c2",
                    "actor_type": "carbon",
                    "public_id": "carbon:owner"
                },
                "org_id": "tos",
                "organization_role": "owner",
                "capabilities": [],
                "visible_silicon_ids": [],
                "audience": "silicon-hook"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let context = IamClient::new(&settings(&server)?)?
            .authorize(&bearer_request()?)
            .await?;
        assert_eq!(context.actor().kind(), ActorKind::Carbon);
        assert_eq!(context.organization_role(), OrganizationRole::Owner);
        assert_eq!(context.organization_id().as_str(), "tos");
        Ok(())
    }

    #[tokio::test]
    async fn inactive_and_malformed_responses_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let inactive_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "active": false
            })))
            .mount(&inactive_server)
            .await;
        assert!(matches!(
            IamClient::new(&settings(&inactive_server)?)?
                .authorize(&bearer_request()?)
                .await,
            Err(IamError::InvalidCredential)
        ));

        let malformed_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "active": true,
                "org_id": "tos",
                "organization_role": "owner",
                "audience": "silicon-hook"
            })))
            .mount(&malformed_server)
            .await;
        assert!(matches!(
            IamClient::new(&settings(&malformed_server)?)?
                .authorize(&bearer_request()?)
                .await,
            Err(IamError::InvalidResponse)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn oversized_iam_response_is_rejected_before_deserialization()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "active": true,
                "padding": "x".repeat(256)
            })))
            .mount(&server)
            .await;
        let mut bounded_settings = settings(&server)?;
        bounded_settings.max_response_bytes = 64;

        assert!(matches!(
            IamClient::new(&bounded_settings)?
                .authorize(&bearer_request()?)
                .await,
            Err(IamError::ResponseTooLarge)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn obo_verification_binds_app_audience_action_resource_and_expiry()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        let expires_at = (OffsetDateTime::now_utc() + TimeDuration::minutes(1)).format(&Rfc3339)?;
        let app_id = ApplicationId::new("github")?;
        let proof = SecretString::from("obo-proof");
        let request = AuthorizationRequest {
            credential: PresentedCredential::Obo {
                app_id: app_id.clone(),
                proof: proof.clone(),
            },
            org_id: OrganizationId::new("tos")?,
            action: "hook.hooks.delete".to_owned(),
            resource: Some("hook-id".to_owned()),
        };
        let expected_idempotency_key = obo_verification_idempotency_key(&proof, &app_id, &request);
        Mock::given(method("POST"))
            .and(path("/api/v1/obo-access/verify"))
            .and(header("x-org-id", "tos"))
            .and(header("idempotency-key", expected_idempotency_key.as_str()))
            .and(body_json(serde_json::json!({
                "access_proof": "obo-proof",
                "audience": "silicon-hook",
                "action": "hook.hooks.delete",
                "resource": "hook-id"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "valid": true,
                "actor": {
                    "principal_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91c3",
                    "actor_type": "silicon",
                    "public_id": "cos:tos"
                },
                "org_id": "tos",
                "organization_role": "member",
                "capabilities": [],
                "visible_silicon_ids": [],
                "audience": "silicon-hook",
                "action": "hook.hooks.delete",
                "issuer_app_id": "github",
                "resource": "hook-id",
                "expires_at": expires_at
            })))
            .expect(1)
            .mount(&server)
            .await;

        let context = IamClient::new(&settings(&server)?)?
            .authorize(&request)
            .await?;
        assert_eq!(
            context.acting_application().map(ApplicationId::as_str),
            Some("github")
        );
        Ok(())
    }

    #[test]
    fn obo_success_rejects_a_contradictory_singular_action_echo()
    -> Result<(), Box<dyn std::error::Error>> {
        let response: wire::OboResult = serde_json::from_value(serde_json::json!({
            "valid": true,
            "actor": {
                "actor_type": "carbon",
                "public_id": "alice"
            },
            "org_id": "acme",
            "organization_role": "admin",
            "capabilities": ["hook.hooks.delete"],
            "visible_silicon_ids": ["support:acme"],
            "audience": "silicon-hook",
            "action": "hook.hooks.list",
            "actions": ["hook.hooks.delete"],
            "scope": "hook.hooks.delete",
            "issuer_app_id": "silicon-console",
            "resource": "hook-id",
            "expires_at": (OffsetDateTime::now_utc() + TimeDuration::minutes(1))
                .format(&Rfc3339)?
        }))?;
        let application_id = ApplicationId::new("silicon-console")?;
        let request = AuthorizationRequest {
            credential: PresentedCredential::Obo {
                app_id: application_id.clone(),
                proof: SecretString::from("obo-proof"),
            },
            org_id: OrganizationId::new("acme")?,
            action: "hook.hooks.delete".to_owned(),
            resource: Some("hook-id".to_owned()),
        };

        assert!(matches!(
            context_from_obo(&response, &request, &application_id, "silicon-hook"),
            Err(IamError::InvalidResponse)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn service_authentication_accepts_explicit_service_introspection_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "active": true,
                "principal_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91c4",
                "actor_type": "service",
                "client_id": "silicon-iam",
                "audience": "silicon-hook",
                "scope": "hook.iam.provision"
            })))
            .mount(&server)
            .await;

        let actor = IamClient::new(&settings(&server)?)?
            .authenticate_iam_service(&SecretString::from("svt_token"))
            .await?;
        assert!(actor.is_service_named("silicon-iam"));
        Ok(())
    }

    #[tokio::test]
    async fn service_authentication_never_infers_service_kind_from_client_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "active": true,
                "principal_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91c4",
                "client_id": "silicon-iam",
                "audience": "silicon-hook",
                "scope": "hook.iam.provision"
            })))
            .mount(&server)
            .await;

        let result = IamClient::new(&settings(&server)?)?
            .authenticate_iam_service(&SecretString::from("svt_token"))
            .await;
        assert!(matches!(result, Err(IamError::InvalidResponse)));
        Ok(())
    }

    #[tokio::test]
    async fn service_authentication_rejects_contradictory_actor_kind_as_invalid_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "active": true,
                "actor_type": "application",
                "public_id": "silicon-iam",
                "client_id": "silicon-iam",
                "audience": "silicon-hook",
                "scope": "hook.iam.provision"
            })))
            .mount(&server)
            .await;

        let result = IamClient::new(&settings(&server)?)?
            .authenticate_iam_service(&SecretString::from("svt_token"))
            .await;
        assert!(matches!(result, Err(IamError::InvalidResponse)));
        Ok(())
    }

    #[tokio::test]
    async fn service_authentication_rejects_actor_and_client_id_disagreement()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "active": true,
                "actor": {
                    "principal_id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91c4",
                    "actor_type": "service",
                    "public_id": "silicon-iam"
                },
                "client_id": "different-service",
                "audience": "silicon-hook",
                "scope": "hook.iam.provision"
            })))
            .mount(&server)
            .await;

        let result = IamClient::new(&settings(&server)?)?
            .authenticate_iam_service(&SecretString::from("svt_token"))
            .await;
        assert!(matches!(result, Err(IamError::InvalidResponse)));
        Ok(())
    }

    #[tokio::test]
    async fn service_authentication_rejects_a_contradictory_singular_action()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "active": true,
                "actor_type": "service",
                "client_id": "silicon-iam",
                "audience": "silicon-hook",
                "action": "hook.hooks.list",
                "scope": "hook.iam.provision"
            })))
            .mount(&server)
            .await;

        let result = IamClient::new(&settings(&server)?)?
            .authenticate_iam_service(&SecretString::from("svt_token"))
            .await;
        assert!(matches!(result, Err(IamError::InvalidResponse)));
        Ok(())
    }

    #[test]
    fn obo_verification_idempotency_is_stable_scoped_and_non_secret()
    -> Result<(), Box<dyn std::error::Error>> {
        let proof = SecretString::from("obo_high_entropy_secret_value");
        let app_id = ApplicationId::new("github")?;
        let mut request = AuthorizationRequest {
            credential: PresentedCredential::Obo {
                app_id: app_id.clone(),
                proof: proof.clone(),
            },
            org_id: OrganizationId::new("tos")?,
            action: "hook.hooks.delete".to_owned(),
            resource: Some("hook-id".to_owned()),
        };

        let first = obo_verification_idempotency_key(&proof, &app_id, &request);
        let retry = obo_verification_idempotency_key(&proof, &app_id, &request);
        assert_eq!(first, retry);
        assert!(first.starts_with("obo_verify_"));
        assert!(!first.contains(proof.expose_secret()));

        let other_proof = obo_verification_idempotency_key(
            &SecretString::from("different_obo_high_entropy_secret"),
            &app_id,
            &request,
        );
        assert_ne!(first, other_proof);

        let other_app =
            obo_verification_idempotency_key(&proof, &ApplicationId::new("slack")?, &request);
        assert_ne!(first, other_app);

        request.org_id = OrganizationId::new("acme")?;
        let other_organization = obo_verification_idempotency_key(&proof, &app_id, &request);
        assert_ne!(first, other_organization);

        request.org_id = OrganizationId::new("tos")?;
        request.action = "hook.hooks.restore".to_owned();
        let other_action = obo_verification_idempotency_key(&proof, &app_id, &request);
        assert_ne!(first, other_action);

        request.action = "hook.hooks.delete".to_owned();
        request.resource = Some("other-hook".to_owned());
        let other_resource = obo_verification_idempotency_key(&proof, &app_id, &request);
        assert_ne!(first, other_resource);

        request.resource = None;
        let unbound_resource = obo_verification_idempotency_key(&proof, &app_id, &request);
        assert_ne!(first, unbound_resource);
        Ok(())
    }

    #[tokio::test]
    async fn current_obo_shape_without_authorization_facts_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        let expires_at = (OffsetDateTime::now_utc() + TimeDuration::minutes(1)).format(&Rfc3339)?;
        Mock::given(method("POST"))
            .and(path("/api/v1/obo-access/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "valid": true,
                "actor": {
                    "type": "silicon",
                    "id": "018eb4ce-e57a-7d2c-8f9f-a35928ef91c3"
                },
                "org_id": "tos",
                "audience": "silicon-hook",
                "action": "hook.hooks.delete",
                "issuer_app_id": "github",
                "resource": "hook-id",
                "expires_at": expires_at
            })))
            .mount(&server)
            .await;

        let result = IamClient::new(&settings(&server)?)?
            .authorize(&AuthorizationRequest {
                credential: PresentedCredential::Obo {
                    app_id: ApplicationId::new("github")?,
                    proof: SecretString::from("obo-proof"),
                },
                org_id: OrganizationId::new("tos")?,
                action: "hook.hooks.delete".to_owned(),
                resource: Some("hook-id".to_owned()),
            })
            .await;
        assert!(matches!(result, Err(IamError::InvalidResponse)));
        Ok(())
    }

    #[tokio::test]
    async fn local_auth_requires_explicit_adapter_configuration()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        let mut settings = settings(&server)?;
        settings.local_auth = Some(LocalAuthSettings {
            iam_service_token: SecretString::from("local-iam-service-token"),
        });
        let client = IamClient::new(&settings)?;
        let context = client
            .authorize(&AuthorizationRequest {
                credential: PresentedCredential::Bearer(SecretString::from(
                    "local:silicon:member:cos:tos",
                )),
                org_id: OrganizationId::new("tos")?,
                action: "hook.hooks.list".to_owned(),
                resource: None,
            })
            .await?;
        assert_eq!(context.actor().kind(), ActorKind::Silicon);
        assert!(
            client
                .authenticate_iam_service(&SecretString::from("local-iam-service-token"))
                .await?
                .is_service_named("silicon-iam")
        );
        Ok(())
    }
}
