//! Silicon IAM integration through the official published Rust client.
//!
//! Every decision is resolved online. Application sessions use IAM's live
//! authorization snapshot; native actors use the directory with their own
//! credential. Environment-bound clients carry the IAM test key and test
//! application credential on every call and cannot fall back to production.

use std::{fmt, sync::Arc, time::Duration};

use http::HeaderMap;
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use silicon_iam_client::{
    Client as SdkClient, Credential, EnvironmentKey, IdempotencyKey, Mutation, VerifiedWebhook,
    WebhookError, WebhookSecret, WebhookSecretKeyring, WebhookVerifier, models,
};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    config::{IamSettings, IamWebhookSettings},
    domain::{
        ActorKind, ActorRef, AuthorizationContext, OrganizationId, OrganizationRole, SigningSecret,
        SiliconId,
    },
    error::AppError,
};

const USER_AGENT: &str = concat!("silicon-hook/", env!("CARGO_PKG_VERSION"));
const LOCAL_TOKEN_PREFIX: &str = "local:";
const SILICON_WEBHOOK_SECRET_PREFIX: &str = "swhs_";
const IAM_IDEMPOTENCY_DOMAIN: &[u8] = b"silicon-hook/iam-silicon-webhook/v1\0";
const LOCAL_SECRET_DOMAIN: &[u8] = b"silicon-hook/local-iam-silicon-webhook/v1\0";

/// Credential and organization to resolve, with the Silicons this call targets.
#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    /// Opaque actor credential.
    pub token: SecretString,
    /// Selected organization.
    pub org_id: OrganizationId,
    /// Requested Silicon visibility.
    pub targets: Vec<SiliconId>,
}

/// Application tokens returned by IAM. Debug never exposes either token.
pub struct IssuedTokens {
    /// Access token.
    pub access_token: Zeroizing<String>,
    /// Rotating refresh token.
    pub refresh_token: Zeroizing<String>,
    /// Access token lifetime.
    pub expires_in: Duration,
    /// Effective scopes.
    pub scopes: Vec<String>,
    /// Authenticated actor.
    pub actor: ActorRef,
    /// Bound organization, if any.
    pub organization_id: Option<OrganizationId>,
}

impl fmt::Debug for IssuedTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedTokens")
            .field("actor", &self.actor)
            .field("organization_id", &self.organization_id)
            .finish_non_exhaustive()
    }
}

/// Result of configuring a Silicon's IAM webhook.
pub struct RegisteredSiliconWebhook {
    /// Newly issued signing secret.
    pub signing_secret: SigningSecret,
    /// IAM signing key version.
    pub secret_version: u64,
}

impl fmt::Debug for RegisteredSiliconWebhook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisteredSiliconWebhook")
            .field("secret_version", &self.secret_version)
            .finish_non_exhaustive()
    }
}

/// IAM adapter failure with explicit caller-versus-provider semantics.
#[derive(Debug, Error)]
pub enum IamError {
    /// The presented credential is absent from, inactive in, or rejected by IAM.
    #[error("IAM rejected the presented credential")]
    InvalidCredential,
    /// IAM refused the action for this actor.
    #[error("IAM refused the action for this actor")]
    Forbidden,
    /// IAM does not know the target resource, or hides it from this actor.
    #[error("IAM does not know the target resource")]
    NotFound,
    /// IAM rejected the request with a documented client error.
    #[error("IAM rejected the request with HTTP {status}")]
    Rejected {
        /// HTTP status IAM returned.
        status: u16,
    },
    /// IAM asked the caller to slow down.
    #[error("IAM rate limit reached")]
    RateLimited {
        /// Delay IAM asked for.
        retry_after: Duration,
    },
    /// A caller-supplied value cannot be sent to IAM.
    #[error("invalid {0}")]
    InvalidInput(&'static str),
    /// IAM could not be reached before the configured deadline.
    #[error("IAM transport is unavailable")]
    Transport(#[source] anyhow::Error),
    /// IAM returned more data than Hook is configured to accept.
    #[error("IAM response exceeds the configured bound")]
    ResponseTooLarge,
    /// IAM returned a success body that did not satisfy the contract.
    #[error("IAM returned an invalid response")]
    InvalidResponse,
    /// IAM returned a status the contract does not describe.
    #[error("IAM returned an unexpected HTTP status {0}")]
    UnexpectedStatus(u16),
    /// The compatibility handshake failed closed.
    #[error("IAM handshake failed")]
    Handshake(#[source] anyhow::Error),
    /// The requested IAM feature is not configured for this process.
    #[error("the requested IAM feature is not configured")]
    NotConfigured,
    /// An IAM webhook delivery did not authenticate.
    #[error("the IAM webhook delivery could not be verified")]
    WebhookRejected(#[source] WebhookError),
}

impl IamError {
    const fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::InvalidCredential => "invalid_credential",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Rejected { .. } => "rejected",
            Self::RateLimited { .. } => "rate_limited",
            Self::InvalidInput(_) => "invalid_input",
            Self::Transport(_) => "transport",
            Self::ResponseTooLarge => "response_too_large",
            Self::InvalidResponse => "invalid_response",
            Self::UnexpectedStatus(_) => "unexpected_status",
            Self::Handshake(_) => "handshake",
            Self::NotConfigured => "not_configured",
            Self::WebhookRejected(_) => "webhook_rejected",
        }
    }
}

impl From<IamError> for AppError {
    fn from(error: IamError) -> Self {
        match error {
            IamError::InvalidCredential => Self::Unauthenticated,
            IamError::Forbidden => Self::Forbidden,
            IamError::NotFound => Self::NotFound,
            IamError::InvalidInput(field) => Self::validation(format!("invalid_{field}")),
            IamError::RateLimited { retry_after } => Self::RateLimited { retry_after },
            IamError::Rejected { status } => {
                tracing::info!(status, "IAM rejected a forwarded request");
                Self::conflict("iam_rejected")
            }
            IamError::WebhookRejected(reason) => {
                tracing::info!(%reason, "IAM webhook delivery rejected");
                Self::Forbidden
            }
            other => {
                tracing::warn!(
                    error_code = other.diagnostic_code(),
                    "IAM integration failed closed"
                );
                Self::ProviderUnavailable
            }
        }
    }
}

/// Shared IAM boundary. Clones preserve their environment and credentials.
#[derive(Clone)]
pub struct IamClient {
    inner: Arc<Inner>,
}

struct Inner {
    sdk: Option<SdkClient>,
    base_url: Url,
    app_id: Option<String>,
    accept_local_tokens: bool,
    webhook_verifier: Option<WebhookVerifier>,
}

impl fmt::Debug for IamClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IamClient")
            .field("app_id", &self.inner.app_id)
            .field("local_auth", &self.inner.accept_local_tokens)
            .field(
                "testing",
                &self
                    .inner
                    .sdk
                    .as_ref()
                    .is_some_and(|sdk| sdk.environment().is_some()),
            )
            .finish_non_exhaustive()
    }
}

impl IamClient {
    /// Public application identifier used when requesting an IAM SLT.
    #[must_use]
    pub fn application_id(&self) -> Option<&str> {
        self.inner.app_id.as_deref()
    }

    /// IAM service origin, without application credentials or environment keys.
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.inner.base_url
    }

    /// Whether this adapter is strictly bound to an IAM test environment.
    #[must_use]
    pub fn is_testing(&self) -> bool {
        self.inner
            .sdk
            .as_ref()
            .is_some_and(|sdk| sdk.environment().is_some())
    }

    /// Connects and negotiates compatibility using the official SDK.
    ///
    /// # Errors
    /// Fails closed on invalid configuration or an incompatible IAM deployment.
    pub async fn connect(settings: &IamSettings) -> Result<Self, IamError> {
        let sdk = match (&settings.app_id, &settings.app_secret) {
            (Some(id), Some(secret)) => {
                let sdk = SdkClient::builder(settings.base_url.as_str()).map_err(sdk_error)?
                    .credential(Credential::application(id, secret.expose_secret()))
                    .timeout(settings.request_timeout).user_agent(USER_AGENT)
                    // A deployed backend must use its reviewed Cargo.lock.
                    .auto_update(false).build().map_err(sdk_error)?;
                sdk.system().negotiate().await.map_err(sdk_error)?;
                Some(sdk)
            }
            _ if settings.local_auth => None,
            _ => return Err(IamError::NotConfigured),
        };
        Ok(Self {
            inner: Arc::new(Inner {
                sdk,
                base_url: settings.base_url.clone(),
                app_id: settings.app_id.clone(),
                accept_local_tokens: settings.local_auth,
                webhook_verifier: settings.webhook.as_ref().map(build_verifier).transpose()?,
            }),
        })
    }

    /// Confirms that a root key selects a live IAM test environment.
    ///
    /// # Errors
    /// Refuses unknown, inactive or malformed environment keys.
    pub async fn validate_environment(&self, key: &str) -> Result<(), IamError> {
        self.sdk()?
            .with_environment(EnvironmentKey::new(key).map_err(sdk_error)?)
            .with_credential(Credential::Anonymous)
            .environments()
            .current()
            .await
            .map(|_| ())
            .map_err(sdk_error)
    }

    /// Builds a strictly isolated IAM application integration.
    ///
    /// # Errors
    /// Rejects malformed test keys and unreachable or incompatible IAM services.
    pub async fn for_environment(
        &self,
        key: &str,
        app_id: &str,
        app_secret: &str,
        webhook: &IamWebhookSettings,
    ) -> Result<Self, IamError> {
        let sdk = self
            .sdk()?
            .with_environment(EnvironmentKey::new(key).map_err(sdk_error)?)
            .with_credential(Credential::application(app_id, app_secret));
        sdk.system().negotiate().await.map_err(sdk_error)?;
        // An unknown token is deliberately inactive. A successful introspection
        // proves the application credential is accepted in this test plane.
        sdk.oauth()
            .introspect(
                &models::TokenIntrospectionRequest {
                    token: "oat_hook_credential_probe".to_owned(),
                    token_type_hint: None,
                },
                None,
            )
            .await
            .map_err(sdk_error)?;
        Ok(Self {
            inner: Arc::new(Inner {
                sdk: Some(sdk),
                base_url: self.inner.base_url.clone(),
                app_id: Some(app_id.to_owned()),
                accept_local_tokens: false,
                webhook_verifier: Some(build_verifier(webhook)?),
            }),
        })
    }

    /// Exchanges only an IAM-issued short-lived token for application tokens.
    ///
    /// # Errors
    /// Expired, spent and wrong-application tokens are rejected by IAM.
    pub async fn login(&self, slt: &str, idempotency_key: &str) -> Result<IssuedTokens, IamError> {
        if slt.is_empty() || slt.len() > 4096 || !slt.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(IamError::InvalidInput("slt"));
        }
        let tokens = self
            .sdk()?
            .oauth()
            .login(self.app_id()?, slt, &mutation(idempotency_key)?)
            .await
            .map_err(sdk_error)?;
        issued_tokens(tokens)
    }

    /// Rotates a refresh token, with a stable retry key.
    ///
    /// # Errors
    /// Fails when IAM no longer accepts the token.
    pub async fn refresh(
        &self,
        token: &str,
        idempotency_key: &str,
    ) -> Result<IssuedTokens, IamError> {
        let tokens = self
            .sdk()?
            .oauth()
            .refresh(self.app_id()?, token, &mutation(idempotency_key)?)
            .await
            .map_err(sdk_error)?;
        issued_tokens(tokens)
    }

    /// Revokes the caller's token or refresh-token family.
    ///
    /// # Errors
    /// Returns IAM transport and authorization failures.
    pub async fn logout(&self, token: &str, idempotency_key: &str) -> Result<(), IamError> {
        self.sdk()?
            .oauth()
            .revoke(
                &models::OAuthRevocationRequest {
                    token: token.to_owned(),
                    token_type_hint: None,
                },
                &mutation(idempotency_key)?,
            )
            .await
            .map_err(sdk_error)
    }

    /// Resolves current actor authority online, never trusting cached claims.
    ///
    /// # Errors
    /// Rejects inactive sessions, undisclosed roles and cross-organization actors.
    pub async fn authorize(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationContext, IamError> {
        if self.inner.accept_local_tokens
            && request
                .token
                .expose_secret()
                .starts_with(LOCAL_TOKEN_PREFIX)
        {
            return local_authorize(request);
        }
        let sdk = self.sdk()?;
        let bearer = sdk.with_credential(Credential::bearer(request.token.expose_secret()));
        let (actor, role) = if request.token.expose_secret().starts_with("oat_") {
            let snapshot = sdk
                .oauth()
                .authorization(request.token.expose_secret(), Some(request.org_id.as_str()))
                .await
                .map_err(sdk_error)?
                .ok_or(IamError::InvalidCredential)?;
            if snapshot.audience != self.app_id()?
                || snapshot.org_id != request.org_id.as_str()
                || snapshot.testing_environment_id.is_some() != sdk.environment().is_some()
            {
                return Err(IamError::InvalidCredential);
            }
            let kind = match snapshot.actor_type {
                models::ApplicationAuthorizationActorType::Carbon => ActorKind::Carbon,
                models::ApplicationAuthorizationActorType::Silicon => ActorKind::Silicon,
                models::ApplicationAuthorizationActorType::Other(_) => {
                    return Err(IamError::InvalidResponse);
                }
            };
            let actor = actor_from_directory(&snapshot.public_id, &request.org_id)?;
            if actor.kind() != kind {
                return Err(IamError::InvalidResponse);
            }
            (
                actor,
                organization_role(snapshot.org_role.as_deref().ok_or(IamError::Forbidden)?)?,
            )
        } else {
            let member = bearer
                .members()
                .directory_self(request.org_id.as_str(), Some("id,role,org"))
                .await
                .map_err(sdk_error)?;
            if member
                .org
                .as_ref()
                .is_none_or(|org| org.id != request.org_id.as_str())
            {
                return Err(IamError::InvalidCredential);
            }
            let actor = actor_from_directory(
                member.id.as_deref().ok_or(IamError::InvalidResponse)?,
                &request.org_id,
            )?;
            let role = match member.role.ok_or(IamError::Forbidden)?.org_role {
                models::DirectoryRoleOrgRole::Owner => OrganizationRole::Owner,
                models::DirectoryRoleOrgRole::Admin => OrganizationRole::Admin,
                models::DirectoryRoleOrgRole::Member => OrganizationRole::Member,
                models::DirectoryRoleOrgRole::Other(_) => return Err(IamError::Forbidden),
            };
            (actor, role)
        };
        let mut visible = Vec::new();
        for target in &request.targets {
            validate_target(target, &request.org_id)?;
            if actor.kind() == ActorKind::Silicon {
                if actor.id().as_str() == target.as_str() {
                    visible.push(target.clone());
                }
            } else {
                match bearer
                    .silicons()
                    .get(request.org_id.as_str(), target.as_str())
                    .await
                {
                    Ok(silicon)
                        if silicon.silicon_id == target.as_str()
                            && silicon.org_id == request.org_id.as_str()
                            && silicon.status == models::SiliconStatus::Active =>
                    {
                        visible.push(target.clone());
                    }
                    Ok(_) => return Err(IamError::InvalidResponse),
                    Err(silicon_iam_client::Error::Api(error))
                        if error.is_not_found() || error.is_forbidden() => {}
                    Err(error) => return Err(sdk_error(error)),
                }
            }
        }
        Ok(AuthorizationContext::new(
            request.org_id.clone(),
            actor,
            role,
            visible,
        ))
    }

    /// Registers a Silicon webhook using the caller's credential and IAM SDK.
    ///
    /// # Errors
    /// Returns IAM permission, version, validation and transport failures.
    pub async fn register_silicon_webhook(
        &self,
        token: &SecretString,
        organization_id: &OrganizationId,
        silicon_id: &SiliconId,
        endpoint_url: &Url,
        idempotency_key: &str,
    ) -> Result<RegisteredSiliconWebhook, IamError> {
        if self.inner.accept_local_tokens && token.expose_secret().starts_with(LOCAL_TOKEN_PREFIX) {
            return local_silicon_webhook(organization_id, silicon_id, endpoint_url);
        }
        let sdk = self
            .sdk()?
            .with_credential(Credential::bearer(token.expose_secret()));
        let version = match sdk
            .silicons()
            .webhook(organization_id.as_str(), silicon_id.as_str())
            .await
        {
            Ok(webhook) => Some(webhook.version),
            Err(silicon_iam_client::Error::Api(error)) if error.is_not_found() => None,
            Err(error) => return Err(sdk_error(error)),
        };
        let configured = sdk
            .silicons()
            .replace_webhook(
                organization_id.as_str(),
                silicon_id.as_str(),
                version,
                &models::SiliconWebhookReplace {
                    url: endpoint_url.to_string(),
                },
                &mutation(&iam_idempotency_key(
                    organization_id,
                    silicon_id,
                    idempotency_key,
                ))?,
            )
            .await
            .map_err(sdk_error)?;
        Ok(RegisteredSiliconWebhook {
            signing_secret: SigningSecret::from_text(configured.webhook_signing_secret)
                .map_err(|_| IamError::InvalidResponse)?,
            secret_version: u64::try_from(configured.webhook.secret_version)
                .map_err(|_| IamError::InvalidResponse)?,
        })
    }

    /// Verifies exact bytes, then enforces the expected production/test plane.
    ///
    /// # Errors
    /// Rejects signatures or test envelopes belonging to another environment.
    pub fn verify_application_webhook(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<VerifiedWebhook, IamError> {
        let verified = self
            .inner
            .webhook_verifier
            .as_ref()
            .ok_or(IamError::NotConfigured)?
            .verify(headers, body)
            .map_err(IamError::WebhookRejected)?;
        if let Some(key) = self.inner.sdk.as_ref().and_then(SdkClient::environment) {
            verified
                .verify_testing_environment(key)
                .map_err(IamError::WebhookRejected)?;
        } else if verified.is_testing() {
            return Err(IamError::Forbidden);
        }
        Ok(verified)
    }

    fn sdk(&self) -> Result<&SdkClient, IamError> {
        self.inner.sdk.as_ref().ok_or(IamError::NotConfigured)
    }

    fn app_id(&self) -> Result<&str, IamError> {
        self.inner.app_id.as_deref().ok_or(IamError::NotConfigured)
    }
}

fn mutation(key: &str) -> Result<Mutation, IamError> {
    // Hook accepts 8–255 characters; IAM requires at least 16. Hashing every
    // key preserves stable retries without leaking the caller's value to IAM.
    let iam_key = hex::encode(Sha256::digest(key.as_bytes()));
    Ok(Mutation::with_key(
        IdempotencyKey::parse(iam_key).map_err(sdk_error)?,
    ))
}

fn organization_role(value: &str) -> Result<OrganizationRole, IamError> {
    match value {
        "owner" => Ok(OrganizationRole::Owner),
        "admin" => Ok(OrganizationRole::Admin),
        "member" => Ok(OrganizationRole::Member),
        _ => Err(IamError::Forbidden),
    }
}

fn issued_tokens(tokens: models::OAuthTokenResponse) -> Result<IssuedTokens, IamError> {
    let kind = match tokens.actor.type_field {
        models::ActorRefType::Carbon => ActorKind::Carbon,
        models::ActorRefType::Silicon => ActorKind::Silicon,
        _ => return Err(IamError::InvalidResponse),
    };
    Ok(IssuedTokens {
        access_token: Zeroizing::new(tokens.access_token),
        refresh_token: Zeroizing::new(tokens.refresh_token),
        expires_in: Duration::from_secs(
            u64::try_from(tokens.expires_in).map_err(|_| IamError::InvalidResponse)?,
        ),
        scopes: tokens.scope.split_whitespace().map(str::to_owned).collect(),
        actor: ActorRef::try_new(kind, tokens.actor.public_id)
            .map_err(|_| IamError::InvalidResponse)?,
        organization_id: tokens
            .org_id
            .map(OrganizationId::new)
            .transpose()
            .map_err(|_| IamError::InvalidResponse)?,
    })
}

fn build_verifier(settings: &IamWebhookSettings) -> Result<WebhookVerifier, IamError> {
    let secret =
        WebhookSecret::new(settings.secret.expose_secret()).map_err(IamError::WebhookRejected)?;
    let version = i64::try_from(settings.version)
        .map_err(|_| IamError::InvalidInput("iam_webhook_secret_version"))?;
    let mut keyring =
        WebhookSecretKeyring::new(version, secret).map_err(IamError::WebhookRejected)?;
    if let Some((secret, version)) = &settings.previous {
        keyring
            .insert(
                i64::try_from(*version)
                    .map_err(|_| IamError::InvalidInput("iam_webhook_secret_version"))?,
                WebhookSecret::new(secret.expose_secret()).map_err(IamError::WebhookRejected)?,
            )
            .map_err(IamError::WebhookRejected)?;
    }
    Ok(WebhookVerifier::new(keyring))
}

fn sdk_error(error: silicon_iam_client::Error) -> IamError {
    use silicon_iam_client::Error;
    match error {
        Error::Api(error) => match error.status {
            401 => IamError::InvalidCredential,
            403 => IamError::Forbidden,
            404 => IamError::NotFound,
            status => IamError::Rejected { status },
        },
        Error::RateLimited { retry_after, .. } => IamError::RateLimited { retry_after },
        Error::Transport(error) => IamError::Transport(anyhow::Error::new(error)),
        Error::ResponseTooLarge { .. } => IamError::ResponseTooLarge,
        Error::UnstructuredResponse { status, .. } => IamError::UnexpectedStatus(status),
        Error::Invalid(_) => IamError::InvalidInput("iam_request"),
        _ => IamError::InvalidResponse,
    }
}

/// A directory ID with an organization suffix is a global Silicon ID; any
/// other ID is a public Carbon ID. IAM never issues a Silicon ID whose suffix
/// differs from the organization it was read from.
fn validate_target(target: &SiliconId, org: &OrganizationId) -> Result<(), IamError> {
    let Some((handle, organization)) = target.as_str().split_once(':') else {
        return Err(IamError::InvalidInput("silicon_id"));
    };
    if handle.is_empty() || organization.contains(':') {
        return Err(IamError::InvalidInput("silicon_id"));
    }
    if organization != org.as_str() {
        return Err(IamError::Forbidden);
    }
    Ok(())
}

fn actor_from_directory(id: &str, organization_id: &OrganizationId) -> Result<ActorRef, IamError> {
    match id.rsplit_once(':') {
        Some((handle, suffix)) => {
            if handle.is_empty() || suffix != organization_id.as_str() {
                return Err(IamError::InvalidResponse);
            }
            ActorRef::try_new(ActorKind::Silicon, id).map_err(|_| IamError::InvalidResponse)
        }
        None => ActorRef::try_new(ActorKind::Carbon, id).map_err(|_| IamError::InvalidResponse),
    }
}

/// IAM keys idempotent replays on the caller's key. Hook derives a stable
/// key from its own so a Hook-level retry replays the same IAM operation
/// without exposing the caller's key to IAM.
fn iam_idempotency_key(
    organization_id: &OrganizationId,
    silicon_id: &SiliconId,
    hook_idempotency_key: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(IAM_IDEMPOTENCY_DOMAIN);
    for part in [
        organization_id.as_str(),
        silicon_id.as_str(),
        hook_idempotency_key,
    ] {
        digest.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(part.as_bytes());
    }
    hex::encode(digest.finalize())
}

/// Deterministic development credential `local:<carbon|silicon>:<member|admin|owner>:<id>`.
///
/// A local Carbon sees every requested Silicon; a local Silicon sees itself.
fn local_authorize(request: &AuthorizationRequest) -> Result<AuthorizationContext, IamError> {
    let mut parts = request.token.expose_secret().splitn(4, ':');
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
    let visible = match kind {
        ActorKind::Silicon => {
            vec![SiliconId::new(actor_id).map_err(|_| IamError::InvalidCredential)?]
        }
        ActorKind::Carbon => request.targets.clone(),
    };
    Ok(AuthorizationContext::new(
        request.org_id.clone(),
        actor,
        role,
        visible,
    ))
}

/// Stable stand-in for IAM's `swhs_` secret so the development flow works
/// end to end without an IAM deployment.
fn local_silicon_webhook(
    organization_id: &OrganizationId,
    silicon_id: &SiliconId,
    endpoint_url: &Url,
) -> Result<RegisteredSiliconWebhook, IamError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let mut digest = Sha256::new();
    digest.update(LOCAL_SECRET_DOMAIN);
    digest.update(organization_id.as_str().as_bytes());
    digest.update(b"\0");
    digest.update(silicon_id.as_str().as_bytes());
    digest.update(b"\0");
    digest.update(endpoint_url.as_str().as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(digest.finalize());
    let secret = Zeroizing::new(format!("{SILICON_WEBHOOK_SECRET_PREFIX}{encoded}"));
    Ok(RegisteredSiliconWebhook {
        signing_secret: SigningSecret::from_zeroizing(secret)
            .map_err(|_| IamError::InvalidResponse)?,
        secret_version: 1,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hmac::{Hmac, Mac as _};
    use http::{HeaderMap, HeaderValue};
    use secrecy::SecretString;
    use sha2::Sha256;
    use url::Url;
    use uuid::Uuid;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path, query_param},
    };

    use super::{
        AuthorizationRequest, IamClient, IamError, actor_from_directory, iam_idempotency_key,
    };
    use crate::{
        config::{IamSettings, IamWebhookSettings},
        domain::{ActorKind, OrganizationId, OrganizationRole, SiliconId},
    };

    const APP_ID: &str = "tos>hook";
    const APP_SECRET: &str = "ask_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const WEBHOOK_SECRET: &str = "whs_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const ACCESS_TOKEN: &str = "oat_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    const SILICON_TOKEN: &str = "sat_DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
    const CARBON_TOKEN: &str = "cat_EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";

    fn silicon_profile() -> serde_json::Value {
        serde_json::json!({
            "id": Uuid::now_v7(), "principal_id": Uuid::now_v7(), "membership_id": Uuid::now_v7(),
            "silicon_id": "cos:tos", "org_id": "tos", "display_name": "COS", "timezone": "UTC",
            "profile_photo": "https://example.test/cos.png", "job_role": "engineer", "tags": [],
            "hierarchy_level": 1, "webhook_configured": false, "status": "active", "version": 1,
            "created_at": "2026-09-02T10:00:00Z", "updated_at": "2026-09-02T10:00:00Z"
        })
    }

    fn iam_failure(status: u16) -> ResponseTemplate {
        ResponseTemplate::new(status).set_body_json(serde_json::json!({
            "error": {"code": "not_permitted", "message": "Not permitted", "request_id": Uuid::now_v7()}
        }))
    }

    fn webhook_record(secret_version: i64, version: i64) -> serde_json::Value {
        serde_json::json!({
            "silicon_id": "cos:tos", "url": "https://hook.example.test/silicon/cos:tos/A1B2C3D4",
            "status": "active", "secret_version": secret_version, "version": version,
            "created_at": "2026-09-02T10:00:00Z", "updated_at": "2026-09-02T10:00:00Z"
        })
    }

    async fn iam_server() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/version"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("silicon-iam-api-version", "v1")
                    .insert_header("vary", "Silicon-IAM-Supported-API-Versions")
                    .set_body_json(serde_json::json!({
                        "service": "silicon-iam",
                        "selected_api_version": "v1",
                        "supported_api_versions": ["v1"],
                        "build": "test",
                        "commit": "test"
                    })),
            )
            .mount(&server)
            .await;
        server
    }

    fn settings(server: &MockServer) -> Result<IamSettings, Box<dyn std::error::Error>> {
        Ok(IamSettings {
            base_url: Url::parse(&server.uri())?,
            app_id: Some(APP_ID.to_owned()),
            app_secret: Some(SecretString::from(APP_SECRET)),
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(2),
            max_response_bytes: 65_536,
            allow_insecure_local_http: true,
            local_auth: false,
            webhook: Some(IamWebhookSettings {
                secret: SecretString::from(WEBHOOK_SECRET),
                version: 3,
                previous: None,
            }),
        })
    }

    fn local_settings() -> Result<IamSettings, Box<dyn std::error::Error>> {
        Ok(IamSettings {
            base_url: Url::parse("http://127.0.0.1:9")?,
            app_id: None,
            app_secret: None,
            connect_timeout: Duration::from_millis(10),
            request_timeout: Duration::from_millis(10),
            max_response_bytes: 1_024,
            allow_insecure_local_http: true,
            local_auth: true,
            webhook: None,
        })
    }

    fn introspection(actor_type: &str) -> serde_json::Value {
        serde_json::json!({
            "active": true,
            "principal_id": Uuid::now_v7(),
            "actor_type": actor_type,
            "client_id": APP_ID,
            "org_id": "tos",
            "membership_id": Uuid::now_v7(),
            "session_id": Uuid::now_v7(),
            "scope": "memberships.read profile",
            "audience": APP_ID,
            "issued_at": 1_700_000_000,
            "expires_at": 1_700_001_800,
            "authorization_epoch": 4,
            "authorization": {
                "principal_id": Uuid::now_v7(), "actor_type": actor_type, "public_id": "alice",
                "organization_id": Uuid::now_v7(), "org_id": "tos", "membership_id": Uuid::now_v7(),
                "membership_version": 1, "authorization_epoch": 4, "audience": APP_ID,
                "testing_environment_id": null, "scopes": ["roles.read", "memberships.read"],
                "org_role": "member", "tags": []
            }
        })
    }

    fn directory(id: &str, role: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "role": {"org_role": role, "job_role": "engineer"},
            "org": {"id": "tos", "name": "Team of Silicons"}
        })
    }

    fn request(
        token: &str,
        targets: &[&str],
    ) -> Result<AuthorizationRequest, Box<dyn std::error::Error>> {
        Ok(AuthorizationRequest {
            token: SecretString::from(token),
            org_id: OrganizationId::new("tos")?,
            targets: targets
                .iter()
                .map(|target| SiliconId::new(*target))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    #[tokio::test]
    async fn hook_issued_tokens_use_live_authorization_snapshots()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = iam_server().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/oauth/introspect"))
            .and(header("x-org-id", "tos"))
            .respond_with(ResponseTemplate::new(200).set_body_json(introspection("carbon")))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organizations/tos/directory/self"))
            .and(query_param("fields", "id,role,org"))
            .and(header(
                "authorization",
                format!("Bearer {ACCESS_TOKEN}").as_str(),
            ))
            .and(header("silicon-iam-api-version", "v1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(directory("alice", "member")))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organizations/tos/silicons/cos:tos"))
            .respond_with(ResponseTemplate::new(200).set_body_json(silicon_profile()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organizations/tos/silicons/hidden:tos"))
            .respond_with(iam_failure(404))
            .expect(1)
            .mount(&server)
            .await;

        let client = IamClient::connect(&settings(&server)?).await?;
        let context = client
            .authorize(&request(ACCESS_TOKEN, &["cos:tos", "hidden:tos"])?)
            .await?;

        assert_eq!(context.actor().kind(), ActorKind::Carbon);
        assert_eq!(context.actor().id().as_str(), "alice");
        assert_eq!(context.organization_role(), OrganizationRole::Member);
        assert!(context.has_silicon_visibility(&SiliconId::new("cos:tos")?));
        assert!(!context.has_silicon_visibility(&SiliconId::new("hidden:tos")?));
        Ok(())
    }

    #[tokio::test]
    async fn iam_native_silicon_tokens_use_the_directory_alone()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = iam_server().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/oauth/introspect"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organizations/tos/directory/self"))
            .and(header(
                "authorization",
                format!("Bearer {SILICON_TOKEN}").as_str(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(directory("cos:tos", "member")))
            .mount(&server)
            .await;

        let client = IamClient::connect(&settings(&server)?).await?;
        let context = client
            .authorize(&request(SILICON_TOKEN, &["cos:tos", "other:tos"])?)
            .await?;

        assert_eq!(context.actor().kind(), ActorKind::Silicon);
        assert_eq!(context.actor().id().as_str(), "cos:tos");
        assert!(context.has_silicon_visibility(&SiliconId::new("cos:tos")?));
        assert!(!context.has_silicon_visibility(&SiliconId::new("other:tos")?));
        Ok(())
    }

    #[tokio::test]
    async fn administrators_require_a_confirmed_silicon() -> Result<(), Box<dyn std::error::Error>>
    {
        let server = iam_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organizations/tos/directory/self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(directory("bob", "admin")))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organizations/tos/silicons/cos:tos"))
            .respond_with(ResponseTemplate::new(200).set_body_json(silicon_profile()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organizations/tos/silicons/missing:tos"))
            .respond_with(iam_failure(404))
            .expect(1)
            .mount(&server)
            .await;

        let client = IamClient::connect(&settings(&server)?).await?;
        let context = client
            .authorize(&request(CARBON_TOKEN, &["cos:tos", "missing:tos"])?)
            .await?;
        assert_eq!(context.organization_role(), OrganizationRole::Admin);
        assert!(context.has_silicon_visibility(&SiliconId::new("cos:tos")?));
        assert!(!context.has_silicon_visibility(&SiliconId::new("missing:tos")?));
        Ok(())
    }

    #[tokio::test]
    async fn dead_and_foreign_tokens_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let server = iam_server().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/oauth/introspect"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"active": false})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organizations/tos/directory/self"))
            .respond_with(iam_failure(403))
            .mount(&server)
            .await;

        let client = IamClient::connect(&settings(&server)?).await?;
        assert!(matches!(
            client.authorize(&request(ACCESS_TOKEN, &[])?).await,
            Err(IamError::InvalidCredential)
        ));
        assert!(matches!(
            client.authorize(&request(SILICON_TOKEN, &[])?).await,
            Err(IamError::Forbidden)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn silicon_ids_from_another_organization_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = iam_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organizations/tos/directory/self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(directory("cos:acme", "member")))
            .mount(&server)
            .await;

        let client = IamClient::connect(&settings(&server)?).await?;
        assert!(matches!(
            client.authorize(&request(SILICON_TOKEN, &[])?).await,
            Err(IamError::InvalidResponse)
        ));
        let organization = OrganizationId::new("tos")?;
        assert!(actor_from_directory("cos:tos", &organization).is_ok());
        assert!(actor_from_directory(":tos", &organization).is_err());
        assert_eq!(
            actor_from_directory("alice", &organization)?.kind(),
            ActorKind::Carbon
        );
        Ok(())
    }

    #[tokio::test]
    async fn silicon_webhook_registration_reads_the_etag_then_replaces()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = iam_server().await;
        let organization = OrganizationId::new("tos")?;
        let silicon = SiliconId::new("cos:tos")?;
        let endpoint = Url::parse("https://hook.example.test/silicon/cos:tos/A1B2C3D4")?;
        let expected_key = iam_idempotency_key(&organization, &silicon, "connect-0001");
        Mock::given(method("GET"))
            .and(path("/api/v1/organizations/tos/silicons/cos:tos/webhook"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"7\"")
                    .set_body_json(webhook_record(2, 7)),
            )
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/api/v1/organizations/tos/silicons/cos:tos/webhook"))
            .and(header("if-match", "\"7\""))
            .and(header(
                "idempotency-key",
                super::mutation(&expected_key)?.key().as_str(),
            ))
            .and(header(
                "authorization",
                format!("Bearer {SILICON_TOKEN}").as_str(),
            ))
            .and(body_json(serde_json::json!({"url": endpoint.as_str()})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "webhook": webhook_record(3, 8),
                "webhook_signing_secret": format!("swhs_{}", "F".repeat(43)),
                "secret_replay_expires_at": "2026-09-02T10:10:00Z"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = IamClient::connect(&settings(&server)?).await?;
        let registered = client
            .register_silicon_webhook(
                &SecretString::from(SILICON_TOKEN),
                &organization,
                &silicon,
                &endpoint,
                "connect-0001",
            )
            .await?;
        assert_eq!(registered.secret_version, 3);
        assert!(registered.signing_secret.as_str().starts_with("swhs_"));
        assert_eq!(expected_key.len(), 64);
        Ok(())
    }

    #[tokio::test]
    async fn application_webhooks_verify_with_the_configured_keyring()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = iam_server().await;
        let client = IamClient::connect(&settings(&server)?).await?;
        let event_id = Uuid::now_v7();
        let body = format!(
            r#"{{"spec_version":"1.0","event_id":"{event_id}","event_type":"session.logout.v1","occurred_at":"2026-09-02T10:00:00Z","organization_id":null,"aggregate":{{"id":"{}","type":"session","version":1}},"data":{{}}}}"#,
            Uuid::now_v7()
        );
        let timestamp = time::OffsetDateTime::now_utc().unix_timestamp().to_string();
        let mut mac = Hmac::<Sha256>::new_from_slice(WEBHOOK_SECRET.as_bytes())?;
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(body.as_bytes());
        let signature = format!("v1={}", hex::encode(mac.finalize().into_bytes()));
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-silicon-iam-event-id",
            HeaderValue::from_str(&event_id.to_string())?,
        );
        headers.insert(
            "x-silicon-iam-timestamp",
            HeaderValue::from_str(&timestamp)?,
        );
        headers.insert("x-silicon-iam-key-version", HeaderValue::from_static("3"));
        headers.insert(
            "x-silicon-iam-signature",
            HeaderValue::from_str(&signature)?,
        );

        let verified = client.verify_application_webhook(&headers, body.as_bytes())?;
        assert_eq!(verified.event_id(), event_id);
        assert_eq!(verified.event().event_type.as_str(), "session.logout.v1");

        headers.insert("x-silicon-iam-key-version", HeaderValue::from_static("2"));
        assert!(matches!(
            client.verify_application_webhook(&headers, body.as_bytes()),
            Err(IamError::WebhookRejected(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn login_exchanges_only_a_short_lived_token() -> Result<(), Box<dyn std::error::Error>> {
        let server = iam_server().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/app-auth/tokens"))
            .and(header(
                "idempotency-key",
                super::mutation("login-contract-0001")?.key().as_str(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": ACCESS_TOKEN,
                "refresh_token": "ort_example",
                "token_type": "Bearer", "expires_in": 1800,
                "scope": "profile roles.read memberships.read", "org_id": "tos",
                "actor": {"principal_id": Uuid::now_v7(), "type": "carbon", "public_id": "alice"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = IamClient::connect(&settings(&server)?).await?;
        let tokens = client.login("slt_example", "login-contract-0001").await?;
        assert_eq!(tokens.actor.id().as_str(), "alice");
        assert_eq!(tokens.access_token.as_str(), ACCESS_TOKEN);
        assert!(matches!(
            client.login("invalid\nvalue", "login-contract-0002").await,
            Err(IamError::InvalidInput("slt"))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn local_mode_needs_no_network_and_stays_deterministic()
    -> Result<(), Box<dyn std::error::Error>> {
        let client = IamClient::connect(&local_settings()?).await?;
        let context = client
            .authorize(&request(
                "local:silicon:member:cos:tos",
                &["cos:tos", "other:tos"],
            )?)
            .await?;
        assert_eq!(context.actor().kind(), ActorKind::Silicon);
        assert!(context.has_silicon_visibility(&SiliconId::new("cos:tos")?));
        assert!(!context.has_silicon_visibility(&SiliconId::new("other:tos")?));

        let carbon = client
            .authorize(&request("local:carbon:owner:alice", &["cos:tos"])?)
            .await?;
        assert_eq!(carbon.organization_role(), OrganizationRole::Owner);
        assert!(carbon.has_silicon_visibility(&SiliconId::new("cos:tos")?));

        let organization = OrganizationId::new("tos")?;
        let silicon = SiliconId::new("cos:tos")?;
        let endpoint = Url::parse("https://hook.example.test/silicon/cos:tos/A1B2C3D4")?;
        let token = SecretString::from("local:silicon:member:cos:tos");
        let first = client
            .register_silicon_webhook(&token, &organization, &silicon, &endpoint, "k")
            .await?;
        let second = client
            .register_silicon_webhook(&token, &organization, &silicon, &endpoint, "k")
            .await?;
        assert_eq!(
            first.signing_secret.as_str(),
            second.signing_secret.as_str()
        );
        assert_eq!(first.signing_secret.as_str().len(), 48);
        assert!(matches!(
            client.login("slt_example", "local-login-0001").await,
            Err(IamError::NotConfigured)
        ));
        assert!(matches!(
            client.authorize(&request(ACCESS_TOKEN, &[])?).await,
            Err(IamError::NotConfigured)
        ));
        Ok(())
    }
}
