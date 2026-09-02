//! Silicon IAM adapter built on the official `silicon-iam` crate.
//!
//! The crate owns everything a caller could get wrong without noticing: the
//! fail-closed compatibility handshake, PKCE sign-in, token introspection, and
//! exact-byte webhook verification. What it deliberately leaves to the bearer
//! holder, Hook does with the caller's own token against the documented IAM
//! API: the organization directory says who a token is (the public Carbon ID
//! or global Silicon ID) and which organization role it holds, and a
//! per-Silicon read says whether the caller may see a Silicon. Hook caches
//! nothing, so every decision reflects IAM's current state.
//!
//! Hook exposes no OBO endpoints. The only credential a management call can
//! present is a bearer token: an `oat_` token Hook issued through its own
//! sign-in flow, or an IAM-native `cat_`/`sat_` token a Carbon or Silicon
//! obtained from IAM directly.

use std::{fmt, sync::Arc, time::Duration};

use http::{HeaderMap, StatusCode, header};
use reqwest::{Client as HttpClient, Response, Url, redirect::Policy};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use silicon_iam::{
    ApplicationCredentials, AuthorizationCallback, AuthorizationContinuation, AuthorizationOptions,
    Client as SdkClient, IntrospectionOptions, OAuthAccessToken, OAuthRefreshToken,
    OAuthTokenParts, ServiceInfo, TokenIntrospection, VerifiedWebhook, WebhookSecret,
    WebhookSecretKeyring, WebhookVerificationError, WebhookVerifier,
};
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    config::{IamSettings, IamWebhookSettings, LoginSettings},
    domain::{
        ActorKind, ActorRef, AuthorizationContext, OrganizationId, OrganizationRole, SigningSecret,
        SiliconId,
    },
    error::AppError,
};

const USER_AGENT: &str = concat!("silicon-hook/", env!("CARGO_PKG_VERSION"));
/// Every versioned IAM call is pinned to the API major the SDK negotiated.
const API_VERSION_HEADER: &str = "silicon-iam-api-version";
const API_VERSION: &str = "v1";
const OAUTH_ACCESS_TOKEN_PREFIX: &str = "oat_";
const LOCAL_TOKEN_PREFIX: &str = "local:";
const SILICON_WEBHOOK_SECRET_PREFIX: &str = "swhs_";
const SILICON_WEBHOOK_SECRET_LENGTH: usize = 48;
const IAM_IDEMPOTENCY_DOMAIN: &[u8] = b"silicon-hook/iam-silicon-webhook/v1\0";
const LOCAL_SECRET_DOMAIN: &[u8] = b"silicon-hook/local-iam-silicon-webhook/v1\0";
const MAX_CALLBACK_URL_BYTES: usize = 8_192;
const MAX_CONTINUATION_BYTES: usize = 16_384;
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(1);

/// Facts a management request presents for authentication.
#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    /// Opaque bearer token from the HTTP `Authorization` header.
    pub token: SecretString,
    /// Organization selected by `X-Org-ID`.
    pub org_id: OrganizationId,
    /// Silicons the request acts on. A Carbon's visibility of each one is
    /// established online; a Silicon only ever sees itself.
    pub targets: Vec<SiliconId>,
}

/// Browser redirect and sealed continuation that start a Carbon sign-in.
pub struct LoginStart {
    /// IAM authorization URL the browser must be sent to.
    pub authorization_url: String,
    /// Encrypted, Application-bound continuation the client must present on
    /// the callback. It expires after ten minutes.
    pub continuation: Zeroizing<String>,
}

impl fmt::Debug for LoginStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginStart")
            .field("authorization_url", &self.authorization_url)
            .field("continuation", &"[REDACTED]")
            .finish()
    }
}

/// Result of completing a sign-in callback.
#[derive(Debug)]
pub enum LoginOutcome {
    /// IAM issued tokens for the signed-in actor.
    Granted(IssuedTokens),
    /// The actor or IAM declined the authorization.
    Denied {
        /// OAuth protocol error code such as `access_denied`.
        code: String,
    },
}

/// Tokens IAM issued to Hook for an actor.
pub struct IssuedTokens {
    /// Opaque 30-minute access token.
    pub access_token: Zeroizing<String>,
    /// Rotating refresh token; every use replaces it.
    pub refresh_token: Zeroizing<String>,
    /// Access-token lifetime reported by IAM.
    pub expires_in: Duration,
    /// Effective scopes.
    pub scopes: Vec<String>,
    /// Actor the tokens represent.
    pub actor: ActorRef,
    /// Organization the tokens are bound to, when any.
    pub organization_id: Option<OrganizationId>,
}

impl fmt::Debug for IssuedTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedTokens")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field("scopes", &self.scopes)
            .field("actor", &self.actor)
            .field("organization_id", &self.organization_id)
            .finish()
    }
}

/// Outcome of registering a Hook endpoint as a Silicon's IAM webhook.
pub struct RegisteredSiliconWebhook {
    /// Fresh `swhs_` secret IAM will sign deliveries with.
    pub signing_secret: SigningSecret,
    /// Version IAM presents in `X-Silicon-IAM-Key-Version`.
    pub secret_version: u64,
}

impl fmt::Debug for RegisteredSiliconWebhook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisteredSiliconWebhook")
            .field("signing_secret", &"[REDACTED]")
            .field("secret_version", &self.secret_version)
            .finish()
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
    WebhookRejected(#[source] WebhookVerificationError),
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

/// Cloneable IAM adapter shared by every request handler.
#[derive(Clone)]
pub struct IamClient {
    inner: Arc<Inner>,
}

struct Inner {
    online: Option<Online>,
    accept_local_tokens: bool,
    webhook_verifier: Option<WebhookVerifier>,
}

struct Online {
    sdk: SdkClient,
    http: HttpClient,
    base_url: Url,
    max_response_bytes: usize,
    login: Option<LoginSettings>,
}

impl fmt::Debug for IamClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let online = self.inner.online.as_ref();
        formatter
            .debug_struct("IamClient")
            .field("base_url", &online.map(|online| &online.base_url))
            .field(
                "api_version",
                &online.map(|online| online.sdk.service_info().api_version()),
            )
            .field(
                "login_configured",
                &online.is_some_and(|online| online.login.is_some()),
            )
            .field("accept_local_tokens", &self.inner.accept_local_tokens)
            .field(
                "webhook_verifier",
                &self.inner.webhook_verifier.as_ref().map(|_| "[configured]"),
            )
            .finish()
    }
}

impl IamClient {
    /// Connects to IAM with Hook's Application credentials.
    ///
    /// With credentials configured this performs the SDK's fail-closed
    /// compatibility handshake, so a process never starts against an IAM it
    /// cannot talk to. Without credentials the adapter runs in local mode,
    /// which only development and test configuration can enable.
    ///
    /// # Errors
    ///
    /// Returns an error when the credentials or webhook secrets are malformed,
    /// the handshake fails, or neither online nor local mode is configured.
    pub async fn connect(settings: &IamSettings) -> Result<Self, IamError> {
        let webhook_verifier = settings.webhook.as_ref().map(build_verifier).transpose()?;
        let online = match (&settings.app_id, &settings.app_secret) {
            (Some(app_id), Some(app_secret)) => {
                Some(Online::connect(settings, app_id, app_secret).await?)
            }
            _ => None,
        };
        if online.is_none() && !settings.local_auth {
            return Err(IamError::NotConfigured);
        }
        Ok(Self {
            inner: Arc::new(Inner {
                online,
                accept_local_tokens: settings.local_auth,
                webhook_verifier,
            }),
        })
    }

    /// Service metadata fixed by the handshake, when connected online.
    #[must_use]
    pub fn service_info(&self) -> Option<&ServiceInfo> {
        self.inner
            .online
            .as_ref()
            .map(|online| online.sdk.service_info())
    }

    /// Authenticates a bearer token and returns only current IAM facts.
    ///
    /// # Errors
    ///
    /// An unknown, inactive, or foreign-organization token returns
    /// [`IamError::InvalidCredential`]. Transport failures, malformed
    /// responses, and response overflows fail closed.
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
        self.online()?.authorize(request).await
    }

    /// Starts a Carbon sign-in and returns the redirect plus its continuation.
    ///
    /// # Errors
    ///
    /// Returns [`IamError::NotConfigured`] without a redirect URI, or an SDK
    /// failure while building or sealing the attempt.
    pub fn begin_login(
        &self,
        organization_id: Option<&OrganizationId>,
    ) -> Result<LoginStart, IamError> {
        self.online()?.begin_login(organization_id)
    }

    /// Completes a sign-in from the exact callback URL the browser delivered.
    ///
    /// # Errors
    ///
    /// Returns [`IamError::InvalidInput`] for a continuation that is
    /// malformed, expired, tampered with, or bound to another Application, or
    /// for a callback that does not match it; provider failures fail closed.
    pub async fn complete_login(
        &self,
        continuation: &str,
        callback_url: &str,
    ) -> Result<LoginOutcome, IamError> {
        self.online()?
            .complete_login(continuation, callback_url)
            .await
    }

    /// Rotates a refresh token into a new token pair.
    ///
    /// # Errors
    ///
    /// Returns [`IamError::InvalidCredential`] for a token IAM no longer
    /// honors; provider failures fail closed.
    pub async fn refresh(&self, refresh_token: &str) -> Result<IssuedTokens, IamError> {
        self.online()?.refresh(refresh_token).await
    }

    /// Ends the IAM session behind a Hook-issued access token.
    ///
    /// # Errors
    ///
    /// Returns [`IamError::InvalidCredential`] for a token that is not a
    /// Hook-issued access token IAM still honors.
    pub async fn logout(&self, access_token: &str) -> Result<(), IamError> {
        self.online()?.logout(access_token).await
    }

    /// Registers a Hook endpoint as the Silicon's IAM webhook using the
    /// caller's own bearer, and returns the fresh signing secret IAM issued.
    ///
    /// # Errors
    ///
    /// Returns [`IamError::Forbidden`] when IAM requires authority or step-up
    /// the caller lacks, [`IamError::NotFound`] for a Silicon IAM hides from
    /// the caller, and [`IamError::Rejected`] for precondition or validation
    /// failures.
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
        self.online()?
            .register_silicon_webhook(
                token.expose_secret(),
                organization_id,
                silicon_id,
                endpoint_url,
                idempotency_key,
            )
            .await
    }

    /// Authenticates an Application webhook delivery from IAM.
    ///
    /// # Errors
    ///
    /// Returns [`IamError::NotConfigured`] without a webhook secret and
    /// [`IamError::WebhookRejected`] for a delivery that does not verify.
    pub fn verify_application_webhook(
        &self,
        headers: &HeaderMap,
        exact_body: &[u8],
    ) -> Result<VerifiedWebhook, IamError> {
        self.inner
            .webhook_verifier
            .as_ref()
            .ok_or(IamError::NotConfigured)?
            .verify(headers, exact_body)
            .map_err(IamError::WebhookRejected)
    }

    fn online(&self) -> Result<&Online, IamError> {
        self.inner.online.as_ref().ok_or(IamError::NotConfigured)
    }
}

impl Online {
    async fn connect(
        settings: &IamSettings,
        app_id: &str,
        app_secret: &SecretString,
    ) -> Result<Self, IamError> {
        let credentials = ApplicationCredentials::new(app_id, app_secret.expose_secret())
            .map_err(|_| IamError::InvalidInput("iam_app_credentials"))?;
        let sdk = SdkClient::builder(credentials)
            .base_url(settings.base_url.as_str())
            .connect_timeout(settings.connect_timeout)
            .request_timeout(settings.request_timeout)
            .max_response_bytes(settings.max_response_bytes)
            .allow_insecure_local_http(settings.allow_insecure_local_http)
            .connect()
            .await
            .map_err(|error| IamError::Handshake(anyhow::Error::new(error)))?;
        let http = HttpClient::builder()
            .redirect(Policy::none())
            .connect_timeout(settings.connect_timeout)
            .timeout(settings.request_timeout)
            .https_only(!settings.allow_insecure_local_http)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|error| IamError::Transport(anyhow::Error::new(error)))?;
        Ok(Self {
            sdk,
            http,
            base_url: settings.base_url.clone(),
            max_response_bytes: settings.max_response_bytes,
            login: settings.login.clone(),
        })
    }

    async fn authorize(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationContext, IamError> {
        let token = request.token.expose_secret();
        let introspected_kind = if token.starts_with(OAUTH_ACCESS_TOKEN_PREFIX) {
            Some(self.introspect(token, &request.org_id).await?)
        } else {
            None
        };
        let member = self.directory_self(token, &request.org_id).await?;
        let actor = actor_from_directory(&member.id, &request.org_id)?;
        if introspected_kind.is_some_and(|kind| kind != actor.kind()) {
            return Err(IamError::InvalidResponse);
        }
        let role = member
            .role
            .ok_or(IamError::InvalidResponse)?
            .org_role
            .into_domain();
        let visible = self
            .visible_targets(token, &request.org_id, &actor, role, &request.targets)
            .await?;
        Ok(AuthorizationContext::new(
            request.org_id.clone(),
            actor,
            role,
            visible,
        ))
    }

    /// Introspects a Hook-issued access token through the SDK, which also
    /// proves the token was issued to this Application and is still active.
    async fn introspect(
        &self,
        token: &str,
        organization_id: &OrganizationId,
    ) -> Result<ActorKind, IamError> {
        let token = OAuthAccessToken::new(token).map_err(|_| IamError::InvalidCredential)?;
        let options = IntrospectionOptions::new()
            .for_organization(organization_id.as_str())
            .map_err(|_| IamError::InvalidInput("org_id"))?;
        let introspection = self
            .sdk
            .oauth()
            .introspect_access_token_with_options(&token, &options)
            .await
            .map_err(sdk_error)?;
        let active = match introspection {
            TokenIntrospection::Active(active) => active,
            TokenIntrospection::Inactive => return Err(IamError::InvalidCredential),
            _ => return Err(IamError::InvalidResponse),
        };
        if active.organization_id() != Some(organization_id.as_str()) {
            return Err(IamError::InvalidCredential);
        }
        actor_kind_from_sdk(active.actor_kind()).ok_or(IamError::InvalidCredential)
    }

    /// Reads the caller's own directory row, which names the public actor ID
    /// and current organization role. IAM answers 401 for a dead token and
    /// 403/404 for a token without an active membership in the organization.
    async fn directory_self(
        &self,
        token: &str,
        organization_id: &OrganizationId,
    ) -> Result<DirectoryMemberWire, IamError> {
        let mut url = self.api_url(&[
            "organizations",
            organization_id.as_str(),
            "directory",
            "self",
        ])?;
        url.query_pairs_mut().append_pair("fields", "id,role,org");
        let response = self.bearer_get(token, url).await?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => {
                return Err(IamError::InvalidCredential);
            }
            StatusCode::TOO_MANY_REQUESTS => return Err(rate_limited(&response)),
            status => return Err(IamError::UnexpectedStatus(status.as_u16())),
        }
        let member: DirectoryMemberWire = bounded_json(response, self.max_response_bytes).await?;
        if member
            .org
            .as_ref()
            .is_some_and(|organization| organization.id != organization_id.as_str())
        {
            return Err(IamError::InvalidResponse);
        }
        Ok(member)
    }

    async fn visible_targets(
        &self,
        token: &str,
        organization_id: &OrganizationId,
        actor: &ActorRef,
        role: OrganizationRole,
        targets: &[SiliconId],
    ) -> Result<Vec<SiliconId>, IamError> {
        match actor.kind() {
            ActorKind::Silicon => Ok(targets
                .iter()
                .filter(|target| target.as_str() == actor.id().as_str())
                .cloned()
                .collect()),
            // Owners and administrators act on every Silicon in the
            // organization; the policy grants that without a directory read.
            ActorKind::Carbon
                if matches!(role, OrganizationRole::Owner | OrganizationRole::Admin) =>
            {
                Ok(targets.to_vec())
            }
            ActorKind::Carbon => {
                let mut visible = Vec::with_capacity(targets.len());
                for target in targets {
                    if self.silicon_visible(token, organization_id, target).await? {
                        visible.push(target.clone());
                    }
                }
                Ok(visible)
            }
        }
    }

    /// A Silicon is visible to the caller exactly when IAM returns its
    /// profile; IAM hides invisible and cross-organization Silicons as 404.
    async fn silicon_visible(
        &self,
        token: &str,
        organization_id: &OrganizationId,
        silicon_id: &SiliconId,
    ) -> Result<bool, IamError> {
        let url = self.api_url(&[
            "organizations",
            organization_id.as_str(),
            "silicons",
            silicon_id.as_str(),
        ])?;
        let response = self.bearer_get(token, url).await?;
        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => Ok(false),
            StatusCode::UNAUTHORIZED => Err(IamError::InvalidCredential),
            StatusCode::TOO_MANY_REQUESTS => Err(rate_limited(&response)),
            status => Err(IamError::UnexpectedStatus(status.as_u16())),
        }
    }

    fn begin_login(
        &self,
        organization_id: Option<&OrganizationId>,
    ) -> Result<LoginStart, IamError> {
        let login = self.login.as_ref().ok_or(IamError::NotConfigured)?;
        let mut options =
            AuthorizationOptions::new(login.redirect_uri.as_str(), login.scopes.iter().cloned())
                .map_err(|error| {
                    tracing::warn!(%error, "IAM login configuration is invalid");
                    IamError::NotConfigured
                })?;
        if let Some(organization_id) = organization_id {
            options = options
                .for_organization(organization_id.as_str())
                .map_err(|_| IamError::InvalidInput("org_id"))?;
        }
        let attempt = self
            .sdk
            .oauth()
            .begin_authorization(options)
            .map_err(sdk_error)?;
        let authorization_url = attempt.authorization_url().to_string();
        let continuation = self
            .sdk
            .oauth()
            .seal_authorization_attempt(attempt)
            .map_err(sdk_error)?;
        Ok(LoginStart {
            authorization_url,
            continuation: Zeroizing::new(continuation.expose_secret().to_owned()),
        })
    }

    async fn complete_login(
        &self,
        continuation: &str,
        callback_url: &str,
    ) -> Result<LoginOutcome, IamError> {
        if continuation.len() > MAX_CONTINUATION_BYTES {
            return Err(IamError::InvalidInput("continuation"));
        }
        if callback_url.len() > MAX_CALLBACK_URL_BYTES {
            return Err(IamError::InvalidInput("callback_url"));
        }
        let continuation = AuthorizationContinuation::from_encoded(continuation)
            .map_err(|_| IamError::InvalidInput("continuation"))?;
        let attempt = self
            .sdk
            .oauth()
            .restore_authorization_attempt(&continuation)
            .map_err(|_| IamError::InvalidInput("continuation"))?;
        let callback = attempt
            .parse_callback(callback_url)
            .map_err(|_| IamError::InvalidInput("callback_url"))?;
        match callback {
            AuthorizationCallback::Granted(grant) => {
                let tokens = self
                    .sdk
                    .oauth()
                    .exchange_authorization_code(grant)
                    .send()
                    .await
                    .map_err(|error| match sdk_error(error) {
                        IamError::Rejected { .. } | IamError::InvalidCredential => {
                            IamError::InvalidInput("callback_url")
                        }
                        other => other,
                    })?;
                Ok(LoginOutcome::Granted(issued_tokens(tokens.into_parts())?))
            }
            AuthorizationCallback::Denied(denied) => Ok(LoginOutcome::Denied {
                code: denied.code().to_owned(),
            }),
            _ => Err(IamError::InvalidResponse),
        }
    }

    async fn refresh(&self, refresh_token: &str) -> Result<IssuedTokens, IamError> {
        let refresh_token =
            OAuthRefreshToken::new(refresh_token).map_err(|_| IamError::InvalidCredential)?;
        let tokens = self
            .sdk
            .oauth()
            .refresh(refresh_token)
            .send()
            .await
            .map_err(|error| match sdk_error(error) {
                IamError::Rejected { .. } => IamError::InvalidCredential,
                other => other,
            })?;
        issued_tokens(tokens.into_parts())
    }

    async fn logout(&self, access_token: &str) -> Result<(), IamError> {
        let access_token =
            OAuthAccessToken::new(access_token).map_err(|_| IamError::InvalidCredential)?;
        self.sdk
            .logout(access_token)
            .send()
            .await
            .map(|_| ())
            .map_err(|error| match sdk_error(error) {
                IamError::Rejected { .. } => IamError::InvalidCredential,
                other => other,
            })
    }

    async fn register_silicon_webhook(
        &self,
        token: &str,
        organization_id: &OrganizationId,
        silicon_id: &SiliconId,
        endpoint_url: &Url,
        idempotency_key: &str,
    ) -> Result<RegisteredSiliconWebhook, IamError> {
        let url = self.api_url(&[
            "organizations",
            organization_id.as_str(),
            "silicons",
            silicon_id.as_str(),
            "webhook",
        ])?;
        let etag = self.current_webhook_etag(token, url.clone()).await?;
        let mut request = self
            .http
            .put(url)
            .bearer_auth(token)
            .header(API_VERSION_HEADER, API_VERSION)
            .header(
                "Idempotency-Key",
                iam_idempotency_key(organization_id, silicon_id, idempotency_key),
            )
            .json(&SiliconWebhookReplaceWire {
                url: endpoint_url.as_str(),
            });
        if let Some(etag) = etag {
            request = request.header(header::IF_MATCH, etag);
        }
        let response = request.send().await.map_err(transport_error)?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED => return Err(IamError::InvalidCredential),
            StatusCode::FORBIDDEN => return Err(IamError::Forbidden),
            StatusCode::NOT_FOUND => return Err(IamError::NotFound),
            StatusCode::TOO_MANY_REQUESTS => return Err(rate_limited(&response)),
            status @ (StatusCode::CONFLICT
            | StatusCode::PRECONDITION_FAILED
            | StatusCode::UNPROCESSABLE_ENTITY
            | StatusCode::PRECONDITION_REQUIRED) => {
                return Err(IamError::Rejected {
                    status: status.as_u16(),
                });
            }
            status => return Err(IamError::UnexpectedStatus(status.as_u16())),
        }
        let configured: SiliconWebhookConfiguredWire =
            bounded_json(response, self.max_response_bytes).await?;
        let raw = configured.webhook_signing_secret.into_zeroizing();
        if raw.len() != SILICON_WEBHOOK_SECRET_LENGTH
            || !raw.starts_with(SILICON_WEBHOOK_SECRET_PREFIX)
        {
            return Err(IamError::InvalidResponse);
        }
        let signing_secret =
            SigningSecret::from_zeroizing(raw).map_err(|_| IamError::InvalidResponse)?;
        Ok(RegisteredSiliconWebhook {
            signing_secret,
            secret_version: configured.webhook.secret_version,
        })
    }

    /// IAM requires `If-Match` when a webhook already exists and forbids it
    /// on first creation, so the current representation is read first.
    async fn current_webhook_etag(
        &self,
        token: &str,
        url: Url,
    ) -> Result<Option<String>, IamError> {
        let response = self.bearer_get(token, url).await?;
        match response.status() {
            StatusCode::OK => Ok(response
                .headers()
                .get(header::ETAG)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned)),
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::UNAUTHORIZED => Err(IamError::InvalidCredential),
            StatusCode::FORBIDDEN => Err(IamError::Forbidden),
            StatusCode::TOO_MANY_REQUESTS => Err(rate_limited(&response)),
            status => Err(IamError::UnexpectedStatus(status.as_u16())),
        }
    }

    async fn bearer_get(&self, token: &str, url: Url) -> Result<Response, IamError> {
        self.http
            .get(url)
            .bearer_auth(token)
            .header(API_VERSION_HEADER, API_VERSION)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(transport_error)
    }

    fn api_url(&self, segments: &[&str]) -> Result<Url, IamError> {
        let mut url = self.base_url.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| IamError::InvalidResponse)?;
            path.pop_if_empty().push("api").push(API_VERSION);
            for segment in segments {
                path.push(segment);
            }
        }
        url.set_query(None);
        url.set_fragment(None);
        Ok(url)
    }
}

fn build_verifier(settings: &IamWebhookSettings) -> Result<WebhookVerifier, IamError> {
    let secret = WebhookSecret::new(settings.secret.expose_secret())
        .map_err(|_| IamError::InvalidInput("iam_webhook_secret"))?;
    let mut keyring = WebhookSecretKeyring::new(settings.version, secret)
        .map_err(|_| IamError::InvalidInput("iam_webhook_secret_version"))?;
    if let Some((previous, version)) = &settings.previous {
        let previous = WebhookSecret::new(previous.expose_secret())
            .map_err(|_| IamError::InvalidInput("iam_webhook_previous_secret"))?;
        keyring
            .insert(*version, previous)
            .map_err(|_| IamError::InvalidInput("iam_webhook_previous_secret_version"))?;
    }
    Ok(WebhookVerifier::new(keyring))
}

/// A directory ID with an organization suffix is a global Silicon ID; any
/// other ID is a public Carbon ID. IAM never issues a Silicon ID whose suffix
/// differs from the organization it was read from.
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

fn actor_kind_from_sdk(kind: &silicon_iam::ActorKind) -> Option<ActorKind> {
    match kind {
        silicon_iam::ActorKind::Carbon => Some(ActorKind::Carbon),
        silicon_iam::ActorKind::Silicon => Some(ActorKind::Silicon),
        _ => None,
    }
}

fn issued_tokens(parts: OAuthTokenParts) -> Result<IssuedTokens, IamError> {
    let kind = actor_kind_from_sdk(parts.actor.kind()).ok_or(IamError::InvalidResponse)?;
    let actor =
        ActorRef::try_new(kind, parts.actor.public_id()).map_err(|_| IamError::InvalidResponse)?;
    let organization_id = parts
        .organization_id
        .map(OrganizationId::new)
        .transpose()
        .map_err(|_| IamError::InvalidResponse)?;
    Ok(IssuedTokens {
        access_token: Zeroizing::new(parts.access_token.expose_secret().to_owned()),
        refresh_token: Zeroizing::new(parts.refresh_token.expose_secret().to_owned()),
        expires_in: parts.expires_in,
        scopes: parts.scopes,
        actor,
        organization_id,
    })
}

fn sdk_error(error: silicon_iam::Error) -> IamError {
    match error {
        silicon_iam::Error::Api(api) => match api.status() {
            StatusCode::TOO_MANY_REQUESTS => IamError::RateLimited {
                retry_after: api.retry_after().unwrap_or(DEFAULT_RETRY_AFTER),
            },
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => IamError::InvalidCredential,
            status if api.is_retryable() => {
                IamError::Transport(anyhow::anyhow!("IAM returned HTTP {status}"))
            }
            status if status.is_client_error() => IamError::Rejected {
                status: status.as_u16(),
            },
            status => IamError::UnexpectedStatus(status.as_u16()),
        },
        silicon_iam::Error::Transport(transport) => {
            IamError::Transport(anyhow::Error::new(transport))
        }
        silicon_iam::Error::Handshake(handshake) => {
            IamError::Handshake(anyhow::Error::new(handshake))
        }
        silicon_iam::Error::Configuration(_) => IamError::NotConfigured,
        _ => IamError::InvalidResponse,
    }
}

fn transport_error(error: reqwest::Error) -> IamError {
    IamError::Transport(anyhow::Error::new(error))
}

fn rate_limited(response: &Response) -> IamError {
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map_or(DEFAULT_RETRY_AFTER, Duration::from_secs);
    IamError::RateLimited { retry_after }
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

async fn bounded_json<T>(response: Response, maximum: usize) -> Result<T, IamError>
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
    let mut response = response;
    let mut body = Zeroizing::new(Vec::<u8>::new());
    while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
        let remaining = maximum.saturating_sub(body.len());
        if chunk.len() > remaining {
            return Err(IamError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| IamError::InvalidResponse)
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

#[derive(Deserialize)]
struct DirectoryMemberWire {
    id: String,
    #[serde(default)]
    role: Option<DirectoryRoleWire>,
    #[serde(default)]
    org: Option<DirectoryOrganizationWire>,
}

#[derive(Deserialize)]
struct DirectoryRoleWire {
    org_role: OrganizationRoleWire,
}

#[derive(Deserialize)]
struct DirectoryOrganizationWire {
    id: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OrganizationRoleWire {
    Owner,
    Admin,
    Member,
}

impl OrganizationRoleWire {
    const fn into_domain(self) -> OrganizationRole {
        match self {
            Self::Owner => OrganizationRole::Owner,
            Self::Admin => OrganizationRole::Admin,
            Self::Member => OrganizationRole::Member,
        }
    }
}

#[derive(serde::Serialize)]
struct SiliconWebhookReplaceWire<'a> {
    url: &'a str,
}

#[derive(Deserialize)]
struct SiliconWebhookConfiguredWire {
    webhook: SiliconWebhookWire,
    webhook_signing_secret: SecretWire,
}

#[derive(Deserialize)]
struct SiliconWebhookWire {
    secret_version: u64,
}

/// Secret-bearing wire field that is wiped when dropped.
#[derive(Deserialize)]
#[serde(transparent)]
struct SecretWire(String);

impl SecretWire {
    fn into_zeroizing(mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut self.0))
    }
}

impl Drop for SecretWire {
    fn drop(&mut self) {
        self.0.zeroize();
    }
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
        AuthorizationRequest, IamClient, IamError, LoginOutcome, actor_from_directory,
        iam_idempotency_key,
    };
    use crate::{
        config::{IamSettings, IamWebhookSettings, LoginSettings},
        domain::{ActorKind, OrganizationId, OrganizationRole, SiliconId},
    };

    const APP_ID: &str = "silicon-hook";
    const APP_SECRET: &str = "ask_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const WEBHOOK_SECRET: &str = "whs_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const ACCESS_TOKEN: &str = "oat_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    const SILICON_TOKEN: &str = "sat_DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
    const CARBON_TOKEN: &str = "cat_EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";

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
            login: Some(LoginSettings {
                redirect_uri: Url::parse("https://hook.example.test/auth/callback")?,
                scopes: vec!["profile".to_owned(), "memberships.read".to_owned()],
            }),
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
            login: None,
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
            "authorization_epoch": 4
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
    async fn hook_issued_tokens_are_introspected_then_resolved_through_the_directory()
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
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organizations/tos/silicons/cos:tos"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organizations/tos/silicons/hidden:tos"))
            .respond_with(ResponseTemplate::new(404))
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
    async fn administrators_skip_per_silicon_visibility_reads()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = iam_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organizations/tos/directory/self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(directory("bob", "admin")))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/organizations/tos/silicons/cos:tos"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let client = IamClient::connect(&settings(&server)?).await?;
        let context = client
            .authorize(&request(CARBON_TOKEN, &["cos:tos"])?)
            .await?;
        assert_eq!(context.organization_role(), OrganizationRole::Admin);
        assert!(context.has_silicon_visibility(&SiliconId::new("cos:tos")?));
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
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let client = IamClient::connect(&settings(&server)?).await?;
        assert!(matches!(
            client.authorize(&request(ACCESS_TOKEN, &[])?).await,
            Err(IamError::InvalidCredential)
        ));
        assert!(matches!(
            client.authorize(&request(SILICON_TOKEN, &[])?).await,
            Err(IamError::InvalidCredential)
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
                    .set_body_json(serde_json::json!({"secret_version": 2, "version": 7})),
            )
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/api/v1/organizations/tos/silicons/cos:tos/webhook"))
            .and(header("if-match", "\"7\""))
            .and(header("idempotency-key", expected_key.as_str()))
            .and(header(
                "authorization",
                format!("Bearer {SILICON_TOKEN}").as_str(),
            ))
            .and(body_json(serde_json::json!({"url": endpoint.as_str()})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "webhook": {
                    "silicon_id": "cos:tos",
                    "url": endpoint.as_str(),
                    "status": "active",
                    "secret_version": 3,
                    "version": 8
                },
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
        assert_eq!(verified.event().event_type().as_str(), "session.logout.v1");

        headers.insert("x-silicon-iam-key-version", HeaderValue::from_static("2"));
        assert!(matches!(
            client.verify_application_webhook(&headers, body.as_bytes()),
            Err(IamError::WebhookRejected(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn login_begins_with_the_registered_redirect_and_denials_are_reported()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = iam_server().await;
        let client = IamClient::connect(&settings(&server)?).await?;
        let start = client.begin_login(Some(&OrganizationId::new("tos")?))?;
        let url = Url::parse(&start.authorization_url)?;
        assert!(url.as_str().starts_with(&server.uri()));
        let query = url.query_pairs().collect::<Vec<_>>();
        assert!(
            query
                .iter()
                .any(|(key, value)| key == "client_id" && value == APP_ID)
        );
        assert!(
            query
                .iter()
                .any(|(key, value)| key == "org_id" && value == "tos")
        );
        let state = query
            .iter()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.to_string())
            .ok_or("authorization URL carries state")?;

        let denied = client
            .complete_login(
                &start.continuation,
                &format!(
                    "https://hook.example.test/auth/callback?error=access_denied&state={state}"
                ),
            )
            .await?;
        assert!(matches!(denied, LoginOutcome::Denied { code } if code == "access_denied"));
        assert!(matches!(
            client
                .complete_login(
                    "not-a-continuation",
                    "https://hook.example.test/auth/callback"
                )
                .await,
            Err(IamError::InvalidInput("continuation"))
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
            client.begin_login(None),
            Err(IamError::NotConfigured)
        ));
        assert!(matches!(
            client.authorize(&request(ACCESS_TOKEN, &[])?).await,
            Err(IamError::NotConfigured)
        ));
        Ok(())
    }
}
