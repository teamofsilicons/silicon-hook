//! Silicon Accounts: access-token verification, account lookups, proofs and
//! webhook signatures, through the official `silicon-accounts-client`.
//!
//! Access tokens are verified locally against a cached JWKS that is fetched
//! again (at most once every [`JWKS_REFETCH_INTERVAL`]) when a token names a
//! key the cache does not hold. Introspection, used only where revocation must
//! be seen at once, is cached for at most [`INTROSPECTION_CACHE_TTL`].

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use silicon_accounts_client::{
    AccountSummary, AccountsClient, Claims, DEFAULT_WEBHOOK_TOLERANCE, Error as ClientError,
    IssueAppVerification, IssueUserVerification, IssuedProof, Jwks, TokenError, VerifyOptions,
    WebhookError, WebhookEvent, verify_access_token, verify_and_parse_webhook,
};
use tokio::sync::RwLock;

use crate::config::AccountsSettings;

/// Minimum interval between JWKS fetches triggered by unknown key ids: a
/// rotated key is picked up at once, while tokens with made-up key ids cannot
/// make Hook fetch the key set more than once a second.
pub const JWKS_REFETCH_INTERVAL: Duration = Duration::from_secs(1);
/// How long a token Silicon Accounts called inactive is refused without
/// asking again (a revoked token never becomes active, and access tokens live
/// 30 minutes). An active answer is never reused: the routes that introspect
/// must see a sign-out at once.
pub const INACTIVE_TOKEN_MEMORY: Duration = Duration::from_mins(30);
/// Account lookups this process makes per minute at most: half of the 600
/// Silicon Accounts allows one app, leaving room for other replicas.
pub const LOOKUPS_PER_MINUTE: u32 = 300;
const MAX_REMEMBERED_INACTIVE_TOKENS: usize = 10_000;

/// Why an access token was refused, with a message that says what to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenRejection {
    /// Stable code, such as `token_expired`.
    pub code: &'static str,
    /// What is wrong and what to do next.
    pub message: String,
}

/// A failure to use Silicon Accounts.
#[derive(Debug)]
pub enum AccountsError {
    /// Accounts could not be reached or answered unexpectedly; retrying may help.
    Unavailable(String),
    /// Accounts refused the request.
    Rejected {
        /// HTTP status.
        status: u16,
        /// Accounts error code.
        code: String,
        /// Accounts' explanation.
        message: String,
    },
}

impl fmt::Display for AccountsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) => {
                write!(formatter, "Silicon Accounts is unavailable: {message}")
            }
            Self::Rejected {
                status,
                code,
                message,
            } => write!(
                formatter,
                "Silicon Accounts refused ({status} {code}): {message}"
            ),
        }
    }
}

impl std::error::Error for AccountsError {}

impl From<ClientError> for AccountsError {
    fn from(error: ClientError) -> Self {
        match error.status() {
            Some(status) if (400..500).contains(&status) && status != 429 => Self::Rejected {
                status,
                code: error.code().to_owned(),
                message: error.message(),
            },
            _ => Self::Unavailable(error.message()),
        }
    }
}

/// Result of looking an account up.
#[derive(Clone, Debug)]
pub enum Lookup {
    /// The account exists.
    Found(Box<AccountSummary>),
    /// No account has this uuid or current id.
    NotFound,
    /// The account was deleted (its uuid is never reused).
    Deleted,
}

/// Why a webhook delivery was refused.
#[derive(Debug)]
pub enum WebhookRejection {
    /// No webhook secret is configured, so nothing can be verified.
    NotConfigured,
    /// Missing or wrong signature headers, a stale timestamp or a bad signature.
    Signature(WebhookError),
    /// The signature verified but the body is not an Accounts event.
    Body(WebhookError),
}

/// Cheap, cloneable handle to Silicon Accounts for one app.
#[derive(Clone)]
pub struct AccountsGateway {
    inner: Arc<Inner>,
}

struct Inner {
    client: AccountsClient,
    app_id: String,
    app_secret: SecretString,
    issuer: String,
    webhook_secrets: Vec<SecretString>,
    jwks: RwLock<JwksState>,
    jwks_fetch: tokio::sync::Mutex<()>,
    inactive_tokens: Mutex<HashMap<[u8; 32], Instant>>,
    lookups: Mutex<(Instant, u32)>,
}

#[derive(Default)]
struct JwksState {
    keys: Arc<Jwks>,
    fetched_at: Option<Instant>,
}

impl fmt::Debug for AccountsGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountsGateway")
            .field("app_id", &self.inner.app_id)
            .field("issuer", &self.inner.issuer)
            .finish_non_exhaustive()
    }
}

impl AccountsGateway {
    /// Builds a gateway from validated settings. Nothing is fetched yet.
    ///
    /// # Errors
    ///
    /// Returns an error when the HTTP client cannot be built.
    pub fn new(settings: &AccountsSettings) -> Result<Self, AccountsError> {
        let client = AccountsClient::builder()
            .base_url(settings.api_origin())
            .timeout(settings.request_timeout)
            .connect_timeout(settings.request_timeout.min(Duration::from_secs(5)))
            .user_agent(concat!("silicon-hook/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            inner: Arc::new(Inner {
                client,
                app_id: settings.app_id.clone(),
                app_secret: settings.app_secret.clone(),
                issuer: settings.issuer(),
                webhook_secrets: settings.webhook_secrets.clone(),
                jwks: RwLock::new(JwksState::default()),
                jwks_fetch: tokio::sync::Mutex::new(()),
                inactive_tokens: Mutex::new(HashMap::new()),
                lookups: Mutex::new((Instant::now(), 0)),
            }),
        })
    }

    /// Hook's app id (the `aud` of its tokens).
    #[must_use]
    pub fn app_id(&self) -> &str {
        &self.inner.app_id
    }

    /// The issuer Hook accepts (`iss`), which is also the public Accounts URL.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.inner.issuer
    }

    /// Whether a webhook secret is configured.
    #[must_use]
    pub fn webhook_configured(&self) -> bool {
        !self.inner.webhook_secrets.is_empty()
    }

    /// Verifies an access token issued to Hook by Silicon Accounts.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyFailure::Rejected`] for a token that is not valid for
    /// Hook, and [`VerifyFailure::Unavailable`] when the signing keys cannot
    /// be fetched.
    pub async fn verify(&self, token: &str) -> Result<Claims, VerifyFailure> {
        let options =
            VerifyOptions::for_app(&self.inner.app_id).with_issuer(self.inner.issuer.clone());
        let keys = self.current_keys().await?;
        match verify_access_token(&keys, token, &options) {
            Err(ClientError::Token(TokenError::UnknownKey { .. })) => {
                let keys = self.refetch_keys(&keys).await?;
                verify_access_token(&keys, token, &options).map_err(rejection)
            }
            result => result.map_err(rejection),
        }
    }

    async fn current_keys(&self) -> Result<Arc<Jwks>, VerifyFailure> {
        {
            let state = self.inner.jwks.read().await;
            if state.fetched_at.is_some() {
                return Ok(Arc::clone(&state.keys));
            }
        }
        self.fetch_keys(None).await
    }

    async fn refetch_keys(&self, seen: &Arc<Jwks>) -> Result<Arc<Jwks>, VerifyFailure> {
        self.fetch_keys(Some(seen)).await
    }

    /// Fetches the JWKS once at a time. A caller that saw `seen` refetches
    /// only when nobody replaced it meanwhile and the last fetch is older than
    /// the refetch interval, so random key ids cannot make Hook hammer Accounts.
    async fn fetch_keys(&self, seen: Option<&Arc<Jwks>>) -> Result<Arc<Jwks>, VerifyFailure> {
        let _single_flight = self.inner.jwks_fetch.lock().await;
        {
            let state = self.inner.jwks.read().await;
            if let Some(fetched_at) = state.fetched_at {
                let replaced = seen.is_none_or(|seen| !Arc::ptr_eq(seen, &state.keys));
                if replaced || fetched_at.elapsed() < JWKS_REFETCH_INTERVAL {
                    return Ok(Arc::clone(&state.keys));
                }
            }
        }
        let keys = Arc::new(self.inner.client.jwks().await.map_err(|error| {
            VerifyFailure::Unavailable(format!(
                "could not fetch the Silicon Accounts signing keys: {}",
                error.message()
            ))
        })?);
        let mut state = self.inner.jwks.write().await;
        state.keys = Arc::clone(&keys);
        state.fetched_at = Some(Instant::now());
        Ok(keys)
    }

    /// Asks Silicon Accounts whether a token is still active, so a sign-out
    /// is seen at once. Only inactive answers are remembered (for
    /// [`INACTIVE_TOKEN_MEMORY`]).
    ///
    /// # Errors
    ///
    /// Returns an error when Accounts cannot answer.
    pub async fn introspect_active(&self, token: &str) -> Result<bool, AccountsError> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        if let Ok(remembered) = self.inner.inactive_tokens.lock()
            && remembered
                .get(&digest)
                .is_some_and(|at| at.elapsed() < INACTIVE_TOKEN_MEMORY)
        {
            return Ok(false);
        }
        let answer = self.app().introspect(token).await?;
        let active = answer.active
            && answer
                .client_id
                .as_deref()
                .is_none_or(|app| app == self.app_id());
        if !active && let Ok(mut remembered) = self.inner.inactive_tokens.lock() {
            if remembered.len() >= MAX_REMEMBERED_INACTIVE_TOKENS {
                remembered.retain(|_, at| at.elapsed() < INACTIVE_TOKEN_MEMORY);
                if remembered.len() >= MAX_REMEMBERED_INACTIVE_TOKENS {
                    remembered.clear();
                }
            }
            remembered.insert(digest, Instant::now());
        }
        Ok(active)
    }

    /// Looks an account up by uuid (counts against 600 lookups per minute).
    ///
    /// # Errors
    ///
    /// Returns an error when Accounts cannot answer.
    pub async fn lookup(&self, uuid: &str) -> Result<Lookup, AccountsError> {
        self.spend_lookup()?;
        classify_lookup(self.app().lookup(uuid).await)
    }

    /// Counts one lookup against this process's per-minute budget.
    fn spend_lookup(&self) -> Result<(), AccountsError> {
        let mut budget =
            self.inner.lookups.lock().map_err(|_| {
                AccountsError::Unavailable("the lookup budget is poisoned".to_owned())
            })?;
        if budget.0.elapsed() >= Duration::from_secs(60) {
            *budget = (Instant::now(), 0);
        }
        if budget.1 >= LOOKUPS_PER_MINUTE {
            return Err(AccountsError::Unavailable(format!(
                "Hook already looked up {LOOKUPS_PER_MINUTE} accounts this minute; retry in a minute"
            )));
        }
        budget.1 += 1;
        Ok(())
    }

    /// Looks an account up by its current `c:`/`si:` id.
    ///
    /// # Errors
    ///
    /// Returns an error when Accounts cannot answer.
    pub async fn lookup_by_id(&self, id: &str) -> Result<Lookup, AccountsError> {
        self.spend_lookup()?;
        classify_lookup(self.app().lookup_by_id(id).await)
    }

    /// Gets a User verification proof that Hook may act at `receiving_app` for
    /// the account behind `subject_token` (a Hook access token).
    ///
    /// # Errors
    ///
    /// Returns an error when Accounts refuses or cannot answer.
    pub async fn issue_user_verification(
        &self,
        subject_token: &str,
        receiving_app: &str,
        scopes: &[&str],
    ) -> Result<IssuedProof, AccountsError> {
        let request = IssueUserVerification {
            subject_token: subject_token.to_owned(),
            receiving_app: receiving_app.to_owned(),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            access_ttl_seconds: None,
        };
        let key = idempotency_key("user-verification");
        Ok(self
            .app()
            .issue_user_verification(&request, Some(&key))
            .await?)
    }

    /// Gets an App verification proof for Hook itself at `receiving_app`.
    ///
    /// # Errors
    ///
    /// Returns an error when Accounts refuses or cannot answer.
    pub async fn issue_app_verification(
        &self,
        receiving_app: &str,
        scopes: &[&str],
    ) -> Result<IssuedProof, AccountsError> {
        let request = IssueAppVerification {
            receiving_app: receiving_app.to_owned(),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            access_ttl_seconds: None,
        };
        let key = idempotency_key("app-verification");
        Ok(self
            .app()
            .issue_app_verification(&request, Some(&key))
            .await?)
    }

    /// Exchanges a proof refresh token (which rotates) for a new proof.
    ///
    /// # Errors
    ///
    /// Returns an error when Accounts refuses or cannot answer.
    pub async fn refresh_proof(&self, refresh_token: &str) -> Result<IssuedProof, AccountsError> {
        Ok(self.app().refresh_proof(refresh_token, None).await?)
    }

    /// Verifies a webhook delivery against the raw body bytes with the current
    /// secret, then the previous one while a rotation overlaps.
    ///
    /// # Errors
    ///
    /// Returns why the delivery cannot be trusted or parsed.
    pub fn verify_webhook(
        &self,
        timestamp: &str,
        signature: &str,
        body: &[u8],
    ) -> Result<WebhookEvent, WebhookRejection> {
        let mut last = None;
        for secret in &self.inner.webhook_secrets {
            match verify_and_parse_webhook(
                secret.expose_secret(),
                timestamp,
                signature,
                body,
                DEFAULT_WEBHOOK_TOLERANCE,
            ) {
                Ok(event) => return Ok(event),
                Err(error @ WebhookError::InvalidBody(_)) => {
                    return Err(WebhookRejection::Body(error));
                }
                Err(WebhookError::SignatureMismatch) => {
                    last = Some(WebhookError::SignatureMismatch);
                }
                Err(error) => return Err(WebhookRejection::Signature(error)),
            }
        }
        Err(last.map_or(WebhookRejection::NotConfigured, WebhookRejection::Signature))
    }

    fn app(&self) -> silicon_accounts_client::AppClient<'_> {
        self.inner
            .client
            .as_app(&self.inner.app_id, self.inner.app_secret.expose_secret())
    }
}

/// Why a token could not be verified.
#[derive(Debug)]
pub enum VerifyFailure {
    /// The token is not a valid Hook access token.
    Rejected(TokenRejection),
    /// The signing keys could not be fetched.
    Unavailable(String),
}

fn rejection(error: ClientError) -> VerifyFailure {
    match error {
        ClientError::Token(token) => VerifyFailure::Rejected(TokenRejection {
            code: token.code(),
            message: format!("{} {}", token.message(), token_hint(&token)),
        }),
        other => VerifyFailure::Rejected(TokenRejection {
            code: "token_invalid",
            message: other.message(),
        }),
    }
}

fn token_hint(error: &TokenError) -> &'static str {
    match error {
        TokenError::Expired { .. } => {
            "Refresh the session (hook login status shows it) or sign in again with hook login."
        }
        TokenError::WrongAudience { .. } => {
            "Send a token issued to Hook: sign in with hook login, or exchange a short-lived token minted with silicon-accounts login --app hook."
        }
        TokenError::WrongIssuer { .. } => {
            "The token comes from a different Silicon Accounts deployment than the one Hook trusts (ACCOUNTS_URL)."
        }
        _ => "Send the access_token Silicon Accounts issued to Hook, exactly as received.",
    }
}

fn classify_lookup(result: Result<AccountSummary, ClientError>) -> Result<Lookup, AccountsError> {
    match result {
        Ok(summary) if summary.status == "deleted" => Ok(Lookup::Deleted),
        Ok(summary) => Ok(Lookup::Found(Box::new(summary))),
        Err(error) if error.is_code("account_deleted") => Ok(Lookup::Deleted),
        Err(error)
            if error.is_code("account_not_found")
                || error.is_code("invalid_id")
                || error.is_code("invalid_uuid") =>
        {
            Ok(Lookup::NotFound)
        }
        Err(error) => Err(error.into()),
    }
}

fn idempotency_key(purpose: &str) -> String {
    format!("hook-{purpose}-{}", uuid::Uuid::now_v7().simple())
}
