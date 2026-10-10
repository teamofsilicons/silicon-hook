//! Hook's delivery adapter for Ting in the Silicon Accounts era.
//!
//! - Sends and receipts use an App verification proof for Ting's app
//!   (`HOOK_TING_APP_ID`, `ting` by default; scopes `tings.send` and
//!   `sent.query`). Hook keeps each proof and
//!   its rotating refresh token in memory, refreshes single-flight shortly
//!   before expiry, and issues a new proof when a refresh is refused.
//! - Enrolling a recipient uses a User verification proof (scope
//!   `tings.subscribe`) issued from the caller's own Hook access token while
//!   the request is live; it is used once and never stored.
//!
//! - A failed proof request pauses further ones for that scope (30 seconds,
//!   doubling up to 5 minutes), so a queue of sends cannot turn one cause (an
//!   unknown Ting app, Silicon Accounts unavailable) into a request per send.
//!
//! Nothing here runs unless `HOOK_TING_URL` is set.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use secrecy::{ExposeSecret as _, SecretString};
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::infrastructure::{
    accounts::{AccountsError, AccountsGateway},
    ting::{
        TingAcceptance, TingClient, TingDeliveryMode, TingError, TingReceipt, TingRecipient,
        TingSubscription,
    },
};

/// Ting's Silicon Accounts app id unless `HOOK_TING_APP_ID` names another.
pub const TING_APP_ID: &str = crate::config::DEFAULT_TING_APP_ID;
/// Scope of the App verification proof Hook sends with.
pub const SEND_SCOPE: &str = "tings.send";
/// Scope of the App verification proof Hook reads receipts with.
pub const RECEIPT_SCOPE: &str = "sent.query";
/// Scope of the User verification proof that enrols a recipient.
pub const SUBSCRIBE_SCOPE: &str = "tings.subscribe";
/// A cached proof is renewed this long before it expires.
const RENEW_BEFORE_EXPIRY: time::Duration = time::Duration::seconds(60);
/// Pause after a first failed proof request; it doubles with each consecutive
/// failure up to [`MAX_PROOF_PAUSE`].
pub const FIRST_PROOF_PAUSE: Duration = Duration::from_secs(30);
/// Longest pause between proof requests while they keep failing.
pub const MAX_PROOF_PAUSE: Duration = Duration::from_secs(300);

/// Why a delivery operation failed.
#[derive(Debug)]
pub enum DeliveryError {
    /// Silicon Accounts could not issue or refresh the proof.
    Proof(AccountsError),
    /// A recent proof request failed; Hook asks Silicon Accounts again only
    /// after the pause.
    ProofPaused {
        /// Time left before the next proof request.
        retry_in: Duration,
        /// What the last failed request answered.
        reason: String,
    },
    /// Ting refused or could not be reached.
    Ting(TingError),
}

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proof(error) => write!(formatter, "no proof for Ting: {error}"),
            Self::ProofPaused { retry_in, reason } => write!(
                formatter,
                "no proof for Ting: asking Silicon Accounts again in {}s (last answer: {reason})",
                retry_in.as_secs().max(1)
            ),
            Self::Ting(error) => write!(formatter, "Ting: {error}"),
        }
    }
}

/// How long proof requests pause after `failures` consecutive failures.
#[must_use]
pub fn proof_pause(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(8);
    FIRST_PROOF_PAUSE
        .saturating_mul(1 << doublings)
        .min(MAX_PROOF_PAUSE)
}

#[cfg(test)]
mod pause_tests {
    use std::time::Duration;

    use super::proof_pause;

    #[test]
    fn proof_requests_pause_longer_after_each_failure_up_to_five_minutes() {
        let seconds = |failures| proof_pause(failures).as_secs();
        assert_eq!(
            [0, 1, 2, 3, 4, 5, 40].map(seconds),
            [30, 30, 60, 120, 240, 300, 300]
        );
        assert_eq!(proof_pause(u32::MAX), Duration::from_secs(300));
    }
}

impl std::error::Error for DeliveryError {}

struct CachedProof {
    token: SecretString,
    refresh: Option<SecretString>,
    expires_at: Option<OffsetDateTime>,
}

impl CachedProof {
    fn fresh(&self) -> bool {
        self.expires_at
            .is_none_or(|expires_at| OffsetDateTime::now_utc() + RENEW_BEFORE_EXPIRY < expires_at)
    }
}

#[derive(Default)]
struct CacheState {
    proof: Option<CachedProof>,
    /// Consecutive failed proof requests.
    failures: u32,
    /// No proof request before this instant.
    paused_until: Option<Instant>,
    /// What the last failed request answered.
    last_failure: String,
}

/// One App verification proof for Ting, renewed single-flight.
struct ProofCache {
    scope: &'static str,
    state: Mutex<CacheState>,
}

impl ProofCache {
    fn new(scope: &'static str) -> Self {
        Self {
            scope,
            state: Mutex::new(CacheState::default()),
        }
    }

    async fn token(
        &self,
        accounts: &AccountsGateway,
        receiving_app: &str,
    ) -> Result<SecretString, DeliveryError> {
        // Holding the lock across the network call makes renewal single-flight:
        // a rotating refresh token is never presented twice.
        let mut state = self.state.lock().await;
        if let Some(cached) = state.proof.as_ref()
            && cached.fresh()
        {
            return Ok(cached.token.clone());
        }
        if let Some(until) = state.paused_until {
            let now = Instant::now();
            if now < until {
                return Err(DeliveryError::ProofPaused {
                    retry_in: until - now,
                    reason: state.last_failure.clone(),
                });
            }
        }
        match Self::obtain(&mut state, accounts, receiving_app, self.scope).await {
            Ok(token) => {
                state.failures = 0;
                state.paused_until = None;
                Ok(token)
            }
            Err(error) => {
                state.failures = state.failures.saturating_add(1);
                let pause = proof_pause(state.failures);
                state.paused_until = Some(Instant::now() + pause);
                state.last_failure = error.to_string();
                tracing::warn!(
                    %error,
                    scope = self.scope,
                    receiving_app,
                    pause_seconds = pause.as_secs(),
                    "Hook could not get a Silicon Accounts proof for Ting; queued sends wait for the next attempt"
                );
                Err(DeliveryError::Proof(error))
            }
        }
    }

    async fn obtain(
        state: &mut CacheState,
        accounts: &AccountsGateway,
        receiving_app: &str,
        scope: &'static str,
    ) -> Result<SecretString, AccountsError> {
        if let Some(refresh) = state
            .proof
            .as_ref()
            .and_then(|cached| cached.refresh.clone())
        {
            match accounts.refresh_proof(refresh.expose_secret()).await {
                Ok(issued) => {
                    let cached = cache(issued);
                    let token = cached.token.clone();
                    state.proof = Some(cached);
                    return Ok(token);
                }
                Err(AccountsError::Rejected { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        let issued = accounts
            .issue_app_verification(receiving_app, &[scope])
            .await?;
        let cached = cache(issued);
        let token = cached.token.clone();
        state.proof = Some(cached);
        Ok(token)
    }

    /// Forgets the proof token after Ting refused it; the refresh token stays.
    async fn forget_token(&self, refused: &SecretString) {
        let mut state = self.state.lock().await;
        if let Some(cached) = state.proof.as_mut()
            && cached.token.expose_secret() == refused.expose_secret()
        {
            cached.expires_at = Some(OffsetDateTime::UNIX_EPOCH);
        }
    }
}

fn cache(issued: silicon_accounts_client::IssuedProof) -> CachedProof {
    CachedProof {
        token: SecretString::from(issued.proof_token.expose().to_owned()),
        refresh: issued
            .proof_refresh_token
            .map(|token| SecretString::from(token.expose().to_owned())),
        expires_at: issued.expires_at,
    }
}

/// Ting delivery for one Hook process.
#[derive(Clone)]
pub struct TingAdapter {
    inner: Arc<Inner>,
}

struct Inner {
    client: TingClient,
    accounts: AccountsGateway,
    receiving_app: String,
    send: ProofCache,
    receipts: ProofCache,
}

impl std::fmt::Debug for TingAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TingAdapter")
            .field("origin", &self.inner.client.origin().as_str())
            .field("receiving_app", &self.inner.receiving_app)
            .finish_non_exhaustive()
    }
}

impl TingAdapter {
    /// Composes the adapter from the configured transport, the Accounts
    /// gateway and Ting's Silicon Accounts app id (the receiving app of every
    /// proof, normally [`TING_APP_ID`]).
    #[must_use]
    pub fn new(
        client: TingClient,
        accounts: AccountsGateway,
        receiving_app: impl Into<String>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                client,
                accounts,
                receiving_app: receiving_app.into(),
                send: ProofCache::new(SEND_SCOPE),
                receipts: ProofCache::new(RECEIPT_SCOPE),
            }),
        }
    }

    fn app_id(&self) -> &str {
        self.inner.accounts.app_id()
    }

    /// Sends exact persisted bytes as Hook. A proof Ting refuses is renewed
    /// once and the same bytes are sent again.
    ///
    /// # Errors
    ///
    /// Returns a proof or Ting failure.
    pub async fn send(&self, prepared_body: &[u8]) -> Result<TingAcceptance, DeliveryError> {
        let mut retried = false;
        loop {
            let proof = self
                .inner
                .send
                .token(&self.inner.accounts, &self.inner.receiving_app)
                .await?;
            match self
                .inner
                .client
                .send(&proof, self.app_id(), prepared_body)
                .await
            {
                Err(error) if error.proof_refused() && !retried => {
                    self.inner.send.forget_token(&proof).await;
                    retried = true;
                }
                result => return result.map_err(DeliveryError::Ting),
            }
        }
    }

    /// Reads Ting's receipt for one accepted send.
    ///
    /// # Errors
    ///
    /// Returns a proof or Ting failure.
    pub async fn receipt(
        &self,
        ting_id: &str,
        recipient_uuid: &str,
        delivery: TingDeliveryMode,
    ) -> Result<TingReceipt, DeliveryError> {
        let proof = self
            .inner
            .receipts
            .token(&self.inner.accounts, &self.inner.receiving_app)
            .await?;
        let result = self
            .inner
            .client
            .receipt(&proof, self.app_id(), ting_id, recipient_uuid, delivery)
            .await;
        if result.as_ref().is_err_and(TingError::proof_refused) {
            self.inner.receipts.forget_token(&proof).await;
        }
        result.map_err(DeliveryError::Ting)
    }

    /// Enrols the caller as a recipient of Hook's notifications, with a User
    /// verification proof issued from the caller's current Hook access token.
    ///
    /// # Errors
    ///
    /// Returns a proof or Ting failure.
    pub async fn enrol(
        &self,
        subject_token: &SecretString,
        recipient: &TingRecipient,
    ) -> Result<TingSubscription, DeliveryError> {
        let issued = self
            .inner
            .accounts
            .issue_user_verification(
                subject_token.expose_secret(),
                &self.inner.receiving_app,
                &[SUBSCRIBE_SCOPE],
            )
            .await
            .map_err(DeliveryError::Proof)?;
        let proof = SecretString::from(issued.proof_token.expose().to_owned());
        self.inner
            .client
            .register_recipient(&proof, self.app_id(), recipient)
            .await
            .map_err(DeliveryError::Ting)
    }
}
