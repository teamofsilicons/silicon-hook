//! Signing in to Hook with Silicon Accounts as Hook's public client.
//!
//! Hook's command-line tools have no secret, so they use the two sign-ins
//! Silicon Accounts offers public clients (`client_id` = `hook`, no secret):
//!
//! * **Carbons**: the device flow. [`SignIn::start_device`] returns a code and a
//!   URL; the Carbon approves it on the account site while
//!   [`SignIn::wait_for_device`] polls (honouring `interval` and `slow_down`,
//!   up to the code's 10 minutes).
//! * **Silicons** (and Carbons holding one): a short-lived token from
//!   `silicon-accounts login --app hook -q`, exchanged with
//!   [`SignIn::exchange_slt`]. It works once, for two minutes.
//!
//! Both return [`Tokens`]: a 30-minute access token issued to Hook (send it with
//! [`crate::Client::with_token`]) and a rotating refresh token. Every refresh
//! spends the refresh token it sends and returns a new one; presenting a spent
//! one again ends the whole sign-in. So refresh one at a time per sign-in, and
//! store the new pair before using it. [`SignIn::revoke`] signs out.
//!
//! Servers that hold Hook's app secret use `silicon-accounts-client`'s
//! `AppClient` instead.

use std::time::Duration;

use reqwest::Url;
use serde::{Deserialize, Serialize};
use silicon_accounts_client::{AccountsClient, TokenResponse};
use time::OffsetDateTime;

use crate::{
    Error, Result,
    client::is_loopback,
    models::{AccountKind, Secret},
};

mod error;
mod flows;
use error::Step;
pub use error::{SLT_COMMAND, SignInError, SignInErrorKind, SltRefusal};

/// Production Silicon Accounts.
pub const DEFAULT_ACCOUNTS_URL: &str = "https://accounts.teamofsilicons.com";
/// Hook's app id at Silicon Accounts.
pub const APP_ID: &str = "hook";
const SLT_GRANT_TYPE: &str = "urn:silicon:params:oauth:grant-type:slt";

/// The account a sign-in belongs to.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Account {
    /// Permanent uuid (key everything on it).
    pub uuid: String,
    /// Carbon or Silicon.
    pub kind: AccountKind,
    /// Current `c:`/`si:` id (can change).
    pub id: String,
    /// Display name.
    #[serde(default)]
    pub display_name: String,
    /// Profile photo URL.
    #[serde(default)]
    pub pfp_url: String,
    /// A Silicon's custodian, `{uuid, id}`.
    #[serde(default)]
    pub custodian: Option<AccountLink>,
}

/// Another account, by uuid and current id.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AccountLink {
    /// Permanent uuid.
    pub uuid: String,
    /// Current id.
    #[serde(default)]
    pub id: String,
}

/// Hook tokens from Silicon Accounts.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Tokens {
    /// 30-minute access token (`aud` = `hook`).
    pub access_token: Secret,
    /// Rotating refresh token (`sar_…`).
    pub refresh_token: Option<Secret>,
    /// Seconds until the access token expires, counted from receipt.
    pub expires_in: u64,
    /// When the sign-in ends (at most 900 days after it started).
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub refresh_expires_at: Option<OffsetDateTime>,
    /// Granted scopes, space separated.
    #[serde(default)]
    pub scope: Option<String>,
    /// Who signed in.
    #[serde(default)]
    pub account: Option<Account>,
}

impl From<TokenResponse> for Tokens {
    fn from(response: TokenResponse) -> Self {
        Self {
            access_token: Secret::new(response.access_token.expose()),
            refresh_token: response
                .refresh_token
                .as_ref()
                .map(|token| Secret::new(token.expose())),
            expires_in: response.expires_in,
            refresh_expires_at: response.refresh_token_expires_at,
            scope: response.scope.clone(),
            account: response.account.as_ref().map(|account| Account {
                uuid: account.uuid.clone(),
                kind: match account.kind {
                    silicon_accounts_client::AccountKind::Carbon => AccountKind::Carbon,
                    silicon_accounts_client::AccountKind::Silicon => AccountKind::Silicon,
                    #[allow(unreachable_patterns)]
                    _ => AccountKind::Unknown,
                },
                id: account.id.clone(),
                display_name: account.display_name.clone(),
                pfp_url: account.pfp_url.clone(),
                custodian: account.custodian.as_ref().map(|custodian| AccountLink {
                    uuid: custodian.uuid.clone(),
                    id: custodian.id.clone(),
                }),
            }),
        }
    }
}

/// A started device sign-in. Show `user_code` and `verification_uri`; keep
/// `device_code` to yourself.
#[derive(Clone, Debug)]
pub struct DeviceCode {
    /// What the client polls with; never show it.
    pub device_code: Secret,
    /// The code the Carbon confirms, e.g. `WDJB-MJHT`.
    pub user_code: String,
    /// Where the Carbon approves.
    pub verification_uri: String,
    /// The same page with the code filled in.
    pub verification_uri_complete: Option<String>,
    /// Seconds until the code expires (600).
    pub expires_in: u64,
    /// Minimum seconds between polls.
    pub interval: u64,
}

/// One poll of a device sign-in.
#[derive(Clone, Debug)]
pub enum DevicePoll {
    /// Not approved yet.
    Pending,
    /// Polling too fast: wait 5 seconds longer from now on.
    SlowDown,
    /// Approved.
    Approved(Box<Tokens>),
}

/// Progress while waiting for a device approval.
#[derive(Debug)]
#[non_exhaustive]
pub enum DeviceEvent<'a> {
    /// Still waiting.
    Pending,
    /// Silicon Accounts asked to poll more slowly; the new interval.
    SlowDown(Duration),
    /// A poll failed transiently; polling continues after `retry_in`.
    Retrying {
        /// The failure.
        error: &'a Error,
        /// Delay before the next poll.
        retry_in: Duration,
    },
}

/// Signs in to Hook as its public client. Stateless; cheap to clone.
#[derive(Clone, Debug)]
pub struct SignIn {
    accounts: AccountsClient,
    url: Url,
    app_id: String,
    http: reqwest::Client,
}

impl SignIn {
    /// Uses the Silicon Accounts at `accounts_url`: HTTPS, or plain HTTP on this
    /// machine only.
    ///
    /// # Errors
    /// [`Error::Invalid`] for any other URL.
    pub fn new(accounts_url: &str) -> Result<Self> {
        let mut url = Url::parse(accounts_url.trim()).map_err(|error| {
            Error::Invalid(format!(
                "`{accounts_url}` is not a valid Silicon Accounts URL ({error}); use {DEFAULT_ACCOUNTS_URL}"
            ))
        })?;
        if !(url.scheme() == "https" || url.scheme() == "http" && is_loopback(&url))
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(Error::Invalid(format!(
                "`{accounts_url}` is not usable as the Silicon Accounts URL: use HTTPS (plain HTTP only for this machine), with no query, fragment or credentials"
            )));
        }
        let path = url.path().trim_end_matches('/').to_owned();
        url.set_path(&path);
        let accounts = AccountsClient::builder()
            .base_url(url.as_str())
            .user_agent(concat!("silicon-hook-client/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| Error::Invalid(error.to_string()))?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("silicon-hook-client/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            accounts,
            url,
            app_id: APP_ID.to_owned(),
            http,
        })
    }

    /// Production Silicon Accounts.
    ///
    /// # Errors
    /// Only if the HTTP stack cannot be built.
    pub fn production() -> Result<Self> {
        Self::new(DEFAULT_ACCOUNTS_URL)
    }

    /// Signs in to another Hook deployment's app id (default `hook`).
    #[must_use]
    pub fn with_app_id(mut self, app_id: impl Into<String>) -> Self {
        self.app_id = app_id.into();
        self
    }

    /// The app id tokens are issued to.
    #[must_use]
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// The Silicon Accounts URL.
    #[must_use]
    pub fn accounts_url(&self) -> &Url {
        &self.url
    }
}
