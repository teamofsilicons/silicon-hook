//! Sign-in failures, classified so a caller can act on them.

use std::fmt;

use silicon_accounts_client::Error as AccountsError;

/// The command a Silicon runs to get a short-lived token for Hook.
pub const SLT_COMMAND: &str = "silicon-accounts login --app hook -q";

/// Why Silicon Accounts refused a short-lived token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SltRefusal {
    /// It was used before; each one works once.
    AlreadyUsed,
    /// It is older than its two minutes.
    Expired,
    /// It was minted for another app.
    WrongApp,
    /// Silicon Accounts does not know it (mistyped, or another deployment).
    Unknown,
    /// The value is not a short-lived token (`slt_…`) at all.
    NotAnSlt,
    /// The sign-in that minted it has ended since (an STK rotation, the app's
    /// access removed, or a CI sign-in that ended).
    Ended,
}

impl SltRefusal {
    /// `already_used`, `expired`, `wrong_app`, `unknown`, `not_an_slt` or `ended`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AlreadyUsed => "already_used",
            Self::Expired => "expired",
            Self::WrongApp => "wrong_app",
            Self::Unknown => "unknown",
            Self::NotAnSlt => "not_an_slt",
            Self::Ended => "ended",
        }
    }

    /// Reads Silicon Accounts' `error_description` for an `invalid_grant`.
    #[must_use]
    pub fn from_description(description: &str) -> Self {
        let text = description.to_ascii_lowercase();
        if text.contains("already used") {
            Self::AlreadyUsed
        } else if text.contains("was issued for the app") || text.contains("not for '") {
            Self::WrongApp
        } else if text.contains("not known") || text.contains("never issued") {
            Self::Unknown
        } else if text.contains("starts with slt_") || text.contains("must be a short-lived") {
            Self::NotAnSlt
        } else if text.contains("expired at") || text.contains("they last") {
            Self::Expired
        } else {
            Self::Ended
        }
    }
}

/// The category of a sign-in failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignInErrorKind {
    /// The short-lived token was refused; mint a fresh one.
    SltRefused(SltRefusal),
    /// The refresh token no longer works: the sign-in ended (signed out, the
    /// app's access removed, reuse detected, or its 900 days ran out).
    SessionEnded,
    /// The Carbon denied the device sign-in.
    Denied,
    /// The device code expired (10 minutes) before it was approved.
    Expired,
    /// Silicon Accounts does not let Hook's command-line tool sign in this way
    /// (the app's `device_flow` / `public_client` settings).
    NotEnabled,
    /// Silicon Accounts could not be reached or failed. `maybe_processed`:
    /// the request may have been handled before the failure (a rotated refresh
    /// token may then already be spent).
    Unavailable {
        /// Whether the request may have reached the service.
        maybe_processed: bool,
    },
    /// Any other refusal.
    Rejected,
}

/// A sign-in failure with Silicon Accounts' own explanation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignInError {
    /// The category.
    pub kind: SignInErrorKind,
    /// Stable code: the OAuth error (`invalid_grant`, `access_denied`,
    /// `expired_token`…), the service's code, or `unavailable`.
    pub code: String,
    /// What went wrong and why.
    pub message: String,
    /// What to do next.
    pub hint: String,
    /// HTTP status, when the service answered.
    pub status: Option<u16>,
}

impl fmt::Display for SignInError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.message.trim_end(), self.hint)
    }
}

impl std::error::Error for SignInError {}

/// Which call failed, to explain the failure in its terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    Slt,
    Refresh,
    Device,
    Revoke,
}

impl SignInError {
    pub(crate) fn new(
        kind: SignInErrorKind,
        code: impl Into<String>,
        message: impl Into<String>,
        hint: impl Into<String>,
        status: Option<u16>,
    ) -> Self {
        Self {
            kind,
            code: code.into(),
            message: message.into(),
            hint: hint.into(),
            status,
        }
    }

    /// Classifies an OAuth error body (`error`, `error_description`).
    pub(crate) fn oauth(step: Step, status: u16, error: &str, description: Option<&str>) -> Self {
        let message = description
            .filter(|d| !d.trim().is_empty())
            .map_or_else(|| default_message(error), str::to_owned);
        match (step, error) {
            (Step::Slt, "invalid_grant") => Self::new(
                SignInErrorKind::SltRefused(SltRefusal::from_description(&message)),
                error,
                message,
                format!(
                    "Mint a fresh one and sign in again right away (it works once, for two minutes): `{SLT_COMMAND} | hook login --slt-stdin`."
                ),
                Some(status),
            ),
            (Step::Slt, "invalid_request") if message.contains("slt_") => Self::new(
                SignInErrorKind::SltRefused(SltRefusal::NotAnSlt),
                error,
                message,
                format!(
                    "Hook signs Silicons in with a Silicon Accounts short-lived token: `{SLT_COMMAND}`."
                ),
                Some(status),
            ),
            (Step::Refresh, "invalid_grant") => Self::new(
                SignInErrorKind::SessionEnded,
                error,
                message,
                "Sign in again: `hook login` (Carbons) or `silicon-accounts login --app hook -q | hook login --slt-stdin` (Silicons).",
                Some(status),
            ),
            (Step::Device, "access_denied") => Self::new(
                SignInErrorKind::Denied,
                error,
                message,
                "Run `hook login` again if that was a mistake.",
                Some(status),
            ),
            (Step::Device, "expired_token") => Self::new(
                SignInErrorKind::Expired,
                error,
                message,
                "Run `hook login` again for a new code and approve it within 10 minutes.",
                Some(status),
            ),
            (_, "unauthorized_client" | "invalid_client") => Self::new(
                SignInErrorKind::NotEnabled,
                error,
                message,
                "Hook's command-line sign-in needs `device_flow` (Carbons) and `public_client` (Silicons) in Hook's sign-in setup at this Silicon Accounts. Check ACCOUNTS_URL, or ask Hook's operator.",
                Some(status),
            ),
            (_, "slow_down" | "temporarily_unavailable") => Self::new(
                SignInErrorKind::Unavailable {
                    maybe_processed: false,
                },
                error,
                message,
                "Wait a moment and retry.",
                Some(status),
            ),
            _ => Self::new(
                SignInErrorKind::Rejected,
                error,
                message,
                match step {
                    Step::Revoke => {
                        "The local sign-in is removed anyway; revoke the session from your Silicon Accounts sessions if it still shows."
                    }
                    _ => {
                        "Read the message above; `hook docs signin` explains how signing in works."
                    }
                },
                Some(status),
            ),
        }
    }

    /// Classifies a failure reported by `silicon-accounts-client`.
    pub(crate) fn from_accounts(step: Step, error: &AccountsError) -> Self {
        match error {
            AccountsError::OAuth(oauth) => Self::oauth(
                step,
                oauth.status,
                &oauth.error,
                oauth.description.as_deref(),
            ),
            AccountsError::Api(api) if api.status >= 500 || api.status == 429 => Self::new(
                SignInErrorKind::Unavailable {
                    maybe_processed: false,
                },
                api.code.clone(),
                api.message.clone(),
                api.hint.clone().unwrap_or_else(|| {
                    "Silicon Accounts is busy or failing; retry shortly.".into()
                }),
                Some(api.status),
            ),
            AccountsError::Api(api) => Self::new(
                SignInErrorKind::Rejected,
                api.code.clone(),
                api.message.clone(),
                api.hint.clone().unwrap_or_default(),
                Some(api.status),
            ),
            AccountsError::Http {
                message, source, ..
            } => unreachable_accounts(message, !source.is_connect() && !source.is_builder()),
            AccountsError::Decode { message, .. } => Self::new(
                SignInErrorKind::Unavailable {
                    maybe_processed: true,
                },
                "invalid_response",
                message.clone(),
                "Silicon Accounts answered with something this client does not understand; check ACCOUNTS_URL.",
                None,
            ),
            other => Self::new(
                SignInErrorKind::Rejected,
                other.code(),
                other.message(),
                other.hint().unwrap_or_default(),
                other.status(),
            ),
        }
    }

    /// A transport failure of a request this crate sent itself.
    pub(crate) fn transport(error: &reqwest::Error) -> Self {
        unreachable_accounts(
            &format!("Silicon Accounts could not be reached ({error})."),
            !error.is_connect() && !error.is_builder(),
        )
    }
}

fn unreachable_accounts(message: &str, maybe_processed: bool) -> SignInError {
    SignInError::new(
        SignInErrorKind::Unavailable { maybe_processed },
        "unavailable",
        message.to_owned(),
        "Check the network and ACCOUNTS_URL, then retry.",
        None,
    )
}

fn default_message(error: &str) -> String {
    match error {
        "invalid_grant" => "Silicon Accounts refused the token: it was already used, it expired, it was revoked, or it belongs to another app.".into(),
        "access_denied" => "The sign-in was denied on the account site.".into(),
        "expired_token" => "The sign-in code expired before it was approved.".into(),
        "unauthorized_client" | "invalid_client" => "Silicon Accounts does not allow this sign-in for Hook's command-line tool.".into(),
        other => format!("Silicon Accounts refused the request ({other})."),
    }
}
