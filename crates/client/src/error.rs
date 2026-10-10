//! Typed failures. Every error says what failed and why; Hook's own refusals keep
//! the service's `{"error": {"code", "message", "details", "hint", "request_id"}}`
//! envelope so callers can branch on the stable `code`.

use std::fmt;

/// Result returned by every client operation.
pub type Result<T> = std::result::Result<T, Error>;

/// A client failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A local argument cannot be sent safely; nothing was sent.
    #[error("{0}")]
    Invalid(String),
    /// Hook could not be reached. Credentials never appear in request URLs.
    #[error("Hook could not be reached: {0}")]
    Transport(#[from] reqwest::Error),
    /// Hook refused the request with its structured error.
    #[error("{0}")]
    Api(Box<ApiError>),
    /// Hook answered with something this client does not understand, or the
    /// server is not Silicon Hook API v3.
    #[error("Hook returned an incompatible response: {0}")]
    Protocol(String),
    /// A body could not be encoded or decoded.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Signing in with Silicon Accounts failed (see [`crate::signin`]).
    #[error("{0}")]
    SignIn(Box<crate::signin::SignInError>),
}

impl Error {
    /// The stable error code: Hook's `error.code`, or the sign-in failure's code.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Api(api) => Some(&api.code),
            Self::SignIn(error) => Some(&error.code),
            _ => None,
        }
    }

    /// The HTTP status of a refusal, when there was one.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Api(api) => Some(api.status),
            Self::SignIn(error) => error.status,
            Self::Transport(error) => error.status().map(|status| status.as_u16()),
            _ => None,
        }
    }

    /// What to do next, when the service or the client knows.
    #[must_use]
    pub fn hint(&self) -> Option<&str> {
        match self {
            Self::Api(api) => api.hint.as_deref(),
            Self::SignIn(error) => Some(&error.hint),
            _ => None,
        }
    }

    /// Whether this is a refusal with `code`.
    #[must_use]
    pub fn is_code(&self, code: &str) -> bool {
        self.code() == Some(code)
    }

    /// Whether Hook refused the access token itself (HTTP 401): it expired, was
    /// issued to another app, or its sign-in ended.
    #[must_use]
    pub fn is_unauthenticated(&self) -> bool {
        matches!(self, Self::Api(api) if api.status == 401)
    }
}

/// Hook's structured refusal.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct ApiError {
    /// HTTP status code.
    pub status: u16,
    /// Stable machine-readable code, e.g. `forbidden`, `session_ended`, `delivery_disabled`.
    pub code: String,
    /// What went wrong and why.
    pub message: String,
    /// Extra detail some refusals carry (e.g. which field was invalid).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// What to do next, when the service says.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// The request id; quote it in a bug report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Seconds to wait before retrying (`Retry-After`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

impl ApiError {
    /// Builds a refusal (mostly for tests and mocks).
    #[must_use]
    pub fn new(status: u16, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            details: None,
            hint: None,
            request_id: None,
            retry_after: None,
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)?;
        if let Some(details) = self.details.as_deref().filter(|d| !d.is_empty()) {
            write!(f, " ({details})")?;
        }
        if let Some(hint) = self.hint.as_deref().filter(|h| !h.is_empty()) {
            write!(f, " Hint: {hint}")?;
        }
        write!(f, " (HTTP {}", self.status)?;
        if let Some(id) = &self.request_id {
            write!(f, ", request {id}")?;
        }
        f.write_str(")")
    }
}

impl From<crate::signin::SignInError> for Error {
    fn from(error: crate::signin::SignInError) -> Self {
        Self::SignIn(Box::new(error))
    }
}
