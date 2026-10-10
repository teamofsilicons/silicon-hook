use std::{fmt, sync::Arc, time::Duration};

use reqwest::{Method, Url};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::OnceCell;
use uuid::Uuid;

use crate::{
    error::{ApiError, Error, Result},
    models::{DeliveryStatus, LoginStatus, Secret, SignInInformation},
};

/// Production Hook API.
pub const DEFAULT_URL: &str = "https://backend.hook.teamofsilicons.com";
/// The API major this client speaks.
pub const API_VERSION: &str = "v3";

/// Stable identifier for one logical mutation. Reuse it when retrying the same
/// change after an uncertain outcome; Hook then answers with the first result.
#[derive(Clone, Debug)]
pub struct Mutation(String);

impl Default for Mutation {
    fn default() -> Self {
        Self::new()
    }
}

impl Mutation {
    /// A fresh key.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7().to_string())
    }

    /// A caller-chosen key: 8 to 255 visible ASCII characters.
    ///
    /// # Errors
    /// [`Error::Invalid`] for any other key.
    pub fn with_key(key: impl Into<String>) -> Result<Self> {
        let key = key.into();
        if !(8..=255).contains(&key.len()) || !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Error::Invalid(
                "an idempotency key must be 8 to 255 visible ASCII characters".into(),
            ));
        }
        Ok(Self(key))
    }

    /// The key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.0
    }
}

/// A Hook API v3 client. Immutable and cheap to clone: `with_*` methods return a
/// new configuration. It stores no credentials anywhere; the host keeps the
/// Silicon Accounts tokens (see [`crate::signin`]) and passes the current
/// access token with [`Client::with_token`].
#[derive(Clone)]
pub struct Client {
    pub(crate) base_url: Url,
    pub(crate) http: reqwest::Client,
    pub(crate) token: Option<Secret>,
    negotiated: Arc<OnceCell<()>>,
    pub(crate) telemetry: bool,
    pub(crate) trace_id: Uuid,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("url", &self.base_url.as_str())
            .field("signed_in", &self.token.is_some())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client for a pathless HTTPS origin, or plain HTTP on this machine
    /// (`localhost`, `*.localhost` or a loopback address).
    ///
    /// # Errors
    /// [`Error::Invalid`] for any other URL.
    pub fn new(base_url: &str) -> Result<Self> {
        let base_url = Url::parse(base_url.trim()).map_err(|error| {
            Error::Invalid(format!(
                "`{base_url}` is not a valid Hook URL ({error}); use an origin such as {DEFAULT_URL}"
            ))
        })?;
        validate_origin(&base_url)?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("silicon-hook-client/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            base_url,
            http,
            token: None,
            negotiated: Arc::default(),
            telemetry: true,
            trace_id: Uuid::now_v7(),
        })
    }

    /// The production Hook API.
    ///
    /// # Errors
    /// Only if the HTTP stack cannot be built.
    pub fn production() -> Result<Self> {
        Self::new(DEFAULT_URL)
    }

    /// Sends every request with `Authorization: Bearer <access token>`, a
    /// Silicon Accounts access token issued to Hook (`aud` = `hook`).
    #[must_use]
    pub fn with_token(&self, access_token: impl Into<String>) -> Self {
        let mut client = self.clone();
        client.token = Some(Secret::new(access_token));
        client
    }

    /// Controls optional diagnostics (default on). `SILICON_HOOK_TELEMETRY=off`
    /// always wins.
    #[must_use]
    pub fn with_telemetry(&self, enabled: bool) -> Self {
        let mut client = self.clone();
        client.telemetry = enabled;
        client
    }

    /// The Hook origin.
    #[must_use]
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Whether a token is configured.
    #[must_use]
    pub fn is_signed_in(&self) -> bool {
        self.token.is_some()
    }

    pub(crate) fn telemetry_enabled(&self) -> bool {
        self.telemetry
            && std::env::var("SILICON_HOOK_TELEMETRY").map_or(true, |v| {
                !matches!(v.to_ascii_lowercase().as_str(), "off" | "false" | "0")
            })
    }

    /// Sends one best-effort diagnostic event (no payloads, no credentials,
    /// never user input). Only documented names are accepted by Hook; nothing
    /// is sent without a token or with telemetry off. Waits at most 500 ms.
    pub async fn emit_telemetry(
        &self,
        source: &str,
        step: &str,
        outcome: &str,
        operation: &str,
        duration_ms: u64,
        progress: u32,
    ) {
        if !self.telemetry_enabled() || self.token.is_none() {
            return;
        }
        let event = serde_json::json!({
            "event_id": Uuid::now_v7(), "trace_id": self.trace_id, "source": source,
            "step": step, "outcome": outcome, "operation": operation,
            "duration_ms": duration_ms, "progress": progress,
            "version": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
        });
        if let Ok(request) = self.request(Method::POST, &["telemetry"], &[], Some(&event), None) {
            let _ = request.timeout(Duration::from_millis(500)).send().await;
        }
    }

    /// Checks that the server is Silicon Hook and serves API v3. Runs once per
    /// client before the first API call.
    ///
    /// # Errors
    /// [`Error::Protocol`] when the server is not Hook API v3.
    pub async fn negotiate(&self) -> Result<()> {
        self.negotiated
            .get_or_try_init(|| async {
                let response = self
                    .http
                    .get(self.url(&["api", "version"])?)
                    .header("silicon-hook-supported-api-versions", API_VERSION)
                    .header("x-hook-telemetry", self.telemetry_header())
                    .send()
                    .await?;
                let data: serde_json::Value = self.decode(response).await?;
                if data.get("service").and_then(|v| v.as_str()) != Some("silicon-hook")
                    || data.get("selected_api_version").and_then(|v| v.as_str())
                        != Some(API_VERSION)
                {
                    return Err(Error::Protocol(format!(
                        "{} is not Silicon Hook API {API_VERSION}; it answered {data}",
                        self.base_url
                    )));
                }
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// How to sign in to this Hook. Public; needs no token.
    ///
    /// # Errors
    /// Transport and protocol errors.
    pub async fn sign_in_information(&self) -> Result<SignInInformation> {
        self.call(Method::GET, &["auth", "accounts"], &[], None::<&()>, None)
            .await
    }

    /// Whether Hook accepts the configured token, and whose it is. No token,
    /// or a token Hook refuses (HTTP 401), gives `authenticated: false` with
    /// Hook's reason; outages and other errors stay errors.
    ///
    /// # Errors
    /// Transport, protocol and non-401 refusals.
    pub async fn login_status(&self) -> Result<LoginStatus> {
        if self.token.is_none() {
            return Ok(LoginStatus {
                authenticated: false,
                uuid: None,
                id: None,
                kind: None,
                reason: Some("no_token".into()),
                message: None,
            });
        }
        match self
            .call::<LoginStatus, ()>(Method::GET, &["auth", "status"], &[], None, None)
            .await
        {
            Err(Error::Api(api)) if api.status == 401 => Ok(LoginStatus {
                authenticated: false,
                uuid: None,
                id: None,
                kind: None,
                reason: Some(api.code),
                message: Some(api.message),
            }),
            result => result,
        }
    }

    /// Whether this Hook delivers events through Ting.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn delivery_status(&self) -> Result<DeliveryStatus> {
        self.call(Method::GET, &["delivery"], &[], None::<&()>, None)
            .await
    }

    /// The running service version.
    ///
    /// # Errors
    /// Transport and protocol errors.
    pub async fn version(&self) -> Result<serde_json::Value> {
        self.call(Method::GET, &["version"], &[], None::<&()>, None)
            .await
    }

    /// Readiness (`/readyz`), including whether delivery is on.
    ///
    /// # Errors
    /// Transport errors and a not-ready answer.
    pub async fn health(&self) -> Result<serde_json::Value> {
        self.decode(self.http.get(self.url(&["readyz"])?).send().await?)
            .await
    }

    /// The API contract catalogue (`/api/contracts`).
    ///
    /// # Errors
    /// Transport and protocol errors.
    pub async fn contracts(&self) -> Result<serde_json::Value> {
        self.decode(
            self.http
                .get(self.url(&["api", "contracts"])?)
                .send()
                .await?,
        )
        .await
    }

    pub(crate) async fn call<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &[&str],
        query: &[(&str, String)],
        body: Option<&B>,
        mutation: Option<&Mutation>,
    ) -> Result<T> {
        self.negotiate().await?;
        let response = self
            .request(method, path, query, body, mutation)?
            .send()
            .await?;
        self.decode(response).await
    }

    pub(crate) async fn empty(
        &self,
        method: Method,
        path: &[&str],
        mutation: Option<&Mutation>,
    ) -> Result<()> {
        self.negotiate().await?;
        let response = self
            .request::<()>(method, path, &[], None, mutation)?
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(failure(response).await?);
        }
        Ok(())
    }

    fn telemetry_header(&self) -> &'static str {
        if self.telemetry_enabled() {
            "on"
        } else {
            "off"
        }
    }

    fn request<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &[&str],
        query: &[(&str, String)],
        body: Option<&B>,
        mutation: Option<&Mutation>,
    ) -> Result<reqwest::RequestBuilder> {
        let mut segments = vec!["api", API_VERSION];
        segments.extend_from_slice(path);
        let mut request = self
            .http
            .request(method, self.url(&segments)?)
            .query(query)
            .header("silicon-hook-api-version", API_VERSION)
            .header("x-request-id", self.trace_id.to_string())
            .header("x-hook-telemetry", self.telemetry_header());
        if let Some(token) = &self.token {
            request = request.bearer_auth(token.expose());
        }
        if let Some(mutation) = mutation {
            request = request.header("idempotency-key", mutation.key());
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        Ok(request)
    }

    pub(crate) fn url(&self, segments: &[&str]) -> Result<Url> {
        let mut url = self.base_url.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| Error::Invalid("the Hook URL cannot carry a path".into()))?;
            path.clear();
            for segment in segments {
                if segment.is_empty()
                    || matches!(*segment, "." | "..")
                    || segment.contains(['/', '\\', '?', '#'])
                {
                    return Err(Error::Invalid(format!(
                        "`{segment}` is not a valid identifier in a Hook URL"
                    )));
                }
                path.push(segment);
            }
        }
        Ok(url)
    }

    pub(crate) async fn decode<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T> {
        if !response.status().is_success() {
            return Err(failure(response).await?);
        }
        let bytes = bounded_body(response).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

async fn failure(response: reqwest::Response) -> Result<Error> {
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    let header_request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = bounded_body(response).await?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
        Error::Protocol(format!(
            "HTTP {status} without Hook's error envelope; is this URL a Hook API?"
        ))
    })?;
    let error = &value["error"];
    let text = |name: &str| error[name].as_str().map(str::to_owned);
    Ok(Error::Api(Box::new(ApiError {
        status,
        code: text("code").unwrap_or_else(|| "unknown_error".into()),
        message: text("message").unwrap_or_else(|| "Hook refused the request.".into()),
        details: text("details"),
        hint: text("hint"),
        request_id: text("request_id").or(header_request_id),
        retry_after,
    })))
}

pub(crate) fn validate_origin(url: &Url) -> Result<()> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || url.port() == Some(0)
        || !matches!(url.path(), "" | "/")
        || !(url.scheme() == "https" || url.scheme() == "http" && is_loopback(url))
    {
        return Err(Error::Invalid(format!(
            "`{url}` is not usable: give a pathless HTTPS origin (plain HTTP only for this machine: localhost or a loopback address)"
        )));
    }
    Ok(())
}

pub(crate) fn is_loopback(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host == "localhost"
            || host.ends_with(".localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}

pub(crate) async fn bounded_body(
    mut response: reqwest::Response,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    // A history page may hold large bodies; page rather than reading 10,000
    // maximum-size requests at once.
    const MAX: usize = 64 * 1024 * 1024;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > MAX.saturating_sub(bytes.len()) {
            return Err(Error::Protocol(
                "the response exceeds 64 MiB; request a smaller history page".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
