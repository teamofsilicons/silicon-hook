use std::{fmt, sync::Arc, time::Duration};

use reqwest::{Method, Url};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::OnceCell;
use uuid::Uuid;

use crate::models::{Secret, Tokens};

/// A client failure with a stable server error code when available.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A local argument cannot be represented safely on the wire.
    #[error("{0}")]
    Invalid(String),
    /// The transport failed. Credentials are never formatted into request URLs.
    #[error("Hook could not be reached: {0}")]
    Transport(#[from] reqwest::Error),
    /// Hook's structured error response.
    #[error("{code}: {message} (HTTP {status})")]
    Api {
        status: u16,
        code: String,
        message: String,
        request_id: Option<String>,
        retry_after: Option<u64>,
    },
    /// Unexpected response or a service-version mismatch.
    #[error("Hook returned an incompatible response: {0}")]
    Protocol(String),
    /// JSON serialization or decoding failure.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The server closed a stream with a non-normal application reason.
    #[error("Hook stream closed ({code}): {reason}")]
    StreamClosed { code: u16, reason: String },
    /// WebSocket transport/protocol failure.
    #[error("Hook WebSocket failed: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
}

/// Result returned by all client operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Stable identifier for one logical mutation. Reuse it when retrying.
#[derive(Clone, Debug)]
pub struct Mutation(String);

impl Default for Mutation {
    fn default() -> Self {
        Self::new()
    }
}
impl Mutation {
    pub fn new() -> Self {
        Self(Uuid::now_v7().to_string())
    }
    pub fn with_key(key: impl Into<String>) -> Result<Self> {
        let key = key.into();
        if !(8..=255).contains(&key.len()) || !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Error::Invalid(
                "idempotency keys require 8–255 visible ASCII characters".into(),
            ));
        }
        Ok(Self(key))
    }
    pub fn key(&self) -> &str {
        &self.0
    }
}

/// Immutable service, actor and environment selection. No credentials are persisted.
#[derive(Clone)]
pub struct Client {
    pub(crate) base_url: Url,
    pub(crate) http: reqwest::Client,
    pub(crate) token: Option<Secret>,
    pub(crate) org: Option<String>,
    pub(crate) test_key: Option<Secret>,
    negotiated: Arc<OnceCell<()>>,
    auto_update: bool,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("url", &self.base_url)
            .field("org", &self.org)
            .field("testing", &self.test_key.is_some())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Builds a client for HTTPS, or HTTP on a literal loopback/localhost host.
    pub fn new(base_url: &str) -> Result<Self> {
        let base_url = Url::parse(base_url).map_err(|e| Error::Invalid(e.to_string()))?;
        validate_origin(&base_url)?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("silicon-hook-client/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            base_url,
            http,
            token: None,
            org: None,
            test_key: None,
            negotiated: Arc::default(),
            auto_update: true,
        })
    }
    /// Disables or enables automatic hourly dependency checks for this client.
    pub fn with_auto_update(&self, enabled: bool) -> Self {
        let mut client = self.clone();
        client.auto_update = enabled;
        client
    }
    pub fn with_token(&self, token: impl Into<String>) -> Self {
        let mut client = self.clone();
        client.token = Some(Secret::new(token));
        client
    }
    pub fn with_organization(&self, org: impl Into<String>) -> Self {
        let mut client = self.clone();
        client.org = Some(org.into());
        client
    }
    pub fn with_test_key(&self, key: impl Into<String>) -> Result<Self> {
        let key = key.into();
        if key.len() != 32 || !key.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(Error::Invalid("test keys require exactly 32 alphanumeric characters; use the key, not the environment ID".into()));
        }
        let mut client = self.clone();
        client.test_key = Some(Secret::new(key));
        Ok(client)
    }
    pub fn without_test_environment(&self) -> Self {
        let mut client = self.clone();
        client.test_key = None;
        client
    }
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }
    pub fn is_testing(&self) -> bool {
        self.test_key.is_some()
    }

    /// Verifies that the server is Silicon Hook and agrees on API v1.
    pub async fn negotiate(&self) -> Result<()> {
        self.negotiated
            .get_or_try_init(|| async {
                let response = self
                    .http
                    .get(self.url(&["api", "version"])?)
                    .header("silicon-hook-supported-api-versions", "v1")
                    .send()
                    .await?;
                let data: serde_json::Value = self.decode(response).await?;
                if data.get("service").and_then(|v| v.as_str()) != Some("silicon-hook")
                    || data.get("selected_api_version").and_then(|v| v.as_str()) != Some("v1")
                {
                    return Err(Error::Protocol(
                        "server must identify silicon-hook API v1".into(),
                    ));
                }
                Ok(())
            })
            .await
            .map(|_| ())
    }

    /// Low-level token exchange for hosts, such as the CLI, that already own
    /// their relay lifecycle. Most applications should use `login`, which
    /// starts an in-memory relay session. The recipient stays local.
    pub async fn exchange_slt(
        &self,
        slt: &str,
        _recipient: &crate::Recipient,
        mutation: &Mutation,
    ) -> Result<Tokens> {
        self.authenticate(slt, mutation).await
    }

    /// Exchange an SLT before configuring local delivery. No recipient goes on the wire.
    pub async fn authenticate(&self, slt: &str, mutation: &Mutation) -> Result<Tokens> {
        self.call(
            Method::POST,
            &["auth", "login"],
            &[],
            Some(&serde_json::json!({"slt":slt})),
            Some(mutation),
        )
        .await
    }
    /// Discover the selected production/test application's public IAM configuration.
    pub async fn iam(&self) -> Result<crate::models::IamInformation> {
        self.call(Method::GET, &["auth", "iam"], &[], None::<&()>, None)
            .await
    }

    /// Check the bearer online. Invalid/revoked credentials produce authenticated=false;
    /// transport, configuration and authorization errors remain errors.
    pub async fn login_status(&self) -> Result<crate::models::LoginStatus> {
        if self.token.is_none() {
            return Ok(crate::models::LoginStatus {
                authenticated: false,
                actor: None,
                org_id: None,
            });
        }
        match self
            .call(Method::GET, &["auth", "status"], &[], None::<&()>, None)
            .await
        {
            Err(Error::Api { status: 401, .. }) => Ok(crate::models::LoginStatus {
                authenticated: false,
                actor: None,
                org_id: None,
            }),
            result => result,
        }
    }

    pub async fn refresh(&self, refresh_token: &str, mutation: &Mutation) -> Result<Tokens> {
        self.call(
            Method::POST,
            &["auth", "refresh"],
            &[],
            Some(&serde_json::json!({"refresh_token":refresh_token})),
            Some(mutation),
        )
        .await
    }
    pub async fn logout(&self, mutation: &Mutation) -> Result<()> {
        self.empty(Method::POST, &["auth", "logout"], None, Some(mutation))
            .await
    }
    pub async fn version(&self) -> Result<serde_json::Value> {
        self.call(Method::GET, &["version"], &[], None::<&()>, None)
            .await
    }
    pub async fn health(&self) -> Result<serde_json::Value> {
        self.decode(self.http.get(self.url(&["readyz"])?).send().await?)
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
        let result = self.decode(response).await;
        crate::updater::schedule(self.auto_update);
        result
    }
    pub(crate) async fn empty(
        &self,
        method: Method,
        path: &[&str],
        body: Option<&serde_json::Value>,
        mutation: Option<&Mutation>,
    ) -> Result<()> {
        self.negotiate().await?;
        let response = self
            .request(method, path, &[], body, mutation)?
            .send()
            .await?;
        crate::updater::schedule(self.auto_update);
        if !response.status().is_success() {
            return Err(self.failure(response).await?);
        }
        Ok(())
    }
    fn request<B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &[&str],
        query: &[(&str, String)],
        body: Option<&B>,
        mutation: Option<&Mutation>,
    ) -> Result<reqwest::RequestBuilder> {
        let mut segments = vec!["api", "v1"];
        segments.extend_from_slice(path);
        let mut request = self
            .http
            .request(method, self.url(&segments)?)
            .query(query)
            .header("silicon-hook-api-version", "v1");
        if let Some(token) = &self.token {
            request = request.bearer_auth(token.expose());
        }
        if let Some(org) = &self.org {
            request = request.header("x-org-id", org);
        }
        if let Some(key) = &self.test_key {
            request = request.header("x-hook-test-key", key.expose());
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
                .map_err(|_| Error::Invalid("invalid base URL".into()))?;
            path.clear();
            for segment in segments {
                if segment.is_empty()
                    || matches!(*segment, "." | "..")
                    || segment.contains(['/', '\\'])
                {
                    return Err(Error::Invalid("invalid URL path identifier".into()));
                }
                path.push(segment);
            }
        }
        Ok(url)
    }
    async fn decode<T: DeserializeOwned>(&self, response: reqwest::Response) -> Result<T> {
        if !response.status().is_success() {
            return Err(self.failure(response).await?);
        }
        let bytes = bounded_body(response).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }
    async fn failure(&self, response: reqwest::Response) -> Result<Error> {
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let bytes = bounded_body(response).await?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Protocol(format!("HTTP {status} without a Hook error envelope")))?;
        let error = &value["error"];
        Ok(Error::Api {
            status,
            code: error["code"].as_str().unwrap_or("unknown_error").into(),
            message: error["message"].as_str().unwrap_or("Request failed").into(),
            request_id: error["request_id"].as_str().map(str::to_owned),
            retry_after,
        })
    }
}

pub(crate) fn validate_origin(url: &Url) -> Result<()> {
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
        || url.port() == Some(0)
        || !matches!(url.path(), "" | "/")
        || !(url.scheme() == "https" || url.scheme() == "http" && loopback)
    {
        return Err(Error::Invalid(
            "expected a pathless HTTPS service URL (HTTP is allowed only on loopback)".into(),
        ));
    }
    Ok(())
}

pub(crate) async fn bounded_body(
    mut response: reqwest::Response,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    // History pages may contain large bodies; callers should page rather than
    // materialize 10,000 maximum-size requests at once.
    const MAX: usize = 64 * 1024 * 1024;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > MAX.saturating_sub(bytes.len()) {
            return Err(Error::Protocol(
                "response exceeds 64 MiB; request a smaller history page".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
