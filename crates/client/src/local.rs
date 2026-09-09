//! Authenticated loopback API for programs using an already configured relay.
//! No backend token is exposed to a local caller. Each local token selects one
//! identity and environment; the daemon refreshes the associated client.
use crate::{Client, Error, Result, Secret};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, OriginalUri, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use subtle::ConstantTimeEq as _;
use tokio::sync::watch;

pub const DEFAULT_RELAY_PORT: u16 = 18479;

#[derive(Clone, Debug)]
pub struct LocalIdentity {
    pub token: Secret,
    pub client: Client,
}

/// A backend request. Path is relative to the origin and restricted to public
/// Hook API routes. Authorization/organization/environment headers are supplied
/// by the selected identity and cannot be overridden here.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: Vec<(String, String)>,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body_base64: String,
}

#[derive(Clone)]
struct LocalState {
    identities: watch::Receiver<Vec<LocalIdentity>>,
    control_token: Secret,
    stop: watch::Sender<bool>,
    port: u16,
}

/// Runs only on 127.0.0.1. `hook.localhost` is the human-facing name; the
/// client explicitly resolves it to loopback instead of depending on DNS.
/// Control and identity tokens should be random and stored with mode 0600.
pub async fn serve_local(
    port: u16,
    control_token: Secret,
    identities: watch::Receiver<Vec<LocalIdentity>>,
    stop: watch::Sender<bool>,
) -> Result<()> {
    if port == 0 || control_token.expose().len() < 32 {
        return Err(Error::Invalid(
            "local relay needs a nonzero port and a control token of at least 32 characters".into(),
        ));
    }
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|e| Error::Protocol(format!("cannot bind local relay: {e}")))?;
    serve_listener(listener, control_token, identities, stop).await
}

pub(crate) async fn serve_listener(
    listener: tokio::net::TcpListener,
    control_token: Secret,
    identities: watch::Receiver<Vec<LocalIdentity>>,
    stop: watch::Sender<bool>,
) -> Result<()> {
    let port = listener
        .local_addr()
        .map_err(|e| Error::Protocol(format!("cannot read local relay address: {e}")))?
        .port();
    let mut shutdown = stop.subscribe();
    let state = LocalState {
        identities,
        control_token,
        stop,
        port,
    };
    let router = Router::new()
        .route("/health", get(health))
        .route("/control/stop", post(stop_server))
        .route("/request", post(request))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(state);
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            while !*shutdown.borrow() {
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
        .map_err(|e| Error::Protocol(format!("local relay stopped: {e}")))
}
fn token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
fn same(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
fn safe_origin(headers: &HeaderMap, port: u16) -> bool {
    if headers.contains_key("origin") {
        return false;
    }
    headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|host| {
            [
                format!("hook.localhost:{port}"),
                format!("localhost:{port}"),
                format!("127.0.0.1:{port}"),
            ]
            .contains(&host.to_ascii_lowercase())
        })
}
fn controlled(state: &LocalState, headers: &HeaderMap) -> bool {
    safe_origin(headers, state.port)
        && token(headers).is_some_and(|t| same(t, state.control_token.expose()))
}
async fn health(State(state): State<LocalState>, headers: HeaderMap) -> Response {
    if !controlled(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    axum::Json(serde_json::json!({"service":"silicon-hook-relay","version":env!("CARGO_PKG_VERSION"),"identities":state.identities.borrow().len()})).into_response()
}
async fn stop_server(State(state): State<LocalState>, headers: HeaderMap) -> Response {
    if !controlled(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let _ = state.stop.send(true);
    axum::Json(serde_json::json!({"stopping":true})).into_response()
}
async fn request(
    State(state): State<LocalState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    if !safe_origin(&headers, state.port) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(token) = token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let client = state
        .identities
        .borrow()
        .iter()
        .find(|identity| same(token, identity.token.expose()))
        .map(|i| i.client.clone());
    let Some(client) = client else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let input: LocalRequest = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid LocalRequest JSON").into_response(),
    };
    let outcome = forward(&client, &input).await;
    let response = match outcome {
        Ok(response) => response,
        Err(error) => serde_json::json!({"error": error.to_string()}),
    };
    // Base64 preserves the caller's exact JSON bytes, including whitespace and
    // duplicate keys, in the receipt. Never send this receipt to the backend.
    let echoed_headers: Vec<_> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), STANDARD.encode(value.as_bytes())))
        .collect();
    let receipt = serde_json::json!({"received":true,"request":{"method":"POST","path":uri.path(),"query_string":uri.query().unwrap_or(""),"headers_base64":echoed_headers,"body_base64":STANDARD.encode(&bytes)},"response":response});
    ([("cache-control", "no-store")], axum::Json(receipt)).into_response()
}
async fn forward(client: &Client, input: &LocalRequest) -> Result<serde_json::Value> {
    if !(input.path.starts_with("/api/v1/")
        || input.path == "/api/version"
        || input.path == "/readyz")
        || input.path.contains(['?', '#', '\\', '%'])
    {
        return Err(Error::Invalid(
            "local requests require a literal public Hook API path".into(),
        ));
    }
    let path: Vec<_> = input.path.trim_start_matches('/').split('/').collect();
    let method = reqwest::Method::from_bytes(input.method.as_bytes())
        .map_err(|_| Error::Invalid("invalid request method".into()))?;
    if !matches!(
        method,
        reqwest::Method::GET
            | reqwest::Method::POST
            | reqwest::Method::PUT
            | reqwest::Method::PATCH
            | reqwest::Method::DELETE
    ) {
        return Err(Error::Invalid("unsupported request method".into()));
    }
    let body = STANDARD
        .decode(&input.body_base64)
        .map_err(|_| Error::Invalid("body_base64 is not standard base64".into()))?;
    let mut request = client
        .http
        .request(method, client.url(&path)?)
        .query(&input.query)
        .header("silicon-hook-api-version", "v1");
    for (name, value) in &input.headers {
        if !["content-type", "idempotency-key", "accept"]
            .contains(&name.to_ascii_lowercase().as_str())
        {
            return Err(Error::Invalid(
                "only content-type, idempotency-key and accept may be set by local callers".into(),
            ));
        }
        request = request.header(name, value);
    }
    if let Some(token) = &client.token {
        request = request.bearer_auth(token.expose());
    }
    if let Some(org) = &client.org {
        request = request.header("x-org-id", org);
    }
    if input.path.starts_with("/api/v1/")
        && let Some(key) = &client.test_key
    {
        request = request.header("x-hook-test-key", key.expose());
    }
    client.negotiate().await?;
    let response = request.body(body).send().await?;
    let status = response.status().as_u16();
    let response_headers: Vec<_> = response
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_owned(), v.to_owned()))
        })
        .collect();
    let body = crate::client::bounded_body(response).await?;
    Ok(
        serde_json::json!({"status":status,"headers":response_headers,"body_base64":STANDARD.encode(&*body)}),
    )
}

/// Client for the daemon's control and identity-scoped request endpoints.
#[derive(Clone)]
pub struct LocalClient {
    http: reqwest::Client,
    origin: String,
    token: Secret,
}
impl LocalClient {
    pub fn new(port: u16, token: Secret) -> Result<Self> {
        if port == 0 {
            return Err(Error::Invalid("local relay port must be nonzero".into()));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(35))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve(
                "hook.localhost",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            )
            .build()?;
        Ok(Self {
            http,
            origin: format!("http://hook.localhost:{port}"),
            token,
        })
    }
    pub async fn health(&self) -> Result<serde_json::Value> {
        self.send("health", None::<&()>).await
    }
    pub async fn stop(&self) -> Result<serde_json::Value> {
        self.send("control/stop", Some(&())).await
    }
    pub async fn request(&self, input: &LocalRequest) -> Result<serde_json::Value> {
        self.request_bytes(&serde_json::to_vec(input)?).await
    }
    /// Sends the caller's exact JSON bytes, preserving whitespace in the receipt.
    pub async fn request_bytes(&self, bytes: &[u8]) -> Result<serde_json::Value> {
        let _: LocalRequest = serde_json::from_slice(bytes)?;
        let response = self
            .http
            .post(format!("{}/request", self.origin))
            .bearer_auth(self.token.expose())
            .header("content-type", "application/json")
            .body(bytes.to_vec())
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(Error::Protocol(format!(
                "local relay returned HTTP {}",
                response.status().as_u16()
            )));
        }
        Ok(serde_json::from_slice(
            &crate::client::bounded_body(response).await?,
        )?)
    }
    async fn send<B: Serialize>(&self, path: &str, body: Option<&B>) -> Result<serde_json::Value> {
        let url = format!("{}/{path}", self.origin);
        let request = match body {
            Some(body) => self.http.post(url).json(body),
            None => self.http.get(url),
        };
        let response = request.bearer_auth(self.token.expose()).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Protocol(format!(
                "local relay returned HTTP {}",
                status.as_u16()
            )));
        }
        Ok(serde_json::from_slice(
            &crate::client::bounded_body(response).await?,
        )?)
    }
}
