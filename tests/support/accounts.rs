//! A stub Silicon Accounts for tests: JWKS, account lookups, introspection and
//! proofs, over real HTTP so Hook's production client is exercised, plus
//! `EdDSA` access tokens signed with a test key and signed webhook deliveries.
#![allow(dead_code, reason = "each test target uses a different subset")]

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{Form, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};

/// Hook's app id at the stub.
pub const APP_ID: &str = "hook";
/// Hook's app secret at the stub.
pub const APP_SECRET: &str = "sa_app_hook_test-secret-value";
/// The webhook signing secret the stub signs deliveries with.
pub const WEBHOOK_SECRET: &str = "whsec_test-webhook-secret";
/// The key id of the stub's signing key.
pub const KEY_ID: &str = "test-key-1";

/// One account the stub knows.
#[derive(Clone, Debug)]
pub struct StubAccount {
    /// Carbon or Silicon (`carbon` / `silicon`).
    pub kind: &'static str,
    /// Current public id.
    pub id: String,
    /// A Silicon's custodian `(uuid, id)`.
    pub custodian: Option<(String, String)>,
    /// Deleted accounts answer `404 account_deleted`.
    pub deleted: bool,
}

#[derive(Default)]
struct StubState {
    accounts: HashMap<String, StubAccount>,
    inactive_tokens: HashSet<String>,
    introspections: usize,
    refuse_proofs: bool,
    refused_proofs: usize,
    lookups: usize,
    proofs: Vec<Value>,
    keys: Vec<(String, [u8; 32])>,
}

/// A running stub Silicon Accounts.
#[derive(Clone)]
pub struct StubAccounts {
    /// Base URL (also the token issuer).
    pub url: String,
    state: Arc<Mutex<StubState>>,
    signing: Arc<SigningKey>,
}

impl StubAccounts {
    /// Starts the stub on a random loopback port.
    ///
    /// # Panics
    ///
    /// Never in practice: binding 127.0.0.1:0 succeeds on a test machine.
    pub async fn start() -> Self {
        let signing = SigningKey::from_bytes(&[42; 32]);
        let state = Arc::new(Mutex::new(StubState {
            keys: vec![(KEY_ID.to_owned(), signing.verifying_key().to_bytes())],
            ..StubState::default()
        }));
        let app = Router::new()
            .route("/.well-known/jwks.json", get(jwks))
            .route("/v1/accounts/by-id/{id}", get(lookup_by_id))
            .route("/v1/accounts/{uuid}", get(lookup))
            .route("/v1/oauth/introspect", post(introspect))
            .route("/v1/proofs/app-verification", post(app_verification))
            .route("/v1/proofs/user-verification", post(user_verification))
            .route("/v1/proofs/refresh", post(refresh_proof))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("bind the stub Accounts listener: {error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("read the stub Accounts address: {error}"));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url: format!("http://{address}"),
            state,
            signing: Arc::new(signing),
        }
    }

    fn with_state<T>(&self, change: impl FnOnce(&mut StubState) -> T) -> T {
        match self.state.lock() {
            Ok(mut state) => change(&mut state),
            Err(poisoned) => change(&mut poisoned.into_inner()),
        }
    }

    /// Adds (or replaces) a Carbon.
    pub fn add_carbon(&self, uuid: &str, id: &str) {
        self.with_state(|state| {
            state.accounts.insert(
                uuid.to_owned(),
                StubAccount {
                    kind: "carbon",
                    id: id.to_owned(),
                    custodian: None,
                    deleted: false,
                },
            );
        });
    }

    /// Adds (or replaces) a Silicon looked after by `custodian` (uuid, id).
    pub fn add_silicon(&self, uuid: &str, id: &str, custodian: Option<(&str, &str)>) {
        self.with_state(|state| {
            state.accounts.insert(
                uuid.to_owned(),
                StubAccount {
                    kind: "silicon",
                    id: id.to_owned(),
                    custodian: custodian.map(|(uuid, id)| (uuid.to_owned(), id.to_owned())),
                    deleted: false,
                },
            );
        });
    }

    /// Changes an account's public id.
    pub fn rename(&self, uuid: &str, new_id: &str) {
        self.with_state(|state| {
            if let Some(account) = state.accounts.get_mut(uuid) {
                new_id.clone_into(&mut account.id);
            }
        });
    }

    /// Moves a Silicon to another custodian.
    pub fn set_custodian(&self, uuid: &str, custodian: Option<(&str, &str)>) {
        self.with_state(|state| {
            if let Some(account) = state.accounts.get_mut(uuid) {
                account.custodian = custodian.map(|(uuid, id)| (uuid.to_owned(), id.to_owned()));
            }
        });
    }

    /// Marks an account deleted.
    pub fn delete(&self, uuid: &str) {
        self.with_state(|state| {
            if let Some(account) = state.accounts.get_mut(uuid) {
                account.deleted = true;
            }
        });
    }

    /// Makes introspection answer `active: false` for a token.
    pub fn deactivate(&self, token: &str) {
        self.with_state(|state| {
            state.inactive_tokens.insert(token.to_owned());
        });
    }

    /// Makes proof requests fail as for an app id Silicon Accounts does not know.
    pub fn refuse_proofs(&self, refuse: bool) {
        self.with_state(|state| state.refuse_proofs = refuse);
    }

    /// Proof requests refused so far.
    #[must_use]
    pub fn refused_proofs(&self) -> usize {
        self.with_state(|state| state.refused_proofs)
    }

    /// Introspection requests served so far.
    #[must_use]
    pub fn introspections(&self) -> usize {
        self.with_state(|state| state.introspections)
    }

    /// Account lookups served so far.
    #[must_use]
    pub fn lookups(&self) -> usize {
        self.with_state(|state| state.lookups)
    }

    /// Proof requests served so far (their JSON bodies, plus `kind`).
    #[must_use]
    pub fn proofs(&self) -> Vec<Value> {
        self.with_state(|state| state.proofs.clone())
    }

    /// Publishes an extra signing key (rotation) under `kid`.
    pub fn add_key(&self, kid: &str, key: &SigningKey) {
        self.with_state(|state| {
            state
                .keys
                .push((kid.to_owned(), key.verifying_key().to_bytes()));
        });
    }

    /// An access token for Hook (`aud` = hook, `iss` = this stub), valid for
    /// ten minutes.
    #[must_use]
    pub fn token(&self, uuid: &str, kind: &str, id: &str) -> String {
        let now = now();
        self.sign(&json!({
            "iss": self.url, "sub": uuid, "aud": APP_ID, "exp": now + 600, "iat": now,
            "nbf": now, "jti": format!("j-{uuid}-{now}"), "kind": kind, "id": id,
            "mid": format!("{APP_ID}:{uuid}"), "fid": format!("f-{uuid}"), "scope": "profile"
        }))
    }

    /// Signs arbitrary claims with the stub's key (for refusal tests).
    #[must_use]
    pub fn sign(&self, claims: &Value) -> String {
        sign_with(&self.signing, KEY_ID, claims)
    }
}

/// Signs claims as an `EdDSA` JWT with `key` under `kid`.
#[must_use]
pub fn sign_with(key: &SigningKey, kid: &str, claims: &Value) -> String {
    let header = json!({"alg": "EdDSA", "typ": "JWT", "kid": kid});
    let encoded = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = key.sign(encoded.as_bytes());
    format!("{encoded}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

/// Seconds since the Unix epoch.
#[must_use]
pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// A signed Accounts webhook delivery: (timestamp header, signature header, body).
#[must_use]
pub fn webhook(secret: &str, event: &Value) -> (String, String, Vec<u8>) {
    let body = event.to_string().into_bytes();
    let timestamp = now();
    let signature = silicon_accounts_client::sign_webhook(secret, timestamp, &body);
    (timestamp.to_string(), signature, body)
}

fn authorized(headers: &HeaderMap) -> bool {
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{APP_ID}:{APP_SECRET}"))
    );
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected)
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({"error": {"code": code, "message": message, "hint": "stub"}})),
    )
        .into_response()
}

async fn jwks(State(state): State<Arc<Mutex<StubState>>>) -> Json<Value> {
    let keys = state
        .lock()
        .map(|state| state.keys.clone())
        .unwrap_or_default();
    Json(json!({"keys": keys.iter().map(|(kid, x)| json!({
        "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(x),
        "kid": kid, "use": "sig", "alg": "EdDSA"
    })).collect::<Vec<_>>()}))
}

fn summary(uuid: &str, account: &StubAccount) -> Value {
    json!({
        "uuid": uuid, "kind": account.kind, "id": account.id, "status": "active",
        "custodian": account.custodian.as_ref().map(|(uuid, id)| json!({"uuid": uuid, "id": id})),
    })
}

fn find(state: &Arc<Mutex<StubState>>, matches: impl Fn(&str, &StubAccount) -> bool) -> Response {
    let Ok(mut state) = state.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "poisoned", "poisoned");
    };
    state.lookups += 1;
    match state
        .accounts
        .iter()
        .find(|(uuid, account)| matches(uuid, account))
    {
        Some((_, account)) if account.deleted => error(
            StatusCode::NOT_FOUND,
            "account_deleted",
            "The account was deleted.",
        ),
        Some((uuid, account)) => Json(summary(uuid, account)).into_response(),
        None => error(
            StatusCode::NOT_FOUND,
            "account_not_found",
            "No such account.",
        ),
    }
}

async fn lookup(
    State(state): State<Arc<Mutex<StubState>>>,
    Path(uuid): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers) {
        return error(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "bad app credentials",
        );
    }
    find(&state, |candidate, _| candidate == uuid)
}

async fn lookup_by_id(
    State(state): State<Arc<Mutex<StubState>>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !authorized(&headers) {
        return error(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "bad app credentials",
        );
    }
    find(&state, |_, account| account.id == id && !account.deleted)
}

async fn introspect(
    State(state): State<Arc<Mutex<StubState>>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !authorized(&headers) {
        return error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "bad app credentials",
        );
    }
    let token = form.get("token").cloned().unwrap_or_default();
    let inactive = state.lock().map_or(true, |mut state| {
        state.introspections += 1;
        state.inactive_tokens.contains(&token)
    });
    let claims = token
        .split('.')
        .nth(1)
        .and_then(|payload| URL_SAFE_NO_PAD.decode(payload).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    match claims {
        Some(claims) if !inactive => Json(json!({
            "active": true, "sub": claims["sub"], "client_id": claims["aud"], "exp": claims["exp"],
            "iat": claims["iat"], "token_type": "access_token"
        }))
        .into_response(),
        _ => Json(json!({"active": false})).into_response(),
    }
}

fn issue(state: &Arc<Mutex<StubState>>, kind: &str, request: &Value) -> Response {
    let Ok(mut state) = state.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "poisoned", "poisoned");
    };
    if state.refuse_proofs {
        state.refused_proofs += 1;
        return error(
            StatusCode::BAD_REQUEST,
            "unknown_receiving_app",
            "No app with that app_id exists, so it can't receive a proof.",
        );
    }
    let mut record = request.clone();
    record["kind"] = json!(kind);
    state.proofs.push(record);
    let serial = state.proofs.len();
    let expires = time::OffsetDateTime::now_utc() + time::Duration::minutes(30);
    let expires = expires
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    Json(json!({
        "proof_id": format!("proof-{serial}"),
        "kind": kind,
        "proof_token": format!("sap_stub_{serial}"),
        "expires_at": expires,
        "proof_refresh_token": format!("sapr_stub_{serial}"),
        "issuing_app": APP_ID,
        "receiving_app": request.get("receiving_app").cloned().unwrap_or(json!("ting")),
        "user": null,
        "scopes": request.get("scopes").cloned().unwrap_or(json!([])),
    }))
    .into_response()
}

async fn app_verification(
    State(state): State<Arc<Mutex<StubState>>>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    if !authorized(&headers) {
        return error(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "bad app credentials",
        );
    }
    issue(&state, "app_verification", &request)
}

async fn user_verification(
    State(state): State<Arc<Mutex<StubState>>>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    if !authorized(&headers) {
        return error(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "bad app credentials",
        );
    }
    issue(&state, "user_verification", &request)
}

async fn refresh_proof(
    State(state): State<Arc<Mutex<StubState>>>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    if !authorized(&headers) {
        return error(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "bad app credentials",
        );
    }
    issue(&state, "refresh", &request)
}
