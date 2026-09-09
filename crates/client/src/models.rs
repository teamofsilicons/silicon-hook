//! Public API models. No persistence or backend-internal commands are exposed.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Explicitly serializable credential; Debug is always redacted and Drop wipes it.
#[derive(Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Secret(String);
impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Actor {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Tokens {
    pub access_token: Secret,
    pub refresh_token: Secret,
    pub token_type: String,
    pub expires_in: u64,
    pub scopes: Vec<String>,
    pub actor: Actor,
    pub org_id: Option<String>,
}

/// Public IAM discovery information; contains no secrets.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IamInformation {
    pub app_id: Option<String>,
    pub iam_url: String,
    pub testing: bool,
    pub login_method: String,
}

/// Current identity confirmed online by IAM in the selected organization.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoginStatus {
    pub authenticated: bool,
    pub actor: Option<Actor>,
    pub org_id: Option<String>,
}

/// Omitted fields preserve defaults/current values. Explicit JSON null clears a public key.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Signature {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_encoding: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "nullable"
    )]
    pub public_key: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<Secret>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CreateHook {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateHook {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "nullable"
    )]
    pub description: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

fn nullable<'de, T: Deserialize<'de>, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignaturePolicy {
    pub required: bool,
    pub algorithm: String,
    pub payload: String,
    pub signature: String,
    pub signature_encoding: String,
    pub secret_encoding: String,
    pub public_key: Option<String>,
    pub has_secret: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Hook {
    pub id: Uuid,
    pub org_id: String,
    pub silicon_id: String,
    pub name: String,
    pub description: Option<String>,
    pub endpoint_url: url::Url,
    pub endpoint_key: String,
    pub status: String,
    pub signature: SignaturePolicy,
    pub time_zone: String,
    pub created_by: Actor,
    pub created_at: String,
    pub disabled_at: Option<String>,
    pub deleted_at: Option<String>,
    pub recoverable_until: Option<String>,
    pub last_received_at: Option<String>,
    pub last_blocked_at: Option<String>,
    pub endpoint_rotated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HookWithSecret {
    #[serde(flatten)]
    pub hook: Hook,
    pub signing_secret: Option<Secret>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigningSecret {
    pub signing_secret: Secret,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Items<T> {
    pub items: Vec<T>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HistoryPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CapturedRequest {
    pub method: String,
    pub url: String,
    pub path: String,
    pub query_string: String,
    pub headers: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub body: Option<String>,
    pub body_base64: Option<String>,
    pub remote_ip: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Event {
    pub id: Uuid,
    pub org_id: String,
    pub silicon_id: String,
    pub hook_id: Uuid,
    pub provider: String,
    pub summary: String,
    pub delivery_sequence: i64,
    pub received_at: String,
    pub request: CapturedRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockedRequest {
    pub id: Uuid,
    pub org_id: String,
    pub silicon_id: String,
    pub hook_id: Uuid,
    pub provider: String,
    pub reason_code: String,
    pub reason_detail: String,
    pub received_at: String,
    pub request: CapturedRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeliveryCursor {
    pub silicon_id: String,
    pub acknowledged_through: i64,
    pub acknowledged_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeliveryBatch {
    pub items: Vec<Event>,
    pub cursor: DeliveryCursor,
    pub latest_sequence: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IamHook {
    #[serde(flatten)]
    pub hook: Hook,
    pub iam_webhook: IamWebhook,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IamWebhook {
    pub secret_version: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TestIamConfiguration {
    pub app_id: String,
    pub app_secret: Secret,
    pub webhook_secret: Secret,
    #[serde(default = "first_version")]
    pub webhook_secret_version: u64,
}
const fn first_version() -> u64 {
    1
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateEnvironment {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub iam_test_key: Secret,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam: Option<TestIamConfiguration>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TestEnvironment {
    pub id: Uuid,
    pub org_id: String,
    pub creator_kind: String,
    pub creator_id: String,
    pub name: String,
    pub description: Option<String>,
    pub generation: i64,
    pub created_at: String,
    pub last_activity_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnvironmentWithKey {
    #[serde(flatten)]
    pub environment: TestEnvironment,
    pub key: Secret,
    pub max_hooks: u8,
}
