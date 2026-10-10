//! Hook API v3 wire models. Responses tolerate fields added later; requests
//! send only what you set.
//!
//! Accounts are keyed by their Silicon Accounts `uuid` (short, case-sensitive,
//! permanent) and shown by their current `id` (`c:ada`, `si:scout`), which can
//! change.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A credential: `Debug` is always redacted and dropping it wipes the memory.
/// Serialization is explicit because hosts store tokens themselves.
#[derive(Clone, Deserialize, Serialize, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Wraps a credential.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The plaintext, for the one place that needs it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Carbon (a person) or Silicon.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AccountKind {
    /// A Carbon.
    Carbon,
    /// A Silicon.
    Silicon,
    /// A kind this client does not know yet.
    #[serde(other)]
    Unknown,
}

impl AccountKind {
    /// `carbon`, `silicon` or `unknown`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Carbon => "carbon",
            Self::Silicon => "silicon",
            Self::Unknown => "unknown",
        }
    }
}

/// A Silicon: its permanent uuid and its current id (absent when Hook has not
/// learned it yet).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SiliconRef {
    /// Permanent Silicon Accounts uuid.
    pub uuid: String,
    /// Current `si:` id.
    #[serde(default)]
    pub id: Option<String>,
}

impl SiliconRef {
    /// The current id when known, else the uuid.
    #[must_use]
    pub fn display(&self) -> &str {
        self.id.as_deref().unwrap_or(&self.uuid)
    }
}

/// An account as Hook shows it. `uuid` is absent only for attribution recorded
/// before Silicon Accounts that was never linked; `id` is then the stored id.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AccountRef {
    /// Permanent Silicon Accounts uuid.
    #[serde(default)]
    pub uuid: Option<String>,
    /// Carbon or Silicon.
    pub kind: AccountKind,
    /// Current `c:`/`si:` id.
    #[serde(default)]
    pub id: Option<String>,
}

/// How to sign in to this Hook (`GET /api/v3/auth/accounts`). Public.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignInInformation {
    /// Hook's app id at Silicon Accounts (the access token audience).
    pub app_id: String,
    /// The Silicon Accounts URL this Hook trusts (also the token issuer).
    pub accounts_url: String,
    /// Token details: type, format, audience, issuer, JWKS URL.
    #[serde(default)]
    pub token: serde_json::Value,
    /// How Carbons and Silicons sign in.
    #[serde(default)]
    pub sign_in: serde_json::Value,
    /// `ting` when this Hook delivers events through Ting, `disabled` otherwise.
    #[serde(default)]
    pub delivery: Option<String>,
}

/// Who an access token belongs to, as Hook sees it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LoginStatus {
    /// Whether Hook accepted the token.
    pub authenticated: bool,
    /// The account's uuid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// The account's current id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Carbon or Silicon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<AccountKind>,
    /// Why Hook refused the token (its error code), when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Hook's explanation of the refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Whether this Hook delivers events through Ting (`GET /api/v3/delivery`).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeliveryStatus {
    /// True when `HOOK_TING_URL` is set on the server.
    pub enabled: bool,
    /// `ting` when enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Why delivery is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Signing policy supplied at creation or update. Omitted fields keep the
/// defaults (creation) or the current values (update). `public_key: Some(None)`
/// clears the key.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Signature {
    /// Whether unsigned or unverifiable requests are withheld.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    /// Signature algorithm, e.g. `hmac-sha256`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// Expression producing the signed bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Expression locating the provider's signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// How the provider encodes the signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_encoding: Option<String>,
    /// How the secret text is decoded into key bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_encoding: Option<String>,
    /// PEM public key for asymmetric algorithms; `Some(None)` clears it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "nullable"
    )]
    #[allow(clippy::option_option)]
    pub public_key: Option<Option<String>>,
    /// Bring your own secret: stored on creation, or replaces the current
    /// secret on update. Omit to generate one at creation or keep it on update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<Secret>,
}

/// A new hook. Signing is on (HMAC-SHA256, Standard Webhooks) unless changed.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CreateHook {
    /// Provider name shown in event summaries, e.g. `GitHub`.
    pub name: String,
    /// Free text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// IANA time zone for event summaries; default `UTC`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,
    /// Signing policy overrides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

/// A change to one hook. `description: Some(None)` clears it.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UpdateHook {
    /// New provider name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// New description; `Some(None)` clears it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "nullable"
    )]
    #[allow(clippy::option_option)]
    pub description: Option<Option<String>>,
    /// New IANA time zone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,
    /// Pause (`false`) or resume (`true`) ingress.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Signing policy changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

#[allow(clippy::option_option)]
fn nullable<'de, T: Deserialize<'de>, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(d).map(Some)
}

/// A hook's signing policy as Hook reports it; the secret never appears.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignaturePolicy {
    /// Whether unverified requests are withheld.
    pub required: bool,
    /// Signature algorithm.
    pub algorithm: String,
    /// Payload expression.
    pub payload: String,
    /// Signature locator expression.
    pub signature: String,
    /// Signature encoding.
    pub signature_encoding: String,
    /// Secret encoding.
    pub secret_encoding: String,
    /// PEM public key, for asymmetric algorithms.
    pub public_key: Option<String>,
    /// Whether a secret is stored.
    pub has_secret: bool,
}

/// One provider webhook of a Silicon.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Hook {
    /// Hook id.
    pub id: Uuid,
    /// The Silicon the hook belongs to.
    pub silicon: SiliconRef,
    /// Provider name.
    pub name: String,
    /// Free text.
    pub description: Option<String>,
    /// The URL providers call.
    pub endpoint_url: url::Url,
    /// The 8-character key at the end of the URL.
    pub endpoint_key: String,
    /// `active`, `disabled` or `deleted`.
    pub status: String,
    /// Signing policy.
    pub signature: SignaturePolicy,
    /// IANA time zone of event summaries.
    pub time_zone: String,
    /// Who created it.
    pub created_by: AccountRef,
    /// RFC 3339 timestamps.
    pub created_at: String,
    /// When it was paused.
    pub disabled_at: Option<String>,
    /// When it was deleted.
    pub deleted_at: Option<String>,
    /// Last moment a deleted hook can be restored (45 days).
    pub recoverable_until: Option<String>,
    /// Last verified request.
    pub last_received_at: Option<String>,
    /// Last withheld request.
    pub last_blocked_at: Option<String>,
    /// Last endpoint rotation.
    pub endpoint_rotated_at: Option<String>,
}

/// A created hook with its signing secret, shown once.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HookWithSecret {
    /// The hook.
    #[serde(flatten)]
    pub hook: Hook,
    /// Generated secret; absent when you brought your own or signing is off.
    pub signing_secret: Option<Secret>,
}

/// A rotated signing secret, shown once.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigningSecret {
    /// The new secret. The old one stopped verifying.
    pub signing_secret: Secret,
}

/// A list envelope.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Items<T> {
    /// The items.
    pub items: Vec<T>,
}

/// A history page with an opaque cursor for the next one.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HistoryPage<T> {
    /// Newest first.
    pub items: Vec<T>,
    /// Pass back to read the next page; absent on the last page.
    pub next_cursor: Option<String>,
}

/// The provider request exactly as retained.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CapturedRequest {
    /// HTTP method.
    pub method: String,
    /// Full URL.
    pub url: String,
    /// Path.
    pub path: String,
    /// Raw query string.
    pub query_string: String,
    /// Headers in order, repeated names kept.
    pub headers: Vec<(String, String)>,
    /// Content type.
    pub content_type: Option<String>,
    /// Body text when it is UTF-8.
    pub body: Option<String>,
    /// Standard base64 of a body that is not UTF-8.
    pub body_base64: Option<String>,
    /// Client address.
    pub remote_ip: String,
}

/// A verified provider request.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Event {
    /// Event id.
    pub id: Uuid,
    /// The Silicon it belongs to (current id).
    pub silicon: SiliconRef,
    /// The receiving hook.
    pub hook_id: Uuid,
    /// Provider (the hook's name when it arrived).
    pub provider: String,
    /// Position in the hook's stream.
    pub delivery_sequence: i64,
    /// `{provider} triggered at HH:MM:SS DD-MM-YYYY {zone}`.
    pub summary: String,
    /// RFC 3339 receipt time.
    pub received_at: String,
    /// The request.
    pub request: CapturedRequest,
}

/// A withheld (unverified) request, kept 14 days.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockedRequest {
    /// Record id.
    pub id: Uuid,
    /// The Silicon it was sent to.
    pub silicon: SiliconRef,
    /// The receiving hook.
    pub hook_id: Uuid,
    /// Provider.
    pub provider: String,
    /// Why it was withheld, e.g. `signature_mismatch`.
    pub reason_code: String,
    /// Detail.
    pub reason_detail: String,
    /// RFC 3339 receipt time.
    pub received_at: String,
    /// The request.
    pub request: CapturedRequest,
}

/// Access levels another account can be given to a Silicon's hooks.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GrantLevel {
    /// Read hooks, events, blocked requests and delivery status.
    View,
    /// Everything `view` allows, plus creating and changing hooks.
    Manage,
}

impl GrantLevel {
    /// `view` or `manage`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Manage => "manage",
        }
    }
}

/// A Silicon the caller can open (`GET /api/v3/silicons`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccessibleSilicon {
    /// The Silicon.
    pub silicon: SiliconRef,
    /// Why the caller can open it: `self`, `custodian`, `manage` or `view`.
    pub access: String,
    /// The Silicon's custodian's uuid, when known.
    #[serde(default)]
    pub custodian: Option<String>,
}

/// The caller's own access to a Silicon.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct YourAccess {
    /// The caller.
    pub account: AccountRef,
    /// `self`, `custodian`, `manage` or `view`.
    pub access: String,
}

/// One grant of access to a Silicon's hooks.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Grant {
    /// Who has access.
    pub account: AccountRef,
    /// `view` or `manage`.
    pub level: GrantLevel,
    /// Who granted it (the Silicon or its custodian).
    pub granted_by: AccountRef,
    /// RFC 3339.
    pub created_at: String,
    /// RFC 3339.
    pub updated_at: String,
}

/// Who has access to a Silicon's hooks (`GET /api/v3/silicons/{s}/access`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccessSummary {
    /// The Silicon.
    pub silicon: SiliconRef,
    /// The caller's access.
    pub you: YourAccess,
    /// The Silicon's custodian.
    #[serde(default)]
    pub custodian: Option<AccountRef>,
    /// Grants to other accounts.
    #[serde(default)]
    pub grants: Vec<Grant>,
}

/// The result of granting or changing access.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GrantResult {
    /// The Silicon.
    pub silicon: SiliconRef,
    /// The grant as stored.
    pub grant: Grant,
}

/// One account a Silicon allowed to give it access (`allow-list`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AllowEntry {
    /// The allowed account.
    pub account: AccountRef,
    /// uuid of the Silicon or custodian who added it.
    #[serde(default)]
    pub added_by: Option<String>,
    /// RFC 3339.
    #[serde(default)]
    pub created_at: Option<String>,
}

/// A Silicon's allow-list.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AllowList {
    /// The Silicon.
    pub silicon: SiliconRef,
    /// Allowed accounts.
    pub items: Vec<AllowEntry>,
}

/// What to do after preparing the Silicon Accounts updates hook.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountsHookNextSteps {
    /// The `silicon-accounts` command that points the Silicon's Accounts webhook at the hook.
    pub set_webhook: String,
    /// How to store the `whsec_` secret Silicon Accounts prints.
    pub store_secret: String,
    /// Why both steps are needed.
    pub explanation: String,
}

/// The hook that receives a Silicon's own Silicon Accounts events.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountsHook {
    /// The hook (created, or restored when it existed).
    pub hook: Hook,
    /// The remaining steps.
    pub next_steps: AccountsHookNextSteps,
}
