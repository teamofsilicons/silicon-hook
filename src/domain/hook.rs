//! Webhook aggregate, endpoint key, and secret-bearing value objects.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use super::{
    ActorRef, DomainError, EntropyError, HookId, OrganizationId, SiliconId, TransitionError,
    signature::{MAX_SECRET_BYTES, SignatureConfig},
};

/// Prefix of a Hook-generated signing secret.
pub const SIGNING_SECRET_PREFIX: &str = "v1.";
/// Number of random alphanumeric characters in a generated signing secret.
pub const SIGNING_SECRET_GENERATED_LENGTH: usize = 32;
/// Length of an AES-GCM nonce.
pub const ENCRYPTION_NONCE_BYTES: usize = 12;
/// Length of an AES-GCM authentication tag.
pub const ENCRYPTION_TAG_BYTES: usize = 16;
/// Recovery window for a soft-deleted hook.
pub const HOOK_RECOVERY_DAYS: i64 = 45;
/// Number of characters in an endpoint routing key.
pub const ENDPOINT_KEY_LENGTH: usize = 8;

const ENDPOINT_KEY_ALPHABET: &[u8; 36] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const SECRET_ALPHABET: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const MAX_HOOK_NAME_LENGTH: usize = 200;
const MAX_HOOK_DESCRIPTION_LENGTH: usize = 2_000;
const MAX_ENCRYPTION_KEY_ID_BYTES: usize = 64;
const MAX_TIME_ZONE_BYTES: usize = 64;

/// Eight-character uppercase alphanumeric routing key in a public webhook URL.
///
/// The key routes a request to one hook and is never a credential; authenticity
/// comes from the hook's signature configuration.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EndpointKey(String);

impl EndpointKey {
    /// Generates a key from operating-system cryptographic randomness.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyError`] when the operating system cannot provide
    /// cryptographically secure randomness.
    pub fn generate() -> Result<Self, EntropyError> {
        Ok(Self(random_string(
            ENDPOINT_KEY_ALPHABET,
            ENDPOINT_KEY_LENGTH,
        )?))
    }

    /// Parses a route key and normalizes letters to uppercase.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] unless the input contains exactly eight ASCII
    /// letters or digits.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if value.len() != ENDPOINT_KEY_LENGTH
            || !value.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(DomainError::InvalidFormat {
                field: "endpoint_key",
                reason: "must be exactly eight ASCII letters or digits",
            });
        }
        Ok(Self(value.to_ascii_uppercase()))
    }

    /// Returns the canonical uppercase representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EndpointKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for EndpointKey {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for EndpointKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EndpointKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

/// Draws uniformly from an alphabet using rejection sampling.
fn random_string(alphabet: &[u8], length: usize) -> Result<String, EntropyError> {
    let alphabet_size = alphabet.len();
    // Largest multiple of the alphabet size that fits in a byte; bytes at or
    // above it are discarded so every symbol is equally likely.
    let limit = (256 / alphabet_size) * alphabet_size;
    let mut output = String::with_capacity(length);
    let mut buffer = [0_u8; 64];
    while output.len() < length {
        getrandom::fill(&mut buffer).map_err(|_| EntropyError)?;
        for byte in buffer {
            if usize::from(byte) >= limit {
                continue;
            }
            output.push(char::from(alphabet[usize::from(byte) % alphabet_size]));
            if output.len() == length {
                break;
            }
        }
    }
    Ok(output)
}

/// A plaintext signing secret in its textual form.
///
/// Hook-generated secrets are `v1.` followed by 32 random alphanumeric
/// characters. Provider-issued secrets are stored verbatim. Debug output is
/// always redacted and memory is zeroized when the last copy is dropped.
pub struct SigningSecret(Zeroizing<String>);

impl SigningSecret {
    /// Creates a new `v1.`-prefixed secret from operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyError`] when the operating system cannot provide
    /// cryptographically secure randomness.
    pub fn generate() -> Result<Self, EntropyError> {
        let mut secret =
            String::with_capacity(SIGNING_SECRET_PREFIX.len() + SIGNING_SECRET_GENERATED_LENGTH);
        secret.push_str(SIGNING_SECRET_PREFIX);
        secret.push_str(&random_string(
            SECRET_ALPHABET,
            SIGNING_SECRET_GENERATED_LENGTH,
        )?);
        Ok(Self(Zeroizing::new(secret)))
    }

    /// Wraps a caller-supplied provider secret.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the secret is empty, exceeds
    /// [`MAX_SECRET_BYTES`], or contains control characters.
    pub fn from_text(value: impl Into<String>) -> Result<Self, DomainError> {
        Self::from_zeroizing(Zeroizing::new(value.into()))
    }

    pub(crate) fn from_zeroizing(value: Zeroizing<String>) -> Result<Self, DomainError> {
        if value.is_empty() {
            return Err(DomainError::Empty { field: "secret" });
        }
        if value.len() > MAX_SECRET_BYTES {
            return Err(DomainError::TooLong {
                field: "secret",
                max: MAX_SECRET_BYTES,
            });
        }
        if value.chars().any(char::is_control) {
            return Err(DomainError::InvalidFormat {
                field: "secret",
                reason: "must not contain control characters",
            });
        }
        Ok(Self(value))
    }

    /// Returns the secret text for cryptographic operations.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the secret text for a bounded one-time response.
    #[must_use]
    pub fn to_exposed(&self) -> Zeroizing<String> {
        self.0.clone()
    }
}

impl Clone for SigningSecret {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for SigningSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SigningSecret([REDACTED])")
    }
}

/// Identifier of a versioned data-encryption key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EncryptionKeyId(String);

impl EncryptionKeyId {
    /// Validates an encryption-key identifier.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] for an empty or overlong identifier, or one
    /// containing characters outside its configuration grammar.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DomainError::Empty {
                field: "encryption_key_id",
            });
        }
        if value.len() > MAX_ENCRYPTION_KEY_ID_BYTES {
            return Err(DomainError::TooLong {
                field: "encryption_key_id",
                max: MAX_ENCRYPTION_KEY_ID_BYTES,
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(DomainError::InvalidFormat {
                field: "encryption_key_id",
                reason: "must contain only ASCII letters, digits, underscores, or hyphens",
            });
        }
        Ok(Self(value))
    }

    /// Returns the configured identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EncryptionKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for EncryptionKeyId {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Versioned AES-GCM ciphertext stored for a hook signing secret.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedSecret {
    key_id: EncryptionKeyId,
    nonce: [u8; ENCRYPTION_NONCE_BYTES],
    ciphertext: Vec<u8>,
}

impl fmt::Debug for EncryptedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedSecret")
            .field("key_id", &self.key_id)
            .field("nonce", &"[REDACTED]")
            .field("ciphertext", &"[REDACTED]")
            .finish()
    }
}

impl EncryptedSecret {
    /// Constructs a persisted encrypted secret after structural validation.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] unless the ciphertext is a non-empty plaintext
    /// of at most [`MAX_SECRET_BYTES`] bytes plus the AES-GCM tag.
    pub fn new(
        key_id: EncryptionKeyId,
        nonce: [u8; ENCRYPTION_NONCE_BYTES],
        ciphertext: Vec<u8>,
    ) -> Result<Self, DomainError> {
        let plaintext_length = ciphertext.len().saturating_sub(ENCRYPTION_TAG_BYTES);
        if ciphertext.len() <= ENCRYPTION_TAG_BYTES || plaintext_length > MAX_SECRET_BYTES {
            return Err(DomainError::InvalidFormat {
                field: "encrypted_signing_secret",
                reason: "ciphertext must contain a bounded secret and its AES-GCM tag",
            });
        }
        Ok(Self {
            key_id,
            nonce,
            ciphertext,
        })
    }

    /// Returns the versioned key identifier.
    #[must_use]
    pub const fn key_id(&self) -> &EncryptionKeyId {
        &self.key_id
    }

    /// Returns the public nonce stored alongside the ciphertext.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; ENCRYPTION_NONCE_BYTES] {
        &self.nonce
    }

    /// Returns the authenticated ciphertext and tag.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Consumes the value into persistence-friendly parts.
    #[must_use]
    pub fn into_parts(self) -> (EncryptionKeyId, [u8; ENCRYPTION_NONCE_BYTES], Vec<u8>) {
        (self.key_id, self.nonce, self.ciphertext)
    }
}

/// Validated display name for a hook connection, also its provider name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookName(String);

impl HookName {
    /// Trims and validates a hook name.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the trimmed name is empty, exceeds 200
    /// Unicode scalar values, or contains control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let value = value.trim();
        if value.is_empty() {
            return Err(DomainError::Empty { field: "name" });
        }
        if value.chars().any(char::is_control) {
            return Err(DomainError::InvalidFormat {
                field: "name",
                reason: "must not contain control characters",
            });
        }
        if value.chars().count() > MAX_HOOK_NAME_LENGTH {
            return Err(DomainError::TooLong {
                field: "name",
                max: MAX_HOOK_NAME_LENGTH,
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated optional description for a hook connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookDescription(String);

impl HookDescription {
    /// Trims and validates a non-empty description.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the trimmed description is empty, exceeds
    /// 2,000 Unicode scalar values, or contains `U+0000`.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let value = value.trim();
        if value.is_empty() {
            return Err(DomainError::Empty {
                field: "description",
            });
        }
        if value.contains('\0') {
            return Err(DomainError::InvalidFormat {
                field: "description",
                reason: "must not contain U+0000",
            });
        }
        if value.chars().count() > MAX_HOOK_DESCRIPTION_LENGTH {
            return Err(DomainError::TooLong {
                field: "description",
                max: MAX_HOOK_DESCRIPTION_LENGTH,
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// Turns a request string into an optional description, treating blank
    /// input as absence.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when a non-blank description exceeds the
    /// contract length.
    pub fn optional(value: Option<String>) -> Result<Option<Self>, DomainError> {
        value
            .filter(|description| !description.trim().is_empty())
            .map(Self::new)
            .transpose()
    }

    /// Returns the validated description.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// IANA time zone used to render a hook's human-readable delivery summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookTimeZone(String);

impl HookTimeZone {
    /// Validates an IANA zone identifier such as `Europe/Berlin` or `UTC`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the identifier is unknown to the bundled
    /// time zone database or is not a plausible zone name.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let value = value.trim();
        if value.is_empty() {
            return Err(DomainError::Empty { field: "time_zone" });
        }
        if value.len() > MAX_TIME_ZONE_BYTES {
            return Err(DomainError::TooLong {
                field: "time_zone",
                max: MAX_TIME_ZONE_BYTES,
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'+'))
        {
            return Err(DomainError::InvalidFormat {
                field: "time_zone",
                reason: "must be an IANA zone identifier",
            });
        }
        let zone = jiff::tz::TimeZone::get(value).map_err(|_| DomainError::InvalidFormat {
            field: "time_zone",
            reason: "is not a known IANA zone identifier",
        })?;
        Ok(Self(zone.iana_name().unwrap_or(value).to_owned()))
    }

    /// Returns the canonical zone identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Resolves the bundled time zone rules.
    #[must_use]
    pub fn resolve(&self) -> jiff::tz::TimeZone {
        jiff::tz::TimeZone::get(&self.0).unwrap_or(jiff::tz::TimeZone::UTC)
    }
}

impl Default for HookTimeZone {
    fn default() -> Self {
        Self("UTC".to_owned())
    }
}

impl fmt::Display for HookTimeZone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Lifecycle state of a hook.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookStatus {
    /// Accepting provider requests.
    Active,
    /// Retained with its endpoint and secret, but not accepting requests.
    Disabled,
    /// Soft-deleted and retained during the recovery window.
    Deleted,
}

/// How a hook authenticates provider requests.
#[derive(Clone, Debug, PartialEq)]
pub struct SigningPolicy {
    /// Whether unverified requests are blocked rather than delivered.
    pub required: bool,
    /// Verification scheme, retained even while verification is disabled.
    pub config: SignatureConfig,
    /// Encrypted shared secret, absent for asymmetric-only configurations.
    pub encrypted_secret: Option<EncryptedSecret>,
}

impl SigningPolicy {
    /// Reports whether a request must verify before delivery.
    #[must_use]
    pub const fn is_required(&self) -> bool {
        self.required
    }
}

/// Values required to create a new active hook.
#[derive(Clone, Debug)]
pub struct NewHook {
    /// Preallocated `UUIDv7`.
    pub id: HookId,
    /// Owning organization.
    pub organization_id: OrganizationId,
    /// Owning Silicon.
    pub silicon_id: SiliconId,
    /// Display and provider name.
    pub name: HookName,
    /// Optional description.
    pub description: Option<HookDescription>,
    /// URL routing key.
    pub endpoint_key: EndpointKey,
    /// Signature verification policy.
    pub signing: SigningPolicy,
    /// Zone for rendered delivery summaries.
    pub time_zone: HookTimeZone,
    /// Creator.
    pub created_by: ActorRef,
    /// Authoritative creation time.
    pub created_at: OffsetDateTime,
}

/// Persistence snapshot used to rehydrate a hook aggregate.
#[derive(Clone, Debug)]
pub struct HookSnapshot {
    /// Public hook ID.
    pub id: HookId,
    /// Owning organization.
    pub organization_id: OrganizationId,
    /// Owning Silicon.
    pub silicon_id: SiliconId,
    /// Display and provider name.
    pub name: HookName,
    /// Optional description.
    pub description: Option<HookDescription>,
    /// Current URL routing key.
    pub endpoint_key: EndpointKey,
    /// Signature verification policy.
    pub signing: SigningPolicy,
    /// Zone for rendered delivery summaries.
    pub time_zone: HookTimeZone,
    /// Lifecycle state.
    pub status: HookStatus,
    /// Creator.
    pub created_by: ActorRef,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Time at which ingress was disabled for a disabled hook.
    pub disabled_at: Option<OffsetDateTime>,
    /// Deletion time for a deleted hook.
    pub deleted_at: Option<OffsetDateTime>,
    /// Most recent verified request, when any has been received.
    pub last_received_at: Option<OffsetDateTime>,
    /// Most recent unverified request, when any has been blocked.
    pub last_blocked_at: Option<OffsetDateTime>,
    /// Most recent endpoint rotation.
    pub endpoint_rotated_at: Option<OffsetDateTime>,
}

/// Webhook aggregate with lifecycle and secret invariants.
#[derive(Clone, Debug)]
pub struct Hook {
    snapshot: HookSnapshot,
}

impl Hook {
    /// Creates an active hook.
    #[must_use]
    pub fn create(new: NewHook) -> Self {
        Self {
            snapshot: HookSnapshot {
                id: new.id,
                organization_id: new.organization_id,
                silicon_id: new.silicon_id,
                name: new.name,
                description: new.description,
                endpoint_key: new.endpoint_key,
                signing: new.signing,
                time_zone: new.time_zone,
                status: HookStatus::Active,
                created_by: new.created_by,
                created_at: new.created_at,
                disabled_at: None,
                deleted_at: None,
                last_received_at: None,
                last_blocked_at: None,
                endpoint_rotated_at: None,
            },
        }
    }

    /// Rehydrates a persisted hook while checking lifecycle consistency.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when lifecycle state and timestamps are
    /// inconsistent.
    pub fn rehydrate(snapshot: HookSnapshot) -> Result<Self, DomainError> {
        let lifecycle_is_consistent = matches!(
            (snapshot.status, snapshot.disabled_at, snapshot.deleted_at),
            (HookStatus::Active, None, None)
                | (HookStatus::Disabled, Some(_), None)
                | (HookStatus::Deleted, None, Some(_))
        );
        if !lifecycle_is_consistent {
            return Err(DomainError::InvalidFormat {
                field: "hook_status",
                reason: "lifecycle status must have exactly its corresponding timestamp",
            });
        }
        for (field, timestamp) in [
            ("disabled_at", snapshot.disabled_at),
            ("deleted_at", snapshot.deleted_at),
            ("endpoint_rotated_at", snapshot.endpoint_rotated_at),
        ] {
            if timestamp.is_some_and(|timestamp| timestamp < snapshot.created_at) {
                return Err(DomainError::InvalidFormat {
                    field,
                    reason: "must not precede created_at",
                });
            }
        }
        Ok(Self { snapshot })
    }

    /// Returns a read-only persistence snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &HookSnapshot {
        &self.snapshot
    }

    /// Returns the public hook ID.
    #[must_use]
    pub const fn id(&self) -> HookId {
        self.snapshot.id
    }

    /// Returns the owning organization.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.snapshot.organization_id
    }

    /// Returns the owning Silicon.
    #[must_use]
    pub const fn silicon_id(&self) -> &SiliconId {
        &self.snapshot.silicon_id
    }

    /// Returns the display and provider name.
    #[must_use]
    pub const fn name(&self) -> &HookName {
        &self.snapshot.name
    }

    /// Returns the optional description.
    #[must_use]
    pub const fn description(&self) -> Option<&HookDescription> {
        self.snapshot.description.as_ref()
    }

    /// Returns the current routing key.
    #[must_use]
    pub const fn endpoint_key(&self) -> &EndpointKey {
        &self.snapshot.endpoint_key
    }

    /// Returns the signature verification policy.
    #[must_use]
    pub const fn signing(&self) -> &SigningPolicy {
        &self.snapshot.signing
    }

    /// Returns the zone used for delivery summaries.
    #[must_use]
    pub const fn time_zone(&self) -> &HookTimeZone {
        &self.snapshot.time_zone
    }

    /// Returns lifecycle state.
    #[must_use]
    pub const fn status(&self) -> HookStatus {
        self.snapshot.status
    }

    /// Reports whether this hook currently accepts provider requests.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        matches!(self.snapshot.status, HookStatus::Active)
    }

    /// Returns the effective creator.
    #[must_use]
    pub const fn created_by(&self) -> &ActorRef {
        &self.snapshot.created_by
    }

    /// Returns the creation time.
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.snapshot.created_at
    }

    /// Returns the time at which ingress was disabled, if disabled.
    #[must_use]
    pub const fn disabled_at(&self) -> Option<OffsetDateTime> {
        self.snapshot.disabled_at
    }

    /// Returns the deletion time, if deleted.
    #[must_use]
    pub const fn deleted_at(&self) -> Option<OffsetDateTime> {
        self.snapshot.deleted_at
    }

    /// Returns when the provider last reached out with a verified request.
    #[must_use]
    pub const fn last_received_at(&self) -> Option<OffsetDateTime> {
        self.snapshot.last_received_at
    }

    /// Returns when a request was last blocked.
    #[must_use]
    pub const fn last_blocked_at(&self) -> Option<OffsetDateTime> {
        self.snapshot.last_blocked_at
    }

    /// Returns the most recent endpoint rotation time.
    #[must_use]
    pub const fn endpoint_rotated_at(&self) -> Option<OffsetDateTime> {
        self.snapshot.endpoint_rotated_at
    }

    /// Reports whether this aggregate is still inside the product-visible
    /// retention window at the authoritative operation time.
    #[must_use]
    pub fn is_retained_at(&self, now: OffsetDateTime) -> bool {
        self.snapshot.deleted_at.is_none_or(|deleted_at| {
            deleted_at
                .checked_add(Duration::days(HOOK_RECOVERY_DAYS))
                .is_some_and(|deadline| now <= deadline)
        })
    }

    /// Returns the encrypted signing secret, if the policy holds one.
    #[must_use]
    pub const fn encrypted_signing_secret(&self) -> Option<&EncryptedSecret> {
        self.snapshot.signing.encrypted_secret.as_ref()
    }

    /// Stops accepting new requests without deleting the hook or changing its
    /// endpoint and signing secret. Re-applying the current state is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] when the hook is deleted or the disable time
    /// predates creation.
    pub fn disable(&mut self, disabled_at: OffsetDateTime) -> Result<(), TransitionError> {
        match self.snapshot.status {
            HookStatus::Deleted => return Err(TransitionError::HookAlreadyDeleted),
            HookStatus::Disabled => return Ok(()),
            HookStatus::Active => {}
        }
        if disabled_at < self.snapshot.created_at {
            return Err(TransitionError::TimestampOutOfOrder {
                field: "disabled_at",
                predecessor: "created_at",
            });
        }
        self.snapshot.status = HookStatus::Disabled;
        self.snapshot.disabled_at = Some(disabled_at);
        Ok(())
    }

    /// Resumes ingress for a disabled, non-deleted hook. Re-applying the
    /// current state is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] when the hook is deleted or the enable time
    /// predates the disable transition.
    pub fn enable(&mut self, enabled_at: OffsetDateTime) -> Result<(), TransitionError> {
        match self.snapshot.status {
            HookStatus::Deleted => return Err(TransitionError::HookAlreadyDeleted),
            HookStatus::Active => return Ok(()),
            HookStatus::Disabled => {}
        }
        let disabled_at = self
            .snapshot
            .disabled_at
            .ok_or(TransitionError::HookNotDisabled)?;
        if enabled_at < disabled_at {
            return Err(TransitionError::TimestampOutOfOrder {
                field: "enabled_at",
                predecessor: "disabled_at",
            });
        }
        self.snapshot.status = HookStatus::Active;
        self.snapshot.disabled_at = None;
        Ok(())
    }

    /// Soft-deletes an active or disabled hook at the authoritative server time.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] when the hook is already deleted or the
    /// deletion time predates creation or the most recent disable transition.
    pub fn delete(&mut self, deleted_at: OffsetDateTime) -> Result<(), TransitionError> {
        if self.snapshot.status == HookStatus::Deleted {
            return Err(TransitionError::HookAlreadyDeleted);
        }
        if deleted_at < self.snapshot.created_at {
            return Err(TransitionError::TimestampOutOfOrder {
                field: "deleted_at",
                predecessor: "created_at",
            });
        }
        if self
            .snapshot
            .disabled_at
            .is_some_and(|disabled_at| deleted_at < disabled_at)
        {
            return Err(TransitionError::TimestampOutOfOrder {
                field: "deleted_at",
                predecessor: "disabled_at",
            });
        }
        self.snapshot.status = HookStatus::Deleted;
        self.snapshot.disabled_at = None;
        self.snapshot.deleted_at = Some(deleted_at);
        Ok(())
    }

    /// Restores a hook within its 45-day recovery window.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] when the hook is not deleted, the recovery
    /// window expired, or the restore time predates deletion.
    pub fn restore(&mut self, now: OffsetDateTime) -> Result<(), TransitionError> {
        if self.snapshot.status != HookStatus::Deleted {
            return Err(TransitionError::HookNotDeleted);
        }
        let Some(deleted_at) = self.snapshot.deleted_at else {
            return Err(TransitionError::HookNotDeleted);
        };
        let deadline = deleted_at
            .checked_add(Duration::days(HOOK_RECOVERY_DAYS))
            .ok_or(TransitionError::HookRecoveryExpired)?;
        if now > deadline {
            return Err(TransitionError::HookRecoveryExpired);
        }
        if now < deleted_at {
            return Err(TransitionError::TimestampOutOfOrder {
                field: "restored_at",
                predecessor: "deleted_at",
            });
        }
        self.snapshot.status = HookStatus::Active;
        self.snapshot.disabled_at = None;
        self.snapshot.deleted_at = None;
        Ok(())
    }

    /// Replaces the encrypted signing secret of a non-deleted hook.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] when the hook is deleted.
    pub fn rotate_secret(
        &mut self,
        encrypted_signing_secret: EncryptedSecret,
    ) -> Result<(), TransitionError> {
        if self.snapshot.status == HookStatus::Deleted {
            return Err(TransitionError::HookAlreadyDeleted);
        }
        self.snapshot.signing.encrypted_secret = Some(encrypted_signing_secret);
        Ok(())
    }

    /// Replaces the public endpoint of a non-deleted hook and returns the
    /// retired key so persistence can permanently reserve it.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] when the hook is deleted or the rotation
    /// time predates creation.
    pub fn rotate_endpoint(
        &mut self,
        replacement: EndpointKey,
        rotated_at: OffsetDateTime,
    ) -> Result<EndpointKey, TransitionError> {
        if self.snapshot.status == HookStatus::Deleted {
            return Err(TransitionError::HookAlreadyDeleted);
        }
        if rotated_at < self.snapshot.created_at {
            return Err(TransitionError::TimestampOutOfOrder {
                field: "endpoint_rotated_at",
                predecessor: "created_at",
            });
        }
        let retired = std::mem::replace(&mut self.snapshot.endpoint_key, replacement);
        self.snapshot.endpoint_rotated_at = Some(rotated_at);
        Ok(retired)
    }

    /// Updates metadata and signing policy of a non-deleted hook.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] when the hook is deleted.
    pub fn update(&mut self, update: HookUpdate) -> Result<(), TransitionError> {
        if self.snapshot.status == HookStatus::Deleted {
            return Err(TransitionError::HookAlreadyDeleted);
        }
        if let Some(name) = update.name {
            self.snapshot.name = name;
        }
        if let Some(description) = update.description {
            self.snapshot.description = description;
        }
        if let Some(time_zone) = update.time_zone {
            self.snapshot.time_zone = time_zone;
        }
        if let Some(signing) = update.signing {
            self.snapshot.signing = signing;
        }
        Ok(())
    }

    /// Records that a verified request arrived.
    pub fn record_received(&mut self, received_at: OffsetDateTime) {
        self.snapshot.last_received_at = Some(
            self.snapshot
                .last_received_at
                .map_or(received_at, |existing| existing.max(received_at)),
        );
    }

    /// Records that an unverified request was blocked.
    pub fn record_blocked(&mut self, blocked_at: OffsetDateTime) {
        self.snapshot.last_blocked_at = Some(
            self.snapshot
                .last_blocked_at
                .map_or(blocked_at, |existing| existing.max(blocked_at)),
        );
    }
}

/// Partial replacement of hook metadata and signing policy.
///
/// `description: Some(None)` clears the description; `None` leaves it as is.
#[derive(Clone, Debug, Default)]
pub struct HookUpdate {
    /// New display and provider name.
    pub name: Option<HookName>,
    /// New description, or an explicit clear.
    #[allow(clippy::option_option)]
    pub description: Option<Option<HookDescription>>,
    /// New summary time zone.
    pub time_zone: Option<HookTimeZone>,
    /// New signing policy including its encrypted secret.
    pub signing: Option<SigningPolicy>,
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use time::macros::datetime;

    use super::*;
    use crate::domain::{ActorId, ActorKind};

    fn encrypted(byte: u8) -> Result<EncryptedSecret, DomainError> {
        EncryptedSecret::new(
            EncryptionKeyId::new("v1")?,
            [byte; ENCRYPTION_NONCE_BYTES],
            vec![byte; 35 + ENCRYPTION_TAG_BYTES],
        )
    }

    fn policy(byte: u8) -> Result<SigningPolicy, DomainError> {
        Ok(SigningPolicy {
            required: true,
            config: SignatureConfig::default(),
            encrypted_secret: Some(encrypted(byte)?),
        })
    }

    fn hook() -> Result<Hook, Box<dyn std::error::Error>> {
        Ok(Hook::create(NewHook {
            id: HookId::new(),
            organization_id: OrganizationId::new("org:test")?,
            silicon_id: SiliconId::new("silicon:test")?,
            name: HookName::new("GitHub")?,
            description: HookDescription::optional(Some("Source events".to_owned()))?,
            endpoint_key: EndpointKey::parse("A0B1C2D3")?,
            signing: policy(1)?,
            time_zone: HookTimeZone::default(),
            created_by: ActorRef::new(ActorKind::Carbon, ActorId::new("carbon:test")?),
            created_at: datetime!(2026-01-01 0:00 UTC),
        }))
    }

    #[test]
    fn endpoint_key_is_eight_uppercase_alphanumerics() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(EndpointKey::parse("a0z1c2d3")?.as_str(), "A0Z1C2D3");
        assert!(EndpointKey::parse("A0B1C2D").is_err());
        assert!(EndpointKey::parse("A0B1C2D3E").is_err());
        assert!(EndpointKey::parse("A0-1C2D3").is_err());
        let generated = EndpointKey::generate()?;
        assert_eq!(generated.as_str().len(), ENDPOINT_KEY_LENGTH);
        assert!(
            generated
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        );
        Ok(())
    }

    #[test]
    fn generated_secrets_use_the_documented_shape() -> Result<(), Box<dyn std::error::Error>> {
        let secret = SigningSecret::generate()?;
        let text = secret.as_str();
        assert!(text.starts_with(SIGNING_SECRET_PREFIX));
        assert_eq!(
            text.len(),
            SIGNING_SECRET_PREFIX.len() + SIGNING_SECRET_GENERATED_LENGTH
        );
        assert!(
            text[SIGNING_SECRET_PREFIX.len()..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        );
        assert_eq!(format!("{secret:?}"), "SigningSecret([REDACTED])");
        assert!(SigningSecret::from_text("").is_err());
        assert!(SigningSecret::from_text("has\ncontrol").is_err());
        assert!(SigningSecret::from_text("x".repeat(MAX_SECRET_BYTES + 1)).is_err());
        assert!(SigningSecret::from_text("whsec_provider-issued").is_ok());
        Ok(())
    }

    #[test]
    fn encrypted_secret_length_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let key_id = EncryptionKeyId::new("v1")?;
        assert!(EncryptedSecret::new(key_id.clone(), [0; 12], vec![0; 16]).is_err());
        assert!(EncryptedSecret::new(key_id.clone(), [0; 12], vec![0; 17]).is_ok());
        assert!(
            EncryptedSecret::new(key_id.clone(), [0; 12], vec![0; MAX_SECRET_BYTES + 16]).is_ok()
        );
        assert!(EncryptedSecret::new(key_id, [0; 12], vec![0; MAX_SECRET_BYTES + 17]).is_err());
        Ok(())
    }

    #[test]
    fn time_zones_are_validated_against_the_bundled_database() {
        assert_eq!(
            HookTimeZone::new("Europe/Berlin")
                .map(|zone| zone.as_str().to_owned())
                .ok(),
            Some("Europe/Berlin".to_owned())
        );
        assert!(HookTimeZone::new("UTC").is_ok());
        assert!(HookTimeZone::new("Mars/Olympus").is_err());
        assert!(HookTimeZone::new("Europe/Berlin; DROP").is_err());
        assert_eq!(HookTimeZone::default().as_str(), "UTC");
    }

    #[test]
    fn hook_text_limits_count_unicode_characters() {
        assert!(HookName::new("🦀".repeat(MAX_HOOK_NAME_LENGTH)).is_ok());
        assert!(HookName::new("🦀".repeat(MAX_HOOK_NAME_LENGTH + 1)).is_err());
        assert!(HookName::new("service\nname").is_err());
        assert!(HookDescription::new("界".repeat(MAX_HOOK_DESCRIPTION_LENGTH)).is_ok());
        assert!(HookDescription::new("界".repeat(MAX_HOOK_DESCRIPTION_LENGTH + 1)).is_err());
        assert!(HookDescription::new("description\0text").is_err());
    }

    #[test]
    fn soft_delete_and_restore_obey_the_recovery_window() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut hook = hook()?;
        let deleted_at = datetime!(2026-01-02 0:00 UTC);
        hook.delete(deleted_at)?;

        assert_eq!(hook.status(), HookStatus::Deleted);
        assert!(hook.is_retained_at(deleted_at + Duration::days(HOOK_RECOVERY_DAYS)));
        assert!(!hook.is_retained_at(
            deleted_at + Duration::days(HOOK_RECOVERY_DAYS) + Duration::microseconds(1)
        ));
        assert_eq!(
            hook.restore(deleted_at + Duration::days(HOOK_RECOVERY_DAYS + 1)),
            Err(TransitionError::HookRecoveryExpired)
        );
        assert_eq!(
            hook.rotate_endpoint(EndpointKey::parse("ZZZZZZZZ")?, deleted_at),
            Err(TransitionError::HookAlreadyDeleted)
        );
        hook.restore(deleted_at + Duration::days(HOOK_RECOVERY_DAYS))?;
        assert_eq!(hook.status(), HookStatus::Active);
        Ok(())
    }

    #[test]
    fn disable_enable_and_rotation_preserve_identity() -> Result<(), Box<dyn std::error::Error>> {
        let mut hook = hook()?;
        let hook_id = hook.id();
        let disabled_at = datetime!(2026-01-02 0:00 UTC);

        hook.disable(disabled_at)?;
        assert!(!hook.is_enabled());
        hook.disable(datetime!(2026-01-03 0:00 UTC))?;
        assert_eq!(hook.disabled_at(), Some(disabled_at));

        let replacement = encrypted(2)?;
        hook.rotate_secret(replacement.clone())?;
        assert_eq!(hook.encrypted_signing_secret(), Some(&replacement));

        let rotated_at = datetime!(2026-01-04 0:00 UTC);
        let retired = hook.rotate_endpoint(EndpointKey::parse("NEW12345")?, rotated_at)?;
        assert_eq!(retired.as_str(), "A0B1C2D3");
        assert_eq!(hook.endpoint_key().as_str(), "NEW12345");
        assert_eq!(hook.endpoint_rotated_at(), Some(rotated_at));

        hook.enable(datetime!(2026-01-05 0:00 UTC))?;
        assert!(hook.is_enabled());
        assert_eq!(hook.id(), hook_id);

        hook.record_received(datetime!(2026-01-06 0:00 UTC));
        hook.record_received(datetime!(2026-01-05 12:00 UTC));
        assert_eq!(
            hook.last_received_at(),
            Some(datetime!(2026-01-06 0:00 UTC))
        );
        hook.record_blocked(datetime!(2026-01-07 0:00 UTC));
        assert_eq!(hook.last_blocked_at(), Some(datetime!(2026-01-07 0:00 UTC)));

        hook.update(HookUpdate {
            name: Some(HookName::new("GitLab")?),
            description: Some(None),
            time_zone: Some(HookTimeZone::new("Asia/Kolkata")?),
            signing: Some(SigningPolicy {
                required: false,
                config: SignatureConfig::default(),
                encrypted_secret: None,
            }),
        })?;
        assert_eq!(hook.name().as_str(), "GitLab");
        assert_eq!(hook.description(), None);
        assert_eq!(hook.time_zone().as_str(), "Asia/Kolkata");
        assert!(!hook.signing().is_required());
        assert_eq!(hook.encrypted_signing_secret(), None);
        Ok(())
    }

    #[test]
    fn rehydration_rejects_inconsistent_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
        let active = hook()?.snapshot().clone();
        let disabled_at = datetime!(2026-01-02 0:00 UTC);

        let mut disabled = active.clone();
        disabled.status = HookStatus::Disabled;
        disabled.disabled_at = Some(disabled_at);
        assert!(Hook::rehydrate(disabled).is_ok());

        let mut active_with_disabled_at = active.clone();
        active_with_disabled_at.disabled_at = Some(disabled_at);
        assert!(Hook::rehydrate(active_with_disabled_at).is_err());

        let mut early_rotation = active;
        early_rotation.endpoint_rotated_at = Some(datetime!(2025-12-31 0:00 UTC));
        assert!(Hook::rehydrate(early_rotation).is_err());
        Ok(())
    }

    proptest! {
        #[test]
        fn every_alphanumeric_key_round_trips(value in "[A-Za-z0-9]{8}") {
            let parsed = EndpointKey::parse(&value);
            prop_assert!(parsed.is_ok());
            if let Ok(parsed) = parsed {
                prop_assert_eq!(parsed.as_str(), value.to_ascii_uppercase());
            }
        }
    }
}
