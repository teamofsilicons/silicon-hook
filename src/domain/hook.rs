//! Webhook aggregate, endpoint key, and secret-bearing value objects.

use std::{fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use super::{
    ActorRef, ApplicationId, DomainError, EntropyError, HookId, OrganizationId, SiliconId,
    TransitionError,
};

/// Number of random bytes in a webhook HMAC-SHA-256 secret.
pub const SIGNING_SECRET_BYTES: usize = 32;
/// Prefix distinguishing webhook signing credentials from other opaque values.
pub const SIGNING_SECRET_PREFIX: &str = "whsec_";
/// Length of an AES-GCM nonce.
pub const ENCRYPTION_NONCE_BYTES: usize = 12;
/// Recovery window for a soft-deleted hook.
pub const HOOK_RECOVERY_DAYS: i64 = 45;

const ENDPOINT_KEY_BYTES: usize = 3;
const ENDPOINT_KEY_HEX_LENGTH: usize = ENDPOINT_KEY_BYTES * 2;
const MAX_HOOK_NAME_LENGTH: usize = 200;
const MAX_HOOK_DESCRIPTION_LENGTH: usize = 2_000;
const MAX_ENCRYPTION_KEY_ID_BYTES: usize = 64;
const AES_GCM_TAG_BYTES: usize = 16;

/// Six-character hexadecimal routing key in a public webhook URL.
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
        let mut bytes = [0_u8; ENDPOINT_KEY_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| EntropyError)?;
        Ok(Self(hex::encode_upper(bytes)))
    }

    /// Parses a route key and normalizes hexadecimal letters to uppercase.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] unless the input contains exactly six
    /// hexadecimal characters.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if value.len() != ENDPOINT_KEY_HEX_LENGTH
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(DomainError::InvalidFormat {
                field: "endpoint_key",
                reason: "must be exactly six hexadecimal characters",
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

/// A plaintext webhook signing secret.
///
/// Debug output is always redacted and memory is zeroized when the last copy is
/// dropped. This value must never be persisted or logged.
pub struct SigningSecret(Zeroizing<[u8; SIGNING_SECRET_BYTES]>);

impl SigningSecret {
    /// Creates a new signing secret from operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyError`] when the operating system cannot provide
    /// cryptographically secure randomness.
    pub fn generate() -> Result<Self, EntropyError> {
        let mut bytes = Zeroizing::new([0_u8; SIGNING_SECRET_BYTES]);
        getrandom::fill(bytes.as_mut()).map_err(|_| EntropyError)?;
        Ok(Self(bytes))
    }

    /// Wraps exactly 32 secret bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SIGNING_SECRET_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) const fn from_zeroizing(bytes: Zeroizing<[u8; SIGNING_SECRET_BYTES]>) -> Self {
        Self(bytes)
    }

    /// Decodes the one-time `whsec_` credential representation.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] unless the value is the canonical unpadded
    /// base64url encoding of exactly 32 bytes with the `whsec_` prefix.
    pub fn from_encoded(value: &str) -> Result<Self, DomainError> {
        let encoded =
            value
                .strip_prefix(SIGNING_SECRET_PREFIX)
                .ok_or(DomainError::InvalidFormat {
                    field: "signing_secret",
                    reason: "must start with whsec_",
                })?;
        let mut bytes = Zeroizing::new([0_u8; SIGNING_SECRET_BYTES]);
        let decoded_length = URL_SAFE_NO_PAD
            .decode_slice(encoded, bytes.as_mut())
            .map_err(|_| DomainError::InvalidFormat {
                field: "signing_secret",
                reason: "must contain unpadded base64url",
            })?;
        if decoded_length != SIGNING_SECRET_BYTES {
            return Err(DomainError::InvalidFormat {
                field: "signing_secret",
                reason: "must encode exactly 32 bytes",
            });
        }
        if URL_SAFE_NO_PAD.encode(bytes.as_ref()) != encoded {
            return Err(DomainError::InvalidFormat {
                field: "signing_secret",
                reason: "must use canonical unpadded base64url",
            });
        }
        Ok(Self::from_zeroizing(bytes))
    }

    /// Returns the secret bytes for cryptographic operations.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SIGNING_SECRET_BYTES] {
        &self.0
    }

    /// Encodes the secret for its bounded one-time API response.
    #[must_use]
    pub fn to_encoded(&self) -> Zeroizing<String> {
        let mut encoded = String::with_capacity(SIGNING_SECRET_PREFIX.len() + 43);
        encoded.push_str(SIGNING_SECRET_PREFIX);
        URL_SAFE_NO_PAD.encode_string(self.as_bytes(), &mut encoded);
        Zeroizing::new(encoded)
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

impl Serialize for EncryptionKeyId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EncryptionKeyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
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
    /// Returns [`DomainError`] unless the ciphertext has the exact size of a
    /// 32-byte plaintext and the AES-GCM authentication tag.
    pub fn new(
        key_id: EncryptionKeyId,
        nonce: [u8; ENCRYPTION_NONCE_BYTES],
        ciphertext: Vec<u8>,
    ) -> Result<Self, DomainError> {
        if ciphertext.len() != SIGNING_SECRET_BYTES + AES_GCM_TAG_BYTES {
            return Err(DomainError::InvalidFormat {
                field: "encrypted_signing_secret",
                reason: "ciphertext must contain a 32-byte secret and AES-GCM authentication tag",
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

/// Validated display name for a hook connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookName(String);

impl HookName {
    /// Trims and validates a hook name.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the trimmed name is empty or exceeds 200
    /// Unicode scalar values.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let value = value.trim();
        if value.is_empty() {
            return Err(DomainError::Empty { field: "name" });
        }
        reject_postgres_nul(value, "name")?;
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
    /// Returns [`DomainError`] when the trimmed description is empty or
    /// exceeds 2,000 Unicode scalar values.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let value = value.trim();
        if value.is_empty() {
            return Err(DomainError::Empty {
                field: "description",
            });
        }
        reject_postgres_nul(value, "description")?;
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

fn reject_postgres_nul(value: &str, field: &'static str) -> Result<(), DomainError> {
    if value.contains('\0') {
        return Err(DomainError::InvalidFormat {
            field,
            reason: "must not contain U+0000",
        });
    }
    Ok(())
}

/// Lifecycle state of a hook.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookStatus {
    /// Accepting signed events.
    Active,
    /// Disabled and retained during the recovery window.
    Deleted,
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
    /// Display name.
    pub name: HookName,
    /// Optional description.
    pub description: Option<HookDescription>,
    /// URL routing key.
    pub endpoint_key: EndpointKey,
    /// Effective creator.
    pub created_by: ActorRef,
    /// OBO application that created the hook, if any.
    pub created_via_application: Option<ApplicationId>,
    /// Authoritative creation time.
    pub created_at: OffsetDateTime,
    /// Encrypted signing secret.
    pub encrypted_signing_secret: EncryptedSecret,
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
    /// Display name.
    pub name: HookName,
    /// Optional description.
    pub description: Option<HookDescription>,
    /// URL routing key.
    pub endpoint_key: EndpointKey,
    /// Lifecycle state.
    pub status: HookStatus,
    /// Effective creator.
    pub created_by: ActorRef,
    /// OBO application that created it, if any.
    pub created_via_application: Option<ApplicationId>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Deletion time for a deleted hook.
    pub deleted_at: Option<OffsetDateTime>,
    /// Encrypted signing secret.
    pub encrypted_signing_secret: EncryptedSecret,
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
                status: HookStatus::Active,
                created_by: new.created_by,
                created_via_application: new.created_via_application,
                created_at: new.created_at,
                deleted_at: None,
                encrypted_signing_secret: new.encrypted_signing_secret,
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
            (snapshot.status, snapshot.deleted_at),
            (HookStatus::Active, None) | (HookStatus::Deleted, Some(_))
        );
        if !lifecycle_is_consistent {
            return Err(DomainError::InvalidFormat {
                field: "hook_status",
                reason: "active hooks cannot have deleted_at and deleted hooks must have it",
            });
        }
        if snapshot
            .deleted_at
            .is_some_and(|deleted_at| deleted_at < snapshot.created_at)
        {
            return Err(DomainError::InvalidFormat {
                field: "deleted_at",
                reason: "must not precede created_at",
            });
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

    /// Returns the display name.
    #[must_use]
    pub const fn name(&self) -> &HookName {
        &self.snapshot.name
    }

    /// Returns the optional description.
    #[must_use]
    pub const fn description(&self) -> Option<&HookDescription> {
        self.snapshot.description.as_ref()
    }

    /// Returns the routing key.
    #[must_use]
    pub const fn endpoint_key(&self) -> &EndpointKey {
        &self.snapshot.endpoint_key
    }

    /// Returns lifecycle state.
    #[must_use]
    pub const fn status(&self) -> HookStatus {
        self.snapshot.status
    }

    /// Returns the effective creator.
    #[must_use]
    pub const fn created_by(&self) -> &ActorRef {
        &self.snapshot.created_by
    }

    /// Returns the OBO creating application, if any.
    #[must_use]
    pub const fn created_via_application(&self) -> Option<&ApplicationId> {
        self.snapshot.created_via_application.as_ref()
    }

    /// Returns the creation time.
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.snapshot.created_at
    }

    /// Returns the deletion time, if deleted.
    #[must_use]
    pub const fn deleted_at(&self) -> Option<OffsetDateTime> {
        self.snapshot.deleted_at
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

    /// Returns the encrypted signing secret for persistence or verification.
    #[must_use]
    pub const fn encrypted_signing_secret(&self) -> &EncryptedSecret {
        &self.snapshot.encrypted_signing_secret
    }

    /// Soft-deletes an active hook at the authoritative server time.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] when the hook is already deleted or the
    /// deletion time predates creation.
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
        self.snapshot.status = HookStatus::Deleted;
        self.snapshot.deleted_at = Some(deleted_at);
        Ok(())
    }

    /// Restores a hook within its 45-day recovery window.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] when the hook is active, the recovery window
    /// expired, or the restore time predates deletion.
    pub fn restore(&mut self, now: OffsetDateTime) -> Result<(), TransitionError> {
        if self.snapshot.status == HookStatus::Active {
            return Err(TransitionError::HookAlreadyActive);
        }
        let Some(deleted_at) = self.snapshot.deleted_at else {
            return Err(TransitionError::HookAlreadyActive);
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
        self.snapshot.deleted_at = None;
        Ok(())
    }

    /// Immediately replaces the encrypted signing secret of an active hook.
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
        self.snapshot.encrypted_signing_secret = encrypted_signing_secret;
        Ok(())
    }
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
            vec![byte; SIGNING_SECRET_BYTES + AES_GCM_TAG_BYTES],
        )
    }

    fn hook() -> Result<Hook, Box<dyn std::error::Error>> {
        Ok(Hook::create(NewHook {
            id: HookId::new(),
            organization_id: OrganizationId::new("org:test")?,
            silicon_id: SiliconId::new("silicon:test")?,
            name: HookName::new("GitHub")?,
            description: HookDescription::optional(Some("Source events".to_owned()))?,
            endpoint_key: EndpointKey::parse("a0b1c2")?,
            created_by: ActorRef::new(ActorKind::Carbon, ActorId::new("carbon:test")?),
            created_via_application: None,
            created_at: datetime!(2026-01-01 0:00 UTC),
            encrypted_signing_secret: encrypted(1)?,
        }))
    }

    #[test]
    fn endpoint_key_normalizes_route_case() -> Result<(), DomainError> {
        assert_eq!(EndpointKey::parse("a0B1c2")?.as_str(), "A0B1C2");
        assert!(EndpointKey::parse("A0B1C").is_err());
        assert!(EndpointKey::parse("G0B1C2").is_err());
        Ok(())
    }

    #[test]
    fn signing_secret_uses_redacted_prefixed_encoding() -> Result<(), Box<dyn std::error::Error>> {
        let secret = SigningSecret::from_bytes([0x42; SIGNING_SECRET_BYTES]);
        let encoded = secret.to_encoded();
        let decoded = SigningSecret::from_encoded(encoded.as_str())?;

        assert!(encoded.starts_with(SIGNING_SECRET_PREFIX));
        assert!(!encoded.contains('='));
        assert_eq!(decoded.as_bytes(), secret.as_bytes());
        assert_eq!(format!("{secret:?}"), "SigningSecret([REDACTED])");
        Ok(())
    }

    #[test]
    fn signing_secret_rejects_noncanonical_encoding() {
        let secret = SigningSecret::from_bytes([0x42; SIGNING_SECRET_BYTES]);
        let encoded = secret.to_encoded();
        assert!(SigningSecret::from_encoded(&format!("{}=", encoded.as_str())).is_err());
        assert!(SigningSecret::from_encoded(&encoded.to_ascii_uppercase()).is_err());

        let mut alternate_pad_bits = encoded.as_str().to_owned();
        alternate_pad_bits.pop();
        alternate_pad_bits.push('B');
        assert!(SigningSecret::from_encoded(&alternate_pad_bits).is_err());
    }

    #[test]
    fn hook_text_limits_count_unicode_characters() {
        assert!(HookName::new("🦀".repeat(MAX_HOOK_NAME_LENGTH)).is_ok());
        assert!(HookName::new("🦀".repeat(MAX_HOOK_NAME_LENGTH + 1)).is_err());
        assert!(HookDescription::new("界".repeat(MAX_HOOK_DESCRIPTION_LENGTH)).is_ok());
        assert!(HookDescription::new("界".repeat(MAX_HOOK_DESCRIPTION_LENGTH + 1)).is_err());
    }

    #[test]
    fn hook_text_rejects_postgres_incompatible_nul() {
        assert!(HookName::new("service\0name").is_err());
        assert!(HookDescription::new("description\0text").is_err());
    }

    #[test]
    fn hook_soft_delete_and_restore_obey_the_recovery_window()
    -> Result<(), Box<dyn std::error::Error>> {
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
        hook.restore(deleted_at + Duration::days(HOOK_RECOVERY_DAYS))?;
        assert_eq!(hook.status(), HookStatus::Active);
        assert_eq!(hook.deleted_at(), None);
        Ok(())
    }

    #[test]
    fn deleted_hook_cannot_rotate_its_secret() -> Result<(), Box<dyn std::error::Error>> {
        let mut hook = hook()?;
        hook.delete(datetime!(2026-01-02 0:00 UTC))?;

        assert_eq!(
            hook.rotate_secret(encrypted(2)?),
            Err(TransitionError::HookAlreadyDeleted)
        );
        Ok(())
    }

    #[test]
    fn rehydration_rejects_inconsistent_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
        let hook = hook()?;
        let mut snapshot = hook.snapshot().clone();
        snapshot.status = HookStatus::Deleted;

        assert!(Hook::rehydrate(snapshot).is_err());
        Ok(())
    }

    proptest! {
        #[test]
        fn every_three_byte_endpoint_key_round_trips(bytes: [u8; ENDPOINT_KEY_BYTES]) {
            let encoded = hex::encode_upper(bytes);
            let parsed = EndpointKey::parse(&encoded);
            prop_assert!(parsed.is_ok());
            if let Ok(parsed) = parsed {
                prop_assert_eq!(parsed.as_str(), encoded);
            }
        }

        #[test]
        fn signing_secret_encoding_round_trips(bytes: [u8; SIGNING_SECRET_BYTES]) {
            let secret = SigningSecret::from_bytes(bytes);
            let encoded = secret.to_encoded();
            let decoded = SigningSecret::from_encoded(encoded.as_str());
            prop_assert!(decoded.is_ok());
            if let Ok(decoded) = decoded {
                prop_assert_eq!(decoded.as_bytes(), secret.as_bytes());
            }
        }
    }
}
