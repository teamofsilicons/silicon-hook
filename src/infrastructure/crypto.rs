//! Cryptographic boundary for stored secrets and history cursors.
//!
//! Key material and plaintext signing secrets have redacted debug output and
//! zeroize their owned memory on drop. Authentication failures deliberately do
//! not expose computed values. Provider signature verification lives in the
//! domain's `signature` module; this module protects what Hook itself stores.

use std::{collections::BTreeMap, fmt};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead as _, KeyInit as _, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::domain::{
    DomainError, ENCRYPTION_NONCE_BYTES, EncryptedSecret, EncryptionKeyId, HistoryCursor,
    HistoryCursorScope, HookId, SigningSecret,
};

const KEY_BYTES: usize = 32;
const HMAC_TAG_BYTES: usize = 32;
const CURSOR_VERSION: u8 = 2;
const MAX_CURSOR_BYTES: usize = 2_048;
const SECRET_AAD_DOMAIN: &[u8] = b"silicon-hook/signing-secret/v2\0";

type HmacSha256 = Hmac<Sha256>;

/// Redacting 256-bit runtime key material.
///
/// The same representation is accepted by the two distinct consumers, but
/// configuration must provide different values for cursor authentication and
/// data encryption.
pub struct SecretKey(Zeroizing<[u8; KEY_BYTES]>);

impl SecretKey {
    /// Wraps exactly 32 bytes of key material.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Decodes exactly 32 bytes from unpadded base64url configuration.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`] when the value is not canonical unpadded base64url
    /// or does not decode to exactly 32 bytes.
    pub fn from_base64url(value: &str) -> Result<Self, KeyError> {
        if value.contains('=') {
            return Err(KeyError::InvalidEncoding);
        }
        let mut bytes = Zeroizing::new([0_u8; KEY_BYTES]);
        let decoded_length = URL_SAFE_NO_PAD
            .decode_slice(value, bytes.as_mut())
            .map_err(|_| KeyError::InvalidEncoding)?;
        if decoded_length != KEY_BYTES {
            return Err(KeyError::InvalidLength);
        }
        if URL_SAFE_NO_PAD.encode(bytes.as_ref()) != value {
            return Err(KeyError::InvalidEncoding);
        }
        Ok(Self(bytes))
    }

    fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretKey([REDACTED])")
    }
}

/// Invalid cryptographic configuration.
#[derive(Debug, Error)]
pub enum KeyError {
    /// Key configuration was not canonical unpadded base64url.
    #[error("key must be canonical unpadded base64url")]
    InvalidEncoding,
    /// Decoded key material was not exactly 32 bytes.
    #[error("key must decode to exactly 32 bytes")]
    InvalidLength,
    /// The encryption keyring did not contain its configured current key.
    #[error("current encryption key is absent from the keyring")]
    CurrentKeyMissing,
    /// A key ID appeared more than once.
    #[error("duplicate encryption key id: {0}")]
    DuplicateKey(EncryptionKeyId),
    /// No encryption keys were configured.
    #[error("encryption keyring must not be empty")]
    EmptyKeyring,
}

/// A versioned AES-256 encryption keyring.
pub struct SecretKeyring {
    current_key_id: EncryptionKeyId,
    keys: BTreeMap<EncryptionKeyId, SecretKey>,
}

impl SecretKeyring {
    /// Builds a keyring and verifies that the active version is decryptable.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`] for an empty keyring, duplicate key identifiers, or
    /// a current identifier that is not present.
    pub fn new(
        current_key_id: EncryptionKeyId,
        entries: impl IntoIterator<Item = (EncryptionKeyId, SecretKey)>,
    ) -> Result<Self, KeyError> {
        let mut keys = BTreeMap::new();
        for (key_id, key) in entries {
            if keys.insert(key_id.clone(), key).is_some() {
                return Err(KeyError::DuplicateKey(key_id));
            }
        }
        if keys.is_empty() {
            return Err(KeyError::EmptyKeyring);
        }
        if !keys.contains_key(&current_key_id) {
            return Err(KeyError::CurrentKeyMissing);
        }
        Ok(Self {
            current_key_id,
            keys,
        })
    }

    /// Returns the version used for new ciphertexts.
    #[must_use]
    pub const fn current_key_id(&self) -> &EncryptionKeyId {
        &self.current_key_id
    }

    fn current_key(&self) -> Result<&SecretKey, SecretCipherError> {
        self.keys
            .get(&self.current_key_id)
            .ok_or(SecretCipherError::UnknownKey)
    }

    fn key(&self, key_id: &EncryptionKeyId) -> Result<&SecretKey, SecretCipherError> {
        self.keys.get(key_id).ok_or(SecretCipherError::UnknownKey)
    }
}

impl fmt::Debug for SecretKeyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretKeyring")
            .field("current_key_id", &self.current_key_id)
            .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Failure to encrypt or authenticate a persisted signing secret.
#[derive(Debug, Error)]
pub enum SecretCipherError {
    /// The ciphertext references an unavailable key version.
    #[error("encrypted secret references an unavailable key")]
    UnknownKey,
    /// Operating-system randomness was unavailable.
    #[error("operating-system randomness unavailable")]
    Randomness,
    /// Encryption failed without producing a usable ciphertext.
    #[error("signing-secret encryption failed")]
    Encryption,
    /// Authentication failed, including when hook associated data differs.
    #[error("signing-secret authentication failed")]
    Authentication,
    /// An internally generated encrypted-secret value violated its domain shape.
    #[error("invalid encrypted-secret representation: {0}")]
    InvalidRepresentation(#[from] DomainError),
}

/// AES-256-GCM protection for webhook signing secrets.
pub struct SecretCipher {
    keyring: SecretKeyring,
}

impl SecretCipher {
    /// Constructs a cipher from a validated versioned keyring.
    #[must_use]
    pub const fn new(keyring: SecretKeyring) -> Self {
        Self { keyring }
    }

    /// Encrypts a signing secret under the current key with the hook UUID as
    /// associated data.
    ///
    /// # Errors
    ///
    /// Returns [`SecretCipherError`] when randomness is unavailable, the
    /// current key cannot be selected, or authenticated encryption fails.
    pub fn encrypt(
        &self,
        hook_id: HookId,
        secret: &SigningSecret,
    ) -> Result<EncryptedSecret, SecretCipherError> {
        let mut nonce = [0_u8; ENCRYPTION_NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| SecretCipherError::Randomness)?;
        let key = self.keyring.current_key()?;
        let cipher =
            Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| SecretCipherError::Encryption)?;
        let aad = signing_secret_aad(hook_id);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret.as_str().as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| SecretCipherError::Encryption)?;
        EncryptedSecret::new(self.keyring.current_key_id().clone(), nonce, ciphertext)
            .map_err(SecretCipherError::from)
    }

    /// Decrypts and authenticates a stored signing secret for one hook.
    ///
    /// # Errors
    ///
    /// Returns [`SecretCipherError`] for an unknown key version, modified
    /// ciphertext, mismatched hook identity, or a plaintext that is no longer
    /// a valid secret.
    pub fn decrypt(
        &self,
        hook_id: HookId,
        encrypted: &EncryptedSecret,
    ) -> Result<SigningSecret, SecretCipherError> {
        let key = self.keyring.key(encrypted.key_id())?;
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|_| SecretCipherError::Authentication)?;
        let aad = signing_secret_aad(hook_id);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(encrypted.nonce()),
                Payload {
                    msg: encrypted.ciphertext(),
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| SecretCipherError::Authentication)?;
        let text = Zeroizing::new(
            String::from_utf8(plaintext.to_vec()).map_err(|_| SecretCipherError::Authentication)?,
        );
        SigningSecret::from_zeroizing(text).map_err(SecretCipherError::from)
    }

    /// Re-encrypts a value under the active version and a fresh nonce.
    ///
    /// # Errors
    ///
    /// Returns [`SecretCipherError`] when either authentication of the old
    /// value or encryption under the active key fails.
    pub fn reencrypt(
        &self,
        hook_id: HookId,
        encrypted: &EncryptedSecret,
    ) -> Result<EncryptedSecret, SecretCipherError> {
        let plaintext = self.decrypt(hook_id, encrypted)?;
        self.encrypt(hook_id, &plaintext)
    }

    /// Reports whether a stored value uses an older key version.
    #[must_use]
    pub fn needs_reencryption(&self, encrypted: &EncryptedSecret) -> bool {
        encrypted.key_id() != self.keyring.current_key_id()
    }
}

impl fmt::Debug for SecretCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretCipher")
            .field("keyring", &self.keyring)
            .finish()
    }
}

fn signing_secret_aad(hook_id: HookId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SECRET_AAD_DOMAIN.len() + 16);
    aad.extend_from_slice(SECRET_AAD_DOMAIN);
    aad.extend_from_slice(hook_id.as_uuid().as_bytes());
    aad
}

/// Failure to decode or authenticate a history cursor.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CursorError {
    /// Cursor is too large to process.
    #[error("cursor exceeds its maximum size")]
    TooLong,
    /// Cursor was not canonical unpadded base64url or was structurally short.
    #[error("cursor encoding is invalid")]
    InvalidEncoding,
    /// Cursor authentication tag did not verify.
    #[error("cursor authentication failed")]
    Authentication,
    /// Cursor payload was not the supported schema.
    #[error("cursor payload is invalid")]
    InvalidPayload,
    /// Cursor was issued by an unsupported schema version.
    #[error("cursor version is unsupported")]
    UnsupportedVersion,
    /// Cursor belongs to a different tenant, Silicon, collection, or filter set.
    #[error("cursor does not match the current query")]
    ScopeMismatch,
}

#[derive(Deserialize, Serialize)]
struct CursorClaims {
    version: u8,
    scope: HistoryCursorScope,
    received_at_unix_nanos: i128,
    id: Uuid,
}

/// Stateless authenticated codec for history keyset cursors.
pub struct CursorCodec {
    key: SecretKey,
}

impl CursorCodec {
    /// Creates a cursor codec from its dedicated HMAC key.
    #[must_use]
    pub const fn new(key: SecretKey) -> Self {
        Self { key }
    }

    /// Encodes and authenticates a boundary under its complete query scope.
    ///
    /// # Errors
    ///
    /// Returns [`CursorError`] if the claims cannot be serialized or the HMAC
    /// implementation rejects its dedicated key.
    pub fn encode(
        &self,
        scope: &HistoryCursorScope,
        cursor: HistoryCursor,
    ) -> Result<String, CursorError> {
        let claims = CursorClaims {
            version: CURSOR_VERSION,
            scope: scope.clone(),
            received_at_unix_nanos: cursor.received_at().unix_timestamp_nanos(),
            id: cursor.id(),
        };
        let payload = serde_json::to_vec(&claims).map_err(|_| CursorError::InvalidPayload)?;
        let tag = self.authenticate(&payload)?;
        let mut authenticated = Vec::with_capacity(payload.len() + HMAC_TAG_BYTES);
        authenticated.extend_from_slice(&payload);
        authenticated.extend_from_slice(&tag);
        Ok(URL_SAFE_NO_PAD.encode(authenticated))
    }

    /// Authenticates, parses, and scope-checks an opaque cursor.
    ///
    /// # Errors
    ///
    /// Returns [`CursorError`] for oversized or malformed input, failed
    /// authentication, unsupported versions, invalid timestamps, or scope
    /// mismatch.
    pub fn decode(
        &self,
        expected_scope: &HistoryCursorScope,
        encoded: &str,
    ) -> Result<HistoryCursor, CursorError> {
        if encoded.len() > MAX_CURSOR_BYTES {
            return Err(CursorError::TooLong);
        }
        if encoded.is_empty() || encoded.contains('=') {
            return Err(CursorError::InvalidEncoding);
        }
        let authenticated = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| CursorError::InvalidEncoding)?;
        if authenticated.len() <= HMAC_TAG_BYTES {
            return Err(CursorError::InvalidEncoding);
        }
        let payload_length = authenticated.len() - HMAC_TAG_BYTES;
        let (payload, supplied_tag) = authenticated.split_at(payload_length);
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(self.key.as_bytes())
            .map_err(|_| CursorError::Authentication)?;
        mac.update(payload);
        mac.verify_slice(supplied_tag)
            .map_err(|_| CursorError::Authentication)?;

        let claims: CursorClaims =
            serde_json::from_slice(payload).map_err(|_| CursorError::InvalidPayload)?;
        if claims.version != CURSOR_VERSION {
            return Err(CursorError::UnsupportedVersion);
        }
        if &claims.scope != expected_scope {
            return Err(CursorError::ScopeMismatch);
        }
        let received_at = OffsetDateTime::from_unix_timestamp_nanos(claims.received_at_unix_nanos)
            .map_err(|_| CursorError::InvalidPayload)?;
        Ok(HistoryCursor::new(received_at, claims.id))
    }

    fn authenticate(&self, payload: &[u8]) -> Result<[u8; HMAC_TAG_BYTES], CursorError> {
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(self.key.as_bytes())
            .map_err(|_| CursorError::Authentication)?;
        mac.update(payload);
        Ok(mac.finalize().into_bytes().into())
    }
}

impl fmt::Debug for CursorCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CursorCodec { key: [REDACTED] }")
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use time::macros::datetime;

    use super::*;
    use crate::domain::{HistoryCollection, HistoryFilter, OrganizationId, SiliconId};

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_bytes([byte; KEY_BYTES])
    }

    fn key_id(value: &str) -> Result<EncryptionKeyId, DomainError> {
        EncryptionKeyId::new(value)
    }

    fn cipher() -> Result<SecretCipher, Box<dyn std::error::Error>> {
        Ok(SecretCipher::new(SecretKeyring::new(
            key_id("v2")?,
            [(key_id("v1")?, key(1)), (key_id("v2")?, key(2))],
        )?))
    }

    fn scope() -> Result<HistoryCursorScope, DomainError> {
        Ok(HistoryCursorScope::new(
            OrganizationId::new("org:test")?,
            SiliconId::new("silicon:test")?,
            HistoryCollection::Events,
            HistoryFilter::new(None),
        ))
    }

    #[test]
    fn secret_key_configuration_is_strict_and_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = URL_SAFE_NO_PAD.encode([7_u8; KEY_BYTES]);
        let key = SecretKey::from_base64url(&encoded)?;

        assert_eq!(format!("{key:?}"), "SecretKey([REDACTED])");
        assert!(SecretKey::from_base64url(&(encoded + "=")).is_err());
        assert!(SecretKey::from_base64url("short").is_err());
        Ok(())
    }

    #[test]
    fn keyring_rejects_missing_current_and_duplicates() -> Result<(), Box<dyn std::error::Error>> {
        let missing = SecretKeyring::new(key_id("v2")?, [(key_id("v1")?, key(1))]);
        assert!(matches!(missing, Err(KeyError::CurrentKeyMissing)));

        let duplicate = SecretKeyring::new(
            key_id("v1")?,
            [(key_id("v1")?, key(1)), (key_id("v1")?, key(2))],
        );
        assert!(matches!(duplicate, Err(KeyError::DuplicateKey(_))));
        Ok(())
    }

    #[test]
    fn aes_gcm_round_trip_is_bound_to_hook_identity() -> Result<(), Box<dyn std::error::Error>> {
        let cipher = cipher()?;
        let hook_id = HookId::new();
        let other_hook = HookId::new();
        let secret = SigningSecret::from_text("whsec_provider-issued-value")?;
        let encrypted = cipher.encrypt(hook_id, &secret)?;

        assert_eq!(
            cipher.decrypt(hook_id, &encrypted)?.as_str(),
            secret.as_str()
        );
        assert!(matches!(
            cipher.decrypt(other_hook, &encrypted),
            Err(SecretCipherError::Authentication)
        ));
        assert_eq!(encrypted.key_id().as_str(), "v2");
        assert_eq!(
            encrypted.ciphertext().len(),
            secret.as_str().len() + crate::domain::ENCRYPTION_TAG_BYTES
        );
        Ok(())
    }

    #[test]
    fn ciphertext_tampering_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let cipher = cipher()?;
        let hook_id = HookId::new();
        let encrypted = cipher.encrypt(hook_id, &SigningSecret::generate()?)?;
        let (key_id, nonce, mut ciphertext) = encrypted.into_parts();
        if let Some(first) = ciphertext.first_mut() {
            *first ^= 1;
        }
        let tampered = EncryptedSecret::new(key_id, nonce, ciphertext)?;

        assert!(matches!(
            cipher.decrypt(hook_id, &tampered),
            Err(SecretCipherError::Authentication)
        ));
        Ok(())
    }

    #[test]
    fn old_key_ciphertext_can_be_reencrypted_under_current_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let old_cipher = SecretCipher::new(SecretKeyring::new(
            key_id("v1")?,
            [(key_id("v1")?, key(1))],
        )?);
        let rotating_cipher = cipher()?;
        let hook_id = HookId::new();
        let secret = SigningSecret::generate()?;
        let old = old_cipher.encrypt(hook_id, &secret)?;

        assert!(rotating_cipher.needs_reencryption(&old));
        let current = rotating_cipher.reencrypt(hook_id, &old)?;
        assert_eq!(current.key_id().as_str(), "v2");
        assert_eq!(
            rotating_cipher.decrypt(hook_id, &current)?.as_str(),
            secret.as_str()
        );
        Ok(())
    }

    #[test]
    fn cursor_round_trip_preserves_nanosecond_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let codec = CursorCodec::new(key(7));
        let scope = scope()?;
        let cursor =
            HistoryCursor::new(datetime!(2026-08-31 12:34:56.123456789 UTC), Uuid::now_v7());
        let encoded = codec.encode(&scope, cursor)?;

        assert!(!encoded.contains('='));
        assert_eq!(codec.decode(&scope, &encoded)?, cursor);
        Ok(())
    }

    #[test]
    fn cursor_is_bound_to_scope_and_authenticated() -> Result<(), Box<dyn std::error::Error>> {
        let codec = CursorCodec::new(key(7));
        let scope = scope()?;
        let cursor = HistoryCursor::new(datetime!(2026-08-31 12:00 UTC), Uuid::now_v7());
        let encoded = codec.encode(&scope, cursor)?;
        let other_collection = HistoryCursorScope::new(
            scope.organization_id().clone(),
            scope.silicon_id().clone(),
            HistoryCollection::BlockedRequests,
            scope.filter().clone(),
        );

        assert_eq!(
            codec.decode(&other_collection, &encoded),
            Err(CursorError::ScopeMismatch)
        );

        let mut authenticated = URL_SAFE_NO_PAD.decode(&encoded)?;
        if let Some(first) = authenticated.first_mut() {
            *first ^= 1;
        }
        let tampered = URL_SAFE_NO_PAD.encode(authenticated);
        assert_eq!(
            codec.decode(&scope, &tampered),
            Err(CursorError::Authentication)
        );
        Ok(())
    }

    proptest! {
        #[test]
        fn encrypted_secrets_round_trip(secret_text in "[!-~]{1,256}") {
            let cipher = cipher();
            prop_assert!(cipher.is_ok());
            if let Ok(cipher) = cipher {
                let hook_id = HookId::new();
                let secret = SigningSecret::from_text(secret_text.clone());
                prop_assert!(secret.is_ok());
                if let Ok(secret) = secret {
                    let encrypted = cipher.encrypt(hook_id, &secret);
                    prop_assert!(encrypted.is_ok());
                    if let Ok(encrypted) = encrypted {
                        let decrypted = cipher.decrypt(hook_id, &encrypted);
                        prop_assert!(decrypted.is_ok());
                        if let Ok(decrypted) = decrypted {
                            prop_assert_eq!(decrypted.as_str(), secret_text);
                        }
                    }
                }
            }
        }
    }
}
