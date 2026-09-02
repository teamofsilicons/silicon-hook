//! Provider public keys for asymmetric signature verification.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use rsa::{
    pkcs1::DecodeRsaPublicKey as _,
    pkcs8::{DecodePublicKey as _, EncodePublicKey as _},
    traits::PublicKeyParts as _,
};
use thiserror::Error;

use super::config::SignatureAlgorithm;

/// Smallest RSA modulus Hook accepts, in bits.
pub const MIN_RSA_MODULUS_BITS: usize = 2_048;
/// Largest public-key material accepted from a caller, in bytes.
pub const MAX_PUBLIC_KEY_BYTES: usize = 16 * 1024;

/// Public key material could not be used for the configured algorithm.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PublicKeyError {
    /// The algorithm needs a public key and none was configured.
    #[error("a public key is required for this signature algorithm")]
    Missing,
    /// The algorithm is symmetric and cannot use a public key.
    #[error("a public key cannot be used with a symmetric signature algorithm")]
    NotApplicable,
    /// The material exceeds [`MAX_PUBLIC_KEY_BYTES`].
    #[error("public key material exceeds {MAX_PUBLIC_KEY_BYTES} bytes")]
    TooLarge,
    /// The material is not PEM, hexadecimal, or base64 for the algorithm's key type.
    #[error("public key material is malformed for the signature algorithm")]
    Malformed,
    /// The RSA modulus is shorter than [`MIN_RSA_MODULUS_BITS`].
    #[error("RSA public keys must have at least {MIN_RSA_MODULUS_BITS}-bit moduli")]
    WeakRsaKey,
    /// The key could not be re-encoded for the `key.public` block.
    #[error("public key cannot be encoded as SubjectPublicKeyInfo")]
    Encoding,
}

/// A parsed provider public key.
#[derive(Clone, Debug)]
pub enum PublicKey {
    /// Ed25519 verifying key.
    Ed25519(ed25519_dalek::VerifyingKey),
    /// ECDSA P-256 verifying key.
    EcdsaP256(p256::ecdsa::VerifyingKey),
    /// RSA public key for PKCS#1 v1.5 signatures.
    Rsa(rsa::RsaPublicKey),
}

impl PublicKey {
    /// Parses PEM `SubjectPublicKeyInfo`, PEM `RSA PUBLIC KEY`, or raw
    /// hexadecimal / base64 key bytes appropriate for the algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`PublicKeyError`] when the algorithm is symmetric, the material
    /// is oversized or malformed, or an RSA modulus is too short.
    pub fn parse(algorithm: SignatureAlgorithm, material: &str) -> Result<Self, PublicKeyError> {
        if !algorithm.is_asymmetric() {
            return Err(PublicKeyError::NotApplicable);
        }
        if material.len() > MAX_PUBLIC_KEY_BYTES {
            return Err(PublicKeyError::TooLarge);
        }
        let material = material.trim();
        if material.is_empty() {
            return Err(PublicKeyError::Missing);
        }
        match algorithm {
            SignatureAlgorithm::Ed25519 => parse_ed25519(material),
            SignatureAlgorithm::EcdsaSha256 => parse_p256(material),
            SignatureAlgorithm::RsaSha1 | SignatureAlgorithm::RsaSha256 => parse_rsa(material),
            _ => Err(PublicKeyError::NotApplicable),
        }
    }

    /// Encodes the key as DER `SubjectPublicKeyInfo` for the `key.public` block.
    ///
    /// # Errors
    ///
    /// Returns [`PublicKeyError::Encoding`] if the key cannot be serialized.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, PublicKeyError> {
        let document = match self {
            Self::Ed25519(key) => key.to_public_key_der(),
            Self::EcdsaP256(key) => key.to_public_key_der(),
            Self::Rsa(key) => key.to_public_key_der(),
        }
        .map_err(|_| PublicKeyError::Encoding)?;
        Ok(document.as_bytes().to_vec())
    }
}

fn parse_ed25519(material: &str) -> Result<PublicKey, PublicKeyError> {
    if is_pem(material) {
        return ed25519_dalek::VerifyingKey::from_public_key_pem(material)
            .map(PublicKey::Ed25519)
            .map_err(|_| PublicKeyError::Malformed);
    }
    let bytes = decode_raw(material)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| PublicKeyError::Malformed)?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map(PublicKey::Ed25519)
        .map_err(|_| PublicKeyError::Malformed)
}

fn parse_p256(material: &str) -> Result<PublicKey, PublicKeyError> {
    if is_pem(material) {
        return p256::ecdsa::VerifyingKey::from_public_key_pem(material)
            .map(PublicKey::EcdsaP256)
            .map_err(|_| PublicKeyError::Malformed);
    }
    let bytes = decode_raw(material)?;
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)
        .map(PublicKey::EcdsaP256)
        .map_err(|_| PublicKeyError::Malformed)
}

fn parse_rsa(material: &str) -> Result<PublicKey, PublicKeyError> {
    let key = if material.contains("BEGIN RSA PUBLIC KEY") {
        rsa::RsaPublicKey::from_pkcs1_pem(material).map_err(|_| PublicKeyError::Malformed)?
    } else if is_pem(material) {
        rsa::RsaPublicKey::from_public_key_pem(material).map_err(|_| PublicKeyError::Malformed)?
    } else {
        let bytes = decode_raw(material)?;
        match rsa::RsaPublicKey::from_public_key_der(&bytes) {
            Ok(key) => key,
            Err(_) => {
                rsa::RsaPublicKey::from_pkcs1_der(&bytes).map_err(|_| PublicKeyError::Malformed)?
            }
        }
    };
    if key.size().saturating_mul(8) < MIN_RSA_MODULUS_BITS {
        return Err(PublicKeyError::WeakRsaKey);
    }
    Ok(PublicKey::Rsa(key))
}

fn is_pem(material: &str) -> bool {
    material.starts_with("-----BEGIN")
}

fn decode_raw(material: &str) -> Result<Vec<u8>, PublicKeyError> {
    let compact = material
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    if compact.len() % 2 == 0
        && compact.bytes().all(|byte| byte.is_ascii_hexdigit())
        && let Ok(bytes) = hex::decode(&compact)
    {
        return Ok(bytes);
    }
    STANDARD
        .decode(&compact)
        .or_else(|_| STANDARD_NO_PAD.decode(&compact))
        .or_else(|_| URL_SAFE.decode(&compact))
        .or_else(|_| URL_SAFE_NO_PAD.decode(&compact))
        .map_err(|_| PublicKeyError::Malformed)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rsa::pkcs8::EncodePublicKey as _;

    use super::{PublicKey, PublicKeyError};
    use crate::domain::signature::config::SignatureAlgorithm;

    #[test]
    fn ed25519_accepts_pem_hex_and_base64() -> Result<(), Box<dyn std::error::Error>> {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let verifying = signing.verifying_key();
        let pem = verifying.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;
        let raw = verifying.to_bytes();

        for material in [
            pem,
            hex::encode(raw),
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw),
        ] {
            let PublicKey::Ed25519(parsed) =
                PublicKey::parse(SignatureAlgorithm::Ed25519, &material)?
            else {
                return Err("expected an Ed25519 key".into());
            };
            assert_eq!(parsed, verifying);
        }
        assert_eq!(
            PublicKey::parse(SignatureAlgorithm::Ed25519, "not a key").err(),
            Some(PublicKeyError::Malformed)
        );
        assert_eq!(
            PublicKey::parse(SignatureAlgorithm::HmacSha256, "abc").err(),
            Some(PublicKeyError::NotApplicable)
        );
        assert_eq!(
            PublicKey::parse(SignatureAlgorithm::Ed25519, "  ").err(),
            Some(PublicKeyError::Missing)
        );
        Ok(())
    }

    #[test]
    fn p256_accepts_pem_and_sec1_points() -> Result<(), Box<dyn std::error::Error>> {
        let signing = p256::ecdsa::SigningKey::from_bytes(&[9; 32].into())?;
        let verifying = *signing.verifying_key();
        let pem = verifying.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;
        let point = verifying.to_encoded_point(true);

        let PublicKey::EcdsaP256(from_pem) =
            PublicKey::parse(SignatureAlgorithm::EcdsaSha256, &pem)?
        else {
            return Err("expected a P-256 key".into());
        };
        let PublicKey::EcdsaP256(from_point) = PublicKey::parse(
            SignatureAlgorithm::EcdsaSha256,
            &hex::encode(point.as_bytes()),
        )?
        else {
            return Err("expected a P-256 key".into());
        };
        assert_eq!(from_pem, verifying);
        assert_eq!(from_point, verifying);
        assert!(!PublicKey::EcdsaP256(from_pem).to_spki_der()?.is_empty());
        Ok(())
    }

    #[test]
    fn rsa_rejects_short_moduli() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = rsa::rand_core::OsRng;
        let weak = rsa::RsaPrivateKey::new(&mut rng, 1_024)?;
        let weak_pem = weak
            .to_public_key()
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;
        assert_eq!(
            PublicKey::parse(SignatureAlgorithm::RsaSha256, &weak_pem).err(),
            Some(PublicKeyError::WeakRsaKey)
        );
        Ok(())
    }
}
