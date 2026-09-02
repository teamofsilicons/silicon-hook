//! Per-hook description of how a provider signs its requests.

use std::fmt;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{
    ast::Expr,
    keys::{PublicKey, PublicKeyError},
    lexer::ParseError,
    parser,
};

/// Default payload: the Standard Webhooks `id.timestamp.body` construction.
pub const DEFAULT_PAYLOAD_EXPRESSION: &str = r#"concat(request.headers["webhook-id"], ".", request.headers["webhook-timestamp"], ".", request.raw_body)"#;
/// Default location of the presented signature.
pub const DEFAULT_SIGNATURE_EXPRESSION: &str = r#"request.headers["webhook-signature"]"#;
/// Largest secret accepted or generated, in bytes of its textual form.
pub const MAX_SECRET_BYTES: usize = 4_096;

/// Signature primitive applied to the evaluated payload.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum SignatureAlgorithm {
    /// HMAC with SHA-1.
    #[serde(rename = "HMAC-SHA1")]
    HmacSha1,
    /// HMAC with SHA-256.
    #[serde(rename = "HMAC-SHA256")]
    HmacSha256,
    /// HMAC with SHA-384.
    #[serde(rename = "HMAC-SHA384")]
    HmacSha384,
    /// HMAC with SHA-512.
    #[serde(rename = "HMAC-SHA512")]
    HmacSha512,
    /// Plain SHA-1 digest of the payload; the payload must include `secret`.
    #[serde(rename = "SHA1")]
    Sha1,
    /// Plain SHA-256 digest of the payload; the payload must include `secret`.
    #[serde(rename = "SHA256")]
    Sha256,
    /// Plain SHA-384 digest of the payload; the payload must include `secret`.
    #[serde(rename = "SHA384")]
    Sha384,
    /// Plain SHA-512 digest of the payload; the payload must include `secret`.
    #[serde(rename = "SHA512")]
    Sha512,
    /// Ed25519 signature verified with the configured public key.
    #[serde(rename = "Ed25519")]
    Ed25519,
    /// ECDSA over P-256 with SHA-256, DER or raw `r||s` signatures.
    #[serde(rename = "ECDSA-SHA256")]
    EcdsaSha256,
    /// RSA PKCS#1 v1.5 with SHA-1.
    #[serde(rename = "RSA-SHA1")]
    RsaSha1,
    /// RSA PKCS#1 v1.5 with SHA-256.
    #[serde(rename = "RSA-SHA256")]
    RsaSha256,
}

impl SignatureAlgorithm {
    /// Reports whether verification uses a provider public key.
    #[must_use]
    pub const fn is_asymmetric(self) -> bool {
        matches!(
            self,
            Self::Ed25519 | Self::EcdsaSha256 | Self::RsaSha1 | Self::RsaSha256
        )
    }

    /// Reports whether verification uses a shared secret.
    #[must_use]
    pub const fn uses_secret(self) -> bool {
        !self.is_asymmetric()
    }

    /// Returns the contract name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HmacSha1 => "HMAC-SHA1",
            Self::HmacSha256 => "HMAC-SHA256",
            Self::HmacSha384 => "HMAC-SHA384",
            Self::HmacSha512 => "HMAC-SHA512",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
            Self::Ed25519 => "Ed25519",
            Self::EcdsaSha256 => "ECDSA-SHA256",
            Self::RsaSha1 => "RSA-SHA1",
            Self::RsaSha256 => "RSA-SHA256",
        }
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Encoding of the signature the provider transmits.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureEncoding {
    /// Hexadecimal digits in either case.
    Hex,
    /// Standard base64, padded or unpadded.
    #[default]
    Base64,
    /// URL-safe base64, padded or unpadded.
    #[serde(rename = "base64url")]
    Base64Url,
    /// The literal bytes of the presented value.
    Raw,
}

/// Encoding used to turn the stored secret text into key bytes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretEncoding {
    /// The UTF-8 bytes of the secret text.
    #[default]
    Utf8,
    /// The secret text, which must be ASCII.
    Ascii,
    /// The secret text is hexadecimal.
    Hex,
    /// The secret text is standard base64.
    Base64,
    /// The secret text is URL-safe base64.
    #[serde(rename = "base64url")]
    Base64Url,
    /// Identical to `utf8`; JSON cannot carry non-text bytes.
    Raw,
}

/// A stored secret could not be decoded with the configured encoding.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("secret is not valid {encoding:?}")]
pub struct SecretDecodeError {
    /// Encoding that rejected the secret.
    pub encoding: SecretEncoding,
}

impl SecretEncoding {
    /// Decodes secret text into key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SecretDecodeError`] when the text is not in this encoding.
    pub fn decode(self, secret: &str) -> Result<Zeroizing<Vec<u8>>, SecretDecodeError> {
        let error = SecretDecodeError { encoding: self };
        let bytes = match self {
            Self::Utf8 | Self::Raw => secret.as_bytes().to_vec(),
            Self::Ascii => {
                if !secret.is_ascii() {
                    return Err(error);
                }
                secret.as_bytes().to_vec()
            }
            Self::Hex => hex::decode(secret.trim()).map_err(|_| error)?,
            Self::Base64 => STANDARD
                .decode(secret.trim())
                .or_else(|_| STANDARD_NO_PAD.decode(secret.trim()))
                .map_err(|_| error)?,
            Self::Base64Url => URL_SAFE_NO_PAD
                .decode(secret.trim())
                .or_else(|_| URL_SAFE.decode(secret.trim()))
                .map_err(|_| error)?,
        };
        if bytes.is_empty() {
            return Err(error);
        }
        Ok(Zeroizing::new(bytes))
    }
}

/// A parsed expression that remembers its source text.
#[derive(Clone, Debug, PartialEq)]
pub struct Expression {
    source: String,
    parsed: Expr,
}

impl Expression {
    /// Parses expression source.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] for invalid syntax or unknown blocks.
    pub fn parse(source: &str) -> Result<Self, ParseError> {
        let parsed = parser::parse(source)?;
        Ok(Self {
            source: source.trim().to_owned(),
            parsed,
        })
    }

    /// Returns the source text.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the parsed expression.
    #[must_use]
    pub const fn ast(&self) -> &Expr {
        &self.parsed
    }
}

impl Serialize for Expression {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.source)
    }
}

impl<'de> Deserialize<'de> for Expression {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let source = String::deserialize(deserializer)?;
        Self::parse(&source).map_err(D::Error::custom)
    }
}

/// How a hook verifies provider signatures.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureConfig {
    /// Signature primitive.
    pub algorithm: SignatureAlgorithm,
    /// Expression producing the bytes the provider signed.
    pub payload: Expression,
    /// Expression locating the presented signature, normally a header.
    pub signature: Expression,
    /// Encoding of the presented signature.
    pub signature_encoding: SignatureEncoding,
    /// Encoding of the stored secret text.
    pub secret_encoding: SecretEncoding,
    /// Provider public key for asymmetric algorithms, as PEM or raw bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        // Both defaults are constant literals validated by tests; a parse
        // failure here would be a build defect rather than runtime input.
        Self {
            algorithm: SignatureAlgorithm::HmacSha256,
            payload: Expression::parse(DEFAULT_PAYLOAD_EXPRESSION).unwrap_or_else(|_| Expression {
                source: DEFAULT_PAYLOAD_EXPRESSION.to_owned(),
                parsed: Expr::Literal(String::new()),
            }),
            signature: Expression::parse(DEFAULT_SIGNATURE_EXPRESSION).unwrap_or_else(|_| {
                Expression {
                    source: DEFAULT_SIGNATURE_EXPRESSION.to_owned(),
                    parsed: Expr::Literal(String::new()),
                }
            }),
            signature_encoding: SignatureEncoding::Base64,
            secret_encoding: SecretEncoding::Utf8,
            public_key: None,
        }
    }
}

/// A signature configuration is internally inconsistent.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    /// The public key is missing, unusable, or given for a symmetric algorithm.
    #[error("public key: {0}")]
    PublicKey(#[from] PublicKeyError),
}

impl SignatureConfig {
    /// Checks that the algorithm and key material agree.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when an asymmetric algorithm lacks a usable
    /// public key or a symmetric algorithm was given one.
    pub fn validate(&self) -> Result<(), ConfigError> {
        match (self.algorithm.is_asymmetric(), self.public_key.as_deref()) {
            (true, None) => Err(PublicKeyError::Missing.into()),
            (true, Some(material)) => PublicKey::parse(self.algorithm, material)
                .map(|_| ())
                .map_err(ConfigError::from),
            (false, Some(_)) => Err(PublicKeyError::NotApplicable.into()),
            (false, None) => Ok(()),
        }
    }

    /// Parses the configured public key, if any.
    ///
    /// # Errors
    ///
    /// Returns [`PublicKeyError`] when the material cannot be parsed.
    pub fn public_key(&self) -> Result<Option<PublicKey>, PublicKeyError> {
        self.public_key
            .as_deref()
            .map(|material| PublicKey::parse(self.algorithm, material))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_PAYLOAD_EXPRESSION, DEFAULT_SIGNATURE_EXPRESSION, Expression, SecretEncoding,
        SignatureAlgorithm, SignatureConfig, SignatureEncoding,
    };

    #[test]
    fn defaults_parse_and_serialize_as_documented() -> Result<(), Box<dyn std::error::Error>> {
        assert!(Expression::parse(DEFAULT_PAYLOAD_EXPRESSION).is_ok());
        assert!(Expression::parse(DEFAULT_SIGNATURE_EXPRESSION).is_ok());
        let config = SignatureConfig::default();
        config.validate()?;
        let json = serde_json::to_value(&config)?;
        assert_eq!(json["algorithm"], "HMAC-SHA256");
        assert_eq!(json["signature_encoding"], "base64");
        assert_eq!(json["secret_encoding"], "utf8");
        assert_eq!(json["payload"], DEFAULT_PAYLOAD_EXPRESSION);
        assert_eq!(json["signature"], DEFAULT_SIGNATURE_EXPRESSION);
        assert!(json.get("public_key").is_none());
        let decoded: SignatureConfig = serde_json::from_value(json)?;
        assert_eq!(decoded, config);
        Ok(())
    }

    #[test]
    fn deserialization_rejects_invalid_expressions_and_unknown_fields() {
        let invalid = serde_json::json!({
            "algorithm": "HMAC-SHA256",
            "payload": "md5(request.raw_body)",
            "signature": "request.headers.x",
            "signature_encoding": "hex",
            "secret_encoding": "utf8"
        });
        assert!(serde_json::from_value::<SignatureConfig>(invalid).is_err());
        let unknown = serde_json::json!({
            "algorithm": "HMAC-SHA256",
            "payload": "request.raw_body",
            "signature": "request.headers.x",
            "signature_encoding": "hex",
            "secret_encoding": "utf8",
            "extra": true
        });
        assert!(serde_json::from_value::<SignatureConfig>(unknown).is_err());
    }

    #[test]
    fn asymmetric_algorithms_require_keys_and_symmetric_reject_them() {
        let mut config = SignatureConfig {
            algorithm: SignatureAlgorithm::Ed25519,
            ..SignatureConfig::default()
        };
        assert!(config.validate().is_err());
        config.algorithm = SignatureAlgorithm::HmacSha512;
        config.public_key = Some("abc".to_owned());
        assert!(config.validate().is_err());
        assert!(SignatureAlgorithm::RsaSha256.is_asymmetric());
        assert!(SignatureAlgorithm::Sha256.uses_secret());
        assert_eq!(SignatureEncoding::default(), SignatureEncoding::Base64);
    }

    #[test]
    fn secret_encodings_decode_key_bytes() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(SecretEncoding::Utf8.decode("v1.abc")?.as_slice(), b"v1.abc");
        assert_eq!(SecretEncoding::Hex.decode("6869")?.as_slice(), b"hi");
        assert_eq!(SecretEncoding::Base64.decode("aGk=")?.as_slice(), b"hi");
        assert_eq!(SecretEncoding::Base64Url.decode("aGk")?.as_slice(), b"hi");
        assert!(SecretEncoding::Ascii.decode("héllo").is_err());
        assert!(SecretEncoding::Hex.decode("zz").is_err());
        assert!(SecretEncoding::Utf8.decode("").is_err());
        Ok(())
    }
}
