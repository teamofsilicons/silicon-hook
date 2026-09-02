//! Signature verification against a captured request.

use std::fmt;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac as _};
use rsa::signature::Verifier as _;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::Zeroizing;

use super::{
    config::{SecretDecodeError, SignatureAlgorithm, SignatureConfig, SignatureEncoding},
    eval::{EvalContext, EvalError, evaluate},
    keys::{PublicKey, PublicKeyError},
};
use crate::domain::request::CapturedRequest;

/// Largest number of signature candidates examined from one presented value.
pub const MAX_SIGNATURE_CANDIDATES: usize = 16;
/// Largest presented signature value examined, in bytes.
pub const MAX_PRESENTED_SIGNATURE_BYTES: usize = 8 * 1024;

/// Hook facts exposed to expressions.
#[derive(Clone, Copy, Debug)]
pub struct HookContext<'a> {
    /// Public hook identifier.
    pub id: &'a str,
    /// Public endpoint URL.
    pub url: &'a str,
}

/// Decoded key material prepared once per verification.
pub struct VerificationMaterial {
    secret: Option<Zeroizing<Vec<u8>>>,
    public_key: Option<PublicKey>,
    public_key_der: Option<Vec<u8>>,
}

impl fmt::Debug for VerificationMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationMaterial")
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .field("public_key", &self.public_key.is_some())
            .field(
                "public_key_der_bytes",
                &self.public_key_der.as_ref().map(Vec::len),
            )
            .finish()
    }
}

/// Key material could not be prepared for the configuration.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MaterialError {
    /// The stored secret text is not in the configured encoding.
    #[error(transparent)]
    Secret(#[from] SecretDecodeError),
    /// The configured public key is unusable.
    #[error(transparent)]
    PublicKey(#[from] PublicKeyError),
}

impl SignatureConfig {
    /// Decodes the secret and public key this configuration needs.
    ///
    /// # Errors
    ///
    /// Returns [`MaterialError`] when the secret text or public key cannot be
    /// decoded for the configured algorithm.
    pub fn material(&self, secret: Option<&str>) -> Result<VerificationMaterial, MaterialError> {
        let secret = secret
            .map(|secret| self.secret_encoding.decode(secret))
            .transpose()?;
        let public_key = self.public_key()?;
        let public_key_der = public_key
            .as_ref()
            .map(PublicKey::to_spki_der)
            .transpose()?;
        Ok(VerificationMaterial {
            secret,
            public_key,
            public_key_der,
        })
    }
}

/// Why a request failed verification.
///
/// Codes are stable so blocked-request logs can be filtered; they never
/// include request content or key material.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RejectionReason {
    /// The payload expression could not be evaluated.
    #[error("payload unavailable: {0}")]
    PayloadUnavailable(EvalError),
    /// The signature expression could not be evaluated.
    #[error("signature unavailable: {0}")]
    SignatureUnavailable(EvalError),
    /// The signature expression produced no value.
    #[error("signature missing")]
    SignatureMissing,
    /// The signature expression produced a list or object.
    #[error("signature is not text")]
    SignatureNotText,
    /// The presented value was too large to examine safely.
    #[error("signature too large")]
    SignatureTooLarge,
    /// No candidate in the presented value matched.
    #[error("signature mismatch")]
    SignatureMismatch,
    /// The algorithm needs a secret and none is stored.
    #[error("secret missing")]
    SecretMissing,
    /// The algorithm needs a public key and none is usable.
    #[error("public key missing")]
    PublicKeyMissing,
}

impl RejectionReason {
    /// Returns a stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::PayloadUnavailable(_) => "payload_unavailable",
            Self::SignatureUnavailable(_) => "signature_unavailable",
            Self::SignatureMissing => "signature_missing",
            Self::SignatureNotText => "signature_not_text",
            Self::SignatureTooLarge => "signature_too_large",
            Self::SignatureMismatch => "signature_mismatch",
            Self::SecretMissing => "secret_missing",
            Self::PublicKeyMissing => "public_key_missing",
        }
    }
}

/// Result of verifying one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationOutcome {
    /// A presented signature matched the computed value.
    Verified,
    /// No presented signature matched.
    Rejected(RejectionReason),
}

impl VerificationOutcome {
    /// Returns `true` for [`Self::Verified`].
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }
}

/// Verifies a request against a hook's signature configuration.
///
/// Every presented candidate is compared in constant time for symmetric
/// algorithms; asymmetric algorithms use the underlying library verifier.
#[must_use]
pub fn verify(
    config: &SignatureConfig,
    request: &CapturedRequest,
    hook: HookContext<'_>,
    material: &VerificationMaterial,
) -> VerificationOutcome {
    let context = EvalContext {
        request,
        hook_id: hook.id,
        hook_url: hook.url,
        secret: material.secret.as_deref().map(Vec::as_slice),
        public_key: material.public_key_der.as_deref(),
    };
    let payload = match signed_payload(config, &context) {
        Ok(payload) => payload,
        Err(reason) => return VerificationOutcome::Rejected(reason),
    };
    let candidates = match presented_candidates(config, &context) {
        Ok(candidates) => candidates,
        Err(reason) => return VerificationOutcome::Rejected(reason),
    };
    let matched = if config.algorithm.uses_secret() {
        let Some(secret) = material.secret.as_deref() else {
            return VerificationOutcome::Rejected(RejectionReason::SecretMissing);
        };
        let Some(expected) = symmetric_signature(config.algorithm, secret, &payload) else {
            return VerificationOutcome::Rejected(RejectionReason::SecretMissing);
        };
        candidates.iter().any(|candidate| {
            candidate.len() == expected.len() && bool::from(candidate.ct_eq(&expected))
        })
    } else {
        let Some(public_key) = material.public_key.as_ref() else {
            return VerificationOutcome::Rejected(RejectionReason::PublicKeyMissing);
        };
        candidates
            .iter()
            .any(|candidate| asymmetric_matches(config.algorithm, public_key, &payload, candidate))
    };
    if matched {
        VerificationOutcome::Verified
    } else {
        VerificationOutcome::Rejected(RejectionReason::SignatureMismatch)
    }
}

fn signed_payload(
    config: &SignatureConfig,
    context: &EvalContext<'_>,
) -> Result<Vec<u8>, RejectionReason> {
    evaluate(config.payload.ast(), context)
        .map_err(RejectionReason::PayloadUnavailable)?
        .into_bytes()
        .map_err(|error| {
            RejectionReason::PayloadUnavailable(EvalError::from_value(
                "payload",
                "text or bytes",
                error,
            ))
        })
}

fn presented_candidates(
    config: &SignatureConfig,
    context: &EvalContext<'_>,
) -> Result<Vec<Vec<u8>>, RejectionReason> {
    let value =
        evaluate(config.signature.ast(), context).map_err(RejectionReason::SignatureUnavailable)?;
    if value.is_null() {
        return Err(RejectionReason::SignatureMissing);
    }
    let presented = value
        .into_text()
        .map_err(|_| RejectionReason::SignatureNotText)?;
    if presented.len() > MAX_PRESENTED_SIGNATURE_BYTES {
        return Err(RejectionReason::SignatureTooLarge);
    }
    if presented.trim().is_empty() {
        return Err(RejectionReason::SignatureMissing);
    }
    Ok(candidates(&presented)
        .into_iter()
        .filter_map(|candidate| decode_candidate(candidate, config.signature_encoding))
        .collect())
}

/// Splits a presented value into the pieces a provider may have embedded.
///
/// Providers wrap signatures in several conventions: `sha256=<hex>`,
/// `t=<ts>,v1=<hex>`, or `v1,<base64> v1,<base64>`. Each whitespace- or
/// comma-separated token is a candidate, and a short `label=` prefix is also
/// stripped to yield a second candidate.
fn candidates(presented: &str) -> Vec<&str> {
    let mut candidates = Vec::new();
    for token in presented.split(|character: char| character.is_whitespace() || character == ',') {
        if token.is_empty() {
            continue;
        }
        if candidates.len() >= MAX_SIGNATURE_CANDIDATES {
            break;
        }
        candidates.push(token);
        if let Some((label, rest)) = token.split_once('=')
            && !rest.is_empty()
            && (1..=16).contains(&label.len())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            && candidates.len() < MAX_SIGNATURE_CANDIDATES
        {
            candidates.push(rest);
        }
    }
    candidates
}

fn decode_candidate(candidate: &str, encoding: SignatureEncoding) -> Option<Vec<u8>> {
    match encoding {
        SignatureEncoding::Hex => hex::decode(candidate).ok(),
        SignatureEncoding::Base64 => STANDARD
            .decode(candidate)
            .or_else(|_| STANDARD_NO_PAD.decode(candidate))
            .ok(),
        SignatureEncoding::Base64Url => URL_SAFE_NO_PAD
            .decode(candidate)
            .or_else(|_| URL_SAFE.decode(candidate))
            .ok(),
        SignatureEncoding::Raw => Some(candidate.as_bytes().to_vec()),
    }
}

macro_rules! hmac_tag {
    ($digest:ty, $secret:expr, $payload:expr) => {{
        let mut mac = <Hmac<$digest> as hmac::Mac>::new_from_slice($secret).ok()?;
        mac.update($payload);
        mac.finalize().into_bytes().to_vec()
    }};
}

fn symmetric_signature(
    algorithm: SignatureAlgorithm,
    secret: &[u8],
    payload: &[u8],
) -> Option<Vec<u8>> {
    Some(match algorithm {
        SignatureAlgorithm::HmacSha1 => hmac_tag!(Sha1, secret, payload),
        SignatureAlgorithm::HmacSha256 => hmac_tag!(Sha256, secret, payload),
        SignatureAlgorithm::HmacSha384 => hmac_tag!(Sha384, secret, payload),
        SignatureAlgorithm::HmacSha512 => hmac_tag!(Sha512, secret, payload),
        SignatureAlgorithm::Sha1 => Sha1::digest(payload).to_vec(),
        SignatureAlgorithm::Sha256 => Sha256::digest(payload).to_vec(),
        SignatureAlgorithm::Sha384 => Sha384::digest(payload).to_vec(),
        SignatureAlgorithm::Sha512 => Sha512::digest(payload).to_vec(),
        SignatureAlgorithm::Ed25519
        | SignatureAlgorithm::EcdsaSha256
        | SignatureAlgorithm::RsaSha1
        | SignatureAlgorithm::RsaSha256 => return None,
    })
}

fn asymmetric_matches(
    algorithm: SignatureAlgorithm,
    public_key: &PublicKey,
    payload: &[u8],
    candidate: &[u8],
) -> bool {
    match (algorithm, public_key) {
        (SignatureAlgorithm::Ed25519, PublicKey::Ed25519(key)) => {
            let Ok(signature) = ed25519_dalek::Signature::from_slice(candidate) else {
                return false;
            };
            key.verify_strict(payload, &signature).is_ok()
        }
        (SignatureAlgorithm::EcdsaSha256, PublicKey::EcdsaP256(key)) => {
            let signature = p256::ecdsa::Signature::from_der(candidate)
                .or_else(|_| p256::ecdsa::Signature::from_slice(candidate));
            signature.is_ok_and(|signature| key.verify(payload, &signature).is_ok())
        }
        (SignatureAlgorithm::RsaSha1, PublicKey::Rsa(key)) => {
            let Ok(signature) = rsa::pkcs1v15::Signature::try_from(candidate) else {
                return false;
            };
            rsa::pkcs1v15::VerifyingKey::<Sha1>::new(key.clone())
                .verify(payload, &signature)
                .is_ok()
        }
        (SignatureAlgorithm::RsaSha256, PublicKey::Rsa(key)) => {
            let Ok(signature) = rsa::pkcs1v15::Signature::try_from(candidate) else {
                return false;
            };
            rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key.clone())
                .verify(payload, &signature)
                .is_ok()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use bytes::Bytes;
    use ed25519_dalek::Signer as _;
    use hmac::{Hmac, Mac as _};
    use rsa::pkcs8::EncodePublicKey as _;
    use sha2::{Digest as _, Sha256};
    use time::macros::datetime;
    use url::Url;

    use super::{
        HookContext, RejectionReason, SignatureAlgorithm, SignatureConfig, SignatureEncoding,
        VerificationOutcome, candidates, verify,
    };
    use crate::domain::{
        request::{CapturedRequest, CapturedRequestParts},
        signature::config::{Expression, SecretEncoding},
    };

    const HOOK: HookContext<'static> = HookContext {
        id: "018eb4ce-e57a-7d2c-8f9f-a35928ef91e1",
        url: "https://hook.example.test/silicon/cos:tos/A1B2C3",
    };

    fn request(
        headers: &[(&str, &str)],
        body: &'static [u8],
    ) -> Result<CapturedRequest, Box<dyn std::error::Error>> {
        Ok(CapturedRequest::new(CapturedRequestParts {
            method: "POST".to_owned(),
            url: Url::parse("https://hook.example.test/silicon/cos:tos/A1B2C3")?,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            body: Bytes::from_static(body),
            remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            received_at: datetime!(2026-09-02 10:00 UTC),
        })?)
    }

    fn hmac_sha256(secret: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(secret)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
        mac.update(payload);
        mac.finalize().into_bytes().to_vec()
    }

    #[test]
    fn default_configuration_verifies_standard_webhooks_deliveries()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = "v1.ZmFrZXNlY3JldGZha2VzZWNyZXRmYWtl";
        let body = br#"{"event":"ping"}"#;
        let payload = format!("msg_1.1700000000.{}", std::str::from_utf8(body)?);
        let tag = STANDARD.encode(hmac_sha256(secret.as_bytes(), payload.as_bytes()));
        let config = SignatureConfig::default();
        let material = config.material(Some(secret))?;

        let good = request(
            &[
                ("webhook-id", "msg_1"),
                ("webhook-timestamp", "1700000000"),
                ("webhook-signature", &format!("v1,{tag} v1,AAAA")),
            ],
            body,
        )?;
        assert_eq!(
            verify(&config, &good, HOOK, &material),
            VerificationOutcome::Verified
        );

        let tampered = request(
            &[
                ("webhook-id", "msg_1"),
                ("webhook-timestamp", "1700000001"),
                ("webhook-signature", &format!("v1,{tag}")),
            ],
            body,
        )?;
        assert_eq!(
            verify(&config, &tampered, HOOK, &material),
            VerificationOutcome::Rejected(RejectionReason::SignatureMismatch)
        );

        let unsigned = request(&[("webhook-id", "msg_1"), ("webhook-timestamp", "1")], body)?;
        assert_eq!(
            verify(&config, &unsigned, HOOK, &material),
            VerificationOutcome::Rejected(RejectionReason::SignatureMissing)
        );

        let incomplete = request(&[("webhook-signature", "v1,abcd")], body)?;
        assert!(matches!(
            verify(&config, &incomplete, HOOK, &material),
            VerificationOutcome::Rejected(RejectionReason::PayloadUnavailable(_))
        ));
        Ok(())
    }

    #[test]
    fn github_and_stripe_style_headers_verify_with_hex_candidates()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret = "gh-secret";
        let body = br#"{"ref":"refs/heads/main"}"#;
        let github = SignatureConfig {
            payload: Expression::parse("request.raw_body")?,
            signature: Expression::parse(r#"request.headers["x-hub-signature-256"]"#)?,
            signature_encoding: SignatureEncoding::Hex,
            ..SignatureConfig::default()
        };
        let tag = hex::encode(hmac_sha256(secret.as_bytes(), body));
        let request = request(&[("X-Hub-Signature-256", &format!("sha256={tag}"))], body)?;
        let material = github.material(Some(secret))?;
        assert_eq!(
            verify(&github, &request, HOOK, &material),
            VerificationOutcome::Verified
        );

        let stripe = SignatureConfig {
            payload: Expression::parse(r#"concat(request.query.t, ".", request.raw_body)"#)?,
            signature: Expression::parse(r#"request.headers["stripe-signature"]"#)?,
            signature_encoding: SignatureEncoding::Hex,
            ..SignatureConfig::default()
        };
        let stripe_payload = format!("1700000000.{}", std::str::from_utf8(body)?);
        let stripe_tag = hex::encode(hmac_sha256(secret.as_bytes(), stripe_payload.as_bytes()));
        let mut parts = CapturedRequestParts {
            method: "POST".to_owned(),
            url: Url::parse("https://hook.example.test/silicon/cos:tos/A1B2C3?t=1700000000")?,
            headers: vec![(
                "Stripe-Signature".to_owned(),
                format!("t=1700000000,v1={stripe_tag},v0=deadbeef"),
            )],
            body: Bytes::from_static(body),
            remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            received_at: datetime!(2026-09-02 10:00 UTC),
        };
        let stripe_request = CapturedRequest::new(parts.clone())?;
        let stripe_material = stripe.material(Some(secret))?;
        assert_eq!(
            verify(&stripe, &stripe_request, HOOK, &stripe_material),
            VerificationOutcome::Verified
        );

        parts.headers = vec![(
            "Stripe-Signature".to_owned(),
            "t=1700000000,v0=00".to_owned(),
        )];
        let wrong = CapturedRequest::new(parts)?;
        assert_eq!(
            verify(&stripe, &wrong, HOOK, &stripe_material),
            VerificationOutcome::Rejected(RejectionReason::SignatureMismatch)
        );
        Ok(())
    }

    #[test]
    fn plain_digest_algorithms_hash_the_secret_inside_the_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = SignatureConfig {
            algorithm: SignatureAlgorithm::Sha256,
            payload: Expression::parse("concat(secret, request.raw_body)")?,
            signature: Expression::parse("request.query.sig")?,
            signature_encoding: SignatureEncoding::Hex,
            secret_encoding: SecretEncoding::Hex,
            public_key: None,
        };
        let body = b"payload";
        let digest = hex::encode(sha2::Sha256::digest(
            [b"\x01\x02".as_slice(), body].concat(),
        ));
        let request = CapturedRequest::new(CapturedRequestParts {
            method: "POST".to_owned(),
            url: Url::parse(&format!(
                "https://hook.example.test/silicon/cos:tos/A1B2C3?sig={digest}"
            ))?,
            headers: Vec::new(),
            body: Bytes::from_static(body),
            remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            received_at: datetime!(2026-09-02 10:00 UTC),
        })?;
        let material = config.material(Some("0102"))?;
        assert_eq!(
            verify(&config, &request, HOOK, &material),
            VerificationOutcome::Verified
        );
        let no_secret = config.material(None)?;
        assert!(matches!(
            verify(&config, &request, HOOK, &no_secret),
            VerificationOutcome::Rejected(RejectionReason::PayloadUnavailable(_))
        ));
        Ok(())
    }

    #[test]
    fn ed25519_ecdsa_and_rsa_signatures_verify_with_public_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let body = b"asymmetric payload";

        let ed_signing = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let ed_config = SignatureConfig {
            algorithm: SignatureAlgorithm::Ed25519,
            payload: Expression::parse("request.raw_body_bytes")?,
            signature: Expression::parse(r#"request.headers["x-signature-ed25519"]"#)?,
            signature_encoding: SignatureEncoding::Hex,
            secret_encoding: SecretEncoding::Utf8,
            public_key: Some(hex::encode(ed_signing.verifying_key().to_bytes())),
        };
        let ed_signature = hex::encode(ed_signing.sign(body).to_bytes());
        let ed_request = request(&[("x-signature-ed25519", &ed_signature)], body)?;
        let ed_material = ed_config.material(None)?;
        assert_eq!(
            verify(&ed_config, &ed_request, HOOK, &ed_material),
            VerificationOutcome::Verified
        );
        let ed_wrong = request(&[("x-signature-ed25519", &hex::encode([0_u8; 64]))], body)?;
        assert_eq!(
            verify(&ed_config, &ed_wrong, HOOK, &ed_material),
            VerificationOutcome::Rejected(RejectionReason::SignatureMismatch)
        );

        let p256_signing = p256::ecdsa::SigningKey::from_bytes(&[5; 32].into())?;
        let p256_config = SignatureConfig {
            algorithm: SignatureAlgorithm::EcdsaSha256,
            payload: Expression::parse("request.raw_body_bytes")?,
            signature: Expression::parse(r#"request.headers["x-signature"]"#)?,
            signature_encoding: SignatureEncoding::Base64,
            secret_encoding: SecretEncoding::Utf8,
            public_key: Some(
                p256_signing
                    .verifying_key()
                    .to_public_key_pem(rsa::pkcs8::LineEnding::LF)?,
            ),
        };
        let p256_signature: p256::ecdsa::Signature = p256_signing.sign(body);
        let p256_request = request(
            &[(
                "x-signature",
                &STANDARD.encode(p256_signature.to_der().as_bytes()),
            )],
            body,
        )?;
        let p256_material = p256_config.material(None)?;
        assert_eq!(
            verify(&p256_config, &p256_request, HOOK, &p256_material),
            VerificationOutcome::Verified
        );
        let p256_raw = request(
            &[("x-signature", &STANDARD.encode(p256_signature.to_bytes()))],
            body,
        )?;
        assert_eq!(
            verify(&p256_config, &p256_raw, HOOK, &p256_material),
            VerificationOutcome::Verified
        );

        let mut rng = rsa::rand_core::OsRng;
        let rsa_private = rsa::RsaPrivateKey::new(&mut rng, 2_048)?;
        let rsa_config = SignatureConfig {
            algorithm: SignatureAlgorithm::RsaSha256,
            payload: Expression::parse("request.raw_body_bytes")?,
            signature: Expression::parse(r#"request.headers["x-signature"]"#)?,
            signature_encoding: SignatureEncoding::Base64,
            secret_encoding: SecretEncoding::Utf8,
            public_key: Some(
                rsa_private
                    .to_public_key()
                    .to_public_key_pem(rsa::pkcs8::LineEnding::LF)?,
            ),
        };
        let rsa_signing = rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_private);
        let rsa_signature: rsa::pkcs1v15::Signature = rsa_signing.sign(body);
        let rsa_request = request(
            &[(
                "x-signature",
                &STANDARD.encode(rsa::signature::SignatureEncoding::to_bytes(&rsa_signature)),
            )],
            body,
        )?;
        let rsa_material = rsa_config.material(None)?;
        assert_eq!(
            verify(&rsa_config, &rsa_request, HOOK, &rsa_material),
            VerificationOutcome::Verified
        );
        Ok(())
    }

    #[test]
    fn candidate_extraction_strips_labels_and_is_bounded() {
        assert_eq!(candidates("sha256=abc"), vec!["sha256=abc", "abc"]);
        assert_eq!(
            candidates("t=1,v1=aa,v0=bb"),
            vec!["t=1", "1", "v1=aa", "aa", "v0=bb", "bb"]
        );
        assert_eq!(
            candidates("v1,YWJj v1,ZGVm"),
            vec!["v1", "YWJj", "v1", "ZGVm"]
        );
        assert_eq!(candidates("YWJj=="), vec!["YWJj==", "="]);
        let many = std::iter::repeat_n("x", 40).collect::<Vec<_>>().join(" ");
        assert_eq!(candidates(&many).len(), super::MAX_SIGNATURE_CANDIDATES);
    }

    #[test]
    fn oversized_or_structured_signatures_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let config = SignatureConfig {
            signature: Expression::parse("request.body.sig")?,
            payload: Expression::parse("request.raw_body")?,
            ..SignatureConfig::default()
        };
        let material = config.material(Some("s"))?;
        let structured = request(&[], br#"{"sig":{"nested":true}}"#)?;
        assert_eq!(
            verify(&config, &structured, HOOK, &material),
            VerificationOutcome::Rejected(RejectionReason::SignatureNotText)
        );
        let huge = format!(r#"{{"sig":"{}"}}"#, "a".repeat(9_000));
        let huge_request = CapturedRequest::new(CapturedRequestParts {
            method: "POST".to_owned(),
            url: Url::parse("https://hook.example.test/silicon/cos:tos/A1B2C3")?,
            headers: Vec::new(),
            body: Bytes::from(huge),
            remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            received_at: datetime!(2026-09-02 10:00 UTC),
        })?;
        assert_eq!(
            verify(&config, &huge_request, HOOK, &material),
            VerificationOutcome::Rejected(RejectionReason::SignatureTooLarge)
        );
        let no_secret = config.material(None)?;
        let plain = request(&[], br#"{"sig":"abcd"}"#)?;
        assert_eq!(
            verify(&config, &plain, HOOK, &no_secret),
            VerificationOutcome::Rejected(RejectionReason::SecretMissing)
        );
        Ok(())
    }
}
