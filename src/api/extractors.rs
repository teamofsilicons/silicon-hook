//! Strict parsing of security-sensitive HTTP headers.

use axum::http::HeaderMap;
use secrecy::SecretString;

use crate::{
    domain::{ApplicationId, OrganizationId},
    error::AppError,
    infrastructure::iam::PresentedCredential,
};

const OBO_PROOF_HEADER: &str = "x-iam-obo-access-proof";
const APP_ID_HEADER: &str = "x-app-id";
const ORG_ID_HEADER: &str = "x-org-id";
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const SIGNATURE_HEADER: &str = "x-hook-signature";
const TIMESTAMP_HEADER: &str = "x-hook-timestamp";
const MAX_BEARER_TOKEN_BYTES: usize = 4_096;
const MAX_AUTHORIZATION_HEADER_BYTES: usize = "Bearer ".len() + MAX_BEARER_TOKEN_BYTES;
const IAM_PROOF_PREFIX: &str = "obo_";
const IAM_PROOF_PAYLOAD_BYTES: usize = 43;
const IAM_PROOF_BYTES: usize = IAM_PROOF_PREFIX.len() + IAM_PROOF_PAYLOAD_BYTES;
const MAX_LOCAL_PROOF_BYTES: usize = 512;
const MAX_SIGNATURE_BYTES: usize = "v1=".len() + 64;
const MAX_TIMESTAMP_BYTES: usize = 20;

pub(super) struct IngressHeaders {
    pub(super) signature: String,
    pub(super) timestamp: String,
    pub(super) idempotency_key: String,
}

pub(super) fn management_credential(
    headers: &HeaderMap,
    allow_local_credentials: bool,
) -> Result<PresentedCredential, AppError> {
    let bearer = optional_bearer(headers)?;
    let proof = optional_header_bounded(headers, OBO_PROOF_HEADER, MAX_LOCAL_PROOF_BYTES)?;
    let app_id = optional_header_bounded(headers, APP_ID_HEADER, 255)?;

    if let Some(proof) = proof.as_deref()
        && !is_canonical_obo_proof(proof)
        && !(allow_local_credentials && is_local_credential(proof))
    {
        return Err(AppError::Unauthenticated);
    }

    match (bearer, proof, app_id) {
        (Some(token), None, None) => Ok(PresentedCredential::Bearer(token)),
        (None, Some(proof), Some(app_id)) => Ok(PresentedCredential::Obo {
            app_id: ApplicationId::new(app_id)
                .map_err(|_| AppError::bad_request("invalid_app_id"))?,
            proof: SecretString::from(proof),
        }),
        (None, None | Some(_), None) | (None, None, Some(_)) => Err(AppError::Unauthenticated),
        _ => Err(AppError::bad_request("ambiguous_credentials")),
    }
}

pub(super) fn service_bearer(headers: &HeaderMap) -> Result<SecretString, AppError> {
    let token = optional_bearer(headers)?.ok_or(AppError::Unauthenticated)?;
    if headers.contains_key(OBO_PROOF_HEADER) || headers.contains_key(APP_ID_HEADER) {
        return Err(AppError::bad_request("ambiguous_credentials"));
    }
    Ok(token)
}

pub(super) fn organization_id(headers: &HeaderMap) -> Result<OrganizationId, AppError> {
    let value = required_header_bounded(headers, ORG_ID_HEADER, 100)?;
    OrganizationId::new(value).map_err(|_| AppError::validation("invalid_org_id"))
}

pub(super) fn idempotency_key(headers: &HeaderMap) -> Result<String, AppError> {
    let value = required_header_bounded(headers, IDEMPOTENCY_KEY_HEADER, 255)?;
    let valid =
        (8..=255).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic());
    if !valid {
        return Err(AppError::validation("invalid_idempotency_key"));
    }
    Ok(value)
}

pub(super) fn ingress_headers(headers: &HeaderMap) -> Result<IngressHeaders, AppError> {
    let signature = required_header_bounded(headers, SIGNATURE_HEADER, MAX_SIGNATURE_BYTES)?;
    if signature.len() != MAX_SIGNATURE_BYTES
        || !signature.starts_with("v1=")
        || !signature["v1=".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AppError::Unauthenticated);
    }
    let timestamp = required_header_bounded(headers, TIMESTAMP_HEADER, MAX_TIMESTAMP_BYTES)?;
    let parsed_timestamp = timestamp
        .parse::<i64>()
        .map_err(|_| AppError::Unauthenticated)?;
    if parsed_timestamp.to_string() != timestamp {
        return Err(AppError::Unauthenticated);
    }
    Ok(IngressHeaders {
        signature,
        timestamp,
        idempotency_key: idempotency_key(headers)?,
    })
}

pub(super) fn require_json(headers: &HeaderMap) -> Result<(), AppError> {
    if header_count(headers, http::header::CONTENT_TYPE.as_str()) != 1 {
        return Err(AppError::UnsupportedMediaType);
    }
    let media_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !media_type.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
        return Err(AppError::UnsupportedMediaType);
    }
    Ok(())
}

fn optional_bearer(headers: &HeaderMap) -> Result<Option<SecretString>, AppError> {
    let Some(value) = optional_header_bounded(
        headers,
        http::header::AUTHORIZATION.as_str(),
        MAX_AUTHORIZATION_HEADER_BYTES,
    )?
    else {
        return Ok(None);
    };
    let (scheme, token) = value.split_once(' ').ok_or(AppError::Unauthenticated)?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.len() > MAX_BEARER_TOKEN_BYTES
        || token.contains(char::is_whitespace)
        || !token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(AppError::Unauthenticated);
    }
    Ok(Some(SecretString::from(token.to_owned())))
}

fn required_header_bounded(
    headers: &HeaderMap,
    name: &str,
    maximum_bytes: usize,
) -> Result<String, AppError> {
    optional_header_bounded(headers, name, maximum_bytes)?
        .ok_or_else(|| AppError::bad_request("missing_required_header"))
}

fn optional_header_bounded(
    headers: &HeaderMap,
    name: &str,
    maximum_bytes: usize,
) -> Result<Option<String>, AppError> {
    if header_count(headers, name) > 1 {
        return Err(AppError::bad_request("duplicate_header"));
    }
    let Some(value) = headers.get(name) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| AppError::bad_request("invalid_header_encoding"))?;
    if value.is_empty() {
        return Err(AppError::bad_request("empty_header"));
    }
    if value.len() > maximum_bytes {
        return Err(AppError::bad_request("header_too_large"));
    }
    Ok(Some(value.to_owned()))
}

fn header_count(headers: &HeaderMap, name: &str) -> usize {
    headers.get_all(name).iter().count()
}

fn is_canonical_obo_proof(value: &str) -> bool {
    value.len() == IAM_PROOF_BYTES
        && value.starts_with(IAM_PROOF_PREFIX)
        && value[IAM_PROOF_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn is_local_credential(value: &str) -> bool {
    value.starts_with("local:")
        && value.len() <= MAX_LOCAL_PROOF_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};
    use secrecy::ExposeSecret as _;

    use super::{idempotency_key, ingress_headers, management_credential, require_json};
    use crate::infrastructure::iam::PresentedCredential;

    #[test]
    fn parses_an_unambiguous_bearer() -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer token_123"),
        );

        let credential = management_credential(&headers, false)?;
        match credential {
            PresentedCredential::Bearer(token) => {
                assert_eq!(token.expose_secret(), "token_123");
            }
            PresentedCredential::Obo { .. } => return Err("expected bearer".into()),
        }
        Ok(())
    }

    #[test]
    fn rejects_mixed_credential_forms() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer token_123"),
        );
        headers.insert("x-app-id", HeaderValue::from_static("app"));
        headers.insert("x-iam-obo-access-proof", HeaderValue::from_static("proof"));

        assert!(management_credential(&headers, false).is_err());
    }

    #[test]
    fn idempotency_key_excludes_spaces() {
        let mut headers = HeaderMap::new();
        headers.insert("idempotency-key", HeaderValue::from_static("has space"));
        assert!(idempotency_key(&headers).is_err());
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("bearer token_123"),
        );

        assert!(matches!(
            management_credential(&headers, false)?,
            PresentedCredential::Bearer(_)
        ));
        Ok(())
    }

    #[test]
    fn rejects_duplicate_security_headers() {
        let mut headers = HeaderMap::new();
        headers.append("authorization", HeaderValue::from_static("Bearer first"));
        headers.append("authorization", HeaderValue::from_static("Bearer second"));

        assert!(management_credential(&headers, false).is_err());
    }

    #[test]
    fn accepts_case_insensitive_json_media_type_with_parameters() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("Application/JSON; charset=utf-8"),
        );

        assert!(require_json(&headers).is_ok());
    }

    #[test]
    fn validates_canonical_obo_proofs_and_gates_local_proofs()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert("x-app-id", HeaderValue::from_static("calendar"));
        headers.insert(
            "x-iam-obo-access-proof",
            HeaderValue::from_str(&format!("obo_{}", "A".repeat(43)))?,
        );
        assert!(matches!(
            management_credential(&headers, false)?,
            PresentedCredential::Obo { .. }
        ));

        headers.insert(
            "x-iam-obo-access-proof",
            HeaderValue::from_static("local:silicon:member:cos:tos"),
        );
        assert!(management_credential(&headers, false).is_err());
        assert!(management_credential(&headers, true).is_ok());
        Ok(())
    }

    #[test]
    fn rejects_oversized_bearer_tokens_before_credential_creation()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {}", "A".repeat(4_097)))?,
        );

        assert!(management_credential(&headers, false).is_err());
        Ok(())
    }

    #[test]
    fn ingress_headers_require_canonical_signature_and_timestamp()
    -> Result<(), Box<dyn std::error::Error>> {
        let base_headers = || {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-hook-signature",
                HeaderValue::from_str(&format!("v1={}", "a".repeat(64)))?,
            );
            headers.insert("x-hook-timestamp", HeaderValue::from_static("1700000000"));
            headers.insert("idempotency-key", HeaderValue::from_static("request-123"));
            Ok::<_, http::header::InvalidHeaderValue>(headers)
        };

        assert!(ingress_headers(&base_headers()?).is_ok());

        let mut uppercase = base_headers()?;
        uppercase.insert(
            "x-hook-signature",
            HeaderValue::from_str(&format!("v1={}", "A".repeat(64)))?,
        );
        assert!(ingress_headers(&uppercase).is_err());

        let mut leading_zero = base_headers()?;
        leading_zero.insert("x-hook-timestamp", HeaderValue::from_static("01700000000"));
        assert!(ingress_headers(&leading_zero).is_err());
        Ok(())
    }
}
