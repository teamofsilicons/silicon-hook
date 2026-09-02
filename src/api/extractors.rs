//! Strict parsing of security-sensitive HTTP headers and client addresses.

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, request::Parts},
};
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
const FORWARDED_FOR_HEADER: &str = "x-forwarded-for";
const MAX_BEARER_TOKEN_BYTES: usize = 4_096;
const MAX_AUTHORIZATION_HEADER_BYTES: usize = "Bearer ".len() + MAX_BEARER_TOKEN_BYTES;
const IAM_PROOF_PREFIX: &str = "obo_";
const IAM_PROOF_PAYLOAD_BYTES: usize = 43;
const IAM_PROOF_BYTES: usize = IAM_PROOF_PREFIX.len() + IAM_PROOF_PAYLOAD_BYTES;
const MAX_LOCAL_PROOF_BYTES: usize = 512;
const MAX_FORWARDED_FOR_BYTES: usize = 1_024;

/// TCP peer address when the listener was started with connection info.
#[derive(Clone, Copy, Debug)]
pub(super) struct PeerAddress(pub(super) Option<SocketAddr>);

impl<S> FromRequestParts<S> for PeerAddress
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0),
        )))
    }
}

/// Resolves the client address behind a known number of trusted proxies.
///
/// With zero trusted hops the TCP peer is the client and `X-Forwarded-For`
/// is ignored, so a direct client cannot spoof its address. With `n` hops the
/// client is the `n`-th address from the right of the header; a header with
/// fewer entries did not traverse every trusted proxy and falls back to the
/// peer address.
pub(super) fn client_ip(
    headers: &HeaderMap,
    peer: PeerAddress,
    trusted_proxy_hops: u8,
) -> Result<IpAddr, AppError> {
    let peer_ip = peer.0.map(|address| address.ip());
    if trusted_proxy_hops == 0 {
        return peer_ip.ok_or_else(|| {
            AppError::internal(anyhow::anyhow!("listener did not provide peer addresses"))
        });
    }
    let forwarded = headers
        .get_all(FORWARDED_FOR_HEADER)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();
    let total_bytes = forwarded.iter().map(|entry| entry.len()).sum::<usize>();
    if total_bytes > MAX_FORWARDED_FOR_BYTES {
        return Err(AppError::bad_request("header_too_large"));
    }
    let hops = usize::from(trusted_proxy_hops);
    if forwarded.len() >= hops
        && let Some(entry) = forwarded.get(forwarded.len() - hops)
        && let Ok(ip) = parse_forwarded_ip(entry)
    {
        return Ok(ip);
    }
    peer_ip.ok_or_else(|| {
        AppError::internal(anyhow::anyhow!("listener did not provide peer addresses"))
    })
}

fn parse_forwarded_ip(entry: &str) -> Result<IpAddr, std::net::AddrParseError> {
    let entry = entry.trim_matches(|character| character == '"' || character == '\'');
    if let Ok(socket) = entry.parse::<SocketAddr>() {
        return Ok(socket.ip());
    }
    entry
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
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

/// Collects header fields in wire order for exact capture.
///
/// Values that are not UTF-8 are replaced lossily; HTTP header values are
/// opaque bytes, but every provider signing scheme works in ASCII.
pub(super) fn capture_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use axum::http::{HeaderMap, HeaderValue};
    use secrecy::ExposeSecret as _;

    use super::{PeerAddress, client_ip, idempotency_key, management_credential, require_json};
    use crate::infrastructure::iam::PresentedCredential;

    fn peer() -> PeerAddress {
        PeerAddress(Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            443,
        )))
    }

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
    fn client_ip_ignores_forwarding_without_trusted_proxies()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
        assert_eq!(
            client_ip(&headers, peer(), 0)?,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))
        );
        assert!(client_ip(&headers, PeerAddress(None), 0).is_err());
        Ok(())
    }

    #[test]
    fn client_ip_walks_back_through_trusted_proxies() -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.1, 203.0.113.9, 10.0.0.1"),
        );
        assert_eq!(
            client_ip(&headers, peer(), 1)?,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(
            client_ip(&headers, peer(), 2)?,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))
        );
        assert_eq!(
            client_ip(&headers, peer(), 4)?,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            "too few entries falls back to the peer"
        );

        let mut ipv6 = HeaderMap::new();
        ipv6.insert(
            "x-forwarded-for",
            HeaderValue::from_static("[2001:db8::7]:4433"),
        );
        assert_eq!(
            client_ip(&ipv6, peer(), 1)?,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7))
        );
        Ok(())
    }
}
