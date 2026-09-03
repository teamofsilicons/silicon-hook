//! Unversioned API-version negotiation shared with the official clients.
//!
//! A client advertises the API majors it implements in
//! `Silicon-Hook-Supported-API-Versions`; Hook answers with the highest major
//! both sides support, in the body and in `Silicon-Hook-API-Version`, and
//! varies the response on the advertised list so caches never serve one
//! client's catalog to another. Every later request may pin that major in
//! `Silicon-Hook-API-Version`; a pin that disagrees with the route is refused
//! rather than silently served by a different contract.

use http::{HeaderMap, HeaderName, HeaderValue, header};

use crate::error::AppError;

/// API majors this build serves, highest first.
pub const SUPPORTED_API_VERSIONS: &[&str] = &["v1"];
/// Request header carrying the client's supported majors.
pub const SUPPORTED_API_VERSIONS_HEADER: HeaderName =
    HeaderName::from_static("silicon-hook-supported-api-versions");
/// Header carrying the selected major on the handshake response and, when a
/// client pins it, on every versioned request.
pub const API_VERSION_HEADER: HeaderName = HeaderName::from_static("silicon-hook-api-version");
const VARY_VALUE: HeaderValue = HeaderValue::from_static("Silicon-Hook-Supported-API-Versions");
const VERSIONED_PREFIX: &str = "/api/v1/";
const MAX_ADVERTISED_VERSIONS: usize = 16;

/// Selects the highest API major both sides support.
///
/// A missing advertisement selects the current major so plain HTTP clients
/// can still read the catalog.
///
/// # Errors
///
/// Returns `400 invalid_api_version_header` for an empty or oversized list
/// and `406 api_version_unsupported` when no major is shared.
pub fn negotiate(advertised: Option<&str>) -> Result<&'static str, AppError> {
    let Some(advertised) = advertised else {
        return Ok(SUPPORTED_API_VERSIONS[0]);
    };
    let requested = advertised
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .take(MAX_ADVERTISED_VERSIONS + 1)
        .collect::<Vec<_>>();
    if requested.is_empty() || requested.len() > MAX_ADVERTISED_VERSIONS {
        return Err(AppError::bad_request("invalid_api_version_header"));
    }
    SUPPORTED_API_VERSIONS
        .iter()
        .copied()
        .find(|supported| {
            requested
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(supported))
        })
        .ok_or(AppError::ApiVersionUnsupported)
}

/// Reads the client's advertisement, which must occur at most once.
///
/// # Errors
///
/// Returns `400` for a repeated or non-ASCII header.
pub fn advertised_versions(headers: &HeaderMap) -> Result<Option<&str>, AppError> {
    let mut values = headers.get_all(&SUPPORTED_API_VERSIONS_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AppError::bad_request("duplicate_header"));
    }
    value
        .to_str()
        .map(Some)
        .map_err(|_| AppError::bad_request("invalid_header_encoding"))
}

/// Response headers that pin the selected major and key caches on the
/// advertised catalog.
#[must_use]
pub fn response_headers(selected: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::with_capacity(2);
    headers.insert(API_VERSION_HEADER, HeaderValue::from_static(selected));
    headers.insert(header::VARY, VARY_VALUE);
    headers
}

/// Refuses a versioned request pinned to a major other than the route's.
///
/// # Errors
///
/// Returns `400 api_version_mismatch` when the pin disagrees with the route
/// and `400 duplicate_header` when the pin is repeated.
pub fn check_pinned(headers: &HeaderMap, path: &str) -> Result<(), AppError> {
    if !path.starts_with(VERSIONED_PREFIX) {
        return Ok(());
    }
    let mut values = headers.get_all(&API_VERSION_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(AppError::bad_request("duplicate_header"));
    }
    let pinned = value
        .to_str()
        .map_err(|_| AppError::bad_request("invalid_header_encoding"))?;
    if pinned.trim().eq_ignore_ascii_case("v1") {
        Ok(())
    } else {
        Err(AppError::bad_request("api_version_mismatch"))
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue};

    use super::{advertised_versions, check_pinned, negotiate};
    use crate::error::AppError;

    #[test]
    fn negotiation_prefers_the_highest_shared_major() {
        assert_eq!(negotiate(None).ok(), Some("v1"));
        assert_eq!(negotiate(Some("v2, v1")).ok(), Some("v1"));
        assert_eq!(negotiate(Some("V1")).ok(), Some("v1"));
        assert!(matches!(
            negotiate(Some("v2,v3")),
            Err(AppError::ApiVersionUnsupported)
        ));
        assert!(matches!(
            negotiate(Some(" , ")),
            Err(AppError::BadRequest { .. })
        ));
    }

    #[test]
    fn advertisements_and_pins_must_be_single_valued() {
        let mut headers = HeaderMap::new();
        assert_eq!(advertised_versions(&headers).ok(), Some(None));
        headers.append(
            "silicon-hook-supported-api-versions",
            HeaderValue::from_static("v1"),
        );
        assert_eq!(advertised_versions(&headers).ok(), Some(Some("v1")));
        headers.append(
            "silicon-hook-supported-api-versions",
            HeaderValue::from_static("v1"),
        );
        assert!(advertised_versions(&headers).is_err());

        let mut pinned = HeaderMap::new();
        assert!(check_pinned(&pinned, "/api/v1/version").is_ok());
        pinned.insert("silicon-hook-api-version", HeaderValue::from_static("v1"));
        assert!(check_pinned(&pinned, "/api/v1/version").is_ok());
        assert!(check_pinned(&pinned, "/healthz").is_ok());
        pinned.insert("silicon-hook-api-version", HeaderValue::from_static("v2"));
        assert!(matches!(
            check_pinned(&pinned, "/api/v1/version"),
            Err(AppError::BadRequest { .. })
        ));
        assert!(check_pinned(&pinned, "/api/version").is_ok());
    }
}
