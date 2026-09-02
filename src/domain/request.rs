//! Exact capture of an inbound provider request.
//!
//! Providers sign what they transmit, so Hook keeps the raw method, URL,
//! headers, and body bytes rather than a normalized envelope. Parsed views of
//! the body (JSON, form, multipart) are derived lazily for signature
//! expressions and never replace the stored bytes.

use std::{convert::Infallible, fmt, net::IpAddr, sync::OnceLock};

use bytes::Bytes;
use futures::stream;
use serde_json::Value as Json;
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;

/// Largest request body accepted at webhook ingress.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Largest number of header fields retained for one request.
pub const MAX_HEADER_COUNT: usize = 128;
/// Largest combined size of retained header names and values.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Largest number of multipart parts parsed for signature expressions.
pub const MAX_MULTIPART_PARTS: usize = 64;

/// A request exceeded a capture bound.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CaptureError {
    /// The body exceeds [`MAX_BODY_BYTES`].
    #[error("request body exceeds {MAX_BODY_BYTES} bytes")]
    BodyTooLarge,
    /// More than [`MAX_HEADER_COUNT`] header fields were present.
    #[error("request has more than {MAX_HEADER_COUNT} header fields")]
    TooManyHeaders,
    /// Header names and values exceed [`MAX_HEADER_BYTES`] together.
    #[error("request headers exceed {MAX_HEADER_BYTES} bytes")]
    HeadersTooLarge,
    /// The method token is empty or contains non-token characters.
    #[error("request method is not a valid HTTP token")]
    InvalidMethod,
}

/// Multipart parsing failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MultipartError {
    /// The request is not `multipart/form-data` with a boundary.
    #[error("request is not multipart/form-data")]
    NotMultipart,
    /// The body does not follow the multipart syntax.
    #[error("multipart body is malformed")]
    Malformed,
    /// The body has more than [`MAX_MULTIPART_PARTS`] parts.
    #[error("multipart body has more than {MAX_MULTIPART_PARTS} parts")]
    TooManyParts,
}

/// One decoded `multipart/form-data` part.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultipartPart {
    /// Field name from the part's `Content-Disposition`.
    pub name: String,
    /// Optional file name.
    pub filename: Option<String>,
    /// Optional part media type.
    pub content_type: Option<String>,
    /// Exact part bytes.
    pub data: Vec<u8>,
}

/// Raw inputs used to construct a [`CapturedRequest`].
#[derive(Clone, Debug)]
pub struct CapturedRequestParts {
    /// HTTP method token.
    pub method: String,
    /// Public URL of the request including path and query.
    pub url: Url,
    /// Header fields in wire order. Names are matched case-insensitively.
    pub headers: Vec<(String, String)>,
    /// Exact body bytes.
    pub body: Bytes,
    /// Client address after trusted-proxy resolution.
    pub remote_ip: IpAddr,
    /// Authoritative receive time.
    pub received_at: OffsetDateTime,
}

/// An inbound request retained exactly as received.
#[derive(Clone)]
pub struct CapturedRequest {
    method: String,
    url: Url,
    headers: Vec<(String, String)>,
    body: Bytes,
    remote_ip: IpAddr,
    received_at: OffsetDateTime,
    multipart: Option<Vec<MultipartPart>>,
    json: OnceLock<Option<Json>>,
    form: OnceLock<Option<Vec<(String, String)>>>,
}

impl fmt::Debug for CapturedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedRequest")
            .field("method", &self.method)
            .field("url", &self.url.as_str())
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .field("remote_ip", &self.remote_ip)
            .field("received_at", &self.received_at)
            .finish_non_exhaustive()
    }
}

impl CapturedRequest {
    /// Validates capture bounds and normalizes header names to lowercase.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError`] when the method is not an HTTP token or the
    /// body or headers exceed their bounds.
    pub fn new(parts: CapturedRequestParts) -> Result<Self, CaptureError> {
        if parts.method.is_empty() || !parts.method.bytes().all(is_token_byte) {
            return Err(CaptureError::InvalidMethod);
        }
        if parts.body.len() > MAX_BODY_BYTES {
            return Err(CaptureError::BodyTooLarge);
        }
        if parts.headers.len() > MAX_HEADER_COUNT {
            return Err(CaptureError::TooManyHeaders);
        }
        let header_bytes = parts
            .headers
            .iter()
            .map(|(name, value)| name.len().saturating_add(value.len()))
            .fold(0_usize, usize::saturating_add);
        if header_bytes > MAX_HEADER_BYTES {
            return Err(CaptureError::HeadersTooLarge);
        }
        let headers = parts
            .headers
            .into_iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value))
            .collect();
        Ok(Self {
            method: parts.method.to_ascii_uppercase(),
            url: parts.url,
            headers,
            body: parts.body,
            remote_ip: parts.remote_ip,
            received_at: parts.received_at,
            multipart: None,
            json: OnceLock::new(),
            form: OnceLock::new(),
        })
    }

    /// Parses a `multipart/form-data` body so `request.multipart` blocks can
    /// be evaluated synchronously later.
    ///
    /// # Errors
    ///
    /// Returns [`MultipartError`] when the request is not multipart, the body
    /// is malformed, or it has too many parts.
    pub async fn parse_multipart(&mut self) -> Result<usize, MultipartError> {
        let boundary = self
            .header("content-type")
            .and_then(|value| multer::parse_boundary(value).ok())
            .ok_or(MultipartError::NotMultipart)?;
        let body = self.body.clone();
        let body_stream = stream::once(async move { Ok::<Bytes, Infallible>(body) });
        let mut multipart = multer::Multipart::new(body_stream, boundary);
        let mut parts = Vec::new();
        while let Some(field) = multipart
            .next_field()
            .await
            .map_err(|_| MultipartError::Malformed)?
        {
            if parts.len() >= MAX_MULTIPART_PARTS {
                return Err(MultipartError::TooManyParts);
            }
            let name = field.name().unwrap_or_default().to_owned();
            let filename = field.file_name().map(ToOwned::to_owned);
            let content_type = field.content_type().map(ToString::to_string);
            let data = field
                .bytes()
                .await
                .map_err(|_| MultipartError::Malformed)?
                .to_vec();
            parts.push(MultipartPart {
                name,
                filename,
                content_type,
                data,
            });
        }
        let count = parts.len();
        self.multipart = Some(parts);
        Ok(count)
    }

    /// Returns the uppercase method token.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the complete public URL.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the URL scheme.
    #[must_use]
    pub fn scheme(&self) -> &str {
        self.url.scheme()
    }

    /// Returns `host` or `host:port` when a non-default port is present.
    #[must_use]
    pub fn authority(&self) -> String {
        let host = self.url.host_str().unwrap_or_default();
        match self.url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        }
    }

    /// Returns the host name without a port.
    #[must_use]
    pub fn hostname(&self) -> &str {
        self.url.host_str().unwrap_or_default()
    }

    /// Returns the effective port, using the scheme default when omitted.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.url.port_or_known_default()
    }

    /// Returns the URL path.
    #[must_use]
    pub fn path(&self) -> &str {
        self.url.path()
    }

    /// Returns the raw query string without the leading `?`.
    #[must_use]
    pub fn query_string(&self) -> &str {
        self.url.query().unwrap_or_default()
    }

    /// Returns decoded query pairs in wire order.
    #[must_use]
    pub fn query_pairs(&self) -> Vec<(String, String)> {
        self.url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect()
    }

    /// Returns header fields with lowercase names in wire order.
    #[must_use]
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Returns a header's value, combining repeated fields with `, `.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<String> {
        let name = name.to_ascii_lowercase();
        let mut values = self
            .headers
            .iter()
            .filter(|(candidate, _)| *candidate == name)
            .map(|(_, value)| value.as_str())
            .peekable();
        values.peek()?;
        Some(values.collect::<Vec<_>>().join(", "))
    }

    /// Returns cookies from every `Cookie` header in wire order.
    #[must_use]
    pub fn cookies(&self) -> Vec<(String, String)> {
        self.headers
            .iter()
            .filter(|(name, _)| name == "cookie")
            .flat_map(|(_, value)| value.split(';'))
            .filter_map(|pair| {
                let (name, value) = pair.split_once('=')?;
                Some((name.trim().to_owned(), value.trim().to_owned()))
            })
            .collect()
    }

    /// Returns the media type portion of `Content-Type`, lowercased.
    #[must_use]
    pub fn content_type(&self) -> Option<String> {
        self.header("content-type").and_then(|value| {
            value
                .split(';')
                .next()
                .map(str::trim)
                .map(str::to_ascii_lowercase)
        })
    }

    /// Returns the exact body bytes.
    #[must_use]
    pub const fn body(&self) -> &Bytes {
        &self.body
    }

    /// Returns the body as text when it is valid UTF-8.
    #[must_use]
    pub fn body_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.body).ok()
    }

    /// Returns the parsed JSON body, or `None` when it is not JSON.
    #[must_use]
    pub fn body_json(&self) -> Option<&Json> {
        self.json
            .get_or_init(|| serde_json::from_slice(&self.body).ok())
            .as_ref()
    }

    /// Returns decoded form pairs for an `application/x-www-form-urlencoded`
    /// body, or `None` for any other media type.
    #[must_use]
    pub fn form(&self) -> Option<&[(String, String)]> {
        self.form
            .get_or_init(|| {
                if self.content_type().as_deref() != Some("application/x-www-form-urlencoded") {
                    return None;
                }
                Some(
                    form_urlencoded::parse(&self.body)
                        .map(|(key, value)| (key.into_owned(), value.into_owned()))
                        .collect(),
                )
            })
            .as_deref()
    }

    /// Returns multipart parts once [`Self::parse_multipart`] has succeeded.
    #[must_use]
    pub fn multipart_parts(&self) -> Option<&[MultipartPart]> {
        self.multipart.as_deref()
    }

    /// Returns the resolved client address.
    #[must_use]
    pub const fn remote_ip(&self) -> IpAddr {
        self.remote_ip
    }

    /// Returns the authoritative receive time.
    #[must_use]
    pub const fn received_at(&self) -> OffsetDateTime {
        self.received_at
    }
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use bytes::Bytes;
    use serde_json::json;
    use time::macros::datetime;
    use url::Url;

    use super::{CaptureError, CapturedRequest, CapturedRequestParts, MultipartError};

    fn parts(
        headers: Vec<(&str, &str)>,
        body: &'static [u8],
    ) -> Result<CapturedRequestParts, url::ParseError> {
        Ok(CapturedRequestParts {
            method: "post".to_owned(),
            url: Url::parse("https://hook.example.test:8443/silicon/cos:tos/A1B2C3?b=2&a=1")?,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            body: Bytes::from_static(body),
            remote_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            received_at: datetime!(2026-09-02 10:00 UTC),
        })
    }

    #[test]
    fn exposes_url_components_and_case_insensitive_headers()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = CapturedRequest::new(parts(
            vec![
                ("Content-Type", "application/json; charset=utf-8"),
                ("X-Dup", "one"),
                ("x-dup", "two"),
                ("Cookie", "session=abc; theme=dark"),
            ],
            br#"{"ok":true,"items":[1,2]}"#,
        )?)?;

        assert_eq!(request.method(), "POST");
        assert_eq!(request.scheme(), "https");
        assert_eq!(request.authority(), "hook.example.test:8443");
        assert_eq!(request.hostname(), "hook.example.test");
        assert_eq!(request.port(), Some(8443));
        assert_eq!(request.path(), "/silicon/cos:tos/A1B2C3");
        assert_eq!(request.query_string(), "b=2&a=1");
        assert_eq!(request.header("X-DUP").as_deref(), Some("one, two"));
        assert_eq!(request.header("missing"), None);
        assert_eq!(
            request.cookies(),
            vec![
                ("session".to_owned(), "abc".to_owned()),
                ("theme".to_owned(), "dark".to_owned())
            ]
        );
        assert_eq!(request.content_type().as_deref(), Some("application/json"));
        assert_eq!(
            request.body_json(),
            Some(&json!({"ok": true, "items": [1, 2]}))
        );
        assert_eq!(request.form(), None);
        Ok(())
    }

    #[test]
    fn capture_bounds_are_enforced() -> Result<(), Box<dyn std::error::Error>> {
        let mut invalid_method = parts(Vec::new(), b"")?;
        invalid_method.method = "GET POST".to_owned();
        assert_eq!(
            CapturedRequest::new(invalid_method).err(),
            Some(CaptureError::InvalidMethod)
        );

        let mut too_many_headers = parts(Vec::new(), b"")?;
        too_many_headers.headers = (0..129)
            .map(|index| (format!("x-{index}"), "v".to_owned()))
            .collect();
        assert_eq!(
            CapturedRequest::new(too_many_headers).err(),
            Some(CaptureError::TooManyHeaders)
        );

        let mut oversized = parts(Vec::new(), b"")?;
        oversized.body = Bytes::from(vec![0_u8; super::MAX_BODY_BYTES + 1]);
        assert_eq!(
            CapturedRequest::new(oversized).err(),
            Some(CaptureError::BodyTooLarge)
        );
        Ok(())
    }

    #[test]
    fn form_bodies_require_their_media_type() -> Result<(), Box<dyn std::error::Error>> {
        let request = CapturedRequest::new(parts(
            vec![("content-type", "application/x-www-form-urlencoded")],
            b"a=1&b=two+words",
        )?)?;
        assert_eq!(
            request.form(),
            Some(
                &[
                    ("a".to_owned(), "1".to_owned()),
                    ("b".to_owned(), "two words".to_owned())
                ][..]
            )
        );
        assert_eq!(request.body_json(), None);
        Ok(())
    }

    #[tokio::test]
    async fn multipart_parts_are_parsed_on_demand() -> Result<(), Box<dyn std::error::Error>> {
        let body = b"--b\r\nContent-Disposition: form-data; name=\"event\"\r\n\r\npush\r\n--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b--\r\n";
        let mut request = CapturedRequest::new(parts(
            vec![("content-type", "multipart/form-data; boundary=b")],
            body,
        )?)?;
        assert_eq!(request.multipart_parts(), None);
        assert_eq!(request.parse_multipart().await?, 2);
        let decoded = request.multipart_parts().unwrap_or_default();
        assert_eq!(decoded[0].name, "event");
        assert_eq!(decoded[0].data, b"push");
        assert_eq!(decoded[1].filename.as_deref(), Some("a.txt"));
        assert_eq!(decoded[1].content_type.as_deref(), Some("text/plain"));

        let mut plain = CapturedRequest::new(parts(vec![], b"x")?)?;
        assert_eq!(
            plain.parse_multipart().await,
            Err(MultipartError::NotMultipart)
        );
        Ok(())
    }
}
