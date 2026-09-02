//! Evaluation of signature expressions against a captured request.

use std::{borrow::Cow, cmp::Ordering, fmt};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use thiserror::Error;
use url::Url;

use super::{
    ast::{Call, Expr, Function, Path, Root, Segment, SortOrder},
    value::{Value, ValueError},
};
use crate::domain::request::CapturedRequest;

/// RFC 3986 unreserved characters are left as-is; everything else is encoded.
const PERCENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Inputs available to an expression.
#[derive(Clone, Copy)]
pub struct EvalContext<'a> {
    /// Captured provider request.
    pub request: &'a CapturedRequest,
    /// Public hook identifier for the `hook.id` block.
    pub hook_id: &'a str,
    /// Public endpoint URL for the `hook.url` block.
    pub hook_url: &'a str,
    /// Decoded shared secret for the `secret` block.
    pub secret: Option<&'a [u8]>,
    /// DER-encoded `SubjectPublicKeyInfo` for the `key.public` block.
    pub public_key: Option<&'a [u8]>,
}

impl fmt::Debug for EvalContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvalContext")
            .field("hook_id", &self.hook_id)
            .field("hook_url", &self.hook_url)
            .field("secret", &self.secret.map(|_| "[REDACTED]"))
            .field("public_key", &self.public_key.map(<[u8]>::len))
            .finish_non_exhaustive()
    }
}

/// An expression could not be evaluated for this request.
///
/// Messages are stable, short, and never include request content, so they
/// can be stored with blocked-request logs.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EvalError {
    /// A required block resolved to nothing.
    #[error("{path} is missing")]
    MissingValue {
        /// Rendered block path.
        path: String,
    },
    /// The block cannot be evaluated during verification.
    #[error("{path} is not available")]
    UnsupportedBlock {
        /// Rendered block path.
        path: String,
    },
    /// A scalar was indexed as if it were an object or list.
    #[error("{path} cannot be indexed")]
    NotIndexable {
        /// Rendered block path.
        path: String,
    },
    /// `request.body` requires a JSON body.
    #[error("request body is not JSON")]
    BodyNotJson,
    /// `request.form` requires a form-encoded body.
    #[error("request body is not form-encoded")]
    BodyNotForm,
    /// `request.multipart` requires a multipart body.
    #[error("request body is not multipart")]
    BodyNotMultipart,
    /// `request.raw_body` requires UTF-8; use `request.raw_body_bytes`.
    #[error("request body is not UTF-8 text")]
    BodyNotText,
    /// A function received a value of the wrong shape.
    #[error("{function} expected {expected} but received {actual}")]
    Type {
        /// Function name.
        function: &'static str,
        /// Expected shape.
        expected: &'static str,
        /// Actual value type.
        actual: &'static str,
    },
    /// A function received an absent value.
    #[error("{function} received a missing value")]
    Missing {
        /// Function name.
        function: &'static str,
    },
    /// Bytes given to a text function were not UTF-8.
    #[error("{function} received bytes that are not UTF-8")]
    InvalidUtf8 {
        /// Function name.
        function: &'static str,
    },
    /// Text given to a decoding function was not in that encoding.
    #[error("{function} received malformed input")]
    InvalidEncoding {
        /// Function name.
        function: &'static str,
    },
}

impl EvalError {
    pub(super) fn from_value(
        function: &'static str,
        expected: &'static str,
        error: ValueError,
    ) -> Self {
        match error {
            ValueError::Missing => Self::Missing { function },
            ValueError::InvalidUtf8 => Self::InvalidUtf8 { function },
            ValueError::NotScalar { actual }
            | ValueError::NotList { actual }
            | ValueError::NotObject { actual } => Self::Type {
                function,
                expected,
                actual,
            },
        }
    }
}

/// Evaluates an expression.
///
/// # Errors
///
/// Returns [`EvalError`] when a block is unavailable for this request or a
/// function receives an incompatible value.
pub fn evaluate(expression: &Expr, context: &EvalContext<'_>) -> Result<Value, EvalError> {
    match expression {
        Expr::Literal(text) => Ok(Value::Text(text.clone())),
        Expr::Path(path) => evaluate_path(path, context),
        Expr::Call(call) => evaluate_call(call, context),
    }
}

fn evaluate_path(path: &Path, context: &EvalContext<'_>) -> Result<Value, EvalError> {
    let (base, rest) = match path.root {
        Root::Request => request_block(path, context.request)?,
        Root::Hook => hook_block(path, context)?,
        Root::Secret => (
            context
                .secret
                .map_or(Value::Null, |secret| Value::Bytes(secret.to_vec())),
            path.segments.as_slice(),
        ),
        Root::Key => key_block(path, context)?,
    };
    let is_header_block = matches!(
        (path.root, path.segments.first()),
        (Root::Request, Some(Segment::Key(block))) if block == "headers"
    );
    index_into(base, rest, path, is_header_block)
}

fn index_into(
    mut value: Value,
    segments: &[Segment],
    path: &Path,
    lowercase_keys: bool,
) -> Result<Value, EvalError> {
    for segment in segments {
        let next = match segment {
            Segment::Key(key) if lowercase_keys => value.member(&key.to_ascii_lowercase()),
            Segment::Key(key) => value.member(key),
            Segment::Index(index) => value.element(*index),
        };
        value = next.ok_or_else(|| EvalError::NotIndexable {
            path: path.to_string(),
        })?;
    }
    Ok(value)
}

fn request_block<'p>(
    path: &'p Path,
    request: &CapturedRequest,
) -> Result<(Value, &'p [Segment]), EvalError> {
    let Some((Segment::Key(block), rest)) = path.segments.split_first() else {
        return Err(EvalError::UnsupportedBlock {
            path: path.to_string(),
        });
    };
    let value = match block.as_str() {
        "raw_body" => Value::Text(
            request
                .body_text()
                .ok_or(EvalError::BodyNotText)?
                .to_owned(),
        ),
        "raw_body_bytes" => Value::Bytes(request.body().to_vec()),
        "body" => Value::from_json(request.body_json().cloned().ok_or(EvalError::BodyNotJson)?),
        "form" => pairs_object(request.form().ok_or(EvalError::BodyNotForm)?),
        "multipart" => Value::Object(
            request
                .multipart_parts()
                .ok_or(EvalError::BodyNotMultipart)?
                .iter()
                .map(|part| {
                    let data = match String::from_utf8(part.data.clone()) {
                        Ok(text) => Value::Text(text),
                        Err(error) => Value::Bytes(error.into_bytes()),
                    };
                    (part.name.clone(), data)
                })
                .collect(),
        ),
        "method" => Value::Text(request.method().to_owned()),
        "url" => Value::Text(request.url().to_string()),
        "scheme" => Value::Text(request.scheme().to_owned()),
        "authority" | "host" => Value::Text(request.authority()),
        "hostname" => Value::Text(request.hostname().to_owned()),
        "port" => request
            .port()
            .map_or(Value::Null, |port| Value::Text(port.to_string())),
        "path" => Value::Text(request.path().to_owned()),
        "query_string" => Value::Text(request.query_string().to_owned()),
        "query" => pairs_object(&request.query_pairs()),
        "headers" => headers_object(request),
        "cookies" => pairs_object(&request.cookies()),
        _ => {
            return Err(EvalError::UnsupportedBlock {
                path: path.to_string(),
            });
        }
    };
    Ok((value, rest))
}

fn pairs_object(pairs: &[(String, String)]) -> Value {
    Value::Object(
        pairs
            .iter()
            .map(|(key, value)| (key.clone(), Value::Text(value.clone())))
            .collect(),
    )
}

fn headers_object(request: &CapturedRequest) -> Value {
    let mut members: Vec<(String, Value)> = Vec::new();
    for (name, value) in request.headers() {
        match members.iter_mut().find(|(existing, _)| existing == name) {
            Some((_, Value::Text(existing))) => {
                existing.push_str(", ");
                existing.push_str(value);
            }
            _ => members.push((name.clone(), Value::Text(value.clone()))),
        }
    }
    Value::Object(members)
}

fn hook_block<'p>(
    path: &'p Path,
    context: &EvalContext<'_>,
) -> Result<(Value, &'p [Segment]), EvalError> {
    match path.segments.split_first() {
        Some((Segment::Key(block), rest)) if block == "id" => {
            Ok((Value::Text(context.hook_id.to_owned()), rest))
        }
        Some((Segment::Key(block), rest)) if block == "url" => {
            Ok((Value::Text(context.hook_url.to_owned()), rest))
        }
        _ => Err(EvalError::UnsupportedBlock {
            path: path.to_string(),
        }),
    }
}

fn key_block<'p>(
    path: &'p Path,
    context: &EvalContext<'_>,
) -> Result<(Value, &'p [Segment]), EvalError> {
    match path.segments.split_first() {
        Some((Segment::Key(block), rest)) if block == "public" => Ok((
            context
                .public_key
                .map_or(Value::Null, |key| Value::Bytes(key.to_vec())),
            rest,
        )),
        // Hook verifies signatures; it never holds a provider's private key.
        _ => Err(EvalError::UnsupportedBlock {
            path: path.to_string(),
        }),
    }
}

fn evaluate_call(call: &Call, context: &EvalContext<'_>) -> Result<Value, EvalError> {
    let arguments = call
        .arguments
        .iter()
        .map(|argument| evaluate(argument, context))
        .collect::<Result<Vec<_>, _>>()?;
    let function = call.function;
    match function {
        Function::Concat => concatenate(function, arguments, None),
        Function::Join => concatenate(function, flatten(arguments), call.separator.as_deref()),
        Function::Sort => sort(function, single(arguments), call.order.unwrap_or_default()),
        Function::SortKeys => {
            sort_keys(function, single(arguments), call.order.unwrap_or_default())
        }
        Function::Utf8 | Function::Lowercase | Function::Uppercase | Function::Trim => {
            text_function(function, single(arguments))
        }
        Function::Ascii => {
            let text = into_text(function, single(arguments))?;
            if text.is_ascii() {
                Ok(Value::Text(text))
            } else {
                Err(EvalError::InvalidEncoding {
                    function: function.name(),
                })
            }
        }
        Function::UrlEncode
        | Function::UrlDecode
        | Function::PercentEncode
        | Function::PercentDecode
        | Function::CanonicalizeUrl
        | Function::CanonicalizeQuery
        | Function::FormEncode => url_function(function, single(arguments)),
        Function::JsonEncode => {
            let json = single(arguments)
                .to_json()
                .map_err(|error| EvalError::from_value(function.name(), "JSON value", error))?;
            serde_json::to_string(&json)
                .map(Value::Text)
                .map_err(|_| EvalError::InvalidEncoding {
                    function: function.name(),
                })
        }
        Function::Sha1 | Function::Sha256 | Function::Sha384 | Function::Sha512 => {
            digest(function, single(arguments))
        }
        Function::Hex
        | Function::HexDecode
        | Function::Base64
        | Function::Base64Decode
        | Function::Base64Url
        | Function::Base64UrlDecode => encoding_function(function, single(arguments)),
    }
}

fn single(mut arguments: Vec<Value>) -> Value {
    // Arity is validated by the parser, so a missing argument cannot occur;
    // treating it as absent keeps this path panic-free regardless.
    arguments.pop().unwrap_or(Value::Null)
}

fn flatten(arguments: Vec<Value>) -> Vec<Value> {
    arguments
        .into_iter()
        .flat_map(|argument| match argument {
            Value::List(values) => values,
            other => vec![other],
        })
        .collect()
}

fn into_text(function: Function, value: Value) -> Result<String, EvalError> {
    value
        .into_text()
        .map_err(|error| EvalError::from_value(function.name(), "text", error))
}

fn into_bytes(function: Function, value: Value) -> Result<Vec<u8>, EvalError> {
    value
        .into_bytes()
        .map_err(|error| EvalError::from_value(function.name(), "text or bytes", error))
}

fn concatenate(
    function: Function,
    arguments: Vec<Value>,
    separator: Option<&str>,
) -> Result<Value, EvalError> {
    let produce_bytes = arguments.iter().any(Value::is_bytes);
    let mut output = Vec::new();
    for (index, argument) in arguments.into_iter().enumerate() {
        if index > 0
            && let Some(separator) = separator
        {
            output.extend_from_slice(separator.as_bytes());
        }
        output.extend(into_bytes(function, argument)?);
    }
    if produce_bytes {
        return Ok(Value::Bytes(output));
    }
    String::from_utf8(output)
        .map(Value::Text)
        .map_err(|_| EvalError::InvalidUtf8 {
            function: function.name(),
        })
}

fn sort(function: Function, value: Value, order: SortOrder) -> Result<Value, EvalError> {
    let mut values = value
        .into_list()
        .map_err(|error| EvalError::from_value(function.name(), "list", error))?;
    let mut keyed = Vec::with_capacity(values.len());
    for value in values.drain(..) {
        let key = value
            .scalar_bytes()
            .map(Cow::into_owned)
            .map_err(|error| EvalError::from_value(function.name(), "list of scalars", error))?;
        keyed.push((key, value));
    }
    keyed.sort_by(|left, right| ordered(left.0.cmp(&right.0), order));
    Ok(Value::List(
        keyed.into_iter().map(|(_, value)| value).collect(),
    ))
}

fn sort_keys(function: Function, value: Value, order: SortOrder) -> Result<Value, EvalError> {
    let mut members = value
        .into_object()
        .map_err(|error| EvalError::from_value(function.name(), "object", error))?;
    members.sort_by(|left, right| ordered(left.0.cmp(&right.0), order));
    Ok(Value::Object(members))
}

fn ordered(ordering: Ordering, order: SortOrder) -> Ordering {
    match order {
        SortOrder::Ascending => ordering,
        SortOrder::Descending => ordering.reverse(),
    }
}

fn text_function(function: Function, value: Value) -> Result<Value, EvalError> {
    let text = into_text(function, value)?;
    Ok(Value::Text(match function {
        Function::Lowercase => text.to_lowercase(),
        Function::Uppercase => text.to_uppercase(),
        Function::Trim => text.trim().to_owned(),
        _ => text,
    }))
}

fn url_function(function: Function, value: Value) -> Result<Value, EvalError> {
    let name = function.name();
    match function {
        Function::UrlEncode => Ok(Value::Text(
            form_urlencoded::byte_serialize(&into_bytes(function, value)?).collect(),
        )),
        Function::UrlDecode => {
            let text = into_text(function, value)?.replace('+', " ");
            percent_decode_str(&text)
                .decode_utf8()
                .map(|decoded| Value::Text(decoded.into_owned()))
                .map_err(|_| EvalError::InvalidUtf8 { function: name })
        }
        Function::PercentEncode => Ok(Value::Text(
            utf8_percent_encode(&into_text(function, value)?, PERCENT_ENCODE_SET).to_string(),
        )),
        Function::PercentDecode => percent_decode_str(&into_text(function, value)?)
            .decode_utf8()
            .map(|decoded| Value::Text(decoded.into_owned()))
            .map_err(|_| EvalError::InvalidUtf8 { function: name }),
        Function::CanonicalizeUrl => canonicalize_url(function, &into_text(function, value)?),
        Function::CanonicalizeQuery => {
            let mut pairs = match value {
                Value::Object(members) => object_pairs(function, members)?,
                other => form_urlencoded::parse(into_text(function, other)?.as_bytes())
                    .map(|(key, value)| (key.into_owned(), value.into_owned()))
                    .collect(),
            };
            pairs.sort();
            Ok(Value::Text(serialize_pairs(&pairs)))
        }
        Function::FormEncode => {
            let members = value
                .into_object()
                .map_err(|error| EvalError::from_value(name, "object", error))?;
            Ok(Value::Text(serialize_pairs(&object_pairs(
                function, members,
            )?)))
        }
        _ => Err(EvalError::Type {
            function: name,
            expected: "text",
            actual: value.type_name(),
        }),
    }
}

fn object_pairs(
    function: Function,
    members: Vec<(String, Value)>,
) -> Result<Vec<(String, String)>, EvalError> {
    members
        .into_iter()
        .map(|(key, value)| Ok((key, into_text(function, value)?)))
        .collect()
}

fn serialize_pairs(pairs: &[(String, String)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

fn canonicalize_url(function: Function, text: &str) -> Result<Value, EvalError> {
    let mut url = Url::parse(text).map_err(|_| EvalError::InvalidEncoding {
        function: function.name(),
    })?;
    let mut pairs = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    pairs.sort();
    if pairs.is_empty() {
        url.set_query(None);
    } else {
        let mut query = url.query_pairs_mut();
        query.clear();
        for (key, value) in &pairs {
            query.append_pair(key, value);
        }
    }
    url.set_fragment(None);
    Ok(Value::Text(url.to_string()))
}

fn digest(function: Function, value: Value) -> Result<Value, EvalError> {
    let bytes = into_bytes(function, value)?;
    Ok(Value::Bytes(match function {
        Function::Sha1 => Sha1::digest(&bytes).to_vec(),
        Function::Sha384 => Sha384::digest(&bytes).to_vec(),
        Function::Sha512 => Sha512::digest(&bytes).to_vec(),
        _ => Sha256::digest(&bytes).to_vec(),
    }))
}

fn encoding_function(function: Function, value: Value) -> Result<Value, EvalError> {
    let name = function.name();
    let invalid = || EvalError::InvalidEncoding { function: name };
    match function {
        Function::Hex => Ok(Value::Text(hex::encode(into_bytes(function, value)?))),
        Function::HexDecode => hex::decode(into_text(function, value)?.trim())
            .map(Value::Bytes)
            .map_err(|_| invalid()),
        Function::Base64 => Ok(Value::Text(STANDARD.encode(into_bytes(function, value)?))),
        Function::Base64Url => Ok(Value::Text(
            URL_SAFE_NO_PAD.encode(into_bytes(function, value)?),
        )),
        Function::Base64Decode => {
            let text = into_text(function, value)?;
            let text = text.trim();
            STANDARD
                .decode(text)
                .or_else(|_| STANDARD_NO_PAD.decode(text))
                .map(Value::Bytes)
                .map_err(|_| invalid())
        }
        Function::Base64UrlDecode => {
            let text = into_text(function, value)?;
            let text = text.trim();
            URL_SAFE_NO_PAD
                .decode(text)
                .or_else(|_| URL_SAFE.decode(text))
                .map(Value::Bytes)
                .map_err(|_| invalid())
        }
        _ => Err(EvalError::Type {
            function: name,
            expected: "text or bytes",
            actual: value.type_name(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use bytes::Bytes;
    use time::macros::datetime;
    use url::Url;

    use super::{EvalContext, EvalError, Value, evaluate};
    use crate::domain::{
        request::{CapturedRequest, CapturedRequestParts},
        signature::parser::parse,
    };

    fn request(
        headers: &[(&str, &str)],
        body: &'static [u8],
    ) -> Result<CapturedRequest, Box<dyn std::error::Error>> {
        Ok(CapturedRequest::new(CapturedRequestParts {
            method: "POST".to_owned(),
            url: Url::parse("https://hook.example.test/silicon/cos:tos/A1B2C3?z=1&a=2&a=1")?,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            body: Bytes::from_static(body),
            remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            received_at: datetime!(2026-09-02 10:00 UTC),
        })?)
    }

    fn eval(source: &str, request: &CapturedRequest) -> Result<Value, Box<dyn std::error::Error>> {
        let context = EvalContext {
            request,
            hook_id: "018eb4ce-e57a-7d2c-8f9f-a35928ef91e1",
            hook_url: "https://hook.example.test/silicon/cos:tos/A1B2C3D4",
            secret: Some(b"shh"),
            public_key: None,
        };
        Ok(evaluate(&parse(source)?, &context)?)
    }

    #[test]
    fn default_standard_webhooks_payload_concatenates_headers_and_body()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request(
            &[("Webhook-Id", "msg_1"), ("webhook-timestamp", "1700000000")],
            br#"{"ok":true}"#,
        )?;
        let payload = eval(
            r#"concat(request.headers["webhook-id"], ".", request.headers["webhook-timestamp"], ".", request.raw_body)"#,
            &request,
        )?;
        assert_eq!(
            payload,
            Value::Text(r#"msg_1.1700000000.{"ok":true}"#.to_owned())
        );
        Ok(())
    }

    #[test]
    fn missing_headers_fail_instead_of_signing_partial_payloads()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request(&[], b"{}")?;
        let error = eval(
            r#"concat(request.headers["webhook-id"], request.raw_body)"#,
            &request,
        )
        .err()
        .map(|error| error.to_string());
        assert_eq!(error.as_deref(), Some("concat received a missing value"));
        assert_eq!(
            eval(r#"request.headers["webhook-id"]"#, &request)?,
            Value::Null
        );
        Ok(())
    }

    #[test]
    fn json_form_query_and_cookie_blocks_are_addressable() -> Result<(), Box<dyn std::error::Error>>
    {
        let json = request(
            &[("cookie", "sid=abc; t=1")],
            br#"{"data":{"id":"evt_1","items":[{"n":7}]}}"#,
        )?;
        assert_eq!(
            eval("request.body.data.items[0].n", &json)?,
            Value::Number(7.into())
        );
        assert_eq!(
            eval(r#"request.body["data"]["id"]"#, &json)?,
            Value::Text("evt_1".to_owned())
        );
        assert_eq!(eval("request.query.a", &json)?, Value::Text("2".to_owned()));
        assert_eq!(
            eval("request.cookies.sid", &json)?,
            Value::Text("abc".to_owned())
        );
        assert_eq!(
            eval("request.method", &json)?,
            Value::Text("POST".to_owned())
        );
        assert_eq!(eval("request.port", &json)?, Value::Text("443".to_owned()));
        assert_eq!(
            eval("request.path", &json)?,
            Value::Text("/silicon/cos:tos/A1B2C3".to_owned())
        );
        assert_eq!(
            eval("hook.id", &json)?,
            Value::Text("018eb4ce-e57a-7d2c-8f9f-a35928ef91e1".to_owned())
        );
        assert_eq!(eval("secret", &json)?, Value::Bytes(b"shh".to_vec()));
        assert_eq!(eval("key.public", &json)?, Value::Null);
        assert!(matches!(
            eval("request.body.data.id.more", &json),
            Err(error) if error.to_string() == "request.body.data.id.more cannot be indexed"
        ));

        let form = request(
            &[("content-type", "application/x-www-form-urlencoded")],
            b"token=abc&count=2",
        )?;
        assert_eq!(
            eval("request.form.token", &form)?,
            Value::Text("abc".to_owned())
        );
        assert_eq!(
            eval("request.body", &form)
                .err()
                .map(|error| error.to_string()),
            Some("request body is not JSON".to_owned())
        );
        assert_eq!(
            eval("request.form", &json)
                .err()
                .map(|error| error.to_string()),
            Some("request body is not form-encoded".to_owned())
        );
        Ok(())
    }

    #[test]
    fn hashing_and_encoding_functions_match_known_vectors() -> Result<(), Box<dyn std::error::Error>>
    {
        let request = request(&[], b"hello")?;
        assert_eq!(
            eval("hex(sha256(request.raw_body))", &request)?,
            Value::Text(
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".to_owned()
            )
        );
        assert_eq!(
            eval("hex(sha1(request.raw_body_bytes))", &request)?,
            Value::Text("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d".to_owned())
        );
        assert_eq!(
            eval("base64(request.raw_body)", &request)?,
            Value::Text("aGVsbG8=".to_owned())
        );
        assert_eq!(
            eval("base64url(request.raw_body)", &request)?,
            Value::Text("aGVsbG8".to_owned())
        );
        assert_eq!(
            eval(r#"utf8(base64_decode("aGVsbG8"))"#, &request)?,
            Value::Text("hello".to_owned())
        );
        assert_eq!(
            eval(r#"hex_decode("6869")"#, &request)?,
            Value::Bytes(b"hi".to_vec())
        );
        assert!(matches!(
            eval(r#"hex_decode("zz")"#, &request),
            Err(error) if error.to_string() == "hex_decode received malformed input"
        ));
        assert_eq!(
            eval(r#"uppercase(trim(" abc "))"#, &request)?,
            Value::Text("ABC".to_owned())
        );
        assert!(matches!(
            eval(r#"ascii("héllo")"#, &request),
            Err(error) if error.to_string() == "ascii received malformed input"
        ));
        Ok(())
    }

    #[test]
    fn url_and_json_canonicalization_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let request = request(&[], br#"{"b":1,"a":{"y":[3,1],"x":null}}"#)?;
        assert_eq!(
            eval(
                r#"canonicalize_url("HTTPS://Example.COM:443/a/b?z=1&a=2#frag")"#,
                &request
            )?,
            Value::Text("https://example.com/a/b?a=2&z=1".to_owned())
        );
        assert_eq!(
            eval(r#"canonicalize_query("z=1&a=two+words&a=1")"#, &request)?,
            Value::Text("a=1&a=two+words&z=1".to_owned())
        );
        assert_eq!(
            eval("canonicalize_query(request.query)", &request)?,
            Value::Text("a=1&a=2&z=1".to_owned())
        );
        assert_eq!(
            eval("json_encode(sort_keys(request.body, order: asc))", &request)?,
            Value::Text(r#"{"a":{"x":null,"y":[3,1]},"b":1}"#.to_owned())
        );
        assert_eq!(
            eval("form_encode(request.query)", &request)?,
            Value::Text("z=1&a=2&a=1".to_owned())
        );
        assert_eq!(
            eval(r#"url_encode("a b&c")"#, &request)?,
            Value::Text("a+b%26c".to_owned())
        );
        assert_eq!(
            eval(r#"percent_encode("a b/c~")"#, &request)?,
            Value::Text("a%20b%2Fc~".to_owned())
        );
        assert_eq!(
            eval(r#"percent_decode("a%20b")"#, &request)?,
            Value::Text("a b".to_owned())
        );
        assert_eq!(
            eval(r#"url_decode("a+b%26c")"#, &request)?,
            Value::Text("a b&c".to_owned())
        );
        Ok(())
    }

    #[test]
    fn join_and_sort_operate_on_lists_of_scalars() -> Result<(), Box<dyn std::error::Error>> {
        let request = request(&[], br#"{"ids":["b","a","c"]}"#)?;
        assert_eq!(
            eval(
                r#"join(separator: ",", sort(request.body.ids, order: desc))"#,
                &request
            )?,
            Value::Text("c,b,a".to_owned())
        );
        assert_eq!(
            eval(
                r#"join(separator: "\n", request.method, request.path)"#,
                &request
            )?,
            Value::Text("POST\n/silicon/cos:tos/A1B2C3".to_owned())
        );
        assert_eq!(
            eval(
                r#"join(separator: "", request.raw_body_bytes, "x")"#,
                &request
            )?,
            Value::Bytes(br#"{"ids":["b","a","c"]}x"#.to_vec())
        );
        assert!(matches!(
            eval("sort(request.body)", &request),
            Err(error) if matches!(error.downcast_ref::<EvalError>(), Some(EvalError::Type { .. }))
        ));
        Ok(())
    }
}
