//! Parsed representation of a signature expression.

use std::fmt;

/// Root of a block path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Root {
    /// The captured provider request.
    Request,
    /// The receiving hook.
    Hook,
    /// The decoded shared signing secret.
    Secret,
    /// Configured asymmetric key material.
    Key,
}

impl Root {
    pub(super) fn parse(name: &str) -> Option<Self> {
        match name {
            "request" => Some(Self::Request),
            "hook" => Some(Self::Hook),
            "secret" => Some(Self::Secret),
            "key" => Some(Self::Key),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Hook => "hook",
            Self::Secret => "secret",
            Self::Key => "key",
        }
    }
}

/// One step into a block, such as a header name or a JSON member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Segment {
    /// A named member, header, key, or field.
    Key(String),
    /// A zero-based list position.
    Index(usize),
}

impl fmt::Display for Segment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(key) => {
                if is_bare_identifier(key) {
                    write!(formatter, ".{key}")
                } else {
                    write!(formatter, "[{}]", quote(key))
                }
            }
            Self::Index(index) => write!(formatter, "[{index}]"),
        }
    }
}

/// A block reference such as `request.headers["webhook-id"]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Path {
    /// Root block.
    pub root: Root,
    /// Steps below the root, in order.
    pub segments: Vec<Segment>,
}

impl fmt::Display for Path {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.root.as_str())?;
        for segment in &self.segments {
            write!(formatter, "{segment}")?;
        }
        Ok(())
    }
}

/// Sort direction accepted by `sort` and `sort_keys`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SortOrder {
    /// Ascending byte order.
    #[default]
    Ascending,
    /// Descending byte order.
    Descending,
}

impl SortOrder {
    pub(super) fn parse(name: &str) -> Option<Self> {
        match name {
            "asc" => Some(Self::Ascending),
            "desc" => Some(Self::Descending),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Ascending => "asc",
            Self::Descending => "desc",
        }
    }
}

/// Built-in function names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Function {
    /// Concatenate scalars.
    Concat,
    /// Join scalars with a separator.
    Join,
    /// Sort a list of scalars.
    Sort,
    /// Sort the members of an object by key.
    SortKeys,
    /// Interpret bytes as UTF-8 text.
    Utf8,
    /// Interpret bytes as ASCII text.
    Ascii,
    /// Encode text as `application/x-www-form-urlencoded`.
    UrlEncode,
    /// Decode `application/x-www-form-urlencoded` text.
    UrlDecode,
    /// Percent-encode text per RFC 3986.
    PercentEncode,
    /// Percent-decode text per RFC 3986.
    PercentDecode,
    /// Normalize a URL.
    CanonicalizeUrl,
    /// Normalize a query string.
    CanonicalizeQuery,
    /// Serialize a value as compact JSON.
    JsonEncode,
    /// Serialize an object as `application/x-www-form-urlencoded`.
    FormEncode,
    /// SHA-1 digest.
    Sha1,
    /// SHA-256 digest.
    Sha256,
    /// SHA-384 digest.
    Sha384,
    /// SHA-512 digest.
    Sha512,
    /// Lowercase hexadecimal encoding.
    Hex,
    /// Hexadecimal decoding.
    HexDecode,
    /// Standard base64 encoding with padding.
    Base64,
    /// Standard base64 decoding.
    Base64Decode,
    /// URL-safe base64 encoding without padding.
    Base64Url,
    /// URL-safe base64 decoding.
    Base64UrlDecode,
    /// Lowercase text.
    Lowercase,
    /// Uppercase text.
    Uppercase,
    /// Trim surrounding whitespace.
    Trim,
}

impl Function {
    pub(super) fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "concat" => Self::Concat,
            "join" => Self::Join,
            "sort" => Self::Sort,
            "sort_keys" => Self::SortKeys,
            "utf8" => Self::Utf8,
            "ascii" => Self::Ascii,
            "url_encode" => Self::UrlEncode,
            "url_decode" => Self::UrlDecode,
            "percent_encode" => Self::PercentEncode,
            "percent_decode" => Self::PercentDecode,
            "canonicalize_url" => Self::CanonicalizeUrl,
            "canonicalize_query" => Self::CanonicalizeQuery,
            "json_encode" => Self::JsonEncode,
            "form_encode" => Self::FormEncode,
            "sha1" => Self::Sha1,
            "sha256" => Self::Sha256,
            "sha384" => Self::Sha384,
            "sha512" => Self::Sha512,
            "hex" => Self::Hex,
            "hex_decode" => Self::HexDecode,
            "base64" => Self::Base64,
            "base64_decode" => Self::Base64Decode,
            "base64url" => Self::Base64Url,
            "base64url_decode" => Self::Base64UrlDecode,
            "lowercase" => Self::Lowercase,
            "uppercase" => Self::Uppercase,
            "trim" => Self::Trim,
            _ => return None,
        })
    }

    /// Returns the source-level name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Concat => "concat",
            Self::Join => "join",
            Self::Sort => "sort",
            Self::SortKeys => "sort_keys",
            Self::Utf8 => "utf8",
            Self::Ascii => "ascii",
            Self::UrlEncode => "url_encode",
            Self::UrlDecode => "url_decode",
            Self::PercentEncode => "percent_encode",
            Self::PercentDecode => "percent_decode",
            Self::CanonicalizeUrl => "canonicalize_url",
            Self::CanonicalizeQuery => "canonicalize_query",
            Self::JsonEncode => "json_encode",
            Self::FormEncode => "form_encode",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Hex => "hex",
            Self::HexDecode => "hex_decode",
            Self::Base64 => "base64",
            Self::Base64Decode => "base64_decode",
            Self::Base64Url => "base64url",
            Self::Base64UrlDecode => "base64url_decode",
            Self::Lowercase => "lowercase",
            Self::Uppercase => "uppercase",
            Self::Trim => "trim",
        }
    }

    /// Inclusive bounds on positional arguments.
    pub(super) const fn arity(self) -> (usize, usize) {
        match self {
            Self::Concat | Self::Join => (1, usize::MAX),
            _ => (1, 1),
        }
    }

    pub(super) const fn accepts_separator(self) -> bool {
        matches!(self, Self::Join)
    }

    pub(super) const fn requires_separator(self) -> bool {
        matches!(self, Self::Join)
    }

    pub(super) const fn accepts_order(self) -> bool {
        matches!(self, Self::Sort | Self::SortKeys)
    }
}

/// A parsed expression node.
#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    /// A double-quoted literal.
    Literal(String),
    /// A block reference.
    Path(Path),
    /// A built-in function call.
    Call(Call),
}

/// A function call with positional and keyword arguments.
#[derive(Clone, Debug, PartialEq)]
pub struct Call {
    /// Function being invoked.
    pub function: Function,
    /// Positional arguments, in order.
    pub arguments: Vec<Expr>,
    /// `separator:` keyword argument.
    pub separator: Option<String>,
    /// `order:` keyword argument.
    pub order: Option<SortOrder>,
}

impl fmt::Display for Expr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(value) => formatter.write_str(&quote(value)),
            Self::Path(path) => write!(formatter, "{path}"),
            Self::Call(call) => {
                write!(formatter, "{}(", call.function.name())?;
                let mut first = true;
                if let Some(separator) = &call.separator {
                    write!(formatter, "separator: {}", quote(separator))?;
                    first = false;
                }
                if let Some(order) = call.order {
                    if !first {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "order: {}", order.as_str())?;
                    first = false;
                }
                for argument in &call.arguments {
                    if !first {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "{argument}")?;
                    first = false;
                }
                formatter.write_str(")")
            }
        }
    }
}

fn is_bare_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

/// Quotes a string using the expression language's escape rules.
pub(super) fn quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}
