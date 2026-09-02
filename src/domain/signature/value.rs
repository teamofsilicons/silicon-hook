//! Runtime values produced while evaluating a signature expression.

use std::{borrow::Cow, fmt};

use serde_json::{Map, Number, Value as Json};
use thiserror::Error;

/// A value flowing through a signature expression.
///
/// Text and bytes are kept distinct so that hashing and encoding functions
/// operate on exact bytes while string functions operate on Unicode text.
/// Objects preserve member order so canonicalization is explicit.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// An absent value, such as a header the provider did not send.
    Null,
    /// A JSON boolean.
    Bool(bool),
    /// A JSON number.
    Number(Number),
    /// Unicode text.
    Text(String),
    /// Exact bytes.
    Bytes(Vec<u8>),
    /// An ordered list.
    List(Vec<Value>),
    /// An ordered set of named members.
    Object(Vec<(String, Value)>),
}

/// A value could not be coerced to the shape a function requires.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ValueError {
    /// A required value was absent.
    #[error("value is missing")]
    Missing,
    /// A list or object was used where a scalar is required.
    #[error("expected a scalar value but found {actual}")]
    NotScalar {
        /// Type name of the offending value.
        actual: &'static str,
    },
    /// Bytes were used where text is required and they were not UTF-8.
    #[error("bytes are not valid UTF-8")]
    InvalidUtf8,
    /// A non-list value was used where a list is required.
    #[error("expected a list but found {actual}")]
    NotList {
        /// Type name of the offending value.
        actual: &'static str,
    },
    /// A non-object value was used where an object is required.
    #[error("expected an object but found {actual}")]
    NotObject {
        /// Type name of the offending value.
        actual: &'static str,
    },
}

impl Value {
    /// Converts parsed JSON into an expression value.
    #[must_use]
    pub fn from_json(json: Json) -> Self {
        match json {
            Json::Null => Self::Null,
            Json::Bool(value) => Self::Bool(value),
            Json::Number(value) => Self::Number(value),
            Json::String(value) => Self::Text(value),
            Json::Array(values) => Self::List(values.into_iter().map(Self::from_json).collect()),
            Json::Object(members) => Self::Object(
                members
                    .into_iter()
                    .map(|(key, value)| (key, Self::from_json(value)))
                    .collect(),
            ),
        }
    }

    /// Converts the value back into JSON.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::InvalidUtf8`] when the value contains bytes that
    /// are not UTF-8 text.
    pub fn to_json(&self) -> Result<Json, ValueError> {
        Ok(match self {
            Self::Null => Json::Null,
            Self::Bool(value) => Json::Bool(*value),
            Self::Number(value) => Json::Number(value.clone()),
            Self::Text(value) => Json::String(value.clone()),
            Self::Bytes(value) => Json::String(
                std::str::from_utf8(value)
                    .map_err(|_| ValueError::InvalidUtf8)?
                    .to_owned(),
            ),
            Self::List(values) => Json::Array(
                values
                    .iter()
                    .map(Self::to_json)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Self::Object(members) => {
                let mut map = Map::with_capacity(members.len());
                for (key, value) in members {
                    map.insert(key.clone(), value.to_json()?);
                }
                Json::Object(map)
            }
        })
    }

    /// Returns a stable name for diagnostics.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Number(_) => "number",
            Self::Text(_) => "text",
            Self::Bytes(_) => "bytes",
            Self::List(_) => "list",
            Self::Object(_) => "object",
        }
    }

    /// Reports whether the value is absent.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Reports whether the value is exact bytes rather than text.
    #[must_use]
    pub const fn is_bytes(&self) -> bool {
        matches!(self, Self::Bytes(_))
    }

    /// Consumes the value into the bytes a hash or MAC would consume.
    ///
    /// Text becomes its UTF-8 encoding; numbers and booleans become their
    /// JSON text.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] for an absent, list, or object value.
    pub fn into_bytes(self) -> Result<Vec<u8>, ValueError> {
        match self {
            Self::Null => Err(ValueError::Missing),
            Self::Bool(value) => Ok(value.to_string().into_bytes()),
            Self::Number(value) => Ok(value.to_string().into_bytes()),
            Self::Text(value) => Ok(value.into_bytes()),
            Self::Bytes(value) => Ok(value),
            Self::List(_) | Self::Object(_) => Err(ValueError::NotScalar {
                actual: self.type_name(),
            }),
        }
    }

    /// Consumes the value into text.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] for an absent, list, object, or non-UTF-8 value.
    pub fn into_text(self) -> Result<String, ValueError> {
        match self {
            Self::Null => Err(ValueError::Missing),
            Self::Bool(value) => Ok(value.to_string()),
            Self::Number(value) => Ok(value.to_string()),
            Self::Text(value) => Ok(value),
            Self::Bytes(value) => String::from_utf8(value).map_err(|_| ValueError::InvalidUtf8),
            Self::List(_) | Self::Object(_) => Err(ValueError::NotScalar {
                actual: self.type_name(),
            }),
        }
    }

    /// Consumes the value into its list members.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::NotList`] for any other value.
    pub fn into_list(self) -> Result<Vec<Self>, ValueError> {
        match self {
            Self::List(values) => Ok(values),
            other => Err(ValueError::NotList {
                actual: other.type_name(),
            }),
        }
    }

    /// Consumes the value into its object members.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::NotObject`] for any other value.
    pub fn into_object(self) -> Result<Vec<(String, Self)>, ValueError> {
        match self {
            Self::Object(members) => Ok(members),
            other => Err(ValueError::NotObject {
                actual: other.type_name(),
            }),
        }
    }

    /// Borrows the scalar bytes used to order values.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] for an absent, list, or object value.
    pub fn scalar_bytes(&self) -> Result<Cow<'_, [u8]>, ValueError> {
        match self {
            Self::Null => Err(ValueError::Missing),
            Self::Bool(value) => Ok(Cow::Owned(value.to_string().into_bytes())),
            Self::Number(value) => Ok(Cow::Owned(value.to_string().into_bytes())),
            Self::Text(value) => Ok(Cow::Borrowed(value.as_bytes())),
            Self::Bytes(value) => Ok(Cow::Borrowed(value.as_slice())),
            Self::List(_) | Self::Object(_) => Err(ValueError::NotScalar {
                actual: self.type_name(),
            }),
        }
    }

    /// Looks up a member of an object or an element of a list.
    ///
    /// A missing member yields [`Value::Null`]; indexing a scalar yields
    /// `None` so the caller can report the offending path.
    #[must_use]
    pub fn member(&self, key: &str) -> Option<Self> {
        match self {
            Self::Object(members) => Some(
                members
                    .iter()
                    .find(|(name, _)| name == key)
                    .map_or(Self::Null, |(_, value)| value.clone()),
            ),
            Self::Null => Some(Self::Null),
            _ => None,
        }
    }

    /// Looks up a list element by position.
    #[must_use]
    pub fn element(&self, index: usize) -> Option<Self> {
        match self {
            Self::List(values) => Some(values.get(index).cloned().unwrap_or(Self::Null)),
            Self::Null => Some(Self::Null),
            _ => None,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => formatter.write_str("null"),
            Self::Bool(value) => write!(formatter, "{value}"),
            Self::Number(value) => write!(formatter, "{value}"),
            Self::Text(value) => formatter.write_str(value),
            Self::Bytes(value) => write!(formatter, "<{} bytes>", value.len()),
            Self::List(values) => write!(formatter, "<list of {}>", values.len()),
            Self::Object(members) => write!(formatter, "<object of {}>", members.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Value, ValueError};

    #[test]
    fn json_round_trips_through_values() -> Result<(), ValueError> {
        let json = json!({"b": [1, true, null], "a": "x"});
        let value = Value::from_json(json.clone());

        assert_eq!(value.to_json()?, json);
        assert_eq!(
            value.member("b").and_then(|list| list.element(1)),
            Some(Value::Bool(true))
        );
        assert_eq!(value.member("missing"), Some(Value::Null));
        assert_eq!(Value::Text("scalar".to_owned()).member("x"), None);
        Ok(())
    }

    #[test]
    fn scalar_coercions_follow_json_text() -> Result<(), ValueError> {
        assert_eq!(Value::Bool(true).into_bytes()?, b"true");
        assert_eq!(
            Value::Number(serde_json::Number::from(42)).into_text()?,
            "42"
        );
        assert_eq!(Value::Bytes(b"abc".to_vec()).into_text()?, "abc");
        assert_eq!(
            Value::Bytes(vec![0xff]).into_text(),
            Err(ValueError::InvalidUtf8)
        );
        assert_eq!(Value::Null.into_bytes(), Err(ValueError::Missing));
        assert_eq!(
            Value::List(Vec::new()).into_bytes(),
            Err(ValueError::NotScalar { actual: "list" })
        );
        Ok(())
    }
}
