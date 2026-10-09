//! Silicon Accounts identities as Hook sees them.
//!
//! An account is a Carbon (`c:handle`) or a Silicon (`si:handle`). Its `uuid`
//! (the access token's `sub`) is permanent, short and case-sensitive, such as
//! `zQo`; it is what Hook stores. The public id can change and is only shown.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use super::{ActorKind, DomainError};

/// Maximum length Hook accepts for an Accounts uuid.
pub const MAX_ACCOUNT_UUID_LENGTH: usize = 64;

/// Permanent Silicon Accounts identifier: ASCII letters and digits, compared exactly.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccountUuid(String);

impl AccountUuid {
    /// Validates an Accounts uuid.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] unless the value is 1 to 64 ASCII letters or digits.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DomainError::Empty {
                field: "account_uuid",
            });
        }
        if value.len() > MAX_ACCOUNT_UUID_LENGTH {
            return Err(DomainError::TooLong {
                field: "account_uuid",
                max: MAX_ACCOUNT_UUID_LENGTH,
            });
        }
        if !value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(DomainError::InvalidFormat {
                field: "account_uuid",
                reason: "must contain only ASCII letters and digits",
            });
        }
        Ok(Self(value))
    }

    /// Reports whether a value has the shape of an Accounts uuid (and not of a
    /// public id, which always contains a colon).
    #[must_use]
    pub fn looks_like(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= MAX_ACCOUNT_UUID_LENGTH
            && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
    }

    /// Returns the uuid exactly as issued.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountUuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for AccountUuid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AccountUuid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// A public account id: `c:handle` for a Carbon or `si:handle` for a Silicon.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicId(String);

impl PublicId {
    /// Validates a public id.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] unless the value is `c:` or `si:` followed by a
    /// non-empty handle of visible ASCII, at most 255 bytes in total.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let handle = value
            .strip_prefix("si:")
            .or_else(|| value.strip_prefix("c:"))
            .ok_or(DomainError::InvalidFormat {
                field: "id",
                reason: "must start with c: (a Carbon) or si: (a Silicon)",
            })?;
        if handle.is_empty() || value.len() > 255 {
            return Err(DomainError::InvalidFormat {
                field: "id",
                reason: "must have a handle of 1 to 252 characters after the prefix",
            });
        }
        if !handle.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(DomainError::InvalidFormat {
                field: "id",
                reason: "must contain only visible ASCII characters",
            });
        }
        Ok(Self(value))
    }

    /// The account kind the prefix names.
    #[must_use]
    pub fn kind(&self) -> ActorKind {
        if self.0.starts_with("si:") {
            ActorKind::Silicon
        } else {
            ActorKind::Carbon
        }
    }

    /// Returns the id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PublicId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for PublicId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// An authenticated account, established from a verified access token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Actor {
    uuid: AccountUuid,
    kind: ActorKind,
    id: Option<PublicId>,
    scope: Vec<String>,
    token_family: Option<String>,
}

impl Actor {
    /// Constructs an authenticated actor.
    #[must_use]
    pub const fn new(
        uuid: AccountUuid,
        kind: ActorKind,
        id: Option<PublicId>,
        scope: Vec<String>,
        token_family: Option<String>,
    ) -> Self {
        Self {
            uuid,
            kind,
            id,
            scope,
            token_family,
        }
    }

    /// The account's permanent uuid.
    #[must_use]
    pub const fn uuid(&self) -> &AccountUuid {
        &self.uuid
    }

    /// Carbon or Silicon.
    #[must_use]
    pub const fn kind(&self) -> ActorKind {
        self.kind
    }

    /// The account's public id when the token was issued (it may have changed since).
    #[must_use]
    pub const fn id(&self) -> Option<&PublicId> {
        self.id.as_ref()
    }

    /// The token's scopes.
    #[must_use]
    pub fn scope(&self) -> &[String] {
        &self.scope
    }

    /// The token family (one sign-in), when the token names it.
    #[must_use]
    pub fn token_family(&self) -> Option<&str> {
        self.token_family.as_deref()
    }

    /// How the actor is shown: the public id, or the uuid when no id is known.
    #[must_use]
    pub fn display(&self) -> &str {
        self.id
            .as_ref()
            .map_or_else(|| self.uuid.as_str(), PublicId::as_str)
    }
}

/// A Silicon account resolved for one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiliconRef {
    uuid: AccountUuid,
    id: Option<PublicId>,
}

impl SiliconRef {
    /// Constructs a Silicon reference.
    #[must_use]
    pub const fn new(uuid: AccountUuid, id: Option<PublicId>) -> Self {
        Self { uuid, id }
    }

    /// The Silicon's permanent uuid.
    #[must_use]
    pub const fn uuid(&self) -> &AccountUuid {
        &self.uuid
    }

    /// The Silicon's current public id, when known.
    #[must_use]
    pub const fn id(&self) -> Option<&PublicId> {
        self.id.as_ref()
    }

    /// How the Silicon is shown: its current id, or its uuid when unknown.
    #[must_use]
    pub fn display(&self) -> &str {
        self.id
            .as_ref()
            .map_or_else(|| self.uuid.as_str(), PublicId::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_are_case_sensitive_alphanumerics() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(AccountUuid::new("zQo")?.as_str(), "zQo");
        assert_ne!(AccountUuid::new("a8K")?, AccountUuid::new("A8k")?);
        assert!(AccountUuid::new("").is_err());
        assert!(AccountUuid::new("si:cos").is_err());
        assert!(AccountUuid::new("x".repeat(65)).is_err());
        assert!(AccountUuid::looks_like("8HV"));
        assert!(!AccountUuid::looks_like("si:cos"));
        Ok(())
    }

    #[test]
    fn public_ids_carry_their_kind() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(PublicId::new("si:cos")?.kind(), ActorKind::Silicon);
        assert_eq!(PublicId::new("c:saket")?.kind(), ActorKind::Carbon);
        assert!(PublicId::new("cos").is_err());
        assert!(PublicId::new("si:").is_err());
        assert!(PublicId::new("si:a b").is_err());
        Ok(())
    }
}
