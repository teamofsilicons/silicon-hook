//! Strongly typed public identifiers.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use uuid::Uuid;

use super::DomainError;

/// Maximum encoded size of an organization identifier.
pub const MAX_ORGANIZATION_ID_BYTES: usize = 100;
/// Maximum encoded size of other external opaque IAM identifiers.
pub const MAX_EXTERNAL_ID_BYTES: usize = 255;

fn validate_external_id(value: &str, field: &'static str, max: usize) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::Empty { field });
    }
    if value.len() > max {
        return Err(DomainError::TooLong { field, max });
    }
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(DomainError::InvalidFormat {
            field,
            reason: "must contain only visible ASCII characters",
        });
    }
    Ok(())
}

macro_rules! external_id {
    ($(#[$meta:meta])* $name:ident, $field:literal, $max:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Validates and constructs an opaque identifier.
            ///
            /// # Errors
            ///
            /// Returns [`DomainError`] when the identifier is empty, exceeds
            /// its contract length, or contains non-visible ASCII characters.
            pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
                let value = value.into();
                validate_external_id(&value, $field, $max)?;
                Ok(Self(value))
            }

            /// Returns the identifier without interpreting its contents.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the wrapper and returns the opaque identifier.
            #[must_use]
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }
    };
}

external_id!(
    /// Organization identifier issued by Silicon IAM.
    OrganizationId,
    "org_id",
    MAX_ORGANIZATION_ID_BYTES
);
external_id!(
    /// Global Silicon identifier issued by Silicon IAM.
    SiliconId,
    "silicon_id",
    MAX_EXTERNAL_ID_BYTES
);
external_id!(
    /// Opaque identifier for an authenticated actor.
    ActorId,
    "actor_id",
    MAX_EXTERNAL_ID_BYTES
);
external_id!(
    /// Opaque identifier for an IAM application acting on behalf of an actor.
    ApplicationId,
    "application_id",
    MAX_EXTERNAL_ID_BYTES
);

macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Allocates a time-ordered `UUIDv7` identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Wraps an already validated UUID, primarily for persistence rehydration.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

uuid_id!(
    /// Public identifier of a configured webhook.
    HookId
);
uuid_id!(
    /// Stable public identifier of an accepted event.
    EventId
);

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    #[test]
    fn external_identifiers_round_trip_through_json() -> Result<(), Box<dyn std::error::Error>> {
        let id = SiliconId::new("cos:tos")?;
        let encoded = serde_json::to_value(&id)?;
        let decoded: SiliconId = serde_json::from_value(encoded.clone())?;

        assert_eq!(encoded, json!("cos:tos"));
        assert_eq!(decoded, id);
        Ok(())
    }

    #[test]
    fn external_identifiers_reject_control_and_whitespace() {
        assert!(OrganizationId::new("").is_err());
        assert!(OrganizationId::new(" org").is_err());
        assert!(OrganizationId::new("org\nother").is_err());
    }

    #[test]
    fn organization_identifier_enforces_its_contract_boundary() {
        assert!(OrganizationId::new("o".repeat(100)).is_ok());
        assert!(OrganizationId::new("o".repeat(101)).is_err());
        assert!(SiliconId::new("s".repeat(101)).is_ok());
    }

    #[test]
    fn generated_internal_identifiers_are_uuid_v7() {
        assert_eq!(HookId::new().as_uuid().get_version_num(), 7);
        assert_eq!(EventId::new().as_uuid().get_version_num(), 7);
    }

    proptest! {
        #[test]
        fn visible_ascii_external_ids_round_trip(value in "[!-~]{1,255}") {
            let id = ActorId::new(value.clone());
            prop_assert!(id.is_ok());
            if let Ok(id) = id {
                prop_assert_eq!(id.as_str(), value);
            }
        }

        #[test]
        fn overlong_external_ids_are_rejected(value in "[A-Za-z0-9]{256,400}") {
            prop_assert!(ApplicationId::new(value).is_err());
        }
    }
}
