//! Account kinds and stored attribution.

use serde::{Deserialize, Serialize};

use super::{AccountUuid, ActorId, DomainError};

/// Category of a Silicon Accounts account.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// A Carbon (person) account.
    Carbon,
    /// A Silicon account.
    Silicon,
}

impl ActorKind {
    /// `carbon` or `silicon`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Carbon => "carbon",
            Self::Silicon => "silicon",
        }
    }
}

/// Who created or changed something, as stored.
///
/// `id` is the stored attribution key: the account uuid for anything recorded
/// since Silicon Accounts, the IAM-era public id for older records. `uuid` is
/// the Silicon Accounts uuid when known (always for new records, after
/// `link-identities` for mapped old ones).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ActorRef {
    kind: ActorKind,
    id: ActorId,
    uuid: Option<AccountUuid>,
}

impl ActorRef {
    /// Attribution for an Accounts-era actor: the uuid is also the stored key.
    #[must_use]
    pub fn account(kind: ActorKind, uuid: AccountUuid) -> Self {
        Self {
            kind,
            // A valid uuid is always a valid stored key.
            id: ActorId::from_account_uuid(&uuid),
            uuid: Some(uuid),
        }
    }

    /// Rehydrates stored attribution.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the stored key is not a valid identifier.
    pub fn stored(
        kind: ActorKind,
        id: impl Into<String>,
        uuid: Option<AccountUuid>,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            kind,
            id: ActorId::new(id)?,
            uuid,
        })
    }

    /// Returns the account category.
    #[must_use]
    pub const fn kind(&self) -> ActorKind {
        self.kind
    }

    /// Returns the stored attribution key.
    #[must_use]
    pub const fn id(&self) -> &ActorId {
        &self.id
    }

    /// Returns the Silicon Accounts uuid, when known.
    #[must_use]
    pub const fn uuid(&self) -> Option<&AccountUuid> {
        self.uuid.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_era_attribution_keys_on_the_uuid() -> Result<(), Box<dyn std::error::Error>> {
        let actor = ActorRef::account(ActorKind::Silicon, AccountUuid::new("zQo")?);
        assert_eq!(actor.id().as_str(), "zQo");
        assert_eq!(actor.uuid().map(AccountUuid::as_str), Some("zQo"));
        let legacy = ActorRef::stored(ActorKind::Carbon, "c:alice", None)?;
        assert_eq!(legacy.id().as_str(), "c:alice");
        assert!(legacy.uuid().is_none());
        Ok(())
    }
}
