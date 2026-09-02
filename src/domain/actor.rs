//! Authenticated identities and IAM-derived authorization context.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{ActorId, DomainError, OrganizationId, SiliconId};

/// Category of an identity authenticated by Silicon IAM.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// Human account.
    Carbon,
    /// AI-agent account.
    Silicon,
}

/// Stable, non-secret reference to an authenticated identity.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ActorRef {
    /// Actor category, serialized as `type` in API responses.
    #[serde(rename = "type")]
    kind: ActorKind,
    /// IAM-issued opaque actor identifier.
    id: ActorId,
}

impl ActorRef {
    /// Constructs an actor reference from validated parts.
    #[must_use]
    pub const fn new(kind: ActorKind, id: ActorId) -> Self {
        Self { kind, id }
    }

    /// Validates an IAM actor identifier and constructs a reference.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the identifier is empty, too long, or
    /// contains characters that cannot occur in an IAM identifier.
    pub fn try_new(kind: ActorKind, id: impl Into<String>) -> Result<Self, DomainError> {
        Ok(Self::new(kind, ActorId::new(id)?))
    }

    /// Returns the actor category.
    #[must_use]
    pub const fn kind(&self) -> ActorKind {
        self.kind
    }

    /// Returns the public IAM identifier: a Carbon ID or a global Silicon ID.
    #[must_use]
    pub const fn id(&self) -> &ActorId {
        &self.id
    }
}

/// Organization role asserted by current IAM authorization.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRole {
    /// Organization member without administrative standing.
    #[default]
    Member,
    /// Organization administrator.
    Admin,
    /// Organization owner.
    Owner,
}

/// Authorization facts established online with IAM for one request.
///
/// `visible_silicons` holds the request's target Silicons that IAM confirmed
/// the actor may see; it is a per-request fact, never a cached directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationContext {
    organization_id: OrganizationId,
    actor: ActorRef,
    organization_role: OrganizationRole,
    visible_silicons: BTreeSet<SiliconId>,
}

impl AuthorizationContext {
    /// Constructs an IAM-derived authorization context.
    #[must_use]
    pub fn new(
        organization_id: OrganizationId,
        actor: ActorRef,
        organization_role: OrganizationRole,
        visible_silicons: impl IntoIterator<Item = SiliconId>,
    ) -> Self {
        Self {
            organization_id,
            actor,
            organization_role,
            visible_silicons: visible_silicons.into_iter().collect(),
        }
    }

    /// Returns the organization for which IAM issued this decision.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Returns the authenticated actor.
    #[must_use]
    pub const fn actor(&self) -> &ActorRef {
        &self.actor
    }

    /// Returns the effective actor's current organization role.
    #[must_use]
    pub const fn organization_role(&self) -> OrganizationRole {
        self.organization_role
    }

    /// Reports whether IAM says the effective actor can see a Silicon.
    #[must_use]
    pub fn has_silicon_visibility(&self, silicon_id: &SiliconId) -> bool {
        self.visible_silicons.contains(silicon_id)
    }

    /// Iterates over the target Silicons IAM confirmed visible for this request.
    #[must_use]
    pub fn visible_silicons(&self) -> impl ExactSizeIterator<Item = &SiliconId> {
        self.visible_silicons.iter()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn actor_reference_matches_the_api_shape() -> Result<(), Box<dyn std::error::Error>> {
        let actor = ActorRef::try_new(ActorKind::Silicon, "cos:tos")?;

        assert_eq!(
            serde_json::to_value(actor)?,
            json!({"type": "silicon", "id": "cos:tos"})
        );
        Ok(())
    }
}
