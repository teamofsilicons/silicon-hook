//! Authenticated identities and IAM-derived authorization context.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{ActorId, ApplicationId, DomainError, OrganizationId, SiliconId};

/// Category of an identity authenticated by Silicon IAM.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// Human account.
    Carbon,
    /// AI-agent account.
    Silicon,
    /// Application identity. OBO requests normally preserve the represented
    /// Carbon or Silicon as the effective actor instead.
    Application,
    /// Internal service identity.
    Service,
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

    /// Returns the opaque IAM identifier.
    #[must_use]
    pub const fn id(&self) -> &ActorId {
        &self.id
    }

    /// Tests a service identity without assigning authority to its identifier.
    #[must_use]
    pub fn is_service_named(&self, expected_id: &str) -> bool {
        self.kind == ActorKind::Service && self.id.as_str() == expected_id
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

/// Fine-grained capability asserted by IAM for the current organization.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// May list hooks for an organization Silicon.
    ListHooks,
    /// May read a hook for an organization Silicon.
    ReadHook,
    /// May create a hook for an organization Silicon.
    CreateHook,
    /// May soft-delete a hook for an organization Silicon.
    DeleteHook,
    /// May restore a hook for an organization Silicon.
    RestoreHook,
    /// May disable or enable ingress for an organization Silicon's hooks.
    SetHookEnabled,
    /// May rotate a signing secret for an organization Silicon.
    RotateSecret,
    /// May rotate the public endpoint of an organization Silicon's hook.
    RotateEndpoint,
    /// May change metadata or signing policy of an organization Silicon's hook.
    UpdateHook,
    /// May inspect retained event history for an organization Silicon.
    ReadEvents,
    /// May bypass the normal same-application ownership restriction for an OBO
    /// destructive action.
    AdministrativeOverride,
}

/// Authorization facts returned by an online IAM decision.
///
/// OBO calls retain the represented Carbon or Silicon in [`Self::actor`] and
/// record the calling application independently in
/// [`Self::acting_application`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationContext {
    organization_id: OrganizationId,
    actor: ActorRef,
    organization_role: OrganizationRole,
    capabilities: BTreeSet<Capability>,
    visible_silicons: BTreeSet<SiliconId>,
    acting_application: Option<ApplicationId>,
}

impl AuthorizationContext {
    /// Constructs an IAM-derived authorization context.
    #[must_use]
    pub fn new(
        organization_id: OrganizationId,
        actor: ActorRef,
        organization_role: OrganizationRole,
        capabilities: impl IntoIterator<Item = Capability>,
        visible_silicons: impl IntoIterator<Item = SiliconId>,
        acting_application: Option<ApplicationId>,
    ) -> Self {
        Self {
            organization_id,
            actor,
            organization_role,
            capabilities: capabilities.into_iter().collect(),
            visible_silicons: visible_silicons.into_iter().collect(),
            acting_application,
        }
    }

    /// Returns the organization for which IAM issued this decision.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Returns the effective actor, not the OBO caller.
    #[must_use]
    pub const fn actor(&self) -> &ActorRef {
        &self.actor
    }

    /// Returns the effective actor's current organization role.
    #[must_use]
    pub const fn organization_role(&self) -> OrganizationRole {
        self.organization_role
    }

    /// Returns the calling application for an OBO request.
    #[must_use]
    pub const fn acting_application(&self) -> Option<&ApplicationId> {
        self.acting_application.as_ref()
    }

    /// Reports whether IAM granted a capability in this organization.
    #[must_use]
    pub fn has_capability(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// Reports whether IAM says the effective actor can see a Silicon.
    #[must_use]
    pub fn has_silicon_visibility(&self, silicon_id: &SiliconId) -> bool {
        self.visible_silicons.contains(silicon_id)
    }

    /// Iterates over IAM-visible Silicon identifiers.
    #[must_use]
    pub fn visible_silicons(&self) -> impl ExactSizeIterator<Item = &SiliconId> {
        self.visible_silicons.iter()
    }

    /// Iterates over current IAM capabilities.
    #[must_use]
    pub fn capabilities(&self) -> impl ExactSizeIterator<Item = Capability> + '_ {
        self.capabilities.iter().copied()
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

    #[test]
    fn service_name_check_requires_both_kind_and_identifier()
    -> Result<(), Box<dyn std::error::Error>> {
        let service = ActorRef::try_new(ActorKind::Service, "silicon-iam")?;
        let carbon = ActorRef::try_new(ActorKind::Carbon, "silicon-iam")?;

        assert!(service.is_service_named("silicon-iam"));
        assert!(!service.is_service_named("silicon-dm"));
        assert!(!carbon.is_service_named("silicon-iam"));
        Ok(())
    }
}
