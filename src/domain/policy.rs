//! Resource-specific authorization policy over IAM-supplied facts.

use super::{ActorKind, AuthorizationContext, OrganizationRole, SiliconId};

/// Hook action being authorized.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Action {
    /// List hooks for a Silicon.
    ListHooks,
    /// Read one hook.
    ReadHook,
    /// Create a hook.
    CreateHook,
    /// Read event history.
    ReadEvents,
    /// Soft-delete a hook.
    DeleteHook,
    /// Restore a hook.
    RestoreHook,
    /// Disable or enable ingress for one or more hooks.
    SetHookEnabled,
    /// Replace a hook signing secret.
    RotateSecret,
    /// Replace a hook's public endpoint key.
    RotateEndpoint,
    /// Change hook metadata or signing policy.
    UpdateHook,
    /// Register a Hook endpoint as the Silicon's IAM webhook.
    ConnectIamHook,
    /// Acknowledge or pull ordered deliveries.
    ConsumeDeliveries,
}

impl Action {
    /// Destructive actions change a Silicon's hooks or credentials and are
    /// reserved for the Silicon itself, organization owners, and organization
    /// administrators, as UNDERSTANDING.md prescribes for deletion.
    const fn is_destructive(self) -> bool {
        matches!(
            self,
            Self::DeleteHook
                | Self::RestoreHook
                | Self::SetHookEnabled
                | Self::RotateSecret
                | Self::RotateEndpoint
                | Self::UpdateHook
                | Self::ConnectIamHook
        )
    }
}

/// Outcome of an authorization policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// The requested action is allowed.
    Allowed,
    /// The actor cannot act on the target Silicon.
    TargetNotVisible,
    /// The action requires the Silicon itself or an organization owner or admin.
    InsufficientPrivilege,
}

impl AuthorizationDecision {
    /// Returns `true` only for [`Self::Allowed`].
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Evaluates actor- and resource-specific hook authorization.
///
/// A Silicon acts only on itself. A Carbon sees the Silicons IAM confirmed
/// visible for the request. Organization managers may mutate those Silicons,
/// but a role alone never proves that a target Silicon exists.
#[must_use]
pub fn authorize(
    context: &AuthorizationContext,
    action: Action,
    target_silicon: &SiliconId,
) -> AuthorizationDecision {
    let is_carbon = context.actor().kind() == ActorKind::Carbon;
    let owns_target = context.actor().kind() == ActorKind::Silicon
        && context.actor().id().as_str() == target_silicon.as_str();
    let is_organization_manager = is_carbon
        && matches!(
            context.organization_role(),
            OrganizationRole::Owner | OrganizationRole::Admin
        );
    let can_see_target =
        owns_target || (is_carbon && context.has_silicon_visibility(target_silicon));

    if !can_see_target {
        return AuthorizationDecision::TargetNotVisible;
    }
    if !action.is_destructive() || owns_target || is_organization_manager {
        AuthorizationDecision::Allowed
    } else {
        AuthorizationDecision::InsufficientPrivilege
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ActorRef, OrganizationId};

    fn silicon(value: &str) -> Result<SiliconId, crate::domain::DomainError> {
        SiliconId::new(value)
    }

    fn context(
        kind: ActorKind,
        actor_id: &str,
        role: OrganizationRole,
        visible: &[SiliconId],
    ) -> Result<AuthorizationContext, crate::domain::DomainError> {
        Ok(AuthorizationContext::new(
            OrganizationId::new("org:test")?,
            ActorRef::try_new(kind, actor_id)?,
            role,
            visible.iter().cloned(),
        ))
    }

    #[test]
    fn silicon_can_manage_only_itself() -> Result<(), Box<dyn std::error::Error>> {
        let own = silicon("silicon:own")?;
        let other = silicon("silicon:other")?;
        let principal = context(
            ActorKind::Silicon,
            own.as_str(),
            OrganizationRole::Member,
            std::slice::from_ref(&other),
        )?;

        assert_eq!(
            authorize(&principal, Action::DeleteHook, &own),
            AuthorizationDecision::Allowed
        );
        assert_eq!(
            authorize(&principal, Action::ConnectIamHook, &own),
            AuthorizationDecision::Allowed
        );
        assert_eq!(
            authorize(&principal, Action::DeleteHook, &other),
            AuthorizationDecision::TargetNotVisible
        );
        assert_eq!(
            authorize(&principal, Action::ReadEvents, &other),
            AuthorizationDecision::TargetNotVisible
        );
        Ok(())
    }

    #[test]
    fn visible_carbon_can_read_and_create_but_not_mutate() -> Result<(), Box<dyn std::error::Error>>
    {
        let target = silicon("silicon:target")?;
        let hidden = silicon("silicon:hidden")?;
        let principal = context(
            ActorKind::Carbon,
            "carbon-member",
            OrganizationRole::Member,
            std::slice::from_ref(&target),
        )?;

        assert!(authorize(&principal, Action::ReadEvents, &target).is_allowed());
        assert!(authorize(&principal, Action::CreateHook, &target).is_allowed());
        assert!(authorize(&principal, Action::ConsumeDeliveries, &target).is_allowed());
        for action in [
            Action::DeleteHook,
            Action::SetHookEnabled,
            Action::RotateSecret,
            Action::RotateEndpoint,
            Action::UpdateHook,
            Action::RestoreHook,
            Action::ConnectIamHook,
        ] {
            assert_eq!(
                authorize(&principal, action, &target),
                AuthorizationDecision::InsufficientPrivilege
            );
        }
        assert_eq!(
            authorize(&principal, Action::ListHooks, &hidden),
            AuthorizationDecision::TargetNotVisible
        );
        Ok(())
    }

    #[test]
    fn owners_and_admins_need_an_authoritative_target_fact()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = silicon("silicon:target")?;
        for role in [OrganizationRole::Owner, OrganizationRole::Admin] {
            let unconfirmed = context(ActorKind::Carbon, "carbon-manager", role, &[])?;
            assert_eq!(
                authorize(&unconfirmed, Action::CreateHook, &target),
                AuthorizationDecision::TargetNotVisible
            );
            let manager = context(
                ActorKind::Carbon,
                "carbon-manager",
                role,
                std::slice::from_ref(&target),
            )?;
            assert!(authorize(&manager, Action::DeleteHook, &target).is_allowed());
            assert!(authorize(&manager, Action::RotateSecret, &target).is_allowed());
            assert!(authorize(&manager, Action::ReadEvents, &target).is_allowed());
            assert!(authorize(&manager, Action::ConnectIamHook, &target).is_allowed());
        }
        Ok(())
    }
}
