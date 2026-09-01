//! Resource-specific authorization policy over IAM-supplied facts.

use super::{
    ActorKind, ApplicationId, AuthorizationContext, Capability, OrganizationRole, SiliconId,
};

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
}

impl Action {
    const fn is_destructive(self) -> bool {
        matches!(
            self,
            Self::DeleteHook | Self::RestoreHook | Self::SetHookEnabled | Self::RotateSecret
        )
    }

    const fn required_capability(self) -> Capability {
        match self {
            Self::ListHooks => Capability::ListHooks,
            Self::ReadHook => Capability::ReadHook,
            Self::CreateHook => Capability::CreateHook,
            Self::ReadEvents => Capability::ReadEvents,
            Self::DeleteHook => Capability::DeleteHook,
            Self::RestoreHook => Capability::RestoreHook,
            Self::SetHookEnabled => Capability::SetHookEnabled,
            Self::RotateSecret => Capability::RotateSecret,
        }
    }
}

/// Outcome of an authorization policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// The requested action is allowed.
    Allowed,
    /// The effective actor cannot act on the target Silicon.
    TargetNotVisible,
    /// The action requires a Silicon owner or authorized organization admin.
    InsufficientPrivilege,
    /// An OBO application tried to mutate a hook created outside that app.
    ApplicationOwnershipMismatch,
}

impl AuthorizationDecision {
    /// Returns `true` only for [`Self::Allowed`].
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Evaluates actor-, resource-, and OBO-specific hook authorization.
///
/// `creator_application` is required for destructive actions on a persisted
/// hook. `None` means the hook was created without OBO delegation.
#[must_use]
pub fn authorize(
    context: &AuthorizationContext,
    action: Action,
    target_silicon: &SiliconId,
    creator_application: Option<&ApplicationId>,
) -> AuthorizationDecision {
    let owns_target = context.actor().kind() == ActorKind::Silicon
        && context.actor().id().as_str() == target_silicon.as_str();
    let is_owner = context.actor().kind() == ActorKind::Carbon
        && context.organization_role() == OrganizationRole::Owner;
    let is_authorized_admin = context.actor().kind() == ActorKind::Carbon
        && context.organization_role() == OrganizationRole::Admin
        && context.has_capability(action.required_capability());
    let can_see_target = owns_target
        || (context.actor().kind() == ActorKind::Carbon
            && (context.has_silicon_visibility(target_silicon) || is_owner || is_authorized_admin));

    if !can_see_target {
        return AuthorizationDecision::TargetNotVisible;
    }

    if !action.is_destructive() {
        return match context.actor().kind() {
            ActorKind::Carbon | ActorKind::Silicon => AuthorizationDecision::Allowed,
            ActorKind::Application | ActorKind::Service => {
                AuthorizationDecision::InsufficientPrivilege
            }
        };
    }

    if !owns_target && !is_owner && !is_authorized_admin {
        return AuthorizationDecision::InsufficientPrivilege;
    }

    let Some(acting_application) = context.acting_application() else {
        return AuthorizationDecision::Allowed;
    };

    let bypasses_application_ownership =
        is_owner || context.has_capability(Capability::AdministrativeOverride);
    if bypasses_application_ownership || creator_application == Some(acting_application) {
        AuthorizationDecision::Allowed
    } else {
        AuthorizationDecision::ApplicationOwnershipMismatch
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
        capabilities: &[Capability],
        visible: &[SiliconId],
        application: Option<ApplicationId>,
    ) -> Result<AuthorizationContext, crate::domain::DomainError> {
        Ok(AuthorizationContext::new(
            OrganizationId::new("org:test")?,
            ActorRef::try_new(kind, actor_id)?,
            role,
            capabilities.iter().copied(),
            visible.iter().cloned(),
            application,
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
            &[],
            std::slice::from_ref(&other),
            None,
        )?;

        assert_eq!(
            authorize(&principal, Action::DeleteHook, &own, None),
            AuthorizationDecision::Allowed
        );
        assert_eq!(
            authorize(&principal, Action::DeleteHook, &other, None),
            AuthorizationDecision::TargetNotVisible
        );
        Ok(())
    }

    #[test]
    fn visible_carbon_can_read_and_create_but_not_delete() -> Result<(), Box<dyn std::error::Error>>
    {
        let target = silicon("silicon:target")?;
        let principal = context(
            ActorKind::Carbon,
            "carbon:member",
            OrganizationRole::Member,
            &[],
            std::slice::from_ref(&target),
            None,
        )?;

        assert!(authorize(&principal, Action::ReadEvents, &target, None).is_allowed());
        assert!(authorize(&principal, Action::CreateHook, &target, None).is_allowed());
        assert_eq!(
            authorize(&principal, Action::DeleteHook, &target, None),
            AuthorizationDecision::InsufficientPrivilege
        );
        Ok(())
    }

    #[test]
    fn admin_needs_action_specific_capability() -> Result<(), Box<dyn std::error::Error>> {
        let target = silicon("silicon:target")?;
        let without = context(
            ActorKind::Carbon,
            "carbon:admin",
            OrganizationRole::Admin,
            &[],
            &[],
            None,
        )?;
        let with = context(
            ActorKind::Carbon,
            "carbon:admin",
            OrganizationRole::Admin,
            &[Capability::DeleteHook],
            &[],
            None,
        )?;

        assert_eq!(
            authorize(&without, Action::DeleteHook, &target, None),
            AuthorizationDecision::TargetNotVisible
        );
        assert!(authorize(&with, Action::DeleteHook, &target, None).is_allowed());
        assert_eq!(
            authorize(&with, Action::RotateSecret, &target, None),
            AuthorizationDecision::TargetNotVisible
        );
        Ok(())
    }

    #[test]
    fn enablement_is_destructive_and_requires_its_dedicated_capability()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = silicon("silicon:target")?;
        let silicon_owner = context(
            ActorKind::Silicon,
            target.as_str(),
            OrganizationRole::Member,
            &[],
            &[],
            None,
        )?;
        let visible_member = context(
            ActorKind::Carbon,
            "carbon:member",
            OrganizationRole::Member,
            &[],
            std::slice::from_ref(&target),
            None,
        )?;
        let wrong_capability = context(
            ActorKind::Carbon,
            "carbon:admin",
            OrganizationRole::Admin,
            &[Capability::DeleteHook],
            std::slice::from_ref(&target),
            None,
        )?;
        let authorized_admin = context(
            ActorKind::Carbon,
            "carbon:admin",
            OrganizationRole::Admin,
            &[Capability::SetHookEnabled],
            &[],
            None,
        )?;
        let owner = context(
            ActorKind::Carbon,
            "carbon:owner",
            OrganizationRole::Owner,
            &[],
            &[],
            None,
        )?;

        assert!(authorize(&silicon_owner, Action::SetHookEnabled, &target, None).is_allowed());
        assert_eq!(
            authorize(&visible_member, Action::SetHookEnabled, &target, None),
            AuthorizationDecision::InsufficientPrivilege
        );
        assert_eq!(
            authorize(&wrong_capability, Action::SetHookEnabled, &target, None),
            AuthorizationDecision::InsufficientPrivilege
        );
        assert!(authorize(&authorized_admin, Action::SetHookEnabled, &target, None).is_allowed());
        assert!(authorize(&owner, Action::SetHookEnabled, &target, None).is_allowed());
        Ok(())
    }

    #[test]
    fn owner_is_implicitly_authorized_without_capabilities()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = silicon("silicon:target")?;
        let owner = context(
            ActorKind::Carbon,
            "carbon:owner",
            OrganizationRole::Owner,
            &[],
            &[],
            None,
        )?;

        assert!(authorize(&owner, Action::DeleteHook, &target, None).is_allowed());
        assert!(authorize(&owner, Action::RotateSecret, &target, None).is_allowed());
        assert!(authorize(&owner, Action::ReadEvents, &target, None).is_allowed());
        Ok(())
    }

    #[test]
    fn obo_mutation_is_limited_to_the_creating_application()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = silicon("silicon:target")?;
        let caller = ApplicationId::new("app:caller")?;
        let other = ApplicationId::new("app:other")?;
        let principal = context(
            ActorKind::Silicon,
            target.as_str(),
            OrganizationRole::Member,
            &[],
            &[],
            Some(caller.clone()),
        )?;

        assert!(authorize(&principal, Action::RotateSecret, &target, Some(&caller)).is_allowed());
        assert_eq!(
            authorize(&principal, Action::RotateSecret, &target, Some(&other)),
            AuthorizationDecision::ApplicationOwnershipMismatch
        );
        assert_eq!(
            authorize(&principal, Action::RotateSecret, &target, None),
            AuthorizationDecision::ApplicationOwnershipMismatch
        );
        assert!(authorize(&principal, Action::SetHookEnabled, &target, Some(&caller)).is_allowed());
        assert_eq!(
            authorize(&principal, Action::SetHookEnabled, &target, Some(&other)),
            AuthorizationDecision::ApplicationOwnershipMismatch
        );
        assert_eq!(
            authorize(&principal, Action::SetHookEnabled, &target, None),
            AuthorizationDecision::ApplicationOwnershipMismatch
        );
        Ok(())
    }

    #[test]
    fn owner_and_explicit_override_bypass_obo_ownership() -> Result<(), Box<dyn std::error::Error>>
    {
        let target = silicon("silicon:target")?;
        let caller = ApplicationId::new("app:caller")?;
        let other = ApplicationId::new("app:other")?;
        let owner = context(
            ActorKind::Carbon,
            "carbon:owner",
            OrganizationRole::Owner,
            &[],
            &[],
            Some(caller.clone()),
        )?;
        let overridden = context(
            ActorKind::Silicon,
            target.as_str(),
            OrganizationRole::Member,
            &[Capability::AdministrativeOverride],
            &[],
            Some(caller),
        )?;

        assert!(authorize(&owner, Action::DeleteHook, &target, Some(&other)).is_allowed());
        assert!(authorize(&overridden, Action::DeleteHook, &target, Some(&other)).is_allowed());
        assert!(authorize(&owner, Action::SetHookEnabled, &target, Some(&other)).is_allowed());
        assert!(authorize(&overridden, Action::SetHookEnabled, &target, Some(&other)).is_allowed());
        Ok(())
    }
}
