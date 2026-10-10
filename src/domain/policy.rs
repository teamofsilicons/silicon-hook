//! Who may do what with one Silicon's hooks.
//!
//! Hooks belong to the Silicon they were made for. The Silicon and its
//! custodian have full control; anyone else needs an explicit grant from one
//! of them (`view` or `manage`). A custodian acts as itself, never as the
//! Silicon: what it does is attributed to the custodian.

use serde::{Deserialize, Serialize};

use super::{Actor, ActorKind, SiliconRef};

/// Level of an explicit grant on a Silicon's hooks.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantLevel {
    /// Read hooks, events, blocked requests and delivery status.
    View,
    /// Everything `view` allows, plus creating and changing hooks.
    Manage,
}

impl GrantLevel {
    /// `view` or `manage`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Manage => "manage",
        }
    }

    /// Parses `view` or `manage`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "view" => Some(Self::View),
            "manage" => Some(Self::Manage),
            _ => None,
        }
    }
}

/// Why the actor may act on the Silicon's hooks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Access {
    /// The actor is the Silicon.
    Own,
    /// The actor is the Silicon's custodian.
    Custodian,
    /// The Silicon or its custodian granted the actor access.
    Grant(GrantLevel),
}

impl Access {
    /// `self`, `custodian`, `manage` or `view`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Own => "self",
            Self::Custodian => "custodian",
            Self::Grant(level) => level.as_str(),
        }
    }
}

/// Hook action being authorized.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Action {
    /// List hooks.
    ListHooks,
    /// Read one hook.
    ReadHook,
    /// Read verified or blocked request history and publication status.
    ReadEvents,
    /// Create a hook.
    CreateHook,
    /// Change hook metadata, signing policy or secret.
    UpdateHook,
    /// Disable or enable ingress.
    SetHookEnabled,
    /// Soft-delete a hook.
    DeleteHook,
    /// Restore a soft-deleted hook.
    RestoreHook,
    /// Replace a signing secret.
    RotateSecret,
    /// Replace an endpoint key.
    RotateEndpoint,
    /// Prepare the hook that receives the Silicon's own Silicon Accounts events.
    ConnectAccountsHook,
    /// Grant or revoke access, and read who has access.
    ManageAccess,
    /// Change who may share with the Silicon.
    ManageAllowList,
    /// Receive copies of the Silicon's future events (Carbons only).
    Observe,
}

/// Outcome of an authorization policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// The action is allowed.
    Allowed,
    /// The actor's access does not cover the action; the reason explains what would.
    Forbidden(&'static str),
}

impl AuthorizationDecision {
    /// Returns `true` only for [`Self::Allowed`].
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// An authenticated actor's established access to one Silicon's hooks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationContext {
    actor: Actor,
    silicon: SiliconRef,
    access: Access,
}

impl AuthorizationContext {
    /// Constructs a context after the actor's access was established.
    #[must_use]
    pub const fn new(actor: Actor, silicon: SiliconRef, access: Access) -> Self {
        Self {
            actor,
            silicon,
            access,
        }
    }

    /// The authenticated actor.
    #[must_use]
    pub const fn actor(&self) -> &Actor {
        &self.actor
    }

    /// The Silicon whose hooks are being accessed.
    #[must_use]
    pub const fn silicon(&self) -> &SiliconRef {
        &self.silicon
    }

    /// How the actor has access.
    #[must_use]
    pub const fn access(&self) -> Access {
        self.access
    }
}

/// Evaluates whether the actor's access covers an action.
#[must_use]
pub fn authorize(context: &AuthorizationContext, action: Action) -> AuthorizationDecision {
    let access = context.access();
    let full = matches!(access, Access::Own | Access::Custodian);
    let manage = full || access == Access::Grant(GrantLevel::Manage);
    match action {
        Action::ListHooks | Action::ReadHook | Action::ReadEvents => AuthorizationDecision::Allowed,
        Action::CreateHook
        | Action::UpdateHook
        | Action::SetHookEnabled
        | Action::DeleteHook
        | Action::RestoreHook
        | Action::RotateSecret
        | Action::RotateEndpoint => {
            if manage {
                AuthorizationDecision::Allowed
            } else {
                AuthorizationDecision::Forbidden(
                    "changing hooks needs the Silicon itself, its custodian, or a manage grant; you have view access",
                )
            }
        }
        Action::ConnectAccountsHook | Action::ManageAccess | Action::ManageAllowList => {
            if full {
                AuthorizationDecision::Allowed
            } else {
                AuthorizationDecision::Forbidden(
                    "only the Silicon itself or its custodian can do this",
                )
            }
        }
        Action::Observe => {
            if context.actor().kind() != ActorKind::Carbon {
                AuthorizationDecision::Forbidden(
                    "only Carbons observe a Silicon's events; the Silicon itself receives them directly",
                )
            } else if access == Access::Own {
                AuthorizationDecision::Forbidden("a Silicon receives its own events directly")
            } else {
                AuthorizationDecision::Allowed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AccountUuid, PublicId};

    fn context(
        kind: ActorKind,
        access: Access,
    ) -> Result<AuthorizationContext, Box<dyn std::error::Error>> {
        let id = match kind {
            ActorKind::Carbon => "c:ada",
            ActorKind::Silicon => "si:scout",
        };
        Ok(AuthorizationContext::new(
            Actor::new(
                AccountUuid::new("b97")?,
                kind,
                Some(PublicId::new(id)?),
                Vec::new(),
                None,
            ),
            SiliconRef::new(AccountUuid::new("8HV")?, Some(PublicId::new("si:cos")?)),
            access,
        ))
    }

    const WRITES: [Action; 7] = [
        Action::CreateHook,
        Action::UpdateHook,
        Action::SetHookEnabled,
        Action::DeleteHook,
        Action::RestoreHook,
        Action::RotateSecret,
        Action::RotateEndpoint,
    ];
    const OWNER_ONLY: [Action; 3] = [
        Action::ConnectAccountsHook,
        Action::ManageAccess,
        Action::ManageAllowList,
    ];

    #[test]
    fn the_silicon_and_its_custodian_have_full_control() -> Result<(), Box<dyn std::error::Error>> {
        for (kind, access) in [
            (ActorKind::Silicon, Access::Own),
            (ActorKind::Carbon, Access::Custodian),
        ] {
            let context = context(kind, access)?;
            for action in WRITES.iter().chain(OWNER_ONLY.iter()) {
                assert!(authorize(&context, *action).is_allowed(), "{action:?}");
            }
        }
        Ok(())
    }

    #[test]
    fn grants_cover_exactly_their_level() -> Result<(), Box<dyn std::error::Error>> {
        let viewer = context(ActorKind::Carbon, Access::Grant(GrantLevel::View))?;
        let manager = context(ActorKind::Silicon, Access::Grant(GrantLevel::Manage))?;
        for action in [Action::ListHooks, Action::ReadHook, Action::ReadEvents] {
            assert!(authorize(&viewer, action).is_allowed());
            assert!(authorize(&manager, action).is_allowed());
        }
        for action in WRITES {
            assert!(!authorize(&viewer, action).is_allowed(), "{action:?}");
            assert!(authorize(&manager, action).is_allowed(), "{action:?}");
        }
        for action in OWNER_ONLY {
            assert!(!authorize(&viewer, action).is_allowed());
            assert!(!authorize(&manager, action).is_allowed());
        }
        Ok(())
    }

    #[test]
    fn only_carbons_other_than_the_silicon_observe() -> Result<(), Box<dyn std::error::Error>> {
        assert!(
            authorize(
                &context(ActorKind::Carbon, Access::Custodian)?,
                Action::Observe
            )
            .is_allowed()
        );
        assert!(
            authorize(
                &context(ActorKind::Carbon, Access::Grant(GrantLevel::View))?,
                Action::Observe
            )
            .is_allowed()
        );
        assert!(
            !authorize(&context(ActorKind::Silicon, Access::Own)?, Action::Observe).is_allowed()
        );
        assert!(
            !authorize(
                &context(ActorKind::Silicon, Access::Grant(GrantLevel::Manage))?,
                Action::Observe
            )
            .is_allowed()
        );
        Ok(())
    }
}
