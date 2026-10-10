//! Explicit access to a Silicon's hooks, and the allow-list that keeps
//! Silicons from being reached by accounts outside their circle unasked.

use super::{
    ApplicationError, HookApplication,
    access::AccessSummary,
    service::{authorize_action, map_store_error},
};
use crate::{
    domain::{Access, Action, Actor, ActorKind, AuthorizationContext, GrantLevel, PublicId},
    infrastructure::postgres::{AccountRecord, AllowRecord, GrantRecord},
};

fn refused(status: u16, code: &'static str, message: impl Into<String>) -> ApplicationError {
    ApplicationError::refused(status, code, message)
}

fn shown(record: &AccountRecord) -> String {
    record
        .public_id
        .as_ref()
        .map_or_else(|| record.uuid.to_string(), PublicId::to_string)
}

impl HookApplication {
    /// Who has access to the Silicon's hooks. The Silicon and its custodian see
    /// every grant; a grantee sees only its own.
    ///
    /// # Errors
    ///
    /// Returns a persistence or Silicon Accounts failure.
    pub async fn access_summary(
        &self,
        context: &AuthorizationContext,
    ) -> Result<AccessSummary, ApplicationError> {
        let silicon_uuid = context.silicon().uuid();
        let silicon = self
            .store
            .account(silicon_uuid)
            .await
            .map_err(map_store_error)?
            .ok_or(ApplicationError::NotFound)?;
        let custodian_uuid = self.current_custodian(&silicon).await?;
        let mut grants = self
            .store
            .grants_on(silicon_uuid)
            .await
            .map_err(map_store_error)?;
        if !matches!(context.access(), Access::Own | Access::Custodian) {
            grants.retain(|grant| &grant.grantee_uuid == context.actor().uuid());
        }
        let mut referenced = grants
            .iter()
            .flat_map(|grant| [grant.grantee_uuid.clone(), grant.granted_by_uuid.clone()])
            .collect::<Vec<_>>();
        referenced.extend(custodian_uuid.clone());
        referenced.sort();
        referenced.dedup();
        let accounts = self
            .store
            .accounts(&referenced)
            .await
            .map_err(map_store_error)?;
        let custodian = custodian_uuid
            .and_then(|uuid| accounts.iter().find(|record| record.uuid == uuid).cloned());
        Ok(AccessSummary {
            custodian,
            grants,
            accounts,
        })
    }

    /// Grants `grantee` (a `c:`/`si:` id or uuid) access to the Silicon's hooks,
    /// or changes its level.
    ///
    /// A Silicon outside the owner's circle (a different custodian) only
    /// receives a grant when its allow-list names the owning Silicon or the
    /// owner's custodian.
    ///
    /// # Errors
    ///
    /// Returns `403` unless the actor is the Silicon or its custodian, `409`
    /// for a grantee that already has full access, `403 silicon_not_reachable`
    /// for a Silicon that has not allowed the owner, and resolution failures.
    pub async fn grant_access(
        &self,
        context: &AuthorizationContext,
        grantee: &str,
        level: GrantLevel,
        request_id: Option<&str>,
    ) -> Result<(GrantRecord, AccountRecord), ApplicationError> {
        authorize_action(context, Action::ManageAccess)?;
        let owner = self
            .store
            .account(context.silicon().uuid())
            .await
            .map_err(map_store_error)?
            .ok_or(ApplicationError::NotFound)?;
        let grantee = self.resolve_account(grantee).await?;
        if grantee.uuid == owner.uuid {
            return Err(refused(
                409,
                "already_has_access",
                format!(
                    "{} is the Silicon itself and always has full access to its hooks.",
                    shown(&grantee)
                ),
            ));
        }
        let owner_custodian = self.current_custodian(&owner).await?;
        if owner_custodian.as_ref() == Some(&grantee.uuid) {
            return Err(refused(
                409,
                "already_has_access",
                format!(
                    "{} is {}'s custodian and already has full access to its hooks.",
                    shown(&grantee),
                    shown(&owner)
                ),
            ));
        }
        if grantee.kind == ActorKind::Silicon {
            let grantee_custodian = self.current_custodian(&grantee).await?;
            let same_circle = owner_custodian.is_some() && owner_custodian == grantee_custodian;
            let mut allowed_sharers = vec![&owner.uuid];
            allowed_sharers.extend(owner_custodian.as_ref());
            if !same_circle
                && !self
                    .store
                    .allows_any(&grantee.uuid, &allowed_sharers)
                    .await
                    .map_err(map_store_error)?
            {
                return Err(refused(
                    403,
                    "silicon_not_reachable",
                    format!(
                        "{grantee_id} is looked after by a different custodian, and a Silicon only receives access from outside its own custodian's Silicons when it has allowed the sharer first. Ask {grantee_id} or its custodian to add {owner_id} (or its custodian) to {grantee_id}'s allow-list, then grant again.",
                        grantee_id = shown(&grantee),
                        owner_id = shown(&owner)
                    ),
                ));
            }
        }
        let grant = self
            .store
            .put_grant(
                &owner.uuid,
                &grantee.uuid,
                level,
                context.actor(),
                request_id,
            )
            .await
            .map_err(map_store_error)?;
        Ok((grant, grantee))
    }

    /// Removes a grant. The Silicon and its custodian can remove any grant; a
    /// grantee can always remove its own (leave).
    ///
    /// # Errors
    ///
    /// Returns `403` for anyone else, `404` when no such grant exists, and
    /// resolution failures.
    pub async fn revoke_access(
        &self,
        actor: &Actor,
        silicon_segment: &str,
        grantee: &str,
        request_id: Option<&str>,
    ) -> Result<(), ApplicationError> {
        let context = self.authorize_silicon(actor, silicon_segment).await?;
        let grantee = if grantee == "me" {
            actor.uuid().clone()
        } else {
            self.resolve_account(grantee).await?.uuid
        };
        if &grantee != actor.uuid() {
            authorize_action(&context, Action::ManageAccess)?;
        }
        let owner = self
            .store
            .account(context.silicon().uuid())
            .await
            .map_err(map_store_error)?
            .ok_or(ApplicationError::NotFound)?;
        let keeps_access = self.current_custodian(&owner).await?.as_ref() == Some(&grantee);
        let deleted = self
            .store
            .delete_grant(&owner.uuid, &grantee, actor, request_id, keeps_access)
            .await
            .map_err(map_store_error)?;
        if deleted {
            Ok(())
        } else {
            Err(refused(
                404,
                "grant_not_found",
                format!(
                    "{grantee} has no grant on {}'s hooks.",
                    context.silicon().display()
                ),
            ))
        }
    }

    /// Lists the accounts the Silicon accepts shares from.
    ///
    /// # Errors
    ///
    /// Returns `403` unless the actor is the Silicon or its custodian.
    pub async fn allow_list(
        &self,
        context: &AuthorizationContext,
    ) -> Result<(Vec<AllowRecord>, Vec<AccountRecord>), ApplicationError> {
        authorize_action(context, Action::ManageAllowList)?;
        let entries = self
            .store
            .allow_list(context.silicon().uuid())
            .await
            .map_err(map_store_error)?;
        let accounts = self
            .store
            .accounts(
                &entries
                    .iter()
                    .map(|entry| entry.allowed_uuid.clone())
                    .collect::<Vec<_>>(),
            )
            .await
            .map_err(map_store_error)?;
        Ok((entries, accounts))
    }

    /// Lets `account` share hooks with the Silicon from outside its circle.
    ///
    /// # Errors
    ///
    /// Returns `403` unless the actor is the Silicon or its custodian, `409`
    /// for the Silicon itself, and resolution failures.
    pub async fn allow(
        &self,
        context: &AuthorizationContext,
        account: &str,
        request_id: Option<&str>,
    ) -> Result<(AllowRecord, AccountRecord), ApplicationError> {
        authorize_action(context, Action::ManageAllowList)?;
        let account = self.resolve_account(account).await?;
        if &account.uuid == context.silicon().uuid() {
            return Err(refused(
                409,
                "cannot_allow_self",
                "A Silicon does not need to allow itself.",
            ));
        }
        let entry = self
            .store
            .put_allowance(
                context.silicon().uuid(),
                &account.uuid,
                context.actor(),
                request_id,
            )
            .await
            .map_err(map_store_error)?;
        Ok((entry, account))
    }

    /// Removes `account` from the Silicon's allow-list. Grants it already made
    /// stay; the allow-list only gates new grants.
    ///
    /// # Errors
    ///
    /// Returns `403` unless the actor is the Silicon or its custodian, `404`
    /// when the account is not on the list.
    pub async fn disallow(
        &self,
        context: &AuthorizationContext,
        account: &str,
        request_id: Option<&str>,
    ) -> Result<(), ApplicationError> {
        authorize_action(context, Action::ManageAllowList)?;
        let account = self.resolve_account(account).await?;
        if self
            .store
            .delete_allowance(
                context.silicon().uuid(),
                &account.uuid,
                context.actor(),
                request_id,
            )
            .await
            .map_err(map_store_error)?
        {
            Ok(())
        } else {
            Err(refused(
                404,
                "not_allowed",
                format!(
                    "{} is not on {}'s allow-list.",
                    shown(&account),
                    context.silicon().display()
                ),
            ))
        }
    }
}
