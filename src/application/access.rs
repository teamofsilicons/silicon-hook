//! Who the caller is, which Silicon a request names, and what the caller may
//! do with that Silicon's hooks.

use std::time::Duration;

use silicon_accounts_client::{AccountKind, AccountSummary};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{ApplicationError, HookApplication, service::map_store_error};
use crate::{
    domain::{Access, AccountUuid, Actor, ActorKind, AuthorizationContext, PublicId, SiliconRef},
    infrastructure::{
        accounts::{AccountsError, Lookup, VerifyFailure},
        postgres::{AccountRecord, AccountView, GrantRecord},
    },
};

/// Custodian data older than this is confirmed with Silicon Accounts before it
/// decides an authorization.
pub const CUSTODIAN_FRESHNESS: Duration = Duration::from_mins(5);
/// A cached `c:`/`si:` id older than this is confirmed before it resolves a request.
pub const PUBLIC_ID_FRESHNESS: Duration = Duration::from_hours(1);
/// Access tokens live 30 minutes; used to bound a token without `iat`.
const ACCESS_TOKEN_LIFETIME: time::Duration = time::Duration::minutes(30);

/// A Silicon the caller can open, and why.
#[derive(Clone, Debug)]
pub struct AccessibleSilicon {
    /// The Silicon.
    pub silicon: AccountRecord,
    /// How the caller has access.
    pub access: Access,
}

/// Who has access to a Silicon's hooks, as the caller may see it.
#[derive(Clone, Debug)]
pub struct AccessSummary {
    /// The Silicon's custodian, when known.
    pub custodian: Option<AccountRecord>,
    /// Grants: all of them for the Silicon and its custodian, only the
    /// caller's own otherwise.
    pub grants: Vec<GrantRecord>,
    /// Accounts referenced by the grants, for display.
    pub accounts: Vec<AccountRecord>,
}

fn refused(status: u16, code: &'static str, message: impl Into<String>) -> ApplicationError {
    ApplicationError::refused(status, code, message)
}

fn accounts_unavailable(error: AccountsError) -> ApplicationError {
    match error {
        AccountsError::Rejected {
            status,
            code,
            message,
        } => refused(
            502,
            "accounts_refused",
            format!("Silicon Accounts refused Hook's request ({status} {code}): {message}"),
        ),
        AccountsError::Unavailable(message) => {
            // The detail can name private addresses: it goes to the log only.
            tracing::warn!(error = %message, "Silicon Accounts did not answer");
            refused(
                503,
                "accounts_unavailable",
                "Silicon Accounts did not answer, and this request needs it (to confirm that the sign-in is still active, or to look an account up). Retry shortly.",
            )
        }
    }
}

fn kind_of(kind: AccountKind) -> ActorKind {
    match kind {
        AccountKind::Carbon => ActorKind::Carbon,
        AccountKind::Silicon => ActorKind::Silicon,
    }
}

fn view_of(summary: &AccountSummary) -> Result<AccountView, ApplicationError> {
    let uuid = AccountUuid::new(summary.uuid.clone()).map_err(|_| {
        refused(
            502,
            "accounts_invalid",
            "Silicon Accounts returned an account without a valid uuid.",
        )
    })?;
    let custodian = summary.custodian.as_ref().and_then(|custodian| {
        AccountUuid::new(custodian.uuid.clone())
            .ok()
            .map(|uuid| (uuid, PublicId::new(custodian.id.clone()).ok()))
    });
    Ok(AccountView {
        uuid,
        kind: kind_of(summary.kind),
        public_id: PublicId::new(summary.id.clone()).ok(),
        custodian,
    })
}

fn older_than(at: Option<OffsetDateTime>, freshness: Duration) -> bool {
    at.is_none_or(|at| OffsetDateTime::now_utc() - at > freshness)
}

impl HookApplication {
    /// Verifies a Silicon Accounts access token issued to Hook and records what
    /// it says about its account.
    ///
    /// # Errors
    ///
    /// Returns `401` with the exact reason for a token Hook does not accept
    /// (expired, another app's, signed out, deleted account…), or an
    /// unavailability when the signing keys cannot be fetched.
    pub async fn authenticate(&self, token: &str) -> Result<Actor, ApplicationError> {
        let claims = match self.accounts.verify(token).await {
            Ok(claims) => claims,
            Err(VerifyFailure::Rejected(rejection)) => {
                return Err(refused(401, rejection.code, rejection.message));
            }
            Err(VerifyFailure::Unavailable(message)) => {
                // The detail can name private addresses: it goes to the log only.
                tracing::warn!(error = %message, "Silicon Accounts did not answer");
                return Err(refused(
                    503,
                    "accounts_unavailable",
                    "Silicon Accounts did not answer, and Hook needs its signing keys to check this access token. Retry shortly.",
                ));
            }
        };
        let uuid = AccountUuid::new(claims.sub.clone()).map_err(|_| {
            refused(
                401,
                "token_invalid",
                "The access token's subject is not a Silicon Accounts uuid.",
            )
        })?;
        let kind = claims.kind.map(kind_of).ok_or_else(|| {
            refused(
                401,
                "token_missing_claim",
                "The access token does not say whether it belongs to a Carbon or a Silicon (no kind claim).",
            )
        })?;
        let id = claims.id.as_deref().and_then(|id| PublicId::new(id).ok());
        let issued_at = claims
            .iat
            .and_then(|iat| OffsetDateTime::from_unix_timestamp(iat).ok())
            .or_else(|| {
                OffsetDateTime::from_unix_timestamp(claims.exp)
                    .ok()
                    .map(|exp| exp - ACCESS_TOKEN_LIFETIME)
            })
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let cached = self.store.account(&uuid).await.map_err(map_store_error)?;
        let record = match cached {
            Some(record) if record.public_id == id || id.is_none() => record,
            _ => self
                .store
                .observe_token_account(&uuid, kind, id.as_ref(), issued_at)
                .await
                .map_err(map_store_error)?,
        };
        if record.deleted_at.is_some() {
            return Err(refused(
                401,
                "account_deleted",
                "This account was deleted in Silicon Accounts; its tokens no longer work.",
            ));
        }
        if let Some(revoked_before) = record.revoked_before
            && self
                .ended_by_sign_out(token, issued_at, revoked_before)
                .await?
        {
            let at = revoked_before
                .format(&Rfc3339)
                .unwrap_or_else(|_| revoked_before.to_string());
            return Err(refused(
                401,
                "session_ended",
                format!(
                    "This sign-in ended at {at} (signed out or Hook's access removed in Silicon Accounts). Sign in again: hook login (Carbons) or hook login --slt with a token from silicon-accounts login --app hook -q (Silicons)."
                ),
            ));
        }
        if kind == ActorKind::Silicon && record.custodian_checked_at.is_none() {
            // Tokens do not name a Silicon's custodian. Learn it once, so the
            // custodian's list of Silicons includes this one; a failure here
            // only delays that.
            if let Err(error) = self.look_up(uuid.as_str(), false).await {
                tracing::info!(%error, "could not learn a new Silicon's custodian yet");
            }
        }
        Ok(Actor::new(
            uuid,
            kind,
            id.or(record.public_id),
            claims.scopes().into_iter().map(ToOwned::to_owned).collect(),
            claims.fid,
        ))
    }

    /// Whether a sign-out Hook was told about (at `revoked_before`) ended the
    /// sign-in this token belongs to. `iat` has whole seconds: a token from an
    /// earlier second is older, one from a later second newer, and one from
    /// the sign-out's own second is settled by Silicon Accounts.
    async fn ended_by_sign_out(
        &self,
        token: &str,
        issued_at: OffsetDateTime,
        revoked_before: OffsetDateTime,
    ) -> Result<bool, ApplicationError> {
        let sign_out_second = revoked_before
            .replace_nanosecond(0)
            .unwrap_or(revoked_before);
        if issued_at < sign_out_second {
            return Ok(true);
        }
        if issued_at >= revoked_before {
            return Ok(false);
        }
        self.accounts
            .issued_after_sign_out(token, revoked_before)
            .await
            .map(|after| !after)
            .map_err(accounts_unavailable)
    }

    /// Confirms with Silicon Accounts that the token is still active, for
    /// operations that reveal secrets or change who has access.
    ///
    /// # Errors
    ///
    /// Returns `401 session_ended` for an inactive token.
    pub async fn require_active_token(&self, token: &str) -> Result<(), ApplicationError> {
        match self.accounts.introspect_active(token).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(refused(
                401,
                "session_ended",
                "Silicon Accounts says this access token is no longer active (signed out or access removed). Sign in again.",
            )),
            Err(error) => Err(accounts_unavailable(error)),
        }
    }

    async fn look_up(
        &self,
        value: &str,
        by_id: bool,
    ) -> Result<Option<AccountRecord>, ApplicationError> {
        let lookup = if by_id {
            self.accounts.lookup_by_id(value).await
        } else {
            self.accounts.lookup(value).await
        }
        .map_err(accounts_unavailable)?;
        match lookup {
            Lookup::Found(summary) => {
                let view = view_of(&summary)?;
                Ok(Some(
                    self.store
                        .record_account_view(&view, OffsetDateTime::now_utc())
                        .await
                        .map_err(map_store_error)?,
                ))
            }
            Lookup::Deleted => {
                if let Ok(uuid) = AccountUuid::new(value) {
                    self.store
                        .record_account_deleted_by_lookup(&uuid, OffsetDateTime::now_utc())
                        .await
                        .map_err(map_store_error)?;
                }
                Err(refused(
                    410,
                    "account_deleted",
                    format!("{value} was deleted in Silicon Accounts."),
                ))
            }
            Lookup::NotFound => Ok(None),
        }
    }

    /// Resolves an account named by its current `c:`/`si:` id or its uuid,
    /// from Hook's cache or from Silicon Accounts.
    ///
    /// # Errors
    ///
    /// Returns `404 account_not_found` for an unknown id, `410` for a deleted
    /// account, `422` for something that is neither an id nor a uuid.
    pub async fn resolve_account(&self, value: &str) -> Result<AccountRecord, ApplicationError> {
        let value = value.trim();
        if let Ok(id) = PublicId::new(value) {
            if let Some(record) = self
                .store
                .account_by_public_id(&id)
                .await
                .map_err(map_store_error)?
                && !older_than(record.public_id_at, PUBLIC_ID_FRESHNESS)
            {
                return Ok(record);
            }
            return self.look_up(id.as_str(), true).await?.ok_or_else(|| {
                refused(
                    404,
                    "account_not_found",
                    format!(
                        "No account has the id {id} in Silicon Accounts. Ids can change; check the current id, or use the account's uuid."
                    ),
                )
            });
        }
        let uuid = AccountUuid::new(value).map_err(|_| {
            refused(
                422,
                "invalid_account",
                format!(
                    "`{value}` is neither a Silicon Accounts id (c:handle or si:handle) nor a uuid (letters and digits)."
                ),
            )
        })?;
        if let Some(record) = self.store.account(&uuid).await.map_err(map_store_error)?
            && (record.deleted_at.is_some() || record.public_id.is_some())
        {
            if record.deleted_at.is_some() {
                return Err(refused(
                    410,
                    "account_deleted",
                    format!("{uuid} was deleted in Silicon Accounts."),
                ));
            }
            return Ok(record);
        }
        self.look_up(uuid.as_str(), false).await?.ok_or_else(|| {
            refused(
                404,
                "account_not_found",
                format!("No account has the uuid {uuid} in Silicon Accounts."),
            )
        })
    }

    /// Resolves the Silicon a request names (its current `si:` id or uuid).
    ///
    /// # Errors
    ///
    /// Returns `404 silicon_not_found` for an unknown Silicon or a Carbon,
    /// `410 account_deleted` for a deleted one.
    pub async fn resolve_silicon(&self, segment: &str) -> Result<AccountRecord, ApplicationError> {
        let record = match self.resolve_account(segment).await {
            Err(ApplicationError::Refused { status: 404, .. }) => {
                return Err(refused(
                    404,
                    "silicon_not_found",
                    format!(
                        "No Silicon has the id or uuid `{segment}` in Silicon Accounts. Silicon ids look like si:handle and can change; the uuid never does."
                    ),
                ));
            }
            other => other?,
        };
        if record.kind != ActorKind::Silicon {
            return Err(refused(
                404,
                "not_a_silicon",
                format!(
                    "{} is a Carbon. Hooks belong to Silicons: name a Silicon (si:handle) whose hooks you want.",
                    record.public_id.as_ref().map_or(segment, PublicId::as_str)
                ),
            ));
        }
        Ok(record)
    }

    /// The Silicon's custodian, confirmed with Silicon Accounts when the cached
    /// value is older than [`CUSTODIAN_FRESHNESS`].
    pub(super) async fn current_custodian(
        &self,
        silicon: &AccountRecord,
    ) -> Result<Option<AccountUuid>, ApplicationError> {
        if !older_than(silicon.custodian_checked_at, CUSTODIAN_FRESHNESS) {
            return Ok(silicon.custodian_uuid.clone());
        }
        match self.look_up(silicon.uuid.as_str(), false).await? {
            Some(fresh) => Ok(fresh.custodian_uuid),
            None => Ok(None),
        }
    }

    /// Establishes the actor's access to the hooks of the Silicon `segment` names.
    ///
    /// # Errors
    ///
    /// Returns `403 no_access` when the actor is not the Silicon, not its
    /// custodian and holds no grant, and the resolution failures of
    /// [`Self::resolve_silicon`].
    pub async fn authorize_silicon(
        &self,
        actor: &Actor,
        segment: &str,
    ) -> Result<AuthorizationContext, ApplicationError> {
        let silicon = if AccountUuid::looks_like(segment) && segment == actor.uuid().as_str() {
            // A Silicon naming itself by uuid needs no lookup.
            self.store
                .account(actor.uuid())
                .await
                .map_err(map_store_error)?
                .ok_or_else(|| {
                    refused(
                        404,
                        "silicon_not_found",
                        format!("No Silicon has the uuid {segment}."),
                    )
                })?
        } else {
            self.resolve_silicon(segment).await?
        };
        let reference = SiliconRef::new(silicon.uuid.clone(), silicon.public_id.clone());
        if actor.uuid() == &silicon.uuid {
            return Ok(AuthorizationContext::new(
                actor.clone(),
                reference,
                Access::Own,
            ));
        }
        if actor.kind() == ActorKind::Carbon
            && self.current_custodian(&silicon).await?.as_ref() == Some(actor.uuid())
        {
            return Ok(AuthorizationContext::new(
                actor.clone(),
                reference,
                Access::Custodian,
            ));
        }
        if let Some(grant) = self
            .store
            .grant(&silicon.uuid, actor.uuid())
            .await
            .map_err(map_store_error)?
        {
            return Ok(AuthorizationContext::new(
                actor.clone(),
                reference,
                Access::Grant(grant.level),
            ));
        }
        Err(refused(
            403,
            "no_access",
            format!(
                "{} has no access to {}'s hooks. Access comes from being that Silicon, its custodian, or a grant from either of them.",
                actor.display(),
                reference.display()
            ),
        ))
    }

    /// Lists the Silicons the actor can open: itself (a Silicon), the Silicons
    /// Hook knows it looks after (a Carbon), and grants it received.
    ///
    /// # Errors
    ///
    /// Returns a persistence failure.
    pub async fn accessible_silicons(
        &self,
        actor: &Actor,
    ) -> Result<Vec<AccessibleSilicon>, ApplicationError> {
        let mut silicons = Vec::new();
        if actor.kind() == ActorKind::Silicon {
            if let Some(record) = self
                .store
                .account(actor.uuid())
                .await
                .map_err(map_store_error)?
            {
                silicons.push(AccessibleSilicon {
                    silicon: record,
                    access: Access::Own,
                });
            }
        } else {
            for record in self
                .store
                .silicons_looked_after_by(actor.uuid())
                .await
                .map_err(map_store_error)?
            {
                silicons.push(AccessibleSilicon {
                    silicon: record,
                    access: Access::Custodian,
                });
            }
        }
        let grants = self
            .store
            .grants_to(actor.uuid())
            .await
            .map_err(map_store_error)?;
        let granted = self
            .store
            .accounts(
                &grants
                    .iter()
                    .map(|grant| grant.silicon_uuid.clone())
                    .collect::<Vec<_>>(),
            )
            .await
            .map_err(map_store_error)?;
        for grant in grants {
            if silicons
                .iter()
                .any(|known| known.silicon.uuid == grant.silicon_uuid)
            {
                continue;
            }
            if let Some(record) = granted
                .iter()
                .find(|record| record.uuid == grant.silicon_uuid && record.deleted_at.is_none())
            {
                silicons.push(AccessibleSilicon {
                    silicon: record.clone(),
                    access: Access::Grant(grant.level),
                });
            }
        }
        Ok(silicons)
    }
}
