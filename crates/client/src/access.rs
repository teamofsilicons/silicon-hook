//! Which Silicons the caller can open, who has access to a Silicon's hooks,
//! and the hook that receives a Silicon's own Silicon Accounts events.
//!
//! A Silicon and its custodian (the Carbon who looks after it) can do
//! everything with the Silicon's hooks. They can grant other Carbons and
//! Silicons `view` or `manage` access, by `c:`/`si:` id or uuid. A Silicon looked
//! after by a different custodian only accepts a grant after it (or its
//! custodian) put the granting Silicon or its custodian on its allow-list.

use reqwest::Method;

use crate::{
    Client, Error, Mutation, Result,
    models::{
        AccessSummary, AccessibleSilicon, AccountsHook, AllowEntry, AllowList, GrantLevel,
        GrantResult, Items,
    },
};

fn account_segment(account: &str) -> Result<&str> {
    let account = account.trim();
    if account.is_empty() || account.eq_ignore_ascii_case("me") {
        return Err(Error::Invalid(
            "name the account by its c:/si: id or uuid (to remove your own access use leave)"
                .into(),
        ));
    }
    Ok(account)
}

impl Client {
    /// The Silicons the caller can open: itself (a Silicon), the Silicons it
    /// looks after (a custodian), and the ones granted to it.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn silicons(&self) -> Result<Items<AccessibleSilicon>> {
        self.call(Method::GET, &["silicons"], &[], None::<&()>, None)
            .await
    }

    /// Who has access to the Silicon's hooks, and the caller's own access.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn access(&self, silicon: &str) -> Result<AccessSummary> {
        self.call(
            Method::GET,
            &["silicons", silicon, "access"],
            &[],
            None::<&()>,
            None,
        )
        .await
    }

    /// Grants `account` (a `c:`/`si:` id or uuid) access, or changes its level.
    /// Only the Silicon and its custodian can do this.
    ///
    /// # Errors
    /// Transport, protocol and refusals (`forbidden`, `account_not_found`,
    /// `already_has_access` for the Silicon itself or its custodian,
    /// `silicon_not_reachable` for a Silicon that has not allowed this one…).
    pub async fn grant(
        &self,
        silicon: &str,
        account: &str,
        level: GrantLevel,
    ) -> Result<GrantResult> {
        let account = account_segment(account)?;
        self.call(
            Method::PUT,
            &["silicons", silicon, "access", account],
            &[],
            Some(&serde_json::json!({ "level": level.as_str() })),
            None,
        )
        .await
    }

    /// Removes `account`'s access. Only the Silicon and its custodian can.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn revoke(&self, silicon: &str, account: &str) -> Result<()> {
        let account = account_segment(account)?;
        self.empty(
            Method::DELETE,
            &["silicons", silicon, "access", account],
            None,
        )
        .await
    }

    /// Gives up the caller's own grant to the Silicon.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn leave(&self, silicon: &str) -> Result<()> {
        self.empty(Method::DELETE, &["silicons", silicon, "access", "me"], None)
            .await
    }

    /// The accounts the Silicon allowed to grant it access although they are
    /// outside the Silicons its custodian looks after.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn allow_list(&self, silicon: &str) -> Result<AllowList> {
        self.call(
            Method::GET,
            &["silicons", silicon, "allow-list"],
            &[],
            None::<&()>,
            None,
        )
        .await
    }

    /// Adds `account` to the Silicon's allow-list.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn allow(&self, silicon: &str, account: &str) -> Result<AllowEntry> {
        let account = account_segment(account)?;
        self.call(
            Method::PUT,
            &["silicons", silicon, "allow-list", account],
            &[],
            None::<&()>,
            None,
        )
        .await
    }

    /// Removes `account` from the Silicon's allow-list. Grants it already gave
    /// stay until they are revoked.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn disallow(&self, silicon: &str, account: &str) -> Result<()> {
        let account = account_segment(account)?;
        self.empty(
            Method::DELETE,
            &["silicons", silicon, "allow-list", account],
            None,
        )
        .await
    }

    /// Creates (or restores) the hook that receives the Silicon's own Silicon
    /// Accounts events and says how to finish: point the Silicon's Accounts
    /// webhook at it with the returned `silicon-accounts` command, then store
    /// the `whsec_` secret it prints with [`Client::set_secret`]. Only the
    /// Silicon and its custodian can do this.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn connect_accounts_hook(
        &self,
        silicon: &str,
        mutation: &Mutation,
    ) -> Result<AccountsHook> {
        self.call(
            Method::POST,
            &["silicons", silicon, "hooks", "accounts"],
            &[],
            None::<&()>,
            Some(mutation),
        )
        .await
    }
}
