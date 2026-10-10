//! A Silicon's provider webhooks and their request history.
//!
//! `silicon` is the Silicon's current `si:` id or its uuid. The caller must be
//! the Silicon, its custodian, or an account the Silicon granted access to
//! (`view` reads, `manage` also changes).

use reqwest::Method;
use uuid::Uuid;

use crate::{
    Client, Mutation, Result,
    models::{
        BlockedRequest, CreateHook, Event, HistoryPage, Hook, HookWithSecret, Items, Secret,
        Signature, SigningSecret, UpdateHook,
    },
};

impl Client {
    /// The Silicon's hooks; `include_deleted` adds the ones still restorable.
    ///
    /// # Errors
    /// Transport, protocol and refusals (`forbidden`, `not_found`…).
    pub async fn list_hooks(&self, silicon: &str, include_deleted: bool) -> Result<Items<Hook>> {
        self.call(
            Method::GET,
            &["silicons", silicon, "hooks"],
            &[("include_deleted", include_deleted.to_string())],
            None::<&()>,
            None,
        )
        .await
    }

    /// One hook.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn get_hook(&self, silicon: &str, id: Uuid) -> Result<Hook> {
        self.call(
            Method::GET,
            &["silicons", silicon, "hooks", &id.to_string()],
            &[],
            None::<&()>,
            None,
        )
        .await
    }

    /// Creates a hook. The response carries the generated signing secret once.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn create_hook(
        &self,
        silicon: &str,
        input: &CreateHook,
        mutation: &Mutation,
    ) -> Result<HookWithSecret> {
        self.call(
            Method::POST,
            &["silicons", silicon, "hooks"],
            &[],
            Some(input),
            Some(mutation),
        )
        .await
    }

    /// Changes a hook's metadata, activation or signing policy.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn update_hook(
        &self,
        silicon: &str,
        id: Uuid,
        input: &UpdateHook,
        mutation: &Mutation,
    ) -> Result<Hook> {
        self.call(
            Method::PATCH,
            &["silicons", silicon, "hooks", &id.to_string()],
            &[],
            Some(input),
            Some(mutation),
        )
        .await
    }

    /// Sets or replaces a hook's secret (bring your own secret) and keeps every
    /// other setting. Pass `secret_encoding` when the text is not UTF-8 key
    /// material. The previous secret stops verifying at once.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn set_secret(
        &self,
        silicon: &str,
        id: Uuid,
        secret: Secret,
        secret_encoding: Option<String>,
        mutation: &Mutation,
    ) -> Result<Hook> {
        self.update_hook(
            silicon,
            id,
            &UpdateHook {
                signature: Some(Signature {
                    secret: Some(secret),
                    secret_encoding,
                    ..Signature::default()
                }),
                ..UpdateHook::default()
            },
            mutation,
        )
        .await
    }

    /// Soft-deletes a hook; it can be restored for 45 days.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn delete_hook(&self, silicon: &str, id: Uuid, mutation: &Mutation) -> Result<()> {
        self.empty(
            Method::DELETE,
            &["silicons", silicon, "hooks", &id.to_string()],
            Some(mutation),
        )
        .await
    }

    /// Restores a deleted hook with its URL and secret.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn restore_hook(&self, silicon: &str, id: Uuid, mutation: &Mutation) -> Result<Hook> {
        self.call(
            Method::POST,
            &["silicons", silicon, "hooks", &id.to_string(), "restore"],
            &[],
            None::<&()>,
            Some(mutation),
        )
        .await
    }

    /// Retires the hook's URL for good and issues a new one.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn rotate_endpoint(
        &self,
        silicon: &str,
        id: Uuid,
        mutation: &Mutation,
    ) -> Result<Hook> {
        self.call(
            Method::POST,
            &[
                "silicons",
                silicon,
                "hooks",
                &id.to_string(),
                "endpoint",
                "rotate",
            ],
            &[],
            None::<&()>,
            Some(mutation),
        )
        .await
    }

    /// Generates a new signing secret, shown once; the old one stops verifying.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn rotate_secret(
        &self,
        silicon: &str,
        id: Uuid,
        mutation: &Mutation,
    ) -> Result<SigningSecret> {
        self.call(
            Method::POST,
            &[
                "silicons",
                silicon,
                "hooks",
                &id.to_string(),
                "secret",
                "rotate",
            ],
            &[],
            None::<&()>,
            Some(mutation),
        )
        .await
    }

    /// Pauses or resumes several hooks at once (all or nothing).
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn set_enabled(
        &self,
        silicon: &str,
        ids: &[Uuid],
        enabled: bool,
        mutation: &Mutation,
    ) -> Result<Items<Hook>> {
        self.call(
            Method::PATCH,
            &["silicons", silicon, "hooks"],
            &[],
            Some(&serde_json::json!({"hook_ids": ids, "enabled": enabled})),
            Some(mutation),
        )
        .await
    }

    /// Verified requests, newest first: one hook's, or the whole Silicon's when
    /// `hook` is `None`. `limit` is 1 to 10,000; continue with `next_cursor`.
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn events(
        &self,
        silicon: &str,
        hook: Option<Uuid>,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<HistoryPage<Event>> {
        self.history(silicon, hook, "events", limit, cursor).await
    }

    /// Withheld requests (kept 14 days), filtered like [`Client::events`].
    ///
    /// # Errors
    /// Transport, protocol and refusals.
    pub async fn blocked_requests(
        &self,
        silicon: &str,
        hook: Option<Uuid>,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<HistoryPage<BlockedRequest>> {
        self.history(silicon, hook, "blocked-requests", limit, cursor)
            .await
    }

    async fn history<T: serde::de::DeserializeOwned>(
        &self,
        silicon: &str,
        hook: Option<Uuid>,
        kind: &str,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<T> {
        let hook = hook.map(|id| id.to_string());
        let mut path = vec!["silicons", silicon];
        if let Some(id) = &hook {
            path.extend(["hooks", id.as_str()]);
        }
        path.push(kind);
        let mut query = vec![("limit", limit.to_string())];
        if let Some(cursor) = cursor {
            query.push(("cursor", cursor.to_owned()));
        }
        self.call(Method::GET, &path, &query, None::<&()>, None)
            .await
    }
}
