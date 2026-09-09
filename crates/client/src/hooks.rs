use crate::{Client, Mutation, Result, models::*};
use reqwest::Method;
use uuid::Uuid;

impl Client {
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
    pub async fn delete_hook(&self, silicon: &str, id: Uuid, mutation: &Mutation) -> Result<()> {
        self.empty(
            Method::DELETE,
            &["silicons", silicon, "hooks", &id.to_string()],
            None,
            Some(mutation),
        )
        .await
    }
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
            Some(&serde_json::json!({"hook_ids":ids,"enabled":enabled})),
            Some(mutation),
        )
        .await
    }
    pub async fn connect_iam_hook(&self, silicon: &str, mutation: &Mutation) -> Result<IamHook> {
        self.call(
            Method::POST,
            &["silicons", silicon, "hooks", "iam"],
            &[],
            None::<&()>,
            Some(mutation),
        )
        .await
    }
    pub async fn events(
        &self,
        silicon: &str,
        hook: Option<Uuid>,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<HistoryPage<Event>> {
        self.history(silicon, hook, "events", limit, cursor).await
    }
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
    pub async fn deliveries(
        &self,
        silicon: &str,
        limit: u32,
        after_sequence: Option<i64>,
    ) -> Result<DeliveryBatch> {
        let mut query = vec![("limit", limit.to_string())];
        if let Some(after) = after_sequence {
            query.push(("after_sequence", after.to_string()));
        }
        self.call(
            Method::GET,
            &["silicons", silicon, "deliveries"],
            &query,
            None::<&()>,
            None,
        )
        .await
    }
    pub async fn acknowledge(
        &self,
        silicon: &str,
        through_sequence: i64,
        mutation: &Mutation,
    ) -> Result<DeliveryCursor> {
        self.call(
            Method::POST,
            &["silicons", silicon, "deliveries", "ack"],
            &[],
            Some(&serde_json::json!({"through_sequence":through_sequence})),
            Some(mutation),
        )
        .await
    }
    pub async fn delivery_cursor(&self, silicon: &str) -> Result<DeliveryCursor> {
        self.call(
            Method::GET,
            &["silicons", silicon, "deliveries", "cursor"],
            &[],
            None::<&()>,
            None,
        )
        .await
    }
}
