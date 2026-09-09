use crate::{Client, Mutation, Result, models::*};
use reqwest::Method;
use uuid::Uuid;

impl Client {
    pub async fn create_environment(
        &self,
        input: &CreateEnvironment,
        mutation: &Mutation,
    ) -> Result<EnvironmentWithKey> {
        self.call(
            Method::POST,
            &["testing-environments"],
            &[],
            Some(input),
            Some(mutation),
        )
        .await
    }
    /// Reads the first 100 environments. Use list_environments_page to continue.
    pub async fn list_environments(&self, status: &str) -> Result<Items<TestEnvironment>> {
        self.list_environments_page(status, 100, None).await
    }
    /// Keyset page ordered by descending environment ID. Pass the last returned
    /// ID as after; continue until a page has fewer than limit items.
    pub async fn list_environments_page(
        &self,
        status: &str,
        limit: u32,
        after: Option<Uuid>,
    ) -> Result<Items<TestEnvironment>> {
        let mut query = vec![("status", status.to_owned()), ("limit", limit.to_string())];
        if let Some(id) = after {
            query.push(("after", id.to_string()));
        }
        self.call(
            reqwest::Method::GET,
            &["testing-environments"],
            &query,
            None::<&()>,
            None,
        )
        .await
    }
    pub async fn environment(&self, id: Uuid) -> Result<TestEnvironment> {
        self.call(
            Method::GET,
            &["testing-environments", &id.to_string()],
            &[],
            None::<&()>,
            None,
        )
        .await
    }
    pub async fn environment_key(&self, id: Uuid) -> Result<EnvironmentWithKey> {
        self.call(
            Method::GET,
            &["testing-environments", &id.to_string(), "key"],
            &[],
            None::<&()>,
            None,
        )
        .await
    }
    pub async fn rotate_environment_key(
        &self,
        id: Uuid,
        mutation: &Mutation,
    ) -> Result<EnvironmentWithKey> {
        self.call(
            Method::POST,
            &["testing-environments", &id.to_string(), "key", "rotate"],
            &[],
            None::<&()>,
            Some(mutation),
        )
        .await
    }
    pub async fn delete_environment(
        &self,
        id: Uuid,
        mutation: &Mutation,
    ) -> Result<TestEnvironment> {
        self.call(
            Method::DELETE,
            &["testing-environments", &id.to_string()],
            &[],
            None::<&()>,
            Some(mutation),
        )
        .await
    }
    pub async fn restore_environment(
        &self,
        id: Uuid,
        mutation: &Mutation,
    ) -> Result<TestEnvironment> {
        self.call(
            Method::POST,
            &["testing-environments", &id.to_string(), "restore"],
            &[],
            None::<&()>,
            Some(mutation),
        )
        .await
    }
    pub async fn current_environment(&self) -> Result<TestEnvironment> {
        self.call(
            Method::GET,
            &["testing-environment"],
            &[],
            None::<&()>,
            None,
        )
        .await
    }
    pub async fn clean_environment(&self, mutation: &Mutation) -> Result<TestEnvironment> {
        self.call(
            Method::POST,
            &["testing-environment", "clean"],
            &[],
            None::<&()>,
            Some(mutation),
        )
        .await
    }
    pub async fn configure_test_iam(
        &self,
        input: &TestIamConfiguration,
        mutation: &Mutation,
    ) -> Result<TestEnvironment> {
        self.call(
            Method::PUT,
            &["testing-environment", "iam"],
            &[],
            Some(input),
            Some(mutation),
        )
        .await
    }
}
