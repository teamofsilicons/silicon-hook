//! Retained verified and blocked request history.

use super::{
    ApplicationError, HistoryPage, HookApplication, ListHistoryCommand,
    service::{authorize_action, map_store_error},
};
use crate::{
    domain::{
        Action, BlockedRequest, EventRecord, HistoryCollection, HistoryCursorScope, HistoryFilter,
    },
    infrastructure::postgres::{HistoryPageRequest, MAX_HISTORY_LIMIT},
};

impl HookApplication {
    /// Hydrates a retained Ting reference using current authority and its original generation.
    ///
    /// # Errors
    /// Rejects invisible, expired or cleaned events and mismatched environments.
    pub async fn get_event(
        &self,
        authorization: &crate::domain::AuthorizationContext,
        silicon_id: &crate::domain::SiliconId,
        event_id: crate::domain::EventId,
        expected_environment: Option<(uuid::Uuid, i64)>,
    ) -> Result<EventRecord, ApplicationError> {
        authorize_action(authorization, Action::ReadEvents, silicon_id)?;
        if let Some((expected_id, _)) = expected_environment
            && expected_id != self.environment.map_or(uuid::Uuid::nil(), |(id, _)| id)
        {
            return Err(ApplicationError::NotFound);
        }
        let _guard = self.delivery_guard().await?;
        self.store
            .get_event(
                authorization.organization_id(),
                silicon_id,
                event_id,
                expected_environment.map(|(_, generation)| generation),
            )
            .await
            .map_err(map_store_error)?
            .ok_or(ApplicationError::NotFound)
    }

    /// Lists the most recent verified requests, newest first.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, validation, persistence, or cursor failure.
    pub async fn list_events(
        &self,
        command: ListHistoryCommand,
    ) -> Result<HistoryPage<EventRecord>, ApplicationError> {
        let (request, scope) = self.history_request(&command, HistoryCollection::Events)?;
        let page = self
            .store
            .list_events(&request)
            .await
            .map_err(map_store_error)?;
        self.encode_page(page.items, page.next_cursor, &scope)
    }

    /// Lists the most recent withheld requests, newest first.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, validation, persistence, or cursor failure.
    pub async fn list_blocked_requests(
        &self,
        command: ListHistoryCommand,
    ) -> Result<HistoryPage<BlockedRequest>, ApplicationError> {
        let (request, scope) =
            self.history_request(&command, HistoryCollection::BlockedRequests)?;
        let page = self
            .store
            .list_blocked_requests(&request)
            .await
            .map_err(map_store_error)?;
        self.encode_page(page.items, page.next_cursor, &scope)
    }

    fn history_request(
        &self,
        command: &ListHistoryCommand,
        collection: HistoryCollection,
    ) -> Result<(HistoryPageRequest, HistoryCursorScope), ApplicationError> {
        authorize_action(
            &command.authorization,
            Action::ReadEvents,
            &command.silicon_id,
        )?;
        if command.limit == 0 || command.limit > MAX_HISTORY_LIMIT {
            return Err(ApplicationError::Validation { field: "limit" });
        }
        let filter = HistoryFilter::new(command.hook_id);
        let scope = HistoryCursorScope::new(
            command.authorization.organization_id().clone(),
            command.silicon_id.clone(),
            collection,
            filter.clone(),
        )
        .with_environment(self.environment_identity());
        let cursor = command
            .cursor
            .as_deref()
            .map(|encoded| self.cursor_codec.decode(&scope, encoded))
            .transpose()
            .map_err(|_| ApplicationError::Validation { field: "cursor" })?;
        Ok((
            HistoryPageRequest {
                organization_id: command.authorization.organization_id().clone(),
                silicon_id: command.silicon_id.clone(),
                filter,
                cursor,
                limit: command.limit,
            },
            scope,
        ))
    }

    fn encode_page<T>(
        &self,
        items: Vec<T>,
        next_cursor: Option<crate::domain::HistoryCursor>,
        scope: &HistoryCursorScope,
    ) -> Result<HistoryPage<T>, ApplicationError> {
        let next_cursor = next_cursor
            .map(|boundary| self.cursor_codec.encode(scope, boundary))
            .transpose()
            .map_err(ApplicationError::internal)?;
        Ok(HistoryPage { items, next_cursor })
    }
}
