//! Ordered, acknowledged delivery of verified requests to consumers.

use super::{
    AcknowledgeDeliveriesCommand, ApplicationError, DeliveryBatch, HookApplication,
    PullDeliveriesCommand, StreamAccess,
    service::{authorize_action, database_time, map_store_error},
};
use crate::{
    domain::{Action, AuthorizationContext, DeliveryCursor, EventRecord, SiliconId},
    infrastructure::postgres::MAX_DELIVERY_BATCH,
};

impl HookApplication {
    /// Authorizes an actor to consume one Silicon's delivery stream.
    ///
    /// # Errors
    ///
    /// Returns not-found when the Silicon is not visible to the actor.
    pub fn authorize_stream(
        &self,
        authorization: &AuthorizationContext,
        silicon_id: &SiliconId,
    ) -> Result<StreamAccess, ApplicationError> {
        authorize_action(authorization, Action::ConsumeDeliveries, silicon_id, None)?;
        Ok(StreamAccess {
            organization_id: authorization.organization_id().clone(),
            silicon_id: silicon_id.clone(),
            consumer: authorization.actor().clone(),
        })
    }

    /// Returns ordered events after a position and the consumer's cursor.
    ///
    /// Without an explicit position the pull starts after the consumer's
    /// acknowledged cursor, so it yields exactly the unacknowledged backlog.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, validation, or persistence failure.
    pub async fn pull_deliveries(
        &self,
        command: PullDeliveriesCommand,
    ) -> Result<DeliveryBatch, ApplicationError> {
        let access = self.authorize_stream(&command.authorization, &command.silicon_id)?;
        if command.limit == 0 || command.limit > MAX_DELIVERY_BATCH {
            return Err(ApplicationError::Validation { field: "limit" });
        }
        if command.after_sequence.is_some_and(|sequence| sequence < 0) {
            return Err(ApplicationError::Validation {
                field: "after_sequence",
            });
        }
        let cursor = self.stream_cursor(&access).await?;
        let after = command
            .after_sequence
            .unwrap_or(cursor.acknowledged_through);
        let items = self.fetch_after(&access, after, command.limit).await?;
        let latest_sequence = self
            .store
            .latest_sequence(&access.silicon_id)
            .await
            .map_err(map_store_error)?;
        Ok(DeliveryBatch {
            items,
            cursor,
            latest_sequence,
        })
    }

    /// Advances the consumer's acknowledged position.
    ///
    /// # Errors
    ///
    /// Returns a semantic authorization, validation, or persistence failure.
    pub async fn acknowledge_deliveries(
        &self,
        command: AcknowledgeDeliveriesCommand,
    ) -> Result<DeliveryCursor, ApplicationError> {
        let access = self.authorize_stream(&command.authorization, &command.silicon_id)?;
        self.acknowledge_stream(&access, command.through_sequence)
            .await
    }

    /// Advances an already authorized stream's acknowledged position.
    ///
    /// # Errors
    ///
    /// Returns a validation or persistence failure.
    pub async fn acknowledge_stream(
        &self,
        access: &StreamAccess,
        through_sequence: i64,
    ) -> Result<DeliveryCursor, ApplicationError> {
        if through_sequence < 0 {
            return Err(ApplicationError::Validation {
                field: "through_sequence",
            });
        }
        let now = database_time(self.clock.now())?;
        self.store
            .acknowledge_deliveries(&access.silicon_id, &access.consumer, through_sequence, now)
            .await
            .map_err(map_store_error)
    }

    /// Returns an already authorized stream's acknowledged position.
    ///
    /// # Errors
    ///
    /// Returns a persistence failure.
    pub async fn stream_cursor(
        &self,
        access: &StreamAccess,
    ) -> Result<DeliveryCursor, ApplicationError> {
        self.store
            .delivery_cursor(&access.silicon_id, &access.consumer)
            .await
            .map_err(map_store_error)
    }

    /// Returns ordered events after a position for an authorized stream.
    ///
    /// # Errors
    ///
    /// Returns a validation or persistence failure.
    pub async fn fetch_after(
        &self,
        access: &StreamAccess,
        after_sequence: i64,
        limit: u32,
    ) -> Result<Vec<EventRecord>, ApplicationError> {
        self.store
            .fetch_deliveries(
                &access.organization_id,
                &access.silicon_id,
                after_sequence,
                limit,
            )
            .await
            .map_err(map_store_error)
    }
}
