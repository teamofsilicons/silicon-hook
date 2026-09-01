//! Explicit inputs and outputs for application use cases.

use crate::domain::{
    ActorRef, AuthorizationContext, EventRecord, Hook, HookDescription, HookId, HookName,
    OrganizationId, SigningSecret, SiliconId,
};

/// Request attribution shared by authorized management mutations.
#[derive(Clone, Debug)]
pub struct ManagementContext {
    /// IAM-derived authorization facts for this request.
    pub authorization: AuthorizationContext,
    /// Caller-supplied idempotency key.
    pub idempotency_key: String,
    /// Correlation identifier assigned at the HTTP boundary.
    pub request_id: Option<String>,
}

/// Input for normal hook creation.
#[derive(Clone, Debug)]
pub struct CreateHookCommand {
    /// Authorized mutation context.
    pub context: ManagementContext,
    /// Target Silicon.
    pub silicon_id: SiliconId,
    /// Validated display name.
    pub name: HookName,
    /// Optional validated description.
    pub description: Option<HookDescription>,
}

/// Input for a hook mutation with no JSON body.
#[derive(Clone, Debug)]
pub struct HookMutationCommand {
    /// Authorized mutation context.
    pub context: ManagementContext,
    /// Target Silicon.
    pub silicon_id: SiliconId,
    /// Target hook.
    pub hook_id: HookId,
}

/// Input for a non-idempotency-keyed hook deletion.
#[derive(Clone, Debug)]
pub struct DeleteHookCommand {
    /// IAM-derived authorization facts for this request.
    pub authorization: AuthorizationContext,
    /// Target Silicon.
    pub silicon_id: SiliconId,
    /// Target hook.
    pub hook_id: HookId,
    /// Correlation identifier assigned at the HTTP boundary.
    pub request_id: Option<String>,
}

/// Input for changing the desired enabled state of one or more hooks.
#[derive(Clone, Debug)]
pub struct SetHooksEnabledCommand {
    /// IAM-derived authorization facts for this request.
    pub authorization: AuthorizationContext,
    /// Target Silicon.
    pub silicon_id: SiliconId,
    /// Target hooks. The application validates uniqueness and the batch bound.
    pub hook_ids: Vec<HookId>,
    /// Desired ingress state: `true` enables and `false` disables.
    pub enabled: bool,
    /// Correlation identifier assigned at the HTTP boundary.
    pub request_id: Option<String>,
}

/// Privileged IAM default-hook provisioning input.
#[derive(Clone, Debug)]
pub struct ProvisionIamHookCommand {
    /// IAM service identity authenticated at the integration boundary.
    pub actor: ActorRef,
    /// Organization supplied by the authenticated IAM service.
    pub organization_id: OrganizationId,
    /// Silicon whose default hook is being provisioned.
    pub silicon_id: SiliconId,
    /// Caller-supplied idempotency key.
    pub idempotency_key: String,
    /// Correlation identifier assigned at the HTTP boundary.
    pub request_id: Option<String>,
}

/// Raw public-ingress input preserved for signature and idempotency checks.
#[derive(Clone, Debug)]
pub struct AcceptEventCommand {
    /// Silicon encoded in the endpoint path.
    pub silicon_id: SiliconId,
    /// Six-character endpoint routing key.
    pub endpoint_key: crate::domain::EndpointKey,
    /// Exact timestamp header value.
    pub timestamp: String,
    /// Exact signature header value.
    pub signature: String,
    /// Caller-supplied ingress idempotency key.
    pub idempotency_key: String,
    /// Exact, unmodified request body bytes.
    pub body: bytes::Bytes,
    /// Request ID used when an event omits its own trace ID.
    pub request_id: String,
}

/// Authorized event-history query.
#[derive(Clone, Debug)]
pub struct ListEventsCommand {
    /// IAM-derived authorization facts for this request.
    pub authorization: AuthorizationContext,
    /// Target Silicon.
    pub silicon_id: SiliconId,
    /// Optional hook filter.
    pub hook_id: Option<HookId>,
    /// Optional exact event-type filter.
    pub event_type: Option<String>,
    /// Number of rows, from 1 through 10,000.
    pub limit: u32,
    /// Authenticated keyset cursor from an earlier page.
    pub cursor: Option<String>,
}

/// Hook metadata paired with its bounded one-time signing credential.
#[derive(Debug)]
pub struct HookWithSecret {
    /// Created or replayed hook metadata.
    pub hook: Hook,
    /// Plaintext secret held only for the immediate response.
    pub signing_secret: SigningSecret,
}

/// Retained event page with an authenticated continuation cursor.
#[derive(Clone, Debug)]
pub struct EventPage {
    /// Retained events in newest-first order.
    pub items: Vec<EventRecord>,
    /// Opaque cursor for the next page.
    pub next_cursor: Option<String>,
}
