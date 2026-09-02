//! Explicit inputs and outputs for application use cases.

use std::net::IpAddr;

use bytes::Bytes;

use crate::domain::{
    ActorRef, AuthorizationContext, BlockedRequest, BlockedRequestId, DeliveryCursor, EndpointKey,
    EventId, EventRecord, Hook, HookDescription, HookId, HookName, HookTimeZone, OrganizationId,
    SigningSecret, SiliconId,
    signature::{
        Expression, SecretEncoding, SignatureAlgorithm, SignatureConfig, SignatureEncoding,
    },
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

/// Validated signing policy input for creation or update.
#[derive(Clone, Debug)]
pub struct SigningInput {
    /// Whether unverified requests are withheld from delivery.
    pub required: bool,
    /// Verification scheme.
    pub config: SignatureConfig,
    /// Provider-issued shared secret; generated when absent and needed.
    pub secret: Option<SigningSecret>,
}

/// Partial signing policy merged onto defaults (create) or the current policy
/// (update). `public_key: Some(None)` clears the key.
#[derive(Clone, Debug, Default)]
pub struct SigningPatch {
    /// Whether unverified requests are withheld from delivery.
    pub required: Option<bool>,
    /// Signature primitive.
    pub algorithm: Option<SignatureAlgorithm>,
    /// Expression producing the signed bytes.
    pub payload: Option<Expression>,
    /// Expression locating the presented signature.
    pub signature: Option<Expression>,
    /// Encoding of the presented signature.
    pub signature_encoding: Option<SignatureEncoding>,
    /// Encoding of the stored secret text.
    pub secret_encoding: Option<SecretEncoding>,
    /// Provider public key, or an explicit clear.
    #[allow(clippy::option_option)]
    pub public_key: Option<Option<String>>,
    /// Provider-issued shared secret.
    pub secret: Option<SigningSecret>,
}

impl SigningPatch {
    /// Merges the patch onto a base policy.
    #[must_use]
    pub fn resolve(self, base: &SignatureConfig, base_required: bool) -> SigningInput {
        SigningInput {
            required: self.required.unwrap_or(base_required),
            config: SignatureConfig {
                algorithm: self.algorithm.unwrap_or(base.algorithm),
                payload: self.payload.unwrap_or_else(|| base.payload.clone()),
                signature: self.signature.unwrap_or_else(|| base.signature.clone()),
                signature_encoding: self.signature_encoding.unwrap_or(base.signature_encoding),
                secret_encoding: self.secret_encoding.unwrap_or(base.secret_encoding),
                public_key: self.public_key.unwrap_or_else(|| base.public_key.clone()),
            },
            secret: self.secret,
        }
    }
}

/// Input for normal hook creation.
#[derive(Clone, Debug)]
pub struct CreateHookCommand {
    /// Authorized mutation context.
    pub context: ManagementContext,
    /// Target Silicon.
    pub silicon_id: SiliconId,
    /// Validated display and provider name.
    pub name: HookName,
    /// Optional validated description.
    pub description: Option<HookDescription>,
    /// Zone used for delivery summaries.
    pub time_zone: HookTimeZone,
    /// Signature policy merged onto the Standard Webhooks defaults.
    pub signing: SigningPatch,
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

/// Partial replacement of hook metadata, activation, and signing policy.
#[derive(Clone, Debug, Default)]
pub struct HookPatch {
    /// New display and provider name.
    pub name: Option<HookName>,
    /// New description, or an explicit clear.
    #[allow(clippy::option_option)]
    pub description: Option<Option<HookDescription>>,
    /// New summary zone.
    pub time_zone: Option<HookTimeZone>,
    /// Desired activation state.
    pub enabled: Option<bool>,
    /// Signing policy changes merged onto the current policy.
    pub signing: Option<SigningPatch>,
}

impl HookPatch {
    /// Reports whether anything other than activation is changing.
    #[must_use]
    pub const fn changes_metadata(&self) -> bool {
        self.name.is_some()
            || self.description.is_some()
            || self.time_zone.is_some()
            || self.signing.is_some()
    }
}

/// Input for updating one hook.
#[derive(Clone, Debug)]
pub struct UpdateHookCommand {
    /// IAM-derived authorization facts for this request.
    pub authorization: AuthorizationContext,
    /// Target Silicon.
    pub silicon_id: SiliconId,
    /// Target hook.
    pub hook_id: HookId,
    /// Fields to change.
    pub patch: HookPatch,
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

/// Raw public-ingress input preserved exactly as the provider sent it.
#[derive(Clone, Debug)]
pub struct ReceiveRequestCommand {
    /// Silicon encoded in the endpoint path.
    pub silicon_id: SiliconId,
    /// Six-character endpoint routing key.
    pub endpoint_key: EndpointKey,
    /// HTTP method token.
    pub method: String,
    /// Request path as received.
    pub path: String,
    /// Raw query string without `?`, if any.
    pub query: Option<String>,
    /// Header fields in wire order.
    pub headers: Vec<(String, String)>,
    /// Exact, unmodified request body bytes.
    pub body: Bytes,
    /// Client address after trusted-proxy resolution.
    pub remote_ip: IpAddr,
}

/// What happened to a received provider request.
#[derive(Clone, Debug)]
pub enum ReceiveOutcome {
    /// The request verified and was appended to the delivery stream.
    Accepted(EventRecord),
    /// The request could not be verified and was withheld.
    Blocked(BlockedRequest),
}

impl ReceiveOutcome {
    /// Returns the opaque receipt identifier reported to the sender.
    ///
    /// Accepted and blocked receipts are indistinguishable so an attacker
    /// cannot use the response as a signature oracle.
    #[must_use]
    pub fn receipt_id(&self) -> uuid::Uuid {
        match self {
            Self::Accepted(event) => event.id().as_uuid(),
            Self::Blocked(blocked) => blocked.id().as_uuid(),
        }
    }

    /// Returns the event identifier when the request was accepted.
    #[must_use]
    pub const fn event_id(&self) -> Option<EventId> {
        match self {
            Self::Accepted(event) => Some(event.id()),
            Self::Blocked(_) => None,
        }
    }

    /// Returns the blocked identifier when the request was withheld.
    #[must_use]
    pub const fn blocked_id(&self) -> Option<BlockedRequestId> {
        match self {
            Self::Accepted(_) => None,
            Self::Blocked(blocked) => Some(blocked.id()),
        }
    }
}

/// Authorized history query for verified or blocked requests.
#[derive(Clone, Debug)]
pub struct ListHistoryCommand {
    /// IAM-derived authorization facts for this request.
    pub authorization: AuthorizationContext,
    /// Target Silicon.
    pub silicon_id: SiliconId,
    /// Optional hook filter.
    pub hook_id: Option<HookId>,
    /// Number of rows, from 1 through 10,000.
    pub limit: u32,
    /// Authenticated keyset cursor from an earlier page.
    pub cursor: Option<String>,
}

/// Retained history page with an authenticated continuation cursor.
#[derive(Clone, Debug)]
pub struct HistoryPage<T> {
    /// Records in newest-first order.
    pub items: Vec<T>,
    /// Opaque cursor for the next page.
    pub next_cursor: Option<String>,
}

/// Authorized pull of ordered deliveries.
#[derive(Clone, Debug)]
pub struct PullDeliveriesCommand {
    /// IAM-derived authorization facts for this request.
    pub authorization: AuthorizationContext,
    /// Target Silicon stream.
    pub silicon_id: SiliconId,
    /// Explicit stream position; the consumer's acknowledged cursor when absent.
    pub after_sequence: Option<i64>,
    /// Number of events, from 1 through 1,000.
    pub limit: u32,
}

/// Ordered deliveries after a position.
#[derive(Clone, Debug)]
pub struct DeliveryBatch {
    /// Events in ascending sequence order.
    pub items: Vec<EventRecord>,
    /// The consumer's acknowledged position.
    pub cursor: DeliveryCursor,
    /// Highest sequence allocated for the Silicon.
    pub latest_sequence: i64,
}

/// Authorized acknowledgment of ordered deliveries.
#[derive(Clone, Debug)]
pub struct AcknowledgeDeliveriesCommand {
    /// IAM-derived authorization facts for this request.
    pub authorization: AuthorizationContext,
    /// Target Silicon stream.
    pub silicon_id: SiliconId,
    /// Highest sequence the consumer has processed.
    pub through_sequence: i64,
}

/// Hook metadata paired with its bounded one-time signing credential.
#[derive(Debug)]
pub struct HookWithSecret {
    /// Created or replayed hook metadata.
    pub hook: Hook,
    /// Plaintext secret held only for the immediate response.
    pub signing_secret: Option<SigningSecret>,
}
