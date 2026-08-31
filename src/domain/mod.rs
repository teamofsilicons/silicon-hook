//! Transport- and persistence-independent Silicon Hook concepts and policy.
//!
//! Constructors validate values at the boundary so application and
//! infrastructure code can rely on the invariants represented by these types.

mod actor;
mod cursor;
mod error;
mod event;
mod hook;
mod id;
mod policy;

pub use actor::{ActorKind, ActorRef, AuthorizationContext, Capability, OrganizationRole};
pub use cursor::{EventCursor, EventCursorScope, EventFilter};
pub use error::{DomainError, EntropyError, TransitionError};
pub use event::{
    DeliveryDecision, DeliveryPolicy, DeliveryState, DeliveryStatus, EventEnvelope,
    EventEnvelopeInput, EventRecord, EventRecordSnapshot, EventType, RequestDigest, SchemaVersion,
    TraceId,
};
pub use hook::{
    ENCRYPTION_NONCE_BYTES, EncryptedSecret, EncryptionKeyId, EndpointKey, HOOK_RECOVERY_DAYS,
    Hook, HookDescription, HookName, HookSnapshot, HookStatus, NewHook, SIGNING_SECRET_BYTES,
    SIGNING_SECRET_PREFIX, SigningSecret,
};
pub use id::{ActorId, ApplicationId, EventId, HookId, OrganizationId, SiliconId};
pub use policy::{Action, AuthorizationDecision, authorize};
