//! Transport- and persistence-independent Silicon Hook concepts and policy.
//!
//! Constructors validate values at the boundary so application and
//! infrastructure code can rely on the invariants represented by these types.

mod account;
mod actor;
mod cursor;
mod error;
mod event;
mod hook;
mod id;
mod policy;
pub mod request;
pub mod safety;
pub mod signature;

pub use account::{AccountUuid, Actor, MAX_ACCOUNT_UUID_LENGTH, PublicId, SiliconRef};
pub use actor::{ActorKind, ActorRef};
pub use cursor::{HistoryCollection, HistoryCursor, HistoryCursorScope, HistoryFilter};
pub use error::{DomainError, EntropyError, TransitionError};
pub use event::{
    BlockReason, BlockedRequest, BlockedRequestSnapshot, DeliverySequence, EventRecord,
    EventRecordSnapshot, LOG_RETENTION, MAX_REASON_DETAIL_LENGTH, delivery_summary,
};
pub use hook::{
    ENCRYPTION_NONCE_BYTES, ENCRYPTION_TAG_BYTES, ENDPOINT_KEY_LENGTH, EncryptedSecret,
    EncryptionKeyId, EndpointKey, HOOK_RECOVERY_DAYS, Hook, HookDescription, HookName,
    HookSnapshot, HookStatus, HookTimeZone, HookUpdate, NewHook, SIGNING_SECRET_GENERATED_LENGTH,
    SIGNING_SECRET_PREFIX, SigningPolicy, SigningSecret,
};
pub use id::{ActorId, BlockedRequestId, EventId, HookId, SiliconId};
pub use policy::{
    Access, Action, AuthorizationContext, AuthorizationDecision, GrantLevel, authorize,
};
