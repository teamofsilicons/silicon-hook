//! Transport-independent orchestration of Hook use cases.

mod clock;
mod commands;
mod error;
mod service;

pub use clock::{Clock, SystemClock};
pub use commands::{
    AcceptEventCommand, CreateHookCommand, DeleteHookCommand, EventPage, HookMutationCommand,
    HookWithSecret, ListEventsCommand, ManagementContext, ProvisionIamHookCommand,
    SetHooksEnabledCommand,
};
pub use error::ApplicationError;
pub use service::HookApplication;
