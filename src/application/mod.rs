//! Transport-independent orchestration of Hook use cases.

mod clock;
mod commands;
mod error;
mod history;
mod hooks;
mod ingress;
mod service;

pub use clock::{Clock, SystemClock};
pub use commands::{
    BindIamHookSecretCommand, ConnectIamHookCommand, CreateHookCommand, DeleteHookCommand,
    HistoryPage, HookMutationCommand, HookPatch, HookWithSecret, ListHistoryCommand,
    ManagementContext, ReceiveOutcome, ReceiveRequestCommand, SetHooksEnabledCommand, SigningInput,
    SigningPatch, UpdateHookCommand,
};
pub use error::ApplicationError;
pub use service::HookApplication;
