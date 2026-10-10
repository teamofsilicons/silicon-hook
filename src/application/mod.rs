//! Transport-independent orchestration of Hook use cases.

mod access;
mod accounts_events;
mod clock;
mod commands;
mod error;
mod history;
mod hooks;
mod ingress;
mod service;
mod sharing;

pub use access::{AccessSummary, AccessibleSilicon, CUSTODIAN_FRESHNESS, PUBLIC_ID_FRESHNESS};
pub use accounts_events::WebhookOutcome;
pub use clock::{Clock, SystemClock};
pub use commands::{
    ConnectAccountsHookCommand, CreateHookCommand, DeleteHookCommand, HistoryPage,
    HookMutationCommand, HookPatch, HookWithSecret, ListHistoryCommand, ManagementContext,
    ReceiveOutcome, ReceiveRequestCommand, SetHooksEnabledCommand, SigningInput, SigningPatch,
    UpdateHookCommand,
};
pub use error::ApplicationError;
pub use service::HookApplication;
