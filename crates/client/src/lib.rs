//! Silicon Hook's stateless application client.
//!
//! Create a [`Client`], exchange an IAM short-lived token with [`Client::login`],
//! and keep the returned [`RelaySession`] alive for automatic delivery and
//! refresh. [`Client::with_token`] and
//! [`Client::with_test_key`] create immutable configurations; they never read or
//! write an authentication file. Every HTTP call is version-negotiated and
//! pinned. The `hook` CLI stores profiles and uses this library for all actions.

mod client;
mod environments;
mod hooks;
pub mod local;
pub mod models;
mod relay;
mod session;
mod stream;
pub mod updater;
pub use relay::{Recipient, Relay, RelayNotice};
pub use session::{LoginOptions, RelaySession};

pub use client::{Client, Error, Mutation, Result};
pub use models::Secret;
pub use stream::{EventData, ServerFrame, Stream};
