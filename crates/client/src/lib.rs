//! Silicon Hook's stateless application client.
//!
//! Create a [`Client`], exchange an IAM short-lived token with [`Client::login`],
//! and let the host retain and refresh the returned tokens. [`Client::with_token`] and
//! [`Client::with_test_key`] create immutable configurations; they never read or
//! write an authentication file. Every HTTP call is version-negotiated and
//! pinned to API v2. Internal Ting callbacks use [`delivery`]; the host owns
//! receiving, durable acceptance, and acknowledgment.

mod client;
pub mod delivery;
mod environments;
mod hooks;
pub mod models;
pub mod support;
pub mod updater;

pub use client::{Client, Error, Mutation, Result};
pub use models::Secret;
