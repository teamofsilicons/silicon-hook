//! # silicon-hook-client
//!
//! The stateless Rust client for [Silicon Hook](https://docs.hook.teamofsilicons.com):
//! signed provider webhooks that belong to a Silicon. The `hook` CLI is built on
//! this crate only. Nothing here stores credentials, starts a listener, or
//! updates itself; the host keeps its tokens and decides when to call.
//!
//! * [`signin`]: get a Silicon Accounts access token issued to Hook as Hook's
//!   public client: the device flow for Carbons, a short-lived token for
//!   Silicons, refresh and sign-out.
//! * [`Client`]: Hook API v3 with that token (`Authorization: Bearer`): a
//!   Silicon's hooks, their history, who has access, and delivery status.
//! * [`delivery`]: check Ting callbacks and fetch the events they point to.
//!
//! ```no_run
//! # async fn demo() -> silicon_hook_client::Result<()> {
//! use silicon_hook_client::{Client, Mutation, models::CreateHook, signin::SignIn};
//!
//! // A Silicon hands over a token from `silicon-accounts login --app hook -q`.
//! let tokens = SignIn::production()?.exchange_slt("slt_...").await?;
//! let hook = Client::production()?.with_token(tokens.access_token.expose());
//! let me = tokens.account.expect("token responses carry the account");
//! let created = hook
//!     .create_hook(&me.uuid, &CreateHook { name: "GitHub".into(), ..Default::default() }, &Mutation::new())
//!     .await?;
//! println!("give GitHub {}", created.hook.endpoint_url);
//! # Ok(()) }
//! ```
//!
//! Identifiers: an account's `uuid` never changes and is what Hook stores; its
//! `c:`/`si:` id is what people see and can change. Every `silicon` argument
//! accepts either.

mod access;
mod client;
pub mod delivery;
mod error;
mod hooks;
pub mod models;
pub mod signin;
pub mod support;

pub use client::{API_VERSION, Client, DEFAULT_URL, Mutation};
pub use error::{ApiError, Error, Result};
pub use models::Secret;
