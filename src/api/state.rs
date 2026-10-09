//! Cloneable dependencies shared by HTTP handlers.

use crate::{application::HookApplication, infrastructure::iam::IamClient};

/// Fully initialized API dependency graph.
#[derive(Clone, Debug)]
pub(super) struct ApiState {
    pub(super) application: HookApplication,
    pub(super) iam: IamClient,
    pub(super) ting: crate::infrastructure::ting::TingClient,
    pub(super) trusted_proxy_hops: u8,
}
