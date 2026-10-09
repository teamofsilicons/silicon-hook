//! Cloneable dependencies shared by HTTP handlers.

use crate::application::HookApplication;

/// Fully initialized API dependency graph.
#[derive(Clone, Debug)]
pub(super) struct ApiState {
    pub(super) application: HookApplication,
    pub(super) trusted_proxy_hops: u8,
}
