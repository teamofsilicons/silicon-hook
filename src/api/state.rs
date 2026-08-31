//! Cloneable dependencies shared by HTTP handlers.

use url::Url;

use crate::{application::HookApplication, infrastructure::iam::IamClient};

/// Fully initialized API dependency graph.
#[derive(Clone, Debug)]
pub(super) struct ApiState {
    pub(super) application: HookApplication,
    pub(super) iam: IamClient,
    pub(super) allow_local_credentials: bool,
    pub(super) public_base_url: Url,
}
