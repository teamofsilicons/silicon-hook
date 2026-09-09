//! Cloneable dependencies shared by HTTP handlers.

use crate::{
    application::HookApplication,
    config::RealtimeSettings,
    infrastructure::{iam::IamClient, postgres::DeliveryWakeups},
};

/// Fully initialized API dependency graph.
#[derive(Clone, Debug)]
pub(super) struct ApiState {
    pub(super) application: HookApplication,
    pub(super) environments: Option<crate::application::environments::EnvironmentService>,
    pub(super) iam: IamClient,
    pub(super) trusted_proxy_hops: u8,
    pub(super) realtime: RealtimeSettings,
    pub(super) wakeups: DeliveryWakeups,
}
