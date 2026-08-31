//! Structured process telemetry without secret-bearing payloads.

use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::config::{ProcessSettings, RuntimeEnvironment};

/// Installs telemetry from the non-secret process settings shared by every
/// executable.
///
/// # Errors
///
/// Returns an error for an invalid filter or an already-installed subscriber.
pub fn init(settings: &ProcessSettings) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(&settings.log_filter)?;
    let registry = tracing_subscriber::registry().with(filter);

    match settings.environment {
        RuntimeEnvironment::Development | RuntimeEnvironment::Test => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .compact()
                    .with_target(true)
                    .with_thread_ids(false),
            )
            .try_init()?,
        RuntimeEnvironment::Production => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(true)
                    .with_span_list(false),
            )
            .try_init()?,
    }
    Ok(())
}
