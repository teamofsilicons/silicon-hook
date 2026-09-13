//! Structured process telemetry without secret-bearing payloads.

pub(crate) mod events;
pub(crate) mod station;

use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

use crate::config::{ProcessSettings, RuntimeEnvironment};

/// Installs telemetry from the non-secret process settings shared by every
/// executable.
///
/// # Errors
///
/// Returns an error for an invalid filter or an already-installed subscriber.
pub fn init(settings: &ProcessSettings) -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
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

/// Flushes a bounded batch of persisted diagnostics to the configured Space Station table.
///
/// Unconfigured or opted-out processes do nothing. Sandbox export requires an explicit
/// sandbox destination and never uses the production table key.
///
/// # Errors
/// Returns database or local exporter initialization failures; rows remain pending.
pub async fn flush_events(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    station::export_pending(pool).await
}
