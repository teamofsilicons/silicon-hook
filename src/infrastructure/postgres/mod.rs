//! PostgreSQL persistence and durable coordination.
//!
//! Every cross-table invariant is committed in one transaction. Queries use
//! runtime-checked `SQLx` APIs so builds never require a live database or an
//! offline query cache.

mod error;
mod events;
mod hooks;
mod idempotency;
mod maintenance;
mod models;
mod outbox;
mod readiness;
mod schema_contract;
mod types;

use std::str::FromStr as _;

use secrecy::ExposeSecret as _;
use sqlx::{
    ConnectOptions as _, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};

use crate::config::DatabaseSettings;
use crate::domain::ActorKind;

pub use error::{Result, StoreError};
pub use readiness::RuntimeDatabaseRole;
pub use types::{
    AuditAction, AuditContext, ClaimedDelivery, CreateHook, CreateHookOutcome, DeliveryAttempt,
    DeliveryOutcome, EventPage, EventPageRequest, HookMutation, IdempotencyScope,
    IngressAcceptance, IngressHookResolution, MaintenanceResult, NewEvent, PersistedResponse,
    ProvisionHookOutcome, RestoreHook, RestoreHookOutcome, RotateSecret, RotateSecretOutcome,
};
pub(crate) use types::{MaintenanceBatch, MaintenanceTask};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Maximum interval in which an encrypted one-time secret may be replayed.
pub const SECRET_REPLAY_WINDOW: time::Duration = time::Duration::minutes(10);
/// Maximum estimated serialized size of one event-history page.
///
/// A single record is always returned even if it exceeds this budget. The
/// ingress limit keeps that exceptional case bounded, while the continuation
/// cursor prevents a caller-selected item limit from multiplying memory use.
pub const EVENT_HISTORY_PAGE_BYTE_BUDGET: usize = 16 * 1024 * 1024;

/// A cheap, cloneable handle to the PostgreSQL persistence adapter.
#[derive(Clone, Debug)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Wraps an existing pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Returns the underlying pool for composition-level health checks.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Opens a bounded PostgreSQL connection pool.
///
/// Each acquired connection uses UTC and a server-side statement timeout. The
/// application name makes individual Silicon Hook processes identifiable in
/// PostgreSQL activity and logs.
///
/// # Errors
///
/// Returns an error for an invalid URL, a failed connection, or an invalid
/// session setting.
pub async fn connect(
    settings: &DatabaseSettings,
    application_name: &str,
) -> anyhow::Result<PgPool> {
    let options = PgConnectOptions::from_str(settings.url.expose_secret())?
        .application_name(application_name)
        .disable_statement_logging();
    let statement_timeout_ms = settings.statement_timeout.as_millis().to_string();

    let pool = PgPoolOptions::new()
        .min_connections(settings.min_connections)
        .max_connections(settings.max_connections.get())
        .acquire_timeout(settings.acquire_timeout)
        .after_connect(move |connection, _metadata| {
            let statement_timeout_ms = statement_timeout_ms.clone();
            Box::pin(async move {
                sqlx::query("SET TIME ZONE 'UTC'")
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SELECT set_config('statement_timeout', $1, false)")
                    .bind(statement_timeout_ms)
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await?;

    Ok(pool)
}

/// Applies all embedded migrations under an advisory lock managed by `SQLx`.
///
/// # Errors
///
/// Returns an error when migration metadata cannot be read or a migration
/// statement fails.
pub async fn migrate(pool: &PgPool) -> Result<()> {
    MIGRATOR.run(pool).await.map_err(StoreError::from)
}

const fn actor_kind_as_str(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Carbon => "carbon",
        ActorKind::Silicon => "silicon",
        ActorKind::Application => "application",
        ActorKind::Service => "service",
    }
}
