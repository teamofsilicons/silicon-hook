//! Retention maintenance worker composition root.

mod maintenance;

use std::time::Duration;

use anyhow::Context as _;
use tokio::{
    sync::watch,
    time::{MissedTickBehavior, interval},
};

use crate::{
    config::{MaintenanceSettings, WorkerProcessSettings},
    infrastructure::postgres::{PostgresStore, RuntimeDatabaseRole, connect},
    shutdown,
};

const MAX_MAINTENANCE_BATCH_SIZE: usize = 10_000;
const MAX_MAINTENANCE_BATCHES_PER_CYCLE: u16 = 1_000;

/// Runs the maintenance loop until graceful shutdown.
///
/// # Errors
///
/// Returns an error when PostgreSQL cannot start, the loop terminates
/// unexpectedly, or graceful shutdown exceeds its configured deadline.
pub async fn run(settings: WorkerProcessSettings) -> anyhow::Result<()> {
    anyhow::ensure!(
        settings.maintenance.batch_size.get() <= MAX_MAINTENANCE_BATCH_SIZE,
        "maintenance batch size must not exceed {MAX_MAINTENANCE_BATCH_SIZE}"
    );
    anyhow::ensure!(
        settings.maintenance.batches_per_cycle.get() <= MAX_MAINTENANCE_BATCHES_PER_CYCLE,
        "maintenance batches per cycle must not exceed {MAX_MAINTENANCE_BATCHES_PER_CYCLE}"
    );
    anyhow::ensure!(
        !settings.maintenance.interval.is_zero(),
        "maintenance interval must be greater than zero"
    );

    let pool = connect(&settings.database, "silicon-hook-worker")
        .await
        .context("failed to connect worker to PostgreSQL")?;
    let store = PostgresStore::new(pool);
    store
        .ready_for(RuntimeDatabaseRole::Worker)
        .await
        .context("worker PostgreSQL readiness check failed")?;

    tracing::info!(
        maintenance_batch_size = settings.maintenance.batch_size.get(),
        maintenance_batches_per_cycle = settings.maintenance.batches_per_cycle.get(),
        maintenance_interval_seconds = settings.maintenance.interval.as_secs(),
        "Silicon Hook worker started"
    );

    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let mut task = tokio::spawn(maintenance_loop(
        store.clone(),
        settings.maintenance.clone(),
        shutdown_receiver,
    ));

    let unexpected_exit = tokio::select! {
        () = shutdown::signal() => None,
        result = &mut task => Some(result),
    };
    if shutdown_sender.send(true).is_err() {
        tracing::debug!("maintenance loop had already stopped before shutdown broadcast");
    }

    let task_error = unexpected_exit.map(|result| match result {
        Ok(()) => anyhow::anyhow!("maintenance loop stopped unexpectedly"),
        Err(error) => anyhow::Error::new(error).context("maintenance loop panicked"),
    });
    let shutdown_result = drain(&mut task, settings.shutdown.timeout).await;
    store.pool().close().await;

    if let Some(error) = task_error {
        return Err(error);
    }
    shutdown_result?;
    tracing::info!("Silicon Hook worker stopped");
    Ok(())
}

async fn maintenance_loop(
    store: PostgresStore,
    settings: MaintenanceSettings,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut schedule = interval(settings.interval);
    schedule.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            _instant = schedule.tick() => {
                if *shutdown.borrow() {
                    return;
                }
                maintenance::run_maintenance_cycle(&store, &settings).await;
            }
        }
    }
}

async fn drain(
    task: &mut tokio::task::JoinHandle<()>,
    shutdown_timeout: Duration,
) -> anyhow::Result<()> {
    match tokio::time::timeout(shutdown_timeout, &mut *task).await {
        Ok(result) => result.context("maintenance loop panicked during shutdown"),
        Err(_elapsed) => {
            task.abort();
            let _aborted = (&mut *task).await;
            anyhow::bail!("worker graceful shutdown deadline elapsed")
        }
    }
}
