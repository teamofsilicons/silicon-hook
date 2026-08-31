//! Durable DM delivery and retention worker composition root.

mod delivery;
mod maintenance;

use std::{fmt, time::Duration};

use anyhow::Context as _;
use tokio::{
    sync::watch,
    task::JoinSet,
    time::{MissedTickBehavior, interval},
};

use crate::{
    config::{WorkerProcessSettings, WorkerSettings},
    infrastructure::{
        dm::DmClient,
        postgres::{PostgresStore, connect},
    },
    shutdown,
};

const MAX_BATCH_SIZE: usize = 1_000;
const MAX_DELIVERY_CONCURRENCY: usize = 1_000;
const MAX_MAINTENANCE_BATCH_SIZE: usize = 10_000;
const MAX_MAINTENANCE_BATCHES_PER_CYCLE: u16 = 1_000;

#[derive(Clone, Copy, Debug)]
enum WorkerLoop {
    Delivery,
    Maintenance,
}

impl fmt::Display for WorkerLoop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delivery => formatter.write_str("delivery"),
            Self::Maintenance => formatter.write_str("maintenance"),
        }
    }
}

/// Runs delivery and maintenance loops until graceful shutdown.
///
/// # Errors
///
/// Returns an error when PostgreSQL or a required worker dependency cannot
/// start, a supervised loop terminates unexpectedly, or graceful shutdown
/// exceeds its configured deadline.
pub async fn run(settings: WorkerProcessSettings) -> anyhow::Result<()> {
    anyhow::ensure!(
        settings.worker.batch_size.get() <= MAX_BATCH_SIZE,
        "worker batch size must not exceed {MAX_BATCH_SIZE}"
    );
    anyhow::ensure!(
        settings.worker.delivery_concurrency.get() <= MAX_DELIVERY_CONCURRENCY,
        "worker delivery concurrency must not exceed {MAX_DELIVERY_CONCURRENCY}"
    );
    anyhow::ensure!(
        settings.worker.maintenance_batch_size.get() <= MAX_MAINTENANCE_BATCH_SIZE,
        "maintenance batch size must not exceed {MAX_MAINTENANCE_BATCH_SIZE}"
    );
    anyhow::ensure!(
        settings.worker.maintenance_batches_per_cycle.get() <= MAX_MAINTENANCE_BATCHES_PER_CYCLE,
        "maintenance batches per cycle must not exceed {MAX_MAINTENANCE_BATCHES_PER_CYCLE}"
    );
    anyhow::ensure!(
        !settings.worker.maintenance_interval.is_zero(),
        "worker maintenance interval must be greater than zero"
    );

    let pool = connect(&settings.database, "silicon-hook-worker")
        .await
        .context("failed to connect worker to PostgreSQL")?;
    let store = PostgresStore::new(pool);
    store
        .ready_for(crate::infrastructure::postgres::RuntimeDatabaseRole::Worker)
        .await
        .context("worker PostgreSQL readiness check failed")?;
    let dm = DmClient::new(&settings.dm, settings.worker.max_retry_delay)
        .context("failed to construct DM client")?;

    tracing::info!(
        batch_size = settings.worker.batch_size.get(),
        delivery_concurrency = settings.worker.delivery_concurrency.get(),
        poll_interval_ms = settings.worker.poll_interval.as_millis(),
        maintenance_batch_size = settings.worker.maintenance_batch_size.get(),
        maintenance_batches_per_cycle = settings.worker.maintenance_batches_per_cycle.get(),
        maintenance_interval_seconds = settings.worker.maintenance_interval.as_secs(),
        "Silicon Hook worker started"
    );

    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let mut tasks = JoinSet::new();
    tasks.spawn(delivery_loop(
        store.clone(),
        dm,
        settings.worker.clone(),
        shutdown_receiver.clone(),
    ));
    tasks.spawn(maintenance_loop(
        store.clone(),
        settings.worker.clone(),
        shutdown_receiver,
    ));

    let unexpected_exit = tokio::select! {
        () = shutdown::signal() => None,
        task = tasks.join_next() => Some(task),
    };
    if shutdown_sender.send(true).is_err() {
        tracing::debug!("worker loops had already stopped before shutdown broadcast");
    }

    let task_error = unexpected_exit.map(unexpected_task_error);
    let shutdown_result = drain_tasks(&mut tasks, settings.shutdown.timeout).await;
    store.pool().close().await;

    if let Some(error) = task_error {
        return Err(error);
    }
    shutdown_result?;
    tracing::info!("Silicon Hook worker stopped");
    Ok(())
}

async fn delivery_loop(
    store: PostgresStore,
    dm: DmClient,
    settings: WorkerSettings,
    mut shutdown: watch::Receiver<bool>,
) -> WorkerLoop {
    loop {
        if shutdown_requested(&shutdown) {
            return WorkerLoop::Delivery;
        }

        let should_pause = match delivery::process_delivery_batch(&store, &dm, &settings).await {
            Ok(0) => true,
            Ok(processed) => {
                tracing::debug!(processed, "DM delivery batch completed");
                false
            }
            Err(error) => {
                tracing::error!(
                    error_code = error.diagnostic_code(),
                    "failed to claim or process DM delivery batch"
                );
                true
            }
        };

        if should_pause {
            if wait_or_shutdown(&mut shutdown, settings.poll_interval).await {
                return WorkerLoop::Delivery;
            }
        } else {
            tokio::task::yield_now().await;
        }
    }
}

async fn maintenance_loop(
    store: PostgresStore,
    settings: WorkerSettings,
    mut shutdown: watch::Receiver<bool>,
) -> WorkerLoop {
    let mut schedule = interval(settings.maintenance_interval);
    schedule.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || shutdown_requested(&shutdown) {
                    return WorkerLoop::Maintenance;
                }
            }
            _instant = schedule.tick() => {
                if shutdown_requested(&shutdown) {
                    return WorkerLoop::Maintenance;
                }
                maintenance::run_maintenance_cycle(&store, &settings).await;
            }
        }
    }
}

async fn wait_or_shutdown(shutdown: &mut watch::Receiver<bool>, duration: Duration) -> bool {
    if shutdown_requested(shutdown) {
        return true;
    }

    tokio::select! {
        () = tokio::time::sleep(duration) => false,
        changed = shutdown.changed() => changed.is_err() || shutdown_requested(shutdown),
    }
}

fn shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}

fn unexpected_task_error(
    result: Option<Result<WorkerLoop, tokio::task::JoinError>>,
) -> anyhow::Error {
    match result {
        Some(Ok(worker_loop)) => anyhow::anyhow!("{worker_loop} worker loop stopped unexpectedly"),
        Some(Err(error)) => anyhow::Error::new(error).context("worker loop panicked"),
        None => anyhow::anyhow!("all worker loops stopped unexpectedly"),
    }
}

async fn drain_tasks(
    tasks: &mut JoinSet<WorkerLoop>,
    shutdown_timeout: Duration,
) -> anyhow::Result<()> {
    let drain = async {
        while let Some(result) = tasks.join_next().await {
            result.context("worker loop panicked during shutdown")?;
        }
        anyhow::Ok(())
    };

    match tokio::time::timeout(shutdown_timeout, drain).await {
        Ok(result) => result,
        Err(_elapsed) => {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            anyhow::bail!("worker graceful shutdown deadline elapsed")
        }
    }
}
