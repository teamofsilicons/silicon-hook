//! Periodic bounded and fair retention maintenance.

use crate::{
    config::WorkerSettings,
    infrastructure::postgres::{
        MaintenanceBatch, MaintenanceResult, MaintenanceTask, PostgresStore,
    },
};

pub(super) async fn run_maintenance_cycle(store: &PostgresStore, settings: &WorkerSettings) {
    let batch_size = match u32::try_from(settings.maintenance_batch_size.get()) {
        Ok(batch_size) => batch_size,
        Err(_error) => {
            tracing::error!("maintenance batch size exceeds the supported integer range");
            return;
        }
    };
    let mut active_tasks = [true; MaintenanceTask::ALL.len()];
    let mut result = MaintenanceResult::default();
    let mut failed_tasks = 0_u8;

    for _round in 0..settings.maintenance_batches_per_cycle.get() {
        for (index, task) in MaintenanceTask::ALL.into_iter().enumerate() {
            if !active_tasks[index] {
                continue;
            }

            match store.run_maintenance_task(task, batch_size).await {
                Ok(batch) => {
                    add_batch(&mut result, task, batch);
                    active_tasks[index] = batch.more_work;
                }
                Err(error) => {
                    active_tasks[index] = false;
                    failed_tasks = failed_tasks.saturating_add(1);
                    tracing::error!(
                        task = task.diagnostic_code(),
                        error_code = error.diagnostic_code(),
                        "retention maintenance task failed"
                    );
                }
            }
        }

        if !active_tasks.iter().copied().any(std::convert::identity) {
            break;
        }
        tokio::task::yield_now().await;
    }

    log_result(
        result,
        active_tasks.iter().copied().any(std::convert::identity),
        failed_tasks,
    );
}

fn add_batch(result: &mut MaintenanceResult, task: MaintenanceTask, batch: MaintenanceBatch) {
    let destination = match task {
        MaintenanceTask::EventHistory => &mut result.events_purged,
        MaintenanceTask::ExpiredHooks => &mut result.hooks_purged,
        MaintenanceTask::TerminalOutbox => &mut result.outbox_rows_purged,
        MaintenanceTask::ExpiredIdempotency => &mut result.idempotency_rows_purged,
    };
    *destination = destination.saturating_add(batch.rows_affected);
}

fn log_result(result: MaintenanceResult, cycle_limit_reached: bool, failed_tasks: u8) {
    let affected_rows = result
        .events_purged
        .saturating_add(result.outbox_rows_purged)
        .saturating_add(result.idempotency_rows_purged)
        .saturating_add(result.hooks_purged);
    if affected_rows == 0 && failed_tasks == 0 && !cycle_limit_reached {
        tracing::debug!("retention maintenance cycle completed without eligible rows");
        return;
    }

    tracing::info!(
        events_purged = result.events_purged,
        outbox_rows_purged = result.outbox_rows_purged,
        idempotency_rows_purged = result.idempotency_rows_purged,
        hooks_purged = result.hooks_purged,
        cycle_limit_reached,
        failed_tasks,
        "retention maintenance cycle completed"
    );
}

#[cfg(test)]
mod tests {
    use super::{MaintenanceBatch, MaintenanceResult, MaintenanceTask, add_batch};

    #[test]
    fn batches_accumulate_in_their_own_maintenance_class() {
        let mut result = MaintenanceResult::default();
        for (task, rows) in MaintenanceTask::ALL.into_iter().zip(1_u64..) {
            add_batch(
                &mut result,
                task,
                MaintenanceBatch {
                    rows_affected: rows,
                    more_work: false,
                },
            );
        }

        assert_eq!(result.events_purged, 1);
        assert_eq!(result.hooks_purged, 2);
        assert_eq!(result.outbox_rows_purged, 3);
        assert_eq!(result.idempotency_rows_purged, 4);
    }
}
