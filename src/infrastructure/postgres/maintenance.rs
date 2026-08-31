//! Bounded, fair retention and permanent-purge operations.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::{
    MaintenanceBatch, MaintenanceTask, PostgresStore, StoreError, types::MaintenanceResult,
};

const MAX_EVENT_HOOKS_PER_BATCH: i64 = 64;

impl PostgresStore {
    /// Runs one independently committed batch for every maintenance class.
    ///
    /// The four tasks do not share a transaction. All are started before any
    /// error is returned, so a failing or contended retention class cannot
    /// roll back successful work from another class. Worker scheduling uses
    /// `run_maintenance_task` directly to drain each backlog fairly.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid batch size or when any PostgreSQL task
    /// fails. Successful sibling tasks remain committed.
    pub async fn run_maintenance_pass(
        &self,
        batch_size: u32,
    ) -> Result<MaintenanceResult, StoreError> {
        let (events, hooks, outbox, idempotency) = tokio::join!(
            Box::pin(self.run_maintenance_task(MaintenanceTask::EventHistory, batch_size)),
            Box::pin(self.run_maintenance_task(MaintenanceTask::ExpiredHooks, batch_size)),
            Box::pin(self.run_maintenance_task(MaintenanceTask::TerminalOutbox, batch_size)),
            Box::pin(self.run_maintenance_task(MaintenanceTask::ExpiredIdempotency, batch_size)),
        );

        Ok(MaintenanceResult {
            events_purged: events?.rows_affected,
            hooks_purged: hooks?.rows_affected,
            outbox_rows_purged: outbox?.rows_affected,
            idempotency_rows_purged: idempotency?.rows_affected,
        })
    }

    /// Runs one short transaction for one maintenance class.
    ///
    /// # Errors
    ///
    /// Returns an error for a batch size outside `1..=10_000` or a PostgreSQL
    /// failure.
    pub(crate) async fn run_maintenance_task(
        &self,
        task: MaintenanceTask,
        batch_size: u32,
    ) -> Result<MaintenanceBatch, StoreError> {
        if batch_size == 0 || batch_size > 10_000 {
            return Err(StoreError::InvalidArgument {
                field: "batch_size",
                reason: "must be between 1 and 10000",
            });
        }
        let batch_size = i64::from(batch_size);

        match task {
            MaintenanceTask::EventHistory => purge_event_history(&self.pool, batch_size).await,
            MaintenanceTask::ExpiredHooks => purge_expired_hooks(&self.pool, batch_size).await,
            MaintenanceTask::TerminalOutbox => purge_terminal_outbox(&self.pool, batch_size).await,
            MaintenanceTask::ExpiredIdempotency => {
                purge_expired_idempotency(&self.pool, batch_size).await
            }
        }
    }
}

async fn purge_event_history(
    pool: &PgPool,
    batch_size: i64,
) -> Result<MaintenanceBatch, StoreError> {
    let mut transaction = pool.begin().await?;
    let maintenance_now = sqlx::query_scalar::<_, time::OffsetDateTime>("SELECT clock_timestamp()")
        .fetch_one(&mut *transaction)
        .await?;
    let hook_ids = retention_candidates(&mut transaction, maintenance_now, batch_size).await?;
    if hook_ids.is_empty() {
        transaction.commit().await?;
        return Ok(MaintenanceBatch::default());
    }

    let rows_affected =
        delete_excess_events(&mut transaction, &hook_ids, maintenance_now, batch_size).await?;
    reschedule_retention(&mut transaction, &hook_ids, maintenance_now).await?;
    let more_work = due_retention_exists(&mut transaction, maintenance_now).await?;
    transaction.commit().await?;

    Ok(MaintenanceBatch {
        rows_affected,
        more_work,
    })
}

async fn retention_candidates(
    transaction: &mut Transaction<'_, Postgres>,
    maintenance_now: time::OffsetDateTime,
    batch_size: i64,
) -> Result<Vec<Uuid>, StoreError> {
    let candidate_limit = batch_size.min(MAX_EVENT_HOOKS_PER_BATCH);
    sqlx::query_scalar::<_, Uuid>(
        r"
        SELECT hook_id
        FROM hook_private.event_retention_state
        WHERE maintenance_due_at <= $1
        ORDER BY maintenance_due_at, hook_id
        FOR UPDATE SKIP LOCKED
        LIMIT $2
        ",
    )
    .bind(maintenance_now)
    .bind(candidate_limit)
    .fetch_all(&mut **transaction)
    .await
    .map_err(StoreError::from)
}

async fn delete_excess_events(
    transaction: &mut Transaction<'_, Postgres>,
    hook_ids: &[Uuid],
    maintenance_now: time::OffsetDateTime,
    batch_size: i64,
) -> Result<u64, StoreError> {
    let hook_count = i64::try_from(hook_ids.len()).map_err(|_error| StoreError::NumericRange {
        field: "maintenance_hook_count",
    })?;
    let per_hook_limit = (batch_size / hook_count).max(1);
    sqlx::query(
        r"
        WITH candidates(hook_id) AS (
            SELECT unnest($1::uuid[])
        ), boundaries AS MATERIALIZED (
            SELECT candidate.hook_id,
                   boundary.received_at,
                   boundary.id
            FROM candidates AS candidate
            CROSS JOIN LATERAL (
                SELECT event.received_at, event.id
                FROM hook.events AS event
                WHERE event.hook_id = candidate.hook_id
                ORDER BY event.received_at DESC, event.id DESC
                OFFSET 9999
                LIMIT 1
            ) AS boundary
        ), victims AS MATERIALIZED (
            SELECT boundary.hook_id, victim.id
            FROM boundaries AS boundary
            CROSS JOIN LATERAL (
                SELECT event.id
                FROM hook.events AS event
                WHERE event.hook_id = boundary.hook_id
                  AND (event.received_at, event.id)
                        < (boundary.received_at, boundary.id)
                  AND event.replay_protected_until < $2
                ORDER BY event.received_at, event.id
                FOR UPDATE SKIP LOCKED
                LIMIT $3
            ) AS victim
        )
        DELETE FROM hook.events AS event
        USING victims
        WHERE event.id = victims.id
        ",
    )
    .bind(hook_ids)
    .bind(maintenance_now)
    .bind(per_hook_limit)
    .execute(&mut **transaction)
    .await
    .map(|result| result.rows_affected())
    .map_err(StoreError::from)
}

async fn reschedule_retention(
    transaction: &mut Transaction<'_, Postgres>,
    hook_ids: &[Uuid],
    maintenance_now: time::OffsetDateTime,
) -> Result<(), StoreError> {
    // The delete trigger has already adjusted event_count. A hook remains due
    // while any excess row is replay-safe; otherwise it sleeps until the
    // earliest excess-row deadline. The deadline index keeps this lookup
    // proportional to one hook rather than its physical backlog.
    sqlx::query(
        r"
        UPDATE hook_private.event_retention_state AS retention
        SET maintenance_due_at = CASE
                WHEN retention.event_count <= 10000 THEN NULL
                ELSE GREATEST(
                    $2,
                    COALESCE(
                        (
                            SELECT overflow.replay_protected_until
                                   + INTERVAL '1 microsecond'
                            FROM (
                                SELECT event.received_at, event.id
                                FROM hook.events AS event
                                WHERE event.hook_id = retention.hook_id
                                ORDER BY event.received_at DESC, event.id DESC
                                OFFSET 9999
                                LIMIT 1
                            ) AS boundary
                            CROSS JOIN LATERAL (
                                SELECT event.replay_protected_until
                                FROM hook.events AS event
                                WHERE event.hook_id = retention.hook_id
                                  AND (event.received_at, event.id)
                                        < (boundary.received_at, boundary.id)
                                ORDER BY event.replay_protected_until, event.id
                                LIMIT 1
                            ) AS overflow
                        ),
                        $2 + INTERVAL '1 second'
                    )
                )
            END
        WHERE retention.hook_id = ANY($1::uuid[])
        ",
    )
    .bind(hook_ids)
    .bind(maintenance_now)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn due_retention_exists(
    transaction: &mut Transaction<'_, Postgres>,
    maintenance_now: time::OffsetDateTime,
) -> Result<bool, StoreError> {
    sqlx::query_scalar::<_, bool>(
        r"
        SELECT EXISTS (
            SELECT 1
            FROM hook_private.event_retention_state
            WHERE maintenance_due_at <= $1
        )
        ",
    )
    .bind(maintenance_now)
    .fetch_one(&mut **transaction)
    .await
    .map_err(StoreError::from)
}

async fn purge_expired_hooks(
    pool: &PgPool,
    batch_size: i64,
) -> Result<MaintenanceBatch, StoreError> {
    let result = sqlx::query(
        r"
        WITH maintenance_clock AS MATERIALIZED (
            SELECT clock_timestamp() AS now
        ), victims AS (
            SELECT id
            FROM hook.hooks, maintenance_clock
            WHERE deleted_at < maintenance_clock.now - INTERVAL '45 days'
            ORDER BY deleted_at, id
            FOR UPDATE SKIP LOCKED
            LIMIT $1
        )
        DELETE FROM hook.hooks AS hook
        USING victims
        WHERE hook.id = victims.id
        ",
    )
    .bind(batch_size)
    .execute(pool)
    .await?;
    Ok(batch_outcome(&result, batch_size))
}

async fn purge_terminal_outbox(
    pool: &PgPool,
    batch_size: i64,
) -> Result<MaintenanceBatch, StoreError> {
    let result = sqlx::query(
        r"
        WITH victims AS (
            SELECT delivery.event_id
            FROM hook_private.dm_outbox AS delivery
            WHERE delivery.status IN ('delivered', 'failed')
              AND NOT EXISTS (
                  SELECT 1
                  FROM hook.events AS event
                  WHERE event.id = delivery.event_id
              )
            ORDER BY delivery.updated_at, delivery.event_id
            FOR UPDATE OF delivery SKIP LOCKED
            LIMIT $1
        )
        DELETE FROM hook_private.dm_outbox AS delivery
        USING victims
        WHERE delivery.event_id = victims.event_id
        ",
    )
    .bind(batch_size)
    .execute(pool)
    .await?;
    Ok(batch_outcome(&result, batch_size))
}

async fn purge_expired_idempotency(
    pool: &PgPool,
    batch_size: i64,
) -> Result<MaintenanceBatch, StoreError> {
    let result = sqlx::query(
        r"
        WITH maintenance_clock AS MATERIALIZED (
            SELECT clock_timestamp() AS now
        ), victims AS (
            SELECT tableoid, ctid
            FROM hook_private.management_idempotency, maintenance_clock
            WHERE expires_at <= maintenance_clock.now
            ORDER BY expires_at
            FOR UPDATE SKIP LOCKED
            LIMIT $1
        )
        DELETE FROM hook_private.management_idempotency AS record
        USING victims
        WHERE record.tableoid = victims.tableoid
          AND record.ctid = victims.ctid
        ",
    )
    .bind(batch_size)
    .execute(pool)
    .await?;
    Ok(batch_outcome(&result, batch_size))
}

fn batch_outcome(result: &sqlx::postgres::PgQueryResult, batch_size: i64) -> MaintenanceBatch {
    let rows_affected = result.rows_affected();
    MaintenanceBatch {
        rows_affected,
        more_work: rows_affected == batch_size.cast_unsigned(),
    }
}
