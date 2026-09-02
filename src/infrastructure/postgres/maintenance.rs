//! Bounded, fair retention and permanent-purge operations.

use sqlx::PgPool;

use super::{
    MaintenanceBatch, MaintenanceTask, PostgresStore, StoreError, types::MaintenanceResult,
};

/// Inactive temporary blocks are forgotten after this many days without a
/// new strike, so a provider that fixed its configuration starts clean.
const STALE_IP_BLOCK_DAYS: i64 = 30;

impl PostgresStore {
    /// Runs one independently committed batch for every maintenance class.
    ///
    /// The tasks do not share a transaction. All are started before any error
    /// is returned, so a failing or contended retention class cannot roll back
    /// successful work from another class.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid batch size or when any PostgreSQL task
    /// fails. Successful sibling tasks remain committed.
    pub async fn run_maintenance_pass(
        &self,
        batch_size: u32,
    ) -> Result<MaintenanceResult, StoreError> {
        let (events, blocked, hooks, idempotency, ip_blocks) = tokio::join!(
            Box::pin(self.run_maintenance_task(MaintenanceTask::ExpiredEvents, batch_size)),
            Box::pin(
                self.run_maintenance_task(MaintenanceTask::ExpiredBlockedRequests, batch_size)
            ),
            Box::pin(self.run_maintenance_task(MaintenanceTask::ExpiredHooks, batch_size)),
            Box::pin(self.run_maintenance_task(MaintenanceTask::ExpiredIdempotency, batch_size)),
            Box::pin(self.run_maintenance_task(MaintenanceTask::StaleIpBlocks, batch_size)),
        );

        Ok(MaintenanceResult {
            events_purged: events?.rows_affected,
            blocked_requests_purged: blocked?.rows_affected,
            hooks_purged: hooks?.rows_affected,
            idempotency_rows_purged: idempotency?.rows_affected,
            ip_blocks_purged: ip_blocks?.rows_affected,
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
        let sql = match task {
            MaintenanceTask::ExpiredEvents => PURGE_EXPIRED_EVENTS_SQL,
            MaintenanceTask::ExpiredBlockedRequests => PURGE_EXPIRED_BLOCKED_SQL,
            MaintenanceTask::ExpiredHooks => PURGE_EXPIRED_HOOKS_SQL,
            MaintenanceTask::ExpiredIdempotency => PURGE_EXPIRED_IDEMPOTENCY_SQL,
            MaintenanceTask::StaleIpBlocks => PURGE_STALE_IP_BLOCKS_SQL,
        };
        purge(&self.pool, sql, batch_size).await
    }
}

async fn purge(
    pool: &PgPool,
    sql: &'static str,
    batch_size: i64,
) -> Result<MaintenanceBatch, StoreError> {
    let result = sqlx::query(sql)
        .bind(batch_size)
        .bind(STALE_IP_BLOCK_DAYS)
        .execute(pool)
        .await?;
    let rows_affected = result.rows_affected();
    Ok(MaintenanceBatch {
        rows_affected,
        more_work: rows_affected == batch_size.cast_unsigned(),
    })
}

const PURGE_EXPIRED_EVENTS_SQL: &str = "
    WITH maintenance_clock AS MATERIALIZED (SELECT clock_timestamp() AS now),
    victims AS (
        SELECT id FROM hook.events, maintenance_clock
        WHERE expires_at <= maintenance_clock.now
        ORDER BY expires_at, id
        FOR UPDATE SKIP LOCKED
        LIMIT $1
    )
    DELETE FROM hook.events AS event USING victims
    WHERE event.id = victims.id AND $2::bigint IS NOT NULL
";

const PURGE_EXPIRED_BLOCKED_SQL: &str = "
    WITH maintenance_clock AS MATERIALIZED (SELECT clock_timestamp() AS now),
    victims AS (
        SELECT id FROM hook.blocked_requests, maintenance_clock
        WHERE expires_at <= maintenance_clock.now
        ORDER BY expires_at, id
        FOR UPDATE SKIP LOCKED
        LIMIT $1
    )
    DELETE FROM hook.blocked_requests AS blocked USING victims
    WHERE blocked.id = victims.id AND $2::bigint IS NOT NULL
";

const PURGE_EXPIRED_HOOKS_SQL: &str = "
    WITH maintenance_clock AS MATERIALIZED (SELECT clock_timestamp() AS now),
    victims AS (
        SELECT id FROM hook.hooks, maintenance_clock
        WHERE deleted_at < maintenance_clock.now - INTERVAL '45 days'
        ORDER BY deleted_at, id
        FOR UPDATE SKIP LOCKED
        LIMIT $1
    )
    DELETE FROM hook.hooks AS hook USING victims
    WHERE hook.id = victims.id AND $2::bigint IS NOT NULL
";

const PURGE_EXPIRED_IDEMPOTENCY_SQL: &str = "
    WITH maintenance_clock AS MATERIALIZED (SELECT clock_timestamp() AS now),
    victims AS (
        SELECT tableoid, ctid FROM hook_private.management_idempotency, maintenance_clock
        WHERE expires_at <= maintenance_clock.now
        ORDER BY expires_at
        FOR UPDATE SKIP LOCKED
        LIMIT $1
    )
    DELETE FROM hook_private.management_idempotency AS record USING victims
    WHERE record.tableoid = victims.tableoid AND record.ctid = victims.ctid
      AND $2::bigint IS NOT NULL
";

const PURGE_STALE_IP_BLOCKS_SQL: &str = "
    WITH maintenance_clock AS MATERIALIZED (SELECT clock_timestamp() AS now),
    victims AS (
        SELECT hook_id, remote_ip FROM hook_private.ip_blocks, maintenance_clock
        WHERE NOT permanent
          AND (blocked_until IS NULL OR blocked_until <= maintenance_clock.now)
          AND updated_at < maintenance_clock.now - ($2 * INTERVAL '1 day')
        ORDER BY updated_at
        FOR UPDATE SKIP LOCKED
        LIMIT $1
    )
    DELETE FROM hook_private.ip_blocks AS block USING victims
    WHERE block.hook_id = victims.hook_id AND block.remote_ip = victims.remote_ip
";
