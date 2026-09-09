//! Bounded, fair maintenance of the shared test database.

use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;

use crate::{
    config::{DatabaseSettings, MaintenanceSettings},
    infrastructure::postgres::{self, PostgresStore},
};

pub(super) async fn cycle(
    pool: &PgPool,
    database: &DatabaseSettings,
    settings: &MaintenanceSettings,
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM hook_control.mutation_results WHERE (environment_id, request_hash) IN (SELECT environment_id, request_hash FROM hook_control.mutation_results WHERE created_at <= clock_timestamp() - INTERVAL '24 hours' LIMIT 1000)")
        .execute(pool).await?;
    // Inactivity retirement keeps the existing contents recoverable for 30 days.
    sqlx::query("UPDATE hook_control.environments SET deleted_at = clock_timestamp(), generation = generation + 1 WHERE id IN (SELECT id FROM hook_control.environments WHERE deleted_at IS NULL AND last_activity_at <= clock_timestamp() - INTERVAL '15 days' ORDER BY last_activity_at LIMIT 32 FOR UPDATE SKIP LOCKED)")
        .execute(pool).await?;
    let expired: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM hook_control.environments WHERE deleted_at <= clock_timestamp() - INTERVAL '30 days' ORDER BY deleted_at LIMIT 32")
        .fetch_all(pool).await?;
    for id in expired {
        let mut tx = pool.begin().await?;
        // Lock and recheck; a concurrent recovery must not be erased.
        let still_expired: Option<Uuid> = sqlx::query_scalar("SELECT id FROM hook_control.environments WHERE id = $1 AND deleted_at <= clock_timestamp() - INTERVAL '30 days' FOR UPDATE")
            .bind(id).fetch_optional(&mut *tx).await?;
        if still_expired.is_some() {
            sqlx::query("SELECT hook_control.clean_environment($1)")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM hook_control.environments WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
    }
    // Oldest-serviced environments first avoids starving later-created worlds.
    let active: Vec<(Uuid, i64)> = sqlx::query_as("SELECT id, generation FROM hook_control.environments WHERE deleted_at IS NULL ORDER BY last_maintained_at ASC NULLS FIRST, id LIMIT 32")
        .fetch_all(pool).await?;
    for (id, generation) in active {
        let options = postgres::connect_options(database, "hook-test-worker")?.options([
            ("hook.environment_id", id.to_string()),
            ("hook.environment_generation", generation.to_string()),
        ]);
        let scoped = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        super::maintenance::run_maintenance_cycle(&PostgresStore::new(scoped.clone()), settings)
            .await;
        scoped.close().await;
        sqlx::query("UPDATE hook_control.environments SET last_maintained_at = clock_timestamp() WHERE id = $1")
            .bind(id).execute(pool).await?;
    }
    Ok(())
}
