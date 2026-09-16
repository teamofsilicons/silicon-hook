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
    // Honeycomb owns environment retirement and permanent removal.
    // Oldest-serviced environments first avoids starving later-created worlds.
    let active: Vec<(Uuid, i64)> = sqlx::query_as("SELECT id, generation FROM hook_control.environments WHERE deleted_at IS NULL AND (honeycomb_state IS NULL OR honeycomb_state='ready') ORDER BY last_maintained_at ASC NULLS FIRST, id LIMIT 32")
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
