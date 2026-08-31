//! Silicon Hook one-shot database migration process.

use silicon_hook::{config::MigrationSettings, infrastructure::postgres, telemetry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let settings = MigrationSettings::from_env()?;
    telemetry::init(&settings.process)?;

    let pool = postgres::connect(&settings.database, "hook-migrate").await?;
    postgres::migrate(&pool).await?;
    pool.close().await;
    Ok(())
}
