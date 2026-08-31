//! Silicon Hook asynchronous delivery and maintenance worker.

use silicon_hook::{config::WorkerProcessSettings, telemetry, worker};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let settings = WorkerProcessSettings::from_env()?;
    telemetry::init(&settings.process)?;
    worker::run(settings).await
}
