//! Silicon Hook asynchronous delivery and maintenance worker.

use silicon_hook::{config::WorkerProcessSettings, logging, worker};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let settings = WorkerProcessSettings::from_env()?;
    logging::init(&settings.process)?;
    worker::run(settings).await
}
