//! Silicon Hook HTTP API process.

use silicon_hook::{api, config::ApiSettings, telemetry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let settings = ApiSettings::from_env()?;
    telemetry::init(&settings.process)?;
    api::serve(settings).await
}
