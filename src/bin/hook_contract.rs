//! Operator-only API contract lifecycle control using privileged database access.
use silicon_hook::{config::MigrationSettings, infrastructure::postgres};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help") {
        println!(
            "hook-contract <status|deprecate|activate> v1 [test-environment-uuid]\nUses HOOK_DATABASE_URL for production; a sandbox UUID selects HOOK_TEST_DATABASE_URL.\nDeprecation starts a seven-day idle window. Activity restarts that window. Only deprecated contracts sunset.\nOperator database credentials are required. No actor sessions are accepted."
        );
        return Ok(());
    }
    anyhow::ensure!(
        (2..=3).contains(&args.len()) && args[1] == "v1",
        "use hook-contract --help"
    );
    let settings = MigrationSettings::from_env()?;
    let environment = args
        .get(2)
        .map(|id| id.parse::<uuid::Uuid>())
        .transpose()?
        .unwrap_or(uuid::Uuid::nil());
    let db = if environment.is_nil() {
        &settings.database
    } else {
        settings
            .test_database
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HOOK_TEST_DATABASE_URL is required"))?
    };
    let pool = postgres::connect(db, "hook-contract").await?;
    let mut tx = pool.begin().await?;
    match args[0].as_str() {
        "status" => {}
        "deprecate" | "activate" => {
            let deprecated = args[0] == "deprecate";
            sqlx::query("INSERT INTO hook_private.contract_versions (environment_id, major, status, deprecated_at) VALUES ($1, 'v1', CASE WHEN $2 THEN 'deprecated' ELSE 'active' END, CASE WHEN $2 THEN clock_timestamp() END) ON CONFLICT (environment_id,major) DO UPDATE SET status=EXCLUDED.status, deprecated_at=CASE WHEN $2 AND hook_private.contract_versions.status='deprecated' THEN hook_private.contract_versions.deprecated_at ELSE EXCLUDED.deprecated_at END, sunset_at=NULL")
                .bind(environment).bind(deprecated).execute(&mut *tx).await?;
        }
        _ => anyhow::bail!("unknown lifecycle command; use hook-contract --help"),
    }
    let rows: Vec<serde_json::Value> = sqlx::query_scalar("SELECT to_jsonb(c) FROM hook_private.contract_versions c WHERE environment_id=$1 AND major='v1'").bind(environment).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    println!("{}", serde_json::to_string_pretty(&rows)?);
    Ok(())
}
