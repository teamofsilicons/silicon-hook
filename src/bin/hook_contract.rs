//! Operator-only API contract lifecycle control using privileged database access.
use silicon_hook::{config::MigrationSettings, infrastructure::postgres};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help") {
        println!(
            "hook-contract <status|deprecate|activate> <v3|v2|v1>\nUses HOOK_MIGRATOR_DATABASE_URL.\nDeprecation starts a seven-day idle window. Activity restarts that window. Only deprecated contracts sunset.\nv1 and v2 used Silicon IAM sign-in and stay sunset; activating them changes nothing the API serves.\nOperator database credentials are required. No account sessions are accepted."
        );
        return Ok(());
    }
    anyhow::ensure!(
        args.len() == 2 && matches!(args[1].as_str(), "v3" | "v2" | "v1"),
        "use hook-contract --help"
    );
    let settings = MigrationSettings::from_env()?;
    let environment = uuid::Uuid::nil();
    let db = &settings.database;
    let pool = postgres::connect(db, "hook-contract").await?;
    let mut tx = pool.begin().await?;
    match args[0].as_str() {
        "status" => {}
        "deprecate" | "activate" => {
            let deprecated = args[0] == "deprecate";
            sqlx::query("INSERT INTO hook_private.contract_versions (environment_id, major, status, deprecated_at) VALUES ($1, $2, CASE WHEN $3 THEN 'deprecated' ELSE 'active' END, CASE WHEN $3 THEN clock_timestamp() END) ON CONFLICT (environment_id,major) DO UPDATE SET status=EXCLUDED.status, deprecated_at=CASE WHEN $3 AND hook_private.contract_versions.status='deprecated' THEN hook_private.contract_versions.deprecated_at ELSE EXCLUDED.deprecated_at END, sunset_at=NULL")
                .bind(environment).bind(&args[1]).bind(deprecated).execute(&mut *tx).await?;
        }
        _ => anyhow::bail!("unknown lifecycle command; use hook-contract --help"),
    }
    let rows: Vec<serde_json::Value> = sqlx::query_scalar("SELECT to_jsonb(c) FROM hook_private.contract_versions c WHERE environment_id=$1 AND major=$2").bind(environment).bind(&args[1]).fetch_all(&mut *tx).await?;
    tx.commit().await?;
    println!("{}", serde_json::to_string_pretty(&rows)?);
    Ok(())
}
