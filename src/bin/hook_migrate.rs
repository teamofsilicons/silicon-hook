//! Silicon Hook one-shot database migration process, and the operator command
//! that links IAM-era identities to Silicon Accounts uuids.

use std::path::PathBuf;

use anyhow::Context as _;
use silicon_hook::{
    config::MigrationSettings,
    infrastructure::postgres::{
        self,
        identity_links::{link_identities, parse_mapping},
    },
    telemetry,
};

const HELP: &str = "\
hook-migrate                      Apply every pending migration (HOOK_MIGRATOR_DATABASE_URL).
hook-migrate link-identities --file MAPPING.csv [--dry-run]
                                  Link the IAM-era ids stored in Hook to Silicon Accounts uuids.

link-identities reads a CSV with a header, `iam_public_id,accounts_uuid` (or
`iam_principal_id,iam_public_id,accounts_uuid`), one IAM id per line, such as
`si:cos,8HV`. An empty uuid removes a link. It refuses the whole file when any
line is malformed, an id appears twice, or one uuid is given to two ids.

In one transaction it records the links in hook_private.identity_links and
fills the Silicon Accounts uuid columns of hooks, events, blocked requests,
retired endpoint keys and audit rows that hold a mapped IAM id. The IAM-era
columns are never changed, so running it again with a corrected file is safe.
--dry-run does everything, prints the report, and rolls back.

It must run as the schema owner (the migrator role) after the migrations.";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    match args.first().map(String::as_str) {
        None => migrate().await,
        Some("link-identities") => link(&args[1..]).await,
        Some(other) => anyhow::bail!(
            "unknown command `{other}`; run `hook-migrate --help` for the two commands"
        ),
    }
}

async fn migrate() -> anyhow::Result<()> {
    let settings = MigrationSettings::from_env()?;
    telemetry::init(&settings.process)?;
    let pool = postgres::connect(&settings.database, "hook-migrate").await?;
    postgres::migrate(&pool).await?;
    pool.close().await;
    Ok(())
}

async fn link(args: &[String]) -> anyhow::Result<()> {
    let mut file = None;
    let mut dry_run = false;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--file" => {
                file = Some(PathBuf::from(rest.next().context(
                    "--file needs a path: hook-migrate link-identities --file mapping.csv",
                )?));
            }
            "--dry-run" => dry_run = true,
            other => anyhow::bail!(
                "unknown option `{other}` for link-identities; it takes --file PATH and --dry-run"
            ),
        }
    }
    let file = file.context(
        "link-identities needs --file PATH (a CSV with the header iam_public_id,accounts_uuid)",
    )?;
    let bytes = std::fs::read(&file)
        .with_context(|| format!("could not read the mapping file {}", file.display()))?;
    let mapping = parse_mapping(&bytes).map_err(|errors| anyhow::anyhow!("{errors}"))?;
    let settings = MigrationSettings::from_env()?;
    telemetry::init(&settings.process)?;
    let pool = postgres::connect(&settings.database, "hook-migrate-link").await?;
    let report = link_identities(&pool, &mapping, dry_run)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    pool.close().await;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
