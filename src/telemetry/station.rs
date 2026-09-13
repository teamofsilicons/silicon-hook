//! Durable Hook outbox handed to the official Space Station recorder.
use secrecy::{ExposeSecret as _, SecretString};
use sqlx::PgPool;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct Pending {
    event_id: Uuid,
    environment_id: Uuid,
    recorded_at: time::OffsetDateTime,
    subject_hash: Option<String>,
    data: serde_json::Value,
}

fn table_key(environment: Uuid) -> Option<SecretString> {
    if environment.is_nil() {
        std::env::var("HOOK_TELEMETRY_TABLE_KEY")
            .ok()
            .filter(|key| !key.is_empty())
            .map(SecretString::from)
    } else {
        // Each sandbox needs an explicit separate destination; never fall back to production.
        let raw = std::env::var("HOOK_TEST_TELEMETRY_KEYS").ok()?;
        let keys: std::collections::BTreeMap<Uuid, String> = serde_json::from_str(&raw).ok()?;
        let key = keys.get(&environment)?;
        let prefix = key.rsplit_once('-')?.0;
        if prefix == "table-siliconhook"
            || keys
                .values()
                .filter(|other| {
                    other
                        .rsplit_once('-')
                        .is_some_and(|(candidate, _)| candidate == prefix)
                })
                .count()
                != 1
        {
            return None;
        }
        Some(SecretString::from(key.clone()))
    }
}

pub(crate) async fn export_pending(pool: &PgPool) -> anyhow::Result<()> {
    if !super::events::enabled() {
        return Ok(());
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let environment: Uuid = sqlx::query_scalar("SELECT hook_private.environment_id()")
        .fetch_one(pool)
        .await?;
    let Some(key) = table_key(environment) else {
        return Ok(());
    };
    let mut transaction = pool.begin().await?;
    let records: Vec<Pending> = sqlx::query_as("SELECT event_id,environment_id,recorded_at,subject_hash,data FROM hook_private.telemetry_events WHERE environment_id=hook_private.environment_id() AND exported_at IS NULL ORDER BY recorded_at LIMIT 100 FOR UPDATE SKIP LOCKED")
        .fetch_all(&mut *transaction).await?;
    if records.is_empty() {
        return Ok(());
    }
    let ids: Vec<_> = records.iter().map(|record| record.event_id).collect();
    let home = std::env::var_os("HOOK_TELEMETRY_SPOOL_DIR").map_or_else(
        || space_station::default_home().join("silicon-hook"),
        std::path::PathBuf::from,
    );
    let delivered = tokio::task::spawn_blocking(move || {
        let failed = Arc::new(AtomicBool::new(false));
        let capture = Arc::clone(&failed);
        let client = space_station::SpaceClient::builder(key.expose_secret())
            .url(space_station::DEFAULT_URL)
            .home(home.join(environment.to_string()))
            .flush_timeout(std::time::Duration::from_secs(3))
            .on_error(move |_| { capture.store(true, Ordering::Relaxed); })
            .build().map_err(|_| anyhow::anyhow!("invalid telemetry table configuration"))?;
        for record in records {
            client.record(serde_json::json!({"service":"silicon-hook", "environment_id":record.environment_id, "recorded_at_ms":record.recorded_at.unix_timestamp_nanos()/1_000_000, "subject_hash":record.subject_hash, "event":record.data}));
        }
        Ok::<_, anyhow::Error>(client.flush() && !failed.load(Ordering::Relaxed))
    }).await??;
    if delivered {
        sqlx::query("UPDATE hook_private.telemetry_events SET exported_at=clock_timestamp() WHERE environment_id=hook_private.environment_id() AND event_id=ANY($1)").bind(ids).execute(&mut *transaction).await?;
        transaction.commit().await?;
    }
    Ok(())
}
