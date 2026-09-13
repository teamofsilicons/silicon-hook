//! Best-effort event persistence. Bounded concurrency and timeout protect work.
use serde::{Deserialize, Serialize};
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Event {
    #[serde(rename = "event_id")]
    pub id: Uuid,
    pub trace_id: Uuid,
    pub source: String,
    pub step: String,
    pub outcome: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}
impl Event {
    pub fn new(source: &str, step: &str, outcome: &str) -> Self {
        Self {
            id: Uuid::now_v7(),
            trace_id: Uuid::now_v7(),
            source: source.into(),
            step: step.into(),
            outcome: outcome.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            operation: None,
            duration_ms: None,
            progress: None,
            status: None,
            os: Some(std::env::consts::OS.into()),
            arch: Some(std::env::consts::ARCH.into()),
            route: None,
            method: None,
        }
    }
    pub fn validate_external(&self) -> Result<(), ()> {
        let valid = ["cli", "daemon", "client", "web"].contains(&self.source.as_str())
            && [
                "command",
                "connect",
                "subscribe",
                "deliver",
                "ack",
                "refresh",
                "update",
                "page_view",
                "interaction",
                "error",
            ]
            .contains(&self.step.as_str())
            && ["started", "succeeded", "failed", "retrying", "skipped"]
                .contains(&self.outcome.as_str())
            && (1..=32).contains(&self.version.len())
            && self
                .version
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'.')
            && self.route.is_none()
            && self.method.is_none()
            && self.operation.as_deref().is_none_or(|op| {
                [
                    "login",
                    "logout",
                    "whoami",
                    "refresh",
                    "webhook",
                    "unhook",
                    "hooks",
                    "events",
                    "blocked",
                    "deliveries",
                    "env",
                    "config",
                    "daemon",
                    "docs",
                    "commands",
                    "system",
                    "report",
                    "about",
                    "overview",
                    "live",
                    "testing",
                    "connections",
                    "relay",
                    "iam",
                    "create",
                    "set-secret",
                    "list",
                    "show",
                    "update",
                    "delete",
                    "restore",
                    "enable",
                    "disable",
                    "rotate",
                    "connect-iam",
                    "listen",
                ]
                .contains(&op)
            })
            && self.os.as_deref().is_none_or(|os| {
                [
                    "linux", "macos", "windows", "freebsd", "openbsd", "netbsd", "android", "ios",
                    "unknown",
                ]
                .contains(&os)
            })
            && self.arch.as_deref().is_none_or(|arch| {
                [
                    "x86_64", "aarch64", "x86", "arm", "riscv64", "wasm32", "unknown",
                ]
                .contains(&arch)
            })
            && !self.id.is_nil()
            && !self.trace_id.is_nil();
        if valid { Ok(()) } else { Err(()) }
    }
}

pub(crate) fn enabled() -> bool {
    std::env::var("HOOK_TELEMETRY").map_or(true, |value| {
        !matches!(value.to_ascii_lowercase().as_str(), "off" | "false" | "0")
    })
}

pub(crate) fn record(pool: sqlx::PgPool, event: Event, subject: Option<String>) {
    static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    if !enabled() {
        return;
    }
    let Ok(permit) = SLOTS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(128)))
        .clone()
        .try_acquire_owned()
    else {
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        let query = sqlx::query("INSERT INTO hook_private.telemetry_events(event_id,source,step,trace_id,subject_hash,data) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
            .bind(event.id).bind(&event.source).bind(&event.step).bind(event.trace_id).bind(subject).bind(sqlx::types::Json(&event));
        if let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(500), query.execute(&pool)).await
        {
        } else {
            tracing::debug!("telemetry write skipped");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::Event;
    #[test]
    fn external_events_cannot_smuggle_freeform_context() {
        let mut event = Event::new("cli", "command", "succeeded");
        event.operation = Some("login".into());
        assert!(event.validate_external().is_ok());
        event.operation = Some("create".into());
        assert!(event.validate_external().is_ok());
        event.operation = Some("secret_bearer_value".into());
        assert!(event.validate_external().is_err());
        event.operation = None;
        event.route = Some("/hooks/secret".into());
        assert!(event.validate_external().is_err());
        let mut value =
            serde_json::to_value(Event::new("web", "page_view", "succeeded")).unwrap_or_default();
        value["body"] = serde_json::json!("do not store");
        assert!(serde_json::from_value::<Event>(value).is_err());
    }
}
