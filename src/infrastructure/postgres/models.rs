//! Private SQL row representations.

use serde_json::Value;
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, FromRow)]
pub(super) struct HookRow {
    pub(super) id: Uuid,
    pub(super) org_id: String,
    pub(super) silicon_id: String,
    pub(super) endpoint_key: String,
    pub(super) name: String,
    pub(super) description: Option<String>,
    pub(super) created_by_kind: String,
    pub(super) created_by_id: String,
    pub(super) created_via_app_id: Option<String>,
    pub(super) encryption_key_id: String,
    pub(super) secret_nonce: Vec<u8>,
    pub(super) encrypted_signing_secret: Vec<u8>,
    pub(super) created_at: OffsetDateTime,
    pub(super) deleted_at: Option<OffsetDateTime>,
}

#[derive(Debug, FromRow)]
pub(super) struct IngressHookRow {
    #[sqlx(flatten)]
    pub(super) hook: HookRow,
    pub(super) database_time: OffsetDateTime,
}

#[derive(Debug, FromRow)]
pub(super) struct EventRow {
    pub(super) id: Uuid,
    pub(super) hook_id: Uuid,
    pub(super) org_id: String,
    pub(super) silicon_id: String,
    pub(super) event_type: String,
    pub(super) source: Option<String>,
    pub(super) subject: Option<String>,
    pub(super) occurred_at: OffsetDateTime,
    pub(super) schema_version: String,
    pub(super) trace_id: String,
    pub(super) payload: Value,
    pub(super) request_digest: Vec<u8>,
    pub(super) received_at: OffsetDateTime,
    pub(super) delivery_status: String,
    pub(super) delivery_attempts: i32,
    pub(super) last_attempt_at: Option<OffsetDateTime>,
    pub(super) failure_reason: Option<String>,
}

#[derive(Debug, FromRow)]
pub(super) struct ManagementIdempotencyRow {
    pub(super) request_digest: Vec<u8>,
    pub(super) response_status: Option<i16>,
    pub(super) resource_id: Option<Uuid>,
    pub(super) response_secret_key_id: Option<String>,
    pub(super) response_secret_nonce: Option<Vec<u8>>,
    pub(super) response_encrypted_secret: Option<Vec<u8>>,
    pub(super) secret_replay_until: Option<OffsetDateTime>,
}

#[derive(Debug, FromRow)]
pub(super) struct IngressIdempotencyRow {
    pub(super) request_digest: Vec<u8>,
    pub(super) event_id: Uuid,
}

#[derive(Debug, FromRow)]
pub(super) struct ClaimedDeliveryRow {
    pub(super) event_id: Uuid,
    pub(super) request_body: Vec<u8>,
    pub(super) attempts: i32,
    pub(super) lease_token: Uuid,
    pub(super) leased_until: OffsetDateTime,
}
