//! Private SQL row representations and their domain conversions.

use std::net::IpAddr;

use bytes::Bytes;
use serde_json::Value;
use sqlx::FromRow;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::{StoreError, parse_actor_kind};
use crate::domain::{
    ActorId, ActorRef, BlockReason, BlockedRequest, BlockedRequestId, BlockedRequestSnapshot,
    DeliverySequence, EncryptedSecret, EncryptionKeyId, EndpointKey, EventRecord,
    EventRecordSnapshot, Hook, HookDescription, HookId, HookName, HookSnapshot, HookStatus,
    HookTimeZone, OrganizationId, SigningPolicy, SiliconId,
    request::{CapturedRequest, CapturedRequestParts},
    signature::SignatureConfig,
};

/// Column list shared by every hook projection, usable inside `concat!`.
macro_rules! hook_columns {
    () => {
        "id, org_id, silicon_id, endpoint_key, name, description, \
         signature_required, signature_config, encryption_key_id, secret_nonce, \
         encrypted_signing_secret, time_zone, created_by_kind, created_by_id, \
         created_at, disabled_at, deleted_at, last_received_at, last_blocked_at, \
         endpoint_rotated_at"
    };
}
pub(super) use hook_columns;

#[derive(Debug, FromRow)]
pub(super) struct HookRow {
    pub(super) id: Uuid,
    pub(super) org_id: String,
    pub(super) silicon_id: String,
    pub(super) endpoint_key: String,
    pub(super) name: String,
    pub(super) description: Option<String>,
    pub(super) signature_required: bool,
    pub(super) signature_config: Value,
    pub(super) encryption_key_id: Option<String>,
    pub(super) secret_nonce: Option<Vec<u8>>,
    pub(super) encrypted_signing_secret: Option<Vec<u8>>,
    pub(super) time_zone: String,
    pub(super) created_by_kind: String,
    pub(super) created_by_id: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) disabled_at: Option<OffsetDateTime>,
    pub(super) deleted_at: Option<OffsetDateTime>,
    pub(super) last_received_at: Option<OffsetDateTime>,
    pub(super) last_blocked_at: Option<OffsetDateTime>,
    pub(super) endpoint_rotated_at: Option<OffsetDateTime>,
}

#[derive(Debug, FromRow)]
pub(super) struct ClockedHookRow {
    #[sqlx(flatten)]
    pub(super) hook: HookRow,
    pub(super) database_time: OffsetDateTime,
}

impl TryFrom<HookRow> for Hook {
    type Error = StoreError;

    fn try_from(row: HookRow) -> Result<Self, Self::Error> {
        let corrupt = |error: &dyn std::fmt::Display| StoreError::corrupt("hook", error);
        let status = if row.deleted_at.is_some() {
            HookStatus::Deleted
        } else if row.disabled_at.is_some() {
            HookStatus::Disabled
        } else {
            HookStatus::Active
        };
        let encrypted_secret = match (
            row.encryption_key_id,
            row.secret_nonce,
            row.encrypted_signing_secret,
        ) {
            (Some(key_id), Some(nonce), Some(ciphertext)) => {
                let nonce: [u8; 12] = nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::corrupt("hook", "invalid secret nonce length"))?;
                let key_id = EncryptionKeyId::new(key_id).map_err(|error| corrupt(&error))?;
                Some(
                    EncryptedSecret::new(key_id, nonce, ciphertext)
                        .map_err(|error| corrupt(&error))?,
                )
            }
            (None, None, None) => None,
            _ => return Err(StoreError::corrupt("hook", "incomplete encrypted secret")),
        };
        let config: SignatureConfig =
            serde_json::from_value(row.signature_config).map_err(|error| corrupt(&error))?;
        let created_by = ActorRef::new(
            parse_actor_kind(&row.created_by_kind)?,
            ActorId::new(row.created_by_id).map_err(|error| corrupt(&error))?,
        );

        Hook::rehydrate(HookSnapshot {
            id: row.id.into(),
            organization_id: OrganizationId::new(row.org_id).map_err(|error| corrupt(&error))?,
            silicon_id: SiliconId::new(row.silicon_id).map_err(|error| corrupt(&error))?,
            name: HookName::new(row.name).map_err(|error| corrupt(&error))?,
            description: row
                .description
                .map(HookDescription::new)
                .transpose()
                .map_err(|error| corrupt(&error))?,
            endpoint_key: EndpointKey::parse(&row.endpoint_key).map_err(|error| corrupt(&error))?,
            signing: SigningPolicy {
                required: row.signature_required,
                config,
                encrypted_secret,
            },
            time_zone: HookTimeZone::new(row.time_zone).map_err(|error| corrupt(&error))?,
            status,
            created_by,
            created_at: row.created_at,
            disabled_at: row.disabled_at,
            deleted_at: row.deleted_at,
            last_received_at: row.last_received_at,
            last_blocked_at: row.last_blocked_at,
            endpoint_rotated_at: row.endpoint_rotated_at,
        })
        .map_err(|error| corrupt(&error))
    }
}

/// Column list shared by the captured-request portion of log rows.
macro_rules! capture_columns {
    () => {
        "method, url, path, query_string, headers, content_type, body, remote_ip, received_at"
    };
}
pub(super) use capture_columns;

#[derive(Debug, FromRow)]
pub(super) struct CaptureRow {
    pub(super) method: String,
    pub(super) url: String,
    pub(super) path: String,
    pub(super) query_string: String,
    pub(super) headers: Value,
    pub(super) body: Vec<u8>,
    pub(super) remote_ip: IpAddr,
    pub(super) received_at: OffsetDateTime,
}

impl CaptureRow {
    /// Estimated serialized size used by the page byte budget.
    pub(super) fn estimated_response_bytes(&self) -> usize {
        // Bodies may be base64-expanded and headers are quoted; a generous
        // constant factor keeps the estimate conservative.
        self.body
            .len()
            .saturating_mul(2)
            .saturating_add(self.headers.to_string().len().saturating_mul(2))
            .saturating_add(self.url.len())
            .saturating_add(self.path.len())
            .saturating_add(self.query_string.len())
            .saturating_add(1_024)
    }

    fn into_request(self, entity: &'static str) -> Result<CapturedRequest, StoreError> {
        let headers = decode_headers(&self.headers)
            .ok_or_else(|| StoreError::corrupt(entity, "headers are not name/value pairs"))?;
        let url = Url::parse(&self.url).map_err(|error| StoreError::corrupt(entity, error))?;
        if url.path() != self.path || url.query().unwrap_or_default() != self.query_string {
            return Err(StoreError::corrupt(
                entity,
                "url disagrees with path or query",
            ));
        }
        CapturedRequest::new(CapturedRequestParts {
            method: self.method,
            url,
            headers,
            body: Bytes::from(self.body),
            remote_ip: self.remote_ip,
            received_at: self.received_at,
        })
        .map_err(|error| StoreError::corrupt(entity, error))
    }
}

/// Serializes header pairs as a JSON array of `[name, value]` arrays.
///
/// PostgreSQL `jsonb` cannot represent `U+0000`, so it is replaced with the
/// Unicode replacement character; header values cannot legitimately contain it.
pub(super) fn encode_headers(headers: &[(String, String)]) -> Value {
    Value::Array(
        headers
            .iter()
            .map(|(name, value)| {
                Value::Array(vec![
                    Value::String(name.replace('\0', "\u{FFFD}")),
                    Value::String(value.replace('\0', "\u{FFFD}")),
                ])
            })
            .collect(),
    )
}

fn decode_headers(value: &Value) -> Option<Vec<(String, String)>> {
    value
        .as_array()?
        .iter()
        .map(|pair| {
            let pair = pair.as_array()?;
            match pair.as_slice() {
                [Value::String(name), Value::String(value)] => Some((name.clone(), value.clone())),
                _ => None,
            }
        })
        .collect()
}

#[derive(Debug, FromRow)]
pub(super) struct EventRow {
    pub(super) id: Uuid,
    pub(super) hook_id: Uuid,
    pub(super) org_id: String,
    pub(super) silicon_id: String,
    pub(super) provider: String,
    pub(super) summary: String,
    pub(super) delivery_sequence: i64,
    #[sqlx(flatten)]
    pub(super) capture: CaptureRow,
}

impl TryFrom<EventRow> for EventRecord {
    type Error = StoreError;

    fn try_from(row: EventRow) -> Result<Self, Self::Error> {
        let corrupt = |error: &dyn std::fmt::Display| StoreError::corrupt("event", error);
        let received_at = row.capture.received_at;
        Ok(EventRecord::rehydrate(EventRecordSnapshot {
            id: row.id.into(),
            organization_id: OrganizationId::new(row.org_id).map_err(|error| corrupt(&error))?,
            silicon_id: SiliconId::new(row.silicon_id).map_err(|error| corrupt(&error))?,
            hook_id: row.hook_id.into(),
            provider: HookName::new(row.provider).map_err(|error| corrupt(&error))?,
            summary: row.summary,
            request: row.capture.into_request("event")?,
            delivery_sequence: DeliverySequence::new(row.delivery_sequence)
                .map_err(|error| corrupt(&error))?,
            received_at,
        }))
    }
}

#[derive(Debug, FromRow)]
pub(super) struct BlockedRequestRow {
    pub(super) id: Uuid,
    pub(super) hook_id: Uuid,
    pub(super) org_id: String,
    pub(super) silicon_id: String,
    pub(super) provider: String,
    pub(super) reason_code: String,
    pub(super) reason_detail: String,
    #[sqlx(flatten)]
    pub(super) capture: CaptureRow,
}

impl TryFrom<BlockedRequestRow> for BlockedRequest {
    type Error = StoreError;

    fn try_from(row: BlockedRequestRow) -> Result<Self, Self::Error> {
        let corrupt = |error: &dyn std::fmt::Display| StoreError::corrupt("blocked request", error);
        let received_at = row.capture.received_at;
        Ok(BlockedRequest::rehydrate(BlockedRequestSnapshot {
            id: BlockedRequestId::from_uuid(row.id),
            organization_id: OrganizationId::new(row.org_id).map_err(|error| corrupt(&error))?,
            silicon_id: SiliconId::new(row.silicon_id).map_err(|error| corrupt(&error))?,
            hook_id: HookId::from_uuid(row.hook_id),
            provider: HookName::new(row.provider).map_err(|error| corrupt(&error))?,
            request: row.capture.into_request("blocked request")?,
            reason: BlockReason::rehydrate(row.reason_code, &row.reason_detail)
                .map_err(|error| corrupt(&error))?,
            received_at,
        }))
    }
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
pub(super) struct IpBlockRow {
    pub(super) strikes: i32,
    pub(super) blocked_until: Option<OffsetDateTime>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{decode_headers, encode_headers};

    #[test]
    fn headers_round_trip_and_reject_malformed_shapes() {
        let headers = vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            ("x-nul".to_owned(), "a\0b".to_owned()),
        ];
        let encoded = encode_headers(&headers);
        assert_eq!(
            encoded,
            json!([
                ["content-type", "application/json"],
                ["x-nul", "a\u{FFFD}b"]
            ])
        );
        assert_eq!(decode_headers(&encoded).map(|pairs| pairs.len()), Some(2));
        assert_eq!(decode_headers(&json!([["only-name"]])), None);
        assert_eq!(decode_headers(&json!({"a": "b"})), None);
    }
}
