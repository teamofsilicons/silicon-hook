//! Immutable event envelopes and mutable delivery projections.

use std::{fmt, str::FromStr, time::Duration as StdDuration};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use super::{DomainError, EventId, HookId, OrganizationId, SiliconId, TransitionError};

/// Default schema version assigned when a sender omits it.
pub const DEFAULT_SCHEMA_VERSION: &str = "1.0";
/// Maximum event-type size in bytes.
pub const MAX_EVENT_TYPE_BYTES: usize = 200;
/// Maximum source and subject length in Unicode scalar values.
pub const MAX_EVENT_CONTEXT_LENGTH: usize = 500;
/// Maximum schema-version size in bytes.
pub const MAX_SCHEMA_VERSION_BYTES: usize = 50;
/// Maximum trace identifier size in bytes.
pub const MAX_TRACE_ID_BYTES: usize = 255;
/// Maximum retained failure-reason length in Unicode scalar values.
pub const MAX_FAILURE_REASON_LENGTH: usize = 2_000;
/// Default number of attempted DM requests before a durable failure.
pub const DEFAULT_MAX_DELIVERY_ATTEMPTS: u32 = 20;

/// Validated event type such as `iam.silicon.initialized`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventType(String);

impl EventType {
    /// Validates an event type against the public contract.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] for an empty, overlong, or syntactically invalid
    /// event type.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DomainError::Empty {
                field: "event_type",
            });
        }
        if value.len() > MAX_EVENT_TYPE_BYTES {
            return Err(DomainError::TooLong {
                field: "event_type",
                max: MAX_EVENT_TYPE_BYTES,
            });
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        }) {
            return Err(DomainError::InvalidFormat {
                field: "event_type",
                reason: "must contain only lowercase ASCII letters, digits, dots, underscores, or hyphens",
            });
        }
        Ok(Self(value))
    }

    /// Returns the canonical type name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for EventType {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for EventType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EventType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Validated event schema version.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchemaVersion(String);

impl SchemaVersion {
    /// Validates a sender-provided schema version.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the version is empty, exceeds 50 bytes, or
    /// contains characters outside visible ASCII.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_visible_ascii(&value, "schema_version", MAX_SCHEMA_VERSION_BYTES, false)?;
        Ok(Self(value))
    }

    /// Returns the version string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SchemaVersion {
    fn default() -> Self {
        Self(DEFAULT_SCHEMA_VERSION.to_owned())
    }
}

impl Serialize for SchemaVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Validated trace identifier propagated with an event.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TraceId(String);

impl TraceId {
    /// Validates a trace or request correlation identifier.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the identifier exceeds 255 bytes or
    /// contains characters outside visible ASCII.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_visible_ascii(&value, "trace_id", MAX_TRACE_ID_BYTES, true)?;
        Ok(Self(value))
    }

    /// Returns the trace identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for TraceId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TraceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

fn validate_visible_ascii(
    value: &str,
    field: &'static str,
    max: usize,
    allow_empty: bool,
) -> Result<(), DomainError> {
    if value.is_empty() && !allow_empty {
        return Err(DomainError::Empty { field });
    }
    if value.len() > max {
        return Err(DomainError::TooLong { field, max });
    }
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(DomainError::InvalidFormat {
            field,
            reason: "must contain only visible ASCII characters",
        });
    }
    Ok(())
}

fn validate_context(value: &str, field: &'static str) -> Result<(), DomainError> {
    if value.chars().count() > MAX_EVENT_CONTEXT_LENGTH {
        return Err(DomainError::TooLong {
            field,
            max: MAX_EVENT_CONTEXT_LENGTH,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(DomainError::InvalidFormat {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

/// JSON request shape accepted at webhook ingress before server defaults.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EventEnvelopeInput {
    #[serde(rename = "type")]
    event_type: EventType,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    occurred_at: Option<OffsetDateTime>,
    #[serde(default)]
    schema_version: Option<SchemaVersion>,
    #[serde(default)]
    trace_id: Option<TraceId>,
    payload: Map<String, Value>,
}

impl EventEnvelopeInput {
    /// Constructs the required portion of an ingress envelope.
    #[must_use]
    pub fn new(event_type: EventType, payload: Map<String, Value>) -> Self {
        Self {
            event_type,
            source: None,
            subject: None,
            occurred_at: None,
            schema_version: None,
            trace_id: None,
            payload,
        }
    }

    /// Sets optional sender context before validation.
    #[must_use]
    pub fn with_context(mut self, source: Option<String>, subject: Option<String>) -> Self {
        self.source = source;
        self.subject = subject;
        self
    }

    /// Sets optional sender-controlled metadata before defaults are applied.
    #[must_use]
    pub fn with_metadata(
        mut self,
        occurred_at: Option<OffsetDateTime>,
        schema_version: Option<SchemaVersion>,
        trace_id: Option<TraceId>,
    ) -> Self {
        self.occurred_at = occurred_at;
        self.schema_version = schema_version;
        self.trace_id = trace_id;
        self
    }

    /// Validates optional context and applies receive-time and correlation-ID
    /// defaults, producing the immutable stored envelope.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when source or subject exceeds its contract
    /// length or contains a control character.
    pub fn normalize(
        self,
        received_at: OffsetDateTime,
        fallback_trace_id: TraceId,
    ) -> Result<EventEnvelope, DomainError> {
        if let Some(source) = &self.source {
            validate_context(source, "source")?;
        }
        if let Some(subject) = &self.subject {
            validate_context(subject, "subject")?;
        }
        validate_jsonb_object(&self.payload)?;
        let occurred_at =
            canonical_timestamp(self.occurred_at.unwrap_or(received_at), "occurred_at")?;
        Ok(EventEnvelope {
            event_type: self.event_type,
            source: self.source,
            subject: self.subject,
            occurred_at,
            schema_version: self.schema_version.unwrap_or_default(),
            trace_id: self.trace_id.unwrap_or(fallback_trace_id),
            payload: self.payload,
        })
    }
}

fn validate_jsonb_object(payload: &Map<String, Value>) -> Result<(), DomainError> {
    if payload.keys().any(|key| key.contains('\0')) {
        return Err(postgres_nul_payload_error());
    }
    let mut pending = payload.values().collect::<Vec<_>>();
    while let Some(value) = pending.pop() {
        match value {
            Value::String(value) if value.contains('\0') => {
                return Err(postgres_nul_payload_error());
            }
            Value::Array(values) => pending.extend(values),
            Value::Object(values) => {
                if values.keys().any(|key| key.contains('\0')) {
                    return Err(postgres_nul_payload_error());
                }
                pending.extend(values.values());
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn postgres_nul_payload_error() -> DomainError {
    DomainError::InvalidFormat {
        field: "payload",
        reason: "JSON object keys and strings must not contain U+0000",
    }
}

fn canonical_timestamp(
    value: OffsetDateTime,
    field: &'static str,
) -> Result<OffsetDateTime, DomainError> {
    let value = value.to_offset(time::UtcOffset::UTC);
    let nanosecond = value.nanosecond() / 1_000 * 1_000;
    value
        .replace_nanosecond(nanosecond)
        .map_err(|_| DomainError::InvalidFormat {
            field,
            reason: "timestamp is outside the supported range",
        })
}

/// Validated, defaulted event envelope committed at acceptance.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EventEnvelope {
    #[serde(rename = "type")]
    event_type: EventType,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    occurred_at: OffsetDateTime,
    schema_version: SchemaVersion,
    trace_id: TraceId,
    payload: Map<String, Value>,
}

impl EventEnvelope {
    /// Rehydrates an envelope from individually validated persistence values.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when persisted source or subject violates the
    /// current event contract.
    pub fn rehydrate(
        event_type: EventType,
        source: Option<String>,
        subject: Option<String>,
        occurred_at: OffsetDateTime,
        schema_version: SchemaVersion,
        trace_id: TraceId,
        payload: Map<String, Value>,
    ) -> Result<Self, DomainError> {
        if let Some(source) = &source {
            validate_context(source, "source")?;
        }
        if let Some(subject) = &subject {
            validate_context(subject, "subject")?;
        }
        Ok(Self {
            event_type,
            source,
            subject,
            occurred_at: occurred_at.to_offset(time::UtcOffset::UTC),
            schema_version,
            trace_id,
            payload,
        })
    }

    /// Returns the event type.
    #[must_use]
    pub const fn event_type(&self) -> &EventType {
        &self.event_type
    }

    /// Returns the optional source.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Returns the optional subject.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// Returns sender occurrence time after defaulting.
    #[must_use]
    pub const fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    /// Returns the schema version after defaulting.
    #[must_use]
    pub const fn schema_version(&self) -> &SchemaVersion {
        &self.schema_version
    }

    /// Returns the trace identifier after defaulting.
    #[must_use]
    pub const fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    /// Returns the immutable JSON object payload.
    #[must_use]
    pub const fn payload(&self) -> &Map<String, Value> {
        &self.payload
    }
}

/// SHA-256 digest used to bind an idempotency key to request content.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RequestDigest([u8; 32]);

impl RequestDigest {
    /// Hashes exact request bytes.
    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Hashes a sequence of exact byte slices without allocating a combined buffer.
    #[must_use]
    pub fn sha256_parts(parts: &[&[u8]]) -> Self {
        let mut digest = Sha256::new();
        for part in parts {
            digest.update(part);
        }
        Self(digest.finalize().into())
    }

    /// Wraps a digest loaded from persistence.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-size digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RequestDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RequestDigest")
            .field(&hex::encode(self.0))
            .finish()
    }
}

/// DM delivery state exposed with retained event history.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    /// Accepted but not yet attempted.
    Pending,
    /// Durably accepted by DM with HTTP 202; this is not a client WebSocket ACK.
    Delivered,
    /// A retryable attempt failed and another is scheduled.
    Retrying,
    /// Terminal response or exhausted retry budget.
    Failed,
}

impl DeliveryStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Retrying => "retrying",
            Self::Failed => "failed",
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(self, Self::Delivered | Self::Failed)
    }
}

/// Mutable projection of an outbox delivery receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeliveryState {
    status: DeliveryStatus,
    attempts: u32,
    #[serde(default, with = "time::serde::rfc3339::option")]
    last_attempt_at: Option<OffsetDateTime>,
    failure_reason: Option<String>,
}

impl DeliveryState {
    /// Creates the initial delivery projection.
    #[must_use]
    pub const fn pending() -> Self {
        Self {
            status: DeliveryStatus::Pending,
            attempts: 0,
            last_attempt_at: None,
            failure_reason: None,
        }
    }

    /// Rehydrates a delivery projection while enforcing state invariants.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when status, attempt count, timestamp, or
    /// failure reason are inconsistent or invalid.
    pub fn rehydrate(
        status: DeliveryStatus,
        attempts: u32,
        last_attempt_at: Option<OffsetDateTime>,
        failure_reason: Option<String>,
    ) -> Result<Self, DomainError> {
        let attempts_are_consistent = match status {
            DeliveryStatus::Pending => attempts == 0 && last_attempt_at.is_none(),
            DeliveryStatus::Delivered | DeliveryStatus::Retrying | DeliveryStatus::Failed => {
                attempts > 0 && last_attempt_at.is_some()
            }
        };
        if !attempts_are_consistent {
            return Err(DomainError::InvalidFormat {
                field: "delivery",
                reason: "status, attempts, and last_attempt_at are inconsistent",
            });
        }
        let failure_reason = failure_reason.map(validate_failure_reason).transpose()?;
        if status == DeliveryStatus::Delivered && failure_reason.is_some() {
            return Err(DomainError::InvalidFormat {
                field: "failure_reason",
                reason: "delivered events cannot retain a failure reason",
            });
        }
        Ok(Self {
            status,
            attempts,
            last_attempt_at,
            failure_reason,
        })
    }

    /// Returns the current delivery status.
    #[must_use]
    pub const fn status(&self) -> DeliveryStatus {
        self.status
    }

    /// Returns the number of completed DM attempts.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Returns the last completed attempt time.
    #[must_use]
    pub const fn last_attempt_at(&self) -> Option<OffsetDateTime> {
        self.last_attempt_at
    }

    /// Returns a bounded diagnostic reason with no response body.
    #[must_use]
    pub fn failure_reason(&self) -> Option<&str> {
        self.failure_reason.as_deref()
    }

    /// Records DM's durable `202 Accepted` handoff acknowledgment.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] for a terminal state, an out-of-order
    /// timestamp, or an exhausted numeric attempt counter.
    pub fn record_delivered(
        &mut self,
        attempted_at: OffsetDateTime,
    ) -> Result<(), TransitionError> {
        self.ensure_mutable_and_ordered(attempted_at)?;
        self.attempts = self
            .attempts
            .checked_add(1)
            .ok_or(TransitionError::DeliveryAttemptOverflow)?;
        self.status = DeliveryStatus::Delivered;
        self.last_attempt_at = Some(attempted_at);
        self.failure_reason = None;
        Ok(())
    }

    /// Records a retryable failure and keeps the outbox work due.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] for a terminal state, an out-of-order
    /// timestamp, or an exhausted numeric attempt counter.
    pub fn record_retrying(
        &mut self,
        attempted_at: OffsetDateTime,
        failure_reason: impl Into<String>,
    ) -> Result<(), TransitionError> {
        self.ensure_mutable_and_ordered(attempted_at)?;
        let failure_reason = failure_reason.into();
        self.attempts = self
            .attempts
            .checked_add(1)
            .ok_or(TransitionError::DeliveryAttemptOverflow)?;
        self.status = DeliveryStatus::Retrying;
        self.last_attempt_at = Some(attempted_at);
        self.failure_reason = Some(bounded_failure_reason(&failure_reason));
        Ok(())
    }

    /// Records a terminal or exhausted failure.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] for a terminal state, an out-of-order
    /// timestamp, or an exhausted numeric attempt counter.
    pub fn record_failed(
        &mut self,
        attempted_at: OffsetDateTime,
        failure_reason: impl Into<String>,
    ) -> Result<(), TransitionError> {
        self.ensure_mutable_and_ordered(attempted_at)?;
        let failure_reason = failure_reason.into();
        self.attempts = self
            .attempts
            .checked_add(1)
            .ok_or(TransitionError::DeliveryAttemptOverflow)?;
        self.status = DeliveryStatus::Failed;
        self.last_attempt_at = Some(attempted_at);
        self.failure_reason = Some(bounded_failure_reason(&failure_reason));
        Ok(())
    }

    fn ensure_mutable_and_ordered(
        &self,
        attempted_at: OffsetDateTime,
    ) -> Result<(), TransitionError> {
        if self.status.is_terminal() {
            return Err(TransitionError::DeliveryTerminal {
                status: self.status.as_str(),
            });
        }
        if self
            .last_attempt_at
            .is_some_and(|last_attempt_at| attempted_at < last_attempt_at)
        {
            return Err(TransitionError::TimestampOutOfOrder {
                field: "last_attempt_at",
                predecessor: "previous_attempt_at",
            });
        }
        Ok(())
    }
}

fn validate_failure_reason(value: String) -> Result<String, DomainError> {
    if value.chars().count() > MAX_FAILURE_REASON_LENGTH {
        return Err(DomainError::TooLong {
            field: "failure_reason",
            max: MAX_FAILURE_REASON_LENGTH,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(DomainError::InvalidFormat {
            field: "failure_reason",
            reason: "must not contain control characters",
        });
    }
    Ok(value)
}

fn bounded_failure_reason(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAX_FAILURE_REASON_LENGTH)
        .collect()
}

/// Persistence snapshot for an accepted event and delivery projection.
#[derive(Clone, Debug, PartialEq)]
pub struct EventRecordSnapshot {
    /// Stable `UUIDv7` event ID.
    pub id: EventId,
    /// Owning organization.
    pub organization_id: OrganizationId,
    /// Destination Silicon.
    pub silicon_id: SiliconId,
    /// Receiving hook.
    pub hook_id: HookId,
    /// Validated immutable event envelope.
    pub envelope: EventEnvelope,
    /// Digest of exact ingress request bytes.
    pub request_digest: RequestDigest,
    /// Authoritative server receive time.
    pub received_at: OffsetDateTime,
    /// Current outbox receipt projection.
    pub delivery: DeliveryState,
}

/// Accepted event history record.
#[derive(Clone, Debug, PartialEq)]
pub struct EventRecord {
    snapshot: EventRecordSnapshot,
}

impl EventRecord {
    /// Creates an accepted event with pending DM delivery.
    #[must_use]
    pub fn accept(
        id: EventId,
        organization_id: OrganizationId,
        silicon_id: SiliconId,
        hook_id: HookId,
        envelope: EventEnvelope,
        request_digest: RequestDigest,
        received_at: OffsetDateTime,
    ) -> Self {
        Self {
            snapshot: EventRecordSnapshot {
                id,
                organization_id,
                silicon_id,
                hook_id,
                envelope,
                request_digest,
                received_at,
                delivery: DeliveryState::pending(),
            },
        }
    }

    /// Rehydrates a persisted record.
    #[must_use]
    pub const fn rehydrate(snapshot: EventRecordSnapshot) -> Self {
        Self { snapshot }
    }

    /// Returns a read-only persistence snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &EventRecordSnapshot {
        &self.snapshot
    }

    /// Returns the stable event identifier.
    #[must_use]
    pub const fn id(&self) -> EventId {
        self.snapshot.id
    }

    /// Returns the owning organization.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.snapshot.organization_id
    }

    /// Returns the destination Silicon.
    #[must_use]
    pub const fn silicon_id(&self) -> &SiliconId {
        &self.snapshot.silicon_id
    }

    /// Returns the receiving hook.
    #[must_use]
    pub const fn hook_id(&self) -> HookId {
        self.snapshot.hook_id
    }

    /// Returns the immutable envelope.
    #[must_use]
    pub const fn envelope(&self) -> &EventEnvelope {
        &self.snapshot.envelope
    }

    /// Returns the request content digest.
    #[must_use]
    pub const fn request_digest(&self) -> RequestDigest {
        self.snapshot.request_digest
    }

    /// Returns authoritative receive time.
    #[must_use]
    pub const fn received_at(&self) -> OffsetDateTime {
        self.snapshot.received_at
    }

    /// Returns the current delivery projection.
    #[must_use]
    pub const fn delivery(&self) -> &DeliveryState {
        &self.snapshot.delivery
    }

    /// Mutably borrows the delivery projection for an application-controlled
    /// transition.
    pub const fn delivery_mut(&mut self) -> &mut DeliveryState {
        &mut self.snapshot.delivery
    }
}

/// Result of classifying a completed DM attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryDecision {
    /// DM durably accepted the event with HTTP 202.
    Delivered,
    /// Schedule another attempt using full jitter no greater than this delay.
    Retry {
        /// Exponential-backoff ceiling before jitter.
        delay_ceiling: StdDuration,
    },
    /// Retain the outbox entry as a durable dead letter.
    Failed,
}

/// Bounded retry and response-classification policy for DM delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryPolicy {
    max_attempts: u32,
    base_delay: StdDuration,
    max_delay: StdDuration,
}

impl DeliveryPolicy {
    /// Creates a delivery policy.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] for a zero attempt budget, zero base delay, or a
    /// maximum delay below the base delay.
    pub fn new(
        max_attempts: u32,
        base_delay: StdDuration,
        max_delay: StdDuration,
    ) -> Result<Self, DomainError> {
        if max_attempts == 0 {
            return Err(DomainError::OutOfRange {
                field: "max_delivery_attempts",
                min: 1,
                max: u64::from(u32::MAX),
            });
        }
        if base_delay.is_zero() || max_delay < base_delay {
            return Err(DomainError::InvalidFormat {
                field: "delivery_delay",
                reason: "base delay must be positive and no greater than the maximum",
            });
        }
        Ok(Self {
            max_attempts,
            base_delay,
            max_delay,
        })
    }

    /// Returns the configured attempt budget.
    #[must_use]
    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }

    /// Classifies an HTTP response after `attempts_completed` includes the
    /// response being classified.
    #[must_use]
    pub fn classify_http(self, status: u16, attempts_completed: u32) -> DeliveryDecision {
        if status == 202 {
            return DeliveryDecision::Delivered;
        }
        let retryable = matches!(status, 408 | 425 | 429 | 500..=599);
        if !retryable || attempts_completed >= self.max_attempts {
            return DeliveryDecision::Failed;
        }
        DeliveryDecision::Retry {
            delay_ceiling: self.backoff_ceiling(attempts_completed),
        }
    }

    /// Classifies a connection, timeout, or protocol failure after the given
    /// completed-attempt count.
    #[must_use]
    pub fn classify_transport_failure(self, attempts_completed: u32) -> DeliveryDecision {
        if attempts_completed >= self.max_attempts {
            DeliveryDecision::Failed
        } else {
            DeliveryDecision::Retry {
                delay_ceiling: self.backoff_ceiling(attempts_completed),
            }
        }
    }

    fn backoff_ceiling(self, attempts_completed: u32) -> StdDuration {
        let exponent = attempts_completed.saturating_sub(1).min(31);
        let factor = 1_u32.checked_shl(exponent).unwrap_or(u32::MAX);
        self.base_delay
            .checked_mul(factor)
            .map_or(self.max_delay, |delay| delay.min(self.max_delay))
    }
}

impl Default for DeliveryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_DELIVERY_ATTEMPTS,
            base_delay: StdDuration::from_secs(1),
            max_delay: StdDuration::from_mins(15),
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;
    use time::{Duration, macros::datetime};

    use super::*;

    fn payload() -> Map<String, Value> {
        match json!({"answer": 42}) {
            Value::Object(object) => object,
            _ => Map::new(),
        }
    }

    #[test]
    fn envelope_defaults_are_authoritative_receive_values() -> Result<(), Box<dyn std::error::Error>>
    {
        let received_at = datetime!(2026-08-31 12:00 UTC);
        let trace = TraceId::new("request-123")?;
        let envelope = EventEnvelopeInput::new(EventType::new("github.push")?, payload())
            .normalize(received_at, trace.clone())?;

        assert_eq!(envelope.occurred_at(), received_at);
        assert_eq!(envelope.schema_version().as_str(), DEFAULT_SCHEMA_VERSION);
        assert_eq!(envelope.trace_id(), &trace);
        assert_eq!(envelope.payload(), &payload());
        Ok(())
    }

    #[test]
    fn envelope_timestamps_use_stable_microsecond_precision()
    -> Result<(), Box<dyn std::error::Error>> {
        let received_at = datetime!(2026-08-31 12:00:00.123456789 UTC);
        let envelope = EventEnvelopeInput::new(EventType::new("test.event")?, payload())
            .normalize(received_at, TraceId::new("request-123")?)?;

        assert_eq!(
            envelope.occurred_at(),
            datetime!(2026-08-31 12:00:00.123456 UTC)
        );
        Ok(())
    }

    #[test]
    fn payload_must_be_a_json_object() {
        let result = serde_json::from_value::<EventEnvelopeInput>(json!({
            "type": "github.push",
            "payload": [1, 2, 3]
        }));
        assert!(result.is_err());
    }

    #[test]
    fn payload_rejects_postgres_incompatible_nul_in_keys_and_strings()
    -> Result<(), Box<dyn std::error::Error>> {
        let received_at = datetime!(2026-08-31 12:00 UTC);
        let trace = TraceId::new("request-123")?;
        for invalid in [json!({"nul\0key": true}), json!({"nested": ["nul\0value"]})] {
            let Value::Object(payload) = invalid else {
                return Err("test payload must be an object".into());
            };
            assert!(
                EventEnvelopeInput::new(EventType::new("test.event")?, payload)
                    .normalize(received_at, trace.clone())
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn event_type_matches_contract_grammar() {
        assert!(EventType::new("iam.silicon.initialized").is_ok());
        assert!(EventType::new("GitHub.Push").is_err());
        assert!(EventType::new("contains space").is_err());
        assert!(EventType::new("").is_err());
    }

    #[test]
    fn source_and_subject_limits_count_unicode_characters() -> Result<(), Box<dyn std::error::Error>>
    {
        let at_limit = "界".repeat(MAX_EVENT_CONTEXT_LENGTH);
        let over_limit = "界".repeat(MAX_EVENT_CONTEXT_LENGTH + 1);
        let received_at = datetime!(2026-08-31 12:00 UTC);
        let trace = TraceId::new("request-123")?;

        assert!(
            EventEnvelopeInput::new(EventType::new("test.event")?, payload())
                .with_context(Some(at_limit.clone()), Some(at_limit))
                .normalize(received_at, trace.clone())
                .is_ok()
        );
        assert!(
            EventEnvelopeInput::new(EventType::new("test.event")?, payload())
                .with_context(Some(over_limit), None)
                .normalize(received_at, trace)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn optional_context_and_trace_may_be_empty_per_the_http_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let envelope = EventEnvelopeInput::new(EventType::new("test.event")?, payload())
            .with_context(Some(String::new()), Some(String::new()))
            .with_metadata(None, None, Some(TraceId::new("")?))
            .normalize(datetime!(2026-08-31 12:00 UTC), TraceId::new("fallback")?)?;

        assert_eq!(envelope.source(), Some(""));
        assert_eq!(envelope.subject(), Some(""));
        assert_eq!(envelope.trace_id().as_str(), "");
        Ok(())
    }

    #[test]
    fn event_input_rejects_unknown_fields() {
        let result = serde_json::from_value::<EventEnvelopeInput>(json!({
            "type": "test.event",
            "payload": {},
            "unexpected": true
        }));
        assert!(result.is_err());
    }

    #[test]
    fn delivery_state_transitions_and_is_terminal() -> Result<(), Box<dyn std::error::Error>> {
        let mut state = DeliveryState::pending();
        let first = datetime!(2026-08-31 12:00 UTC);
        state.record_retrying(first, "timeout")?;
        state.record_delivered(first + Duration::seconds(2))?;

        assert_eq!(state.status(), DeliveryStatus::Delivered);
        assert_eq!(state.attempts(), 2);
        assert_eq!(state.failure_reason(), None);
        assert_eq!(
            state.record_failed(first + Duration::seconds(3), "late"),
            Err(TransitionError::DeliveryTerminal {
                status: "delivered"
            })
        );
        Ok(())
    }

    #[test]
    fn delivery_failures_are_sanitized_and_unicode_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut state = DeliveryState::pending();
        let reason = format!("line\n{}", "界".repeat(MAX_FAILURE_REASON_LENGTH));
        state.record_retrying(datetime!(2026-08-31 12:00 UTC), reason)?;
        let stored = state.failure_reason().unwrap_or_default();

        assert!(!stored.chars().any(char::is_control));
        assert_eq!(stored.chars().count(), MAX_FAILURE_REASON_LENGTH);
        Ok(())
    }

    #[test]
    fn delivery_attempt_counter_never_wraps() -> Result<(), Box<dyn std::error::Error>> {
        let attempted_at = datetime!(2026-08-31 12:00 UTC);
        let mut state = DeliveryState::rehydrate(
            DeliveryStatus::Retrying,
            u32::MAX,
            Some(attempted_at),
            Some("timeout".to_owned()),
        )?;

        assert_eq!(
            state.record_retrying(attempted_at, "timeout"),
            Err(TransitionError::DeliveryAttemptOverflow)
        );
        Ok(())
    }

    #[test]
    fn delivery_policy_accepts_only_202_and_retries_the_documented_statuses() {
        let policy = DeliveryPolicy::default();

        assert_eq!(policy.classify_http(202, 1), DeliveryDecision::Delivered);
        assert!(matches!(
            policy.classify_http(429, 1),
            DeliveryDecision::Retry { .. }
        ));
        assert!(matches!(
            policy.classify_http(503, 2),
            DeliveryDecision::Retry { .. }
        ));
        assert_eq!(policy.classify_http(200, 1), DeliveryDecision::Failed);
        assert_eq!(policy.classify_http(400, 1), DeliveryDecision::Failed);
        assert_eq!(policy.classify_http(503, 20), DeliveryDecision::Failed);
    }

    #[test]
    fn retry_backoff_is_exponential_and_capped() {
        let policy = DeliveryPolicy::default();
        let ceilings: Vec<StdDuration> = (1..=20)
            .filter_map(|attempt| match policy.classify_http(503, attempt) {
                DeliveryDecision::Retry { delay_ceiling } => Some(delay_ceiling),
                DeliveryDecision::Delivered | DeliveryDecision::Failed => None,
            })
            .collect();

        assert_eq!(ceilings.first(), Some(&StdDuration::from_secs(1)));
        assert!(ceilings.windows(2).all(|window| window[0] <= window[1]));
        assert!(
            ceilings
                .iter()
                .all(|delay| *delay <= StdDuration::from_mins(15))
        );
        assert_eq!(ceilings.last(), Some(&StdDuration::from_mins(15)));
    }

    #[test]
    fn request_digest_has_a_stable_sha256_vector() {
        assert_eq!(
            hex::encode(RequestDigest::sha256(b"hello").as_bytes()),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(
            RequestDigest::sha256_parts(&[b"he", b"ll", b"o"]),
            RequestDigest::sha256(b"hello")
        );
    }

    proptest! {
        #[test]
        fn valid_event_types_round_trip(value in "[a-z0-9_.-]{1,200}") {
            let event_type = EventType::new(value.clone());
            prop_assert!(event_type.is_ok());
            if let Ok(event_type) = event_type {
                prop_assert_eq!(event_type.as_str(), value);
            }
        }

        #[test]
        fn retry_delay_never_exceeds_cap(attempt in 1_u32..u32::MAX) {
            let policy = DeliveryPolicy::default();
            let decision = policy.classify_transport_failure(attempt);
            if let DeliveryDecision::Retry { delay_ceiling } = decision {
                prop_assert!(delay_ceiling <= StdDuration::from_mins(15));
            }
        }
    }
}
