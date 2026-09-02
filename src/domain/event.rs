//! Verified request records, blocked request records, and delivery ordering.
//!
//! A verified provider request becomes an [`EventRecord`]: the exact captured
//! request, the hook that received it, a human-readable summary, and a
//! per-Silicon delivery sequence used for ordered, acknowledged delivery. A
//! request that fails verification becomes a [`BlockedRequest`] instead and is
//! never delivered.

use std::fmt;

use time::{Duration, OffsetDateTime};

use super::{
    BlockedRequestId, DomainError, EventId, Hook, HookId, HookName, HookTimeZone, OrganizationId,
    SiliconId, request::CapturedRequest, signature::RejectionReason,
};

/// Retention of verified and blocked request logs.
pub const LOG_RETENTION: Duration = Duration::days(14);
/// Maximum retained length of a blocked-request reason detail.
pub const MAX_REASON_DETAIL_LENGTH: usize = 500;

/// Position of an event in one Silicon's ordered delivery stream.
///
/// Sequences start at one and never repeat for a Silicon, so a consumer can
/// acknowledge "everything through N" and resume after it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeliverySequence(i64);

impl DeliverySequence {
    /// Wraps a positive stream position.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] for zero or negative values.
    pub fn new(value: i64) -> Result<Self, DomainError> {
        if value < 1 {
            return Err(DomainError::OutOfRange {
                field: "delivery_sequence",
                min: 1,
                max: u64::MAX,
            });
        }
        Ok(Self(value))
    }

    /// Returns the numeric position.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for DeliverySequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Renders `{provider} triggered at HH:MM:SS DD-MM-YYYY IANA_ZONE_ID`.
///
/// The line accompanies every delivered event so a reader knows which
/// provider sent it and when, in the hook's configured zone.
#[must_use]
pub fn delivery_summary(provider: &HookName, at: OffsetDateTime, zone: &HookTimeZone) -> String {
    let rendered = match jiff::Timestamp::from_nanosecond(at.unix_timestamp_nanos()) {
        Ok(timestamp) => timestamp
            .to_zoned(zone.resolve())
            .strftime("%H:%M:%S %d-%m-%Y")
            .to_string(),
        Err(_) => "00:00:00 01-01-1970".to_owned(),
    };
    format!("{} triggered at {rendered} {zone}", provider.as_str())
}

/// Persistence snapshot for a verified request.
#[derive(Clone, Debug)]
pub struct EventRecordSnapshot {
    /// Stable `UUIDv7` event ID.
    pub id: EventId,
    /// Owning organization.
    pub organization_id: OrganizationId,
    /// Destination Silicon.
    pub silicon_id: SiliconId,
    /// Receiving hook.
    pub hook_id: HookId,
    /// Hook name at receipt, shown as the provider.
    pub provider: HookName,
    /// Human-readable delivery line.
    pub summary: String,
    /// Exact captured request.
    pub request: CapturedRequest,
    /// Position in the Silicon's delivery stream.
    pub delivery_sequence: DeliverySequence,
    /// Authoritative receive time.
    pub received_at: OffsetDateTime,
}

/// A verified provider request retained for delivery and history.
#[derive(Clone, Debug)]
pub struct EventRecord {
    snapshot: EventRecordSnapshot,
}

impl EventRecord {
    /// Creates a verified event for a hook.
    #[must_use]
    pub fn accept(
        id: EventId,
        hook: &Hook,
        request: CapturedRequest,
        delivery_sequence: DeliverySequence,
    ) -> Self {
        let received_at = request.received_at();
        Self {
            snapshot: EventRecordSnapshot {
                id,
                organization_id: hook.organization_id().clone(),
                silicon_id: hook.silicon_id().clone(),
                hook_id: hook.id(),
                provider: hook.name().clone(),
                summary: delivery_summary(hook.name(), received_at, hook.time_zone()),
                request,
                delivery_sequence,
                received_at,
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

    /// Returns the provider name recorded at receipt.
    #[must_use]
    pub const fn provider(&self) -> &HookName {
        &self.snapshot.provider
    }

    /// Returns the rendered delivery line.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.snapshot.summary
    }

    /// Returns the exact captured request.
    #[must_use]
    pub const fn request(&self) -> &CapturedRequest {
        &self.snapshot.request
    }

    /// Returns the delivery stream position.
    #[must_use]
    pub const fn delivery_sequence(&self) -> DeliverySequence {
        self.snapshot.delivery_sequence
    }

    /// Returns authoritative receive time.
    #[must_use]
    pub const fn received_at(&self) -> OffsetDateTime {
        self.snapshot.received_at
    }

    /// Returns the instant after which the record is no longer retained.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.snapshot.received_at.saturating_add(LOG_RETENTION)
    }
}

/// Why a request was withheld from delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockReason {
    code: String,
    detail: String,
}

impl BlockReason {
    /// Records a signature verification failure.
    #[must_use]
    pub fn signature(reason: &RejectionReason) -> Self {
        Self {
            code: reason.code().to_owned(),
            detail: bounded_detail(&reason.to_string()),
        }
    }

    /// Records that the stored secret or key could not be prepared.
    #[must_use]
    pub fn material_unavailable(detail: &str) -> Self {
        Self {
            code: "material_unavailable".to_owned(),
            detail: bounded_detail(detail),
        }
    }

    /// Rehydrates a persisted reason.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the code is not a stable lowercase token.
    pub fn rehydrate(code: String, detail: &str) -> Result<Self, DomainError> {
        if code.is_empty()
            || code.len() > 64
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(DomainError::InvalidFormat {
                field: "reason_code",
                reason: "must be a lowercase snake_case token",
            });
        }
        Ok(Self {
            code,
            detail: bounded_detail(detail),
        })
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the bounded human-readable detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

fn bounded_detail(detail: &str) -> String {
    detail
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAX_REASON_DETAIL_LENGTH)
        .collect()
}

/// Persistence snapshot for a blocked request.
#[derive(Clone, Debug)]
pub struct BlockedRequestSnapshot {
    /// Stable `UUIDv7` identifier.
    pub id: BlockedRequestId,
    /// Owning organization.
    pub organization_id: OrganizationId,
    /// Destination Silicon.
    pub silicon_id: SiliconId,
    /// Receiving hook.
    pub hook_id: HookId,
    /// Hook name at receipt.
    pub provider: HookName,
    /// Exact captured request.
    pub request: CapturedRequest,
    /// Why the request was withheld.
    pub reason: BlockReason,
    /// Authoritative receive time.
    pub received_at: OffsetDateTime,
}

/// A request that failed verification and was withheld from delivery.
#[derive(Clone, Debug)]
pub struct BlockedRequest {
    snapshot: BlockedRequestSnapshot,
}

impl BlockedRequest {
    /// Records a withheld request for a hook.
    #[must_use]
    pub fn record(
        id: BlockedRequestId,
        hook: &Hook,
        request: CapturedRequest,
        reason: BlockReason,
    ) -> Self {
        let received_at = request.received_at();
        Self {
            snapshot: BlockedRequestSnapshot {
                id,
                organization_id: hook.organization_id().clone(),
                silicon_id: hook.silicon_id().clone(),
                hook_id: hook.id(),
                provider: hook.name().clone(),
                request,
                reason,
                received_at,
            },
        }
    }

    /// Rehydrates a persisted record.
    #[must_use]
    pub const fn rehydrate(snapshot: BlockedRequestSnapshot) -> Self {
        Self { snapshot }
    }

    /// Returns a read-only persistence snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &BlockedRequestSnapshot {
        &self.snapshot
    }

    /// Returns the stable identifier.
    #[must_use]
    pub const fn id(&self) -> BlockedRequestId {
        self.snapshot.id
    }

    /// Returns the receiving hook.
    #[must_use]
    pub const fn hook_id(&self) -> HookId {
        self.snapshot.hook_id
    }

    /// Returns the exact captured request.
    #[must_use]
    pub const fn request(&self) -> &CapturedRequest {
        &self.snapshot.request
    }

    /// Returns why the request was withheld.
    #[must_use]
    pub const fn reason(&self) -> &BlockReason {
        &self.snapshot.reason
    }

    /// Returns authoritative receive time.
    #[must_use]
    pub const fn received_at(&self) -> OffsetDateTime {
        self.snapshot.received_at
    }
}

/// A consumer's acknowledged position in one Silicon's delivery stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryCursor {
    /// Stream owner.
    pub silicon_id: SiliconId,
    /// Highest sequence the consumer has acknowledged; zero before any.
    pub acknowledged_through: i64,
    /// Time of the most recent acknowledgment, if any.
    pub updated_at: Option<OffsetDateTime>,
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::{BlockReason, DeliverySequence, delivery_summary};
    use crate::domain::{HookName, HookTimeZone, signature::RejectionReason};

    #[test]
    fn summary_uses_the_documented_layout_in_the_hook_zone()
    -> Result<(), Box<dyn std::error::Error>> {
        let provider = HookName::new("GitHub")?;
        let at = datetime!(2026-09-02 14:03:22.5 UTC);
        assert_eq!(
            delivery_summary(&provider, at, &HookTimeZone::default()),
            "GitHub triggered at 14:03:22 02-09-2026 UTC"
        );
        assert_eq!(
            delivery_summary(&provider, at, &HookTimeZone::new("Asia/Kolkata")?),
            "GitHub triggered at 19:33:22 02-09-2026 Asia/Kolkata"
        );
        Ok(())
    }

    #[test]
    fn sequences_are_positive_and_reasons_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
        assert!(DeliverySequence::new(0).is_err());
        assert_eq!(DeliverySequence::new(7)?.get(), 7);
        let reason = BlockReason::signature(&RejectionReason::SignatureMismatch);
        assert_eq!(reason.code(), "signature_mismatch");
        assert_eq!(reason.detail(), "signature mismatch");
        let long = BlockReason::material_unavailable(&"x\n".repeat(600));
        assert_eq!(long.detail().chars().count(), 500);
        assert!(!long.detail().contains('\n'));
        assert!(BlockReason::rehydrate("Not-Valid".to_owned(), "").is_err());
        Ok(())
    }
}
