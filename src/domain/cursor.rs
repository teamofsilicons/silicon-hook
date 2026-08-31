//! Keyset boundaries and query scope carried by authenticated cursors.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{EventId, EventType, HookId, OrganizationId, SiliconId};

/// Filters that affect an event-history keyset.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventFilter {
    hook_id: Option<HookId>,
    event_type: Option<EventType>,
}

impl EventFilter {
    /// Constructs event-history filters.
    #[must_use]
    pub const fn new(hook_id: Option<HookId>, event_type: Option<EventType>) -> Self {
        Self {
            hook_id,
            event_type,
        }
    }

    /// Returns the optional hook restriction.
    #[must_use]
    pub const fn hook_id(&self) -> Option<HookId> {
        self.hook_id
    }

    /// Returns the optional exact event-type restriction.
    #[must_use]
    pub const fn event_type(&self) -> Option<&EventType> {
        self.event_type.as_ref()
    }
}

/// Tenant and filter identity to which a cursor is bound.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventCursorScope {
    organization_id: OrganizationId,
    silicon_id: SiliconId,
    filter: EventFilter,
}

impl EventCursorScope {
    /// Constructs a cursor scope from the authorized query.
    #[must_use]
    pub const fn new(
        organization_id: OrganizationId,
        silicon_id: SiliconId,
        filter: EventFilter,
    ) -> Self {
        Self {
            organization_id,
            silicon_id,
            filter,
        }
    }

    /// Returns the organization restriction.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Returns the Silicon restriction.
    #[must_use]
    pub const fn silicon_id(&self) -> &SiliconId {
        &self.silicon_id
    }

    /// Returns query filters bound into the cursor.
    #[must_use]
    pub const fn filter(&self) -> &EventFilter {
        &self.filter
    }
}

/// Exclusive `(received_at, id)` boundary for descending event history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventCursor {
    received_at: OffsetDateTime,
    event_id: EventId,
}

impl EventCursor {
    /// Constructs an exclusive keyset boundary.
    #[must_use]
    pub const fn new(received_at: OffsetDateTime, event_id: EventId) -> Self {
        Self {
            received_at,
            event_id,
        }
    }

    /// Returns the receive-time portion of the descending keyset.
    #[must_use]
    pub const fn received_at(self) -> OffsetDateTime {
        self.received_at
    }

    /// Returns the event-ID tiebreaker of the descending keyset.
    #[must_use]
    pub const fn event_id(self) -> EventId {
        self.event_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_default_to_account_wide_history() {
        let filter = EventFilter::default();
        assert_eq!(filter.hook_id(), None);
        assert_eq!(filter.event_type(), None);
    }
}
