//! Keyset boundaries and query scope carried by authenticated cursors.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{AccountUuid, HookId};

/// Which retained log a cursor pages through.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryCollection {
    /// Verified requests.
    Events,
    /// Withheld requests.
    BlockedRequests,
}

/// Filters that affect a history keyset.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HistoryFilter {
    hook_id: Option<HookId>,
}

impl HistoryFilter {
    /// Constructs history filters.
    #[must_use]
    pub const fn new(hook_id: Option<HookId>) -> Self {
        Self { hook_id }
    }

    /// Returns the optional hook restriction.
    #[must_use]
    pub const fn hook_id(&self) -> Option<HookId> {
        self.hook_id
    }
}

/// Silicon, collection, and filter identity to which a cursor is bound.
///
/// Cursors issued before Silicon Accounts named an organization and an
/// IAM-era Silicon id; they no longer decode, which only restarts paging.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HistoryCursorScope {
    silicon: AccountUuid,
    collection: HistoryCollection,
    filter: HistoryFilter,
}

impl HistoryCursorScope {
    /// Constructs a cursor scope from the authorized query.
    #[must_use]
    pub const fn new(
        silicon: AccountUuid,
        collection: HistoryCollection,
        filter: HistoryFilter,
    ) -> Self {
        Self {
            silicon,
            collection,
            filter,
        }
    }

    /// Returns the Silicon restriction.
    #[must_use]
    pub const fn silicon(&self) -> &AccountUuid {
        &self.silicon
    }

    /// Returns the collection being paged.
    #[must_use]
    pub const fn collection(&self) -> HistoryCollection {
        self.collection
    }

    /// Returns query filters bound into the cursor.
    #[must_use]
    pub const fn filter(&self) -> &HistoryFilter {
        &self.filter
    }
}

/// Exclusive `(received_at, id)` boundary for descending history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryCursor {
    received_at: OffsetDateTime,
    id: Uuid,
}

impl HistoryCursor {
    /// Constructs an exclusive keyset boundary.
    #[must_use]
    pub const fn new(received_at: OffsetDateTime, id: Uuid) -> Self {
        Self { received_at, id }
    }

    /// Returns the receive-time portion of the descending keyset.
    #[must_use]
    pub const fn received_at(self) -> OffsetDateTime {
        self.received_at
    }

    /// Returns the identifier tiebreaker of the descending keyset.
    #[must_use]
    pub const fn id(self) -> Uuid {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::HistoryFilter;

    #[test]
    fn filters_default_to_account_wide_history() {
        assert_eq!(HistoryFilter::default().hook_id(), None);
    }
}
