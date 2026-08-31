//! Immutable event acceptance, ingress deduplication, and keyset history.

use std::io;

use futures::TryStreamExt as _;
use serde_json::Value;
use sqlx::{PgPool, Postgres, postgres::PgArguments, query::QueryAs};

use crate::domain::{
    DeliveryState, DeliveryStatus, EventCursor, EventEnvelope, EventRecord, EventRecordSnapshot,
    EventType, OrganizationId, RequestDigest, SchemaVersion, SiliconId, TraceId,
};

use super::{
    EVENT_HISTORY_PAGE_BYTE_BUDGET, PostgresStore, StoreError,
    models::{EventRow, IngressIdempotencyRow},
    types::{EventPage, EventPageRequest, IngressAcceptance, NewEvent},
};

impl PostgresStore {
    /// Atomically persists an immutable event, ingress key, and DM delivery job.
    ///
    /// The hook row is share-locked until commit, allowing concurrent ingress
    /// while preventing a soft delete from racing a successful acceptance. The
    /// deferred ingress foreign key lets the idempotency reservation serialize
    /// identical keys before the new event row exists.
    ///
    /// # Errors
    ///
    /// Returns a not-found error for a deleted/unknown hook, an idempotency
    /// conflict for changed content, or a database failure.
    pub async fn accept_event(&self, command: &NewEvent) -> Result<IngressAcceptance, StoreError> {
        if command.event.delivery().status() != DeliveryStatus::Pending
            || command.event.delivery().attempts() != 0
        {
            return Err(StoreError::InvalidArgument {
                field: "event.delivery",
                reason: "new events must have a pending, unattempted delivery",
            });
        }

        let mut transaction = self.pool.begin().await?;
        lock_hook_for_acceptance(&mut transaction, command).await?;
        if let Some(event_id) = reserve_ingress(&mut transaction, command).await? {
            transaction.commit().await?;
            return Ok(IngressAcceptance::Replayed { event_id });
        }

        insert_event(&mut transaction, &command.event).await?;
        insert_outbox_job(&mut transaction, command).await?;
        transaction.commit().await?;
        Ok(IngressAcceptance::Accepted {
            event_id: command.event.id(),
        })
    }

    /// Reads an authenticated descending keyset over the retained event window.
    ///
    /// The query applies the 10,000-row window per hook before event-type and
    /// cursor filtering, so API visibility remains exact even between
    /// asynchronous purge passes.
    ///
    /// # Errors
    ///
    /// Returns an error for a limit outside `1..=10_000`, a PostgreSQL failure,
    /// or persisted rows that no longer satisfy domain invariants.
    pub async fn list_events(&self, request: &EventPageRequest) -> Result<EventPage, StoreError> {
        if request.limit == 0 || request.limit > 10_000 {
            return Err(StoreError::InvalidArgument {
                field: "limit",
                reason: "must be between 1 and 10000",
            });
        }

        let fetch_limit = i64::from(request.limit) + 1;
        let query = event_history_query(request, fetch_limit);
        collect_event_page(&self.pool, query, request.limit).await
    }
}

type EventHistoryQuery<'query> = QueryAs<'query, Postgres, EventRow, PgArguments>;

fn event_history_query(request: &EventPageRequest, fetch_limit: i64) -> EventHistoryQuery<'_> {
    let event_type = request.filter.event_type().map(EventType::as_str);
    let cursor_time = request.cursor.map(EventCursor::received_at);
    let cursor_id = request
        .cursor
        .map(EventCursor::event_id)
        .map(crate::domain::EventId::as_uuid);

    if let Some(hook_id) = request.filter.hook_id() {
        sqlx::query_as::<_, EventRow>(HOOK_EVENT_HISTORY_SQL)
            .bind(request.organization_id.as_str())
            .bind(request.silicon_id.as_str())
            .bind(hook_id.as_uuid())
            .bind(event_type)
            .bind(cursor_time)
            .bind(cursor_id)
            .bind(fetch_limit)
    } else {
        sqlx::query_as::<_, EventRow>(SILICON_EVENT_HISTORY_SQL)
            .bind(request.organization_id.as_str())
            .bind(request.silicon_id.as_str())
            .bind(event_type)
            .bind(cursor_time)
            .bind(cursor_id)
            .bind(fetch_limit)
    }
}

async fn collect_event_page(
    pool: &PgPool,
    query: EventHistoryQuery<'_>,
    limit: u32,
) -> Result<EventPage, StoreError> {
    let mut stream = query.fetch(pool);
    let mut rows = Vec::with_capacity(limit.min(128) as usize);
    let mut estimated_bytes = 0_usize;
    let mut has_more = false;
    while let Some(row) = stream.try_next().await? {
        if rows.len() == limit as usize {
            has_more = true;
            break;
        }

        let row_bytes = row.estimated_response_bytes()?;
        if !rows.is_empty()
            && estimated_bytes.saturating_add(row_bytes) > EVENT_HISTORY_PAGE_BYTE_BUDGET
        {
            has_more = true;
            break;
        }
        estimated_bytes = estimated_bytes.saturating_add(row_bytes);
        rows.push(EventRecord::try_from(row)?);
    }

    let next_cursor = if has_more {
        rows.last()
            .map(|last| EventCursor::new(last.received_at(), last.id()))
    } else {
        None
    };
    Ok(EventPage {
        items: rows,
        next_cursor,
    })
}

const HOOK_EVENT_HISTORY_SQL: &str = r"
    WITH history_clock AS MATERIALIZED (
        SELECT clock_timestamp() AS now
    ), retained AS MATERIALIZED (
        SELECT event.id,
               event.received_at,
               event.event_type
        FROM hook.events AS event
        JOIN hook.hooks AS hook
          ON hook.id = event.hook_id
         AND hook.org_id = event.org_id
         AND hook.silicon_id = event.silicon_id
        CROSS JOIN history_clock
        WHERE event.org_id = $1
          AND event.silicon_id = $2
          AND event.hook_id = $3
          AND (
              hook.deleted_at IS NULL
              OR hook.deleted_at >= history_clock.now - INTERVAL '45 days'
          )
        ORDER BY event.received_at DESC, event.id DESC
        LIMIT 10000
    ), eligible AS MATERIALIZED (
        SELECT retained.id,
               retained.received_at
        FROM retained
        WHERE ($4::text IS NULL OR retained.event_type = $4)
          AND (
              $5::timestamptz IS NULL
              OR (retained.received_at, retained.id) < ($5, $6)
          )
        ORDER BY retained.received_at DESC, retained.id DESC
        LIMIT $7
    )
    SELECT event.id,
           event.hook_id,
           event.org_id,
           event.silicon_id,
           event.event_type,
           event.source,
           event.subject,
           event.occurred_at,
           event.schema_version,
           event.trace_id,
           event.payload,
           event.request_digest,
           event.received_at,
           delivery.status AS delivery_status,
           delivery.attempts AS delivery_attempts,
           delivery.last_attempt_at,
           delivery.failure_reason
    FROM eligible
    JOIN hook.events AS event
      ON event.id = eligible.id
    JOIN hook_private.dm_outbox AS delivery
      ON delivery.event_id = event.id
    ORDER BY eligible.received_at DESC, eligible.id DESC
    ";

const SILICON_EVENT_HISTORY_SQL: &str = r"
    WITH history_clock AS MATERIALIZED (
        SELECT clock_timestamp() AS now
    ), retained AS MATERIALIZED (
        SELECT retained_event.id,
               retained_event.received_at
        FROM hook.hooks AS hook
        CROSS JOIN history_clock
        CROSS JOIN LATERAL (
            SELECT visible.id,
                   visible.received_at
            FROM (
                SELECT event.id,
                       event.received_at,
                       event.event_type
                FROM hook.events AS event
                WHERE event.hook_id = hook.id
                ORDER BY event.received_at DESC, event.id DESC
                LIMIT 10000
            ) AS visible
            WHERE ($3::text IS NULL OR visible.event_type = $3)
              AND (
                  $4::timestamptz IS NULL
                  OR (visible.received_at, visible.id) < ($4, $5)
              )
            ORDER BY visible.received_at DESC, visible.id DESC
            LIMIT $6
        ) AS retained_event
        WHERE hook.org_id = $1
          AND hook.silicon_id = $2
          AND (
              hook.deleted_at IS NULL
              OR hook.deleted_at >= history_clock.now - INTERVAL '45 days'
          )
    ), eligible AS MATERIALIZED (
        SELECT retained.id,
               retained.received_at
        FROM retained
        ORDER BY retained.received_at DESC, retained.id DESC
        LIMIT $6
    )
    SELECT event.id,
           event.hook_id,
           event.org_id,
           event.silicon_id,
           event.event_type,
           event.source,
           event.subject,
           event.occurred_at,
           event.schema_version,
           event.trace_id,
           event.payload,
           event.request_digest,
           event.received_at,
           delivery.status AS delivery_status,
           delivery.attempts AS delivery_attempts,
           delivery.last_attempt_at,
           delivery.failure_reason
    FROM eligible
    JOIN hook.events AS event
      ON event.id = eligible.id
    JOIN hook_private.dm_outbox AS delivery
      ON delivery.event_id = event.id
    ORDER BY eligible.received_at DESC, eligible.id DESC
    ";

const EVENT_RESPONSE_FIXED_OVERHEAD_BYTES: usize = 1_024;

impl EventRow {
    fn estimated_response_bytes(&self) -> Result<usize, StoreError> {
        let mut payload_size = ByteCounter::default();
        serde_json::to_writer(&mut payload_size, &self.payload)
            .map_err(|error| StoreError::corrupt("event", error))?;
        let string_bytes = [
            Some(self.org_id.as_str()),
            Some(self.silicon_id.as_str()),
            Some(self.event_type.as_str()),
            self.source.as_deref(),
            self.subject.as_deref(),
            Some(self.schema_version.as_str()),
            Some(self.trace_id.as_str()),
            Some(self.delivery_status.as_str()),
            self.failure_reason.as_deref(),
        ]
        .into_iter()
        .flatten()
        .fold(0_usize, |size, value| {
            // Every input byte can require at most one extra byte for JSON
            // quoting under the validated text contracts.
            size.saturating_add(value.len().saturating_mul(2))
        });

        Ok(payload_size
            .bytes
            .saturating_add(string_bytes)
            .saturating_add(EVENT_RESPONSE_FIXED_OVERHEAD_BYTES))
    }
}

#[derive(Default)]
struct ByteCounter {
    bytes: usize,
}

impl io::Write for ByteCounter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes = self.bytes.saturating_add(buffer.len());
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn lock_hook_for_acceptance(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    command: &NewEvent,
) -> Result<(), StoreError> {
    let hook_is_active = sqlx::query_scalar::<_, bool>(
        r"
        SELECT true
        FROM hook.hooks
        WHERE id = $1
          AND org_id = $2
          AND silicon_id = $3
          AND deleted_at IS NULL
          AND encryption_key_id = $4
          AND secret_nonce = $5
          AND encrypted_signing_secret = $6
        FOR SHARE
        ",
    )
    .bind(command.event.hook_id().as_uuid())
    .bind(command.event.organization_id().as_str())
    .bind(command.event.silicon_id().as_str())
    .bind(command.expected_encrypted_secret.key_id().as_str())
    .bind(command.expected_encrypted_secret.nonce().as_slice())
    .bind(command.expected_encrypted_secret.ciphertext())
    .fetch_optional(&mut **transaction)
    .await?
    .unwrap_or(false);

    if hook_is_active {
        Ok(())
    } else {
        Err(StoreError::SecretSuperseded)
    }
}

async fn reserve_ingress(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    command: &NewEvent,
) -> Result<Option<crate::domain::EventId>, StoreError> {
    let authenticated = reserve_authenticated_request(transaction, command).await?;
    let event_id = match authenticated {
        AuthenticatedReservation::Reserved => command.event.id(),
        AuthenticatedReservation::Replayed(event_id) => event_id,
    };
    let inserted_key = insert_ingress_key(transaction, command, event_id).await?;
    if inserted_key {
        return Ok(match authenticated {
            AuthenticatedReservation::Reserved => None,
            AuthenticatedReservation::Replayed(event_id) => Some(event_id),
        });
    }

    if matches!(authenticated, AuthenticatedReservation::Reserved) {
        release_authenticated_request(transaction, command).await?;
    }
    find_ingress_by_key(transaction, command)
        .await?
        .map(Some)
        .ok_or_else(|| StoreError::corrupt("ingress idempotency", "conflict row disappeared"))
}

#[derive(Clone, Copy)]
enum AuthenticatedReservation {
    Reserved,
    Replayed(crate::domain::EventId),
}

async fn insert_ingress_key(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    command: &NewEvent,
    event_id: crate::domain::EventId,
) -> Result<bool, StoreError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO hook_private.ingress_idempotency (
            hook_id,
            idempotency_key,
            request_digest,
            event_id,
            created_at
        )
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(command.event.hook_id().as_uuid())
    .bind(&command.idempotency_key)
    .bind(command.event.request_digest().as_bytes().as_slice())
    .bind(event_id.as_uuid())
    .bind(command.event.received_at())
    .execute(&mut **transaction)
    .await?;
    Ok(inserted.rows_affected() == 1)
}

async fn reserve_authenticated_request(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    command: &NewEvent,
) -> Result<AuthenticatedReservation, StoreError> {
    let inserted = sqlx::query(
        r"
        INSERT INTO hook_private.ingress_authenticated_requests (
            hook_id,
            authenticated_request_digest,
            request_digest,
            event_id,
            created_at
        )
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT DO NOTHING
        ",
    )
    .bind(command.event.hook_id().as_uuid())
    .bind(command.authenticated_request_digest.as_bytes().as_slice())
    .bind(command.event.request_digest().as_bytes().as_slice())
    .bind(command.event.id().as_uuid())
    .bind(command.event.received_at())
    .execute(&mut **transaction)
    .await?;
    if inserted.rows_affected() == 1 {
        return Ok(AuthenticatedReservation::Reserved);
    }

    let (request_digest, event_id) = find_ingress_by_authenticated_request(transaction, command)
        .await?
        .ok_or_else(|| {
            StoreError::corrupt(
                "authenticated ingress request",
                "conflict row disappeared or event identifier collided",
            )
        })?;
    if request_digest.as_slice() != command.event.request_digest().as_bytes().as_slice() {
        return Err(StoreError::IdempotencyConflict);
    }
    Ok(AuthenticatedReservation::Replayed(event_id.into()))
}

async fn release_authenticated_request(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    command: &NewEvent,
) -> Result<(), StoreError> {
    let deleted = sqlx::query(
        r"
        DELETE FROM hook_private.ingress_authenticated_requests
        WHERE hook_id = $1
          AND authenticated_request_digest = $2
          AND event_id = $3
        ",
    )
    .bind(command.event.hook_id().as_uuid())
    .bind(command.authenticated_request_digest.as_bytes().as_slice())
    .bind(command.event.id().as_uuid())
    .execute(&mut **transaction)
    .await?;
    if deleted.rows_affected() != 1 {
        return Err(StoreError::corrupt(
            "authenticated ingress request",
            "new reservation disappeared",
        ));
    }
    Ok(())
}

async fn find_ingress_by_key(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    command: &NewEvent,
) -> Result<Option<crate::domain::EventId>, StoreError> {
    let existing = sqlx::query_as::<_, IngressIdempotencyRow>(
        r"
        SELECT request_digest, event_id
        FROM hook_private.ingress_idempotency
        WHERE hook_id = $1 AND idempotency_key = $2
        ",
    )
    .bind(command.event.hook_id().as_uuid())
    .bind(&command.idempotency_key)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    let digest: [u8; 32] = existing
        .request_digest
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::corrupt("ingress idempotency", "invalid digest"))?;
    if RequestDigest::from_bytes(digest) != command.event.request_digest() {
        return Err(StoreError::IdempotencyConflict);
    }
    Ok(Some(existing.event_id.into()))
}

async fn find_ingress_by_authenticated_request(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    command: &NewEvent,
) -> Result<Option<(Vec<u8>, uuid::Uuid)>, StoreError> {
    sqlx::query_as::<_, (Vec<u8>, uuid::Uuid)>(
        r"
        SELECT request_digest, event_id
        FROM hook_private.ingress_authenticated_requests
        WHERE hook_id = $1 AND authenticated_request_digest = $2
        ",
    )
    .bind(command.event.hook_id().as_uuid())
    .bind(command.authenticated_request_digest.as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::from)
}

impl TryFrom<EventRow> for EventRecord {
    type Error = StoreError;

    fn try_from(row: EventRow) -> Result<Self, Self::Error> {
        let Value::Object(payload) = row.payload else {
            return Err(StoreError::corrupt("event", "payload is not a JSON object"));
        };
        let event_type =
            EventType::new(row.event_type).map_err(|error| StoreError::corrupt("event", error))?;
        let schema_version = SchemaVersion::new(row.schema_version)
            .map_err(|error| StoreError::corrupt("event", error))?;
        let trace_id =
            TraceId::new(row.trace_id).map_err(|error| StoreError::corrupt("event", error))?;
        let envelope = EventEnvelope::rehydrate(
            event_type,
            row.source,
            row.subject,
            row.occurred_at,
            schema_version,
            trace_id,
            payload,
        )
        .map_err(|error| StoreError::corrupt("event", error))?;
        let status = parse_delivery_status(&row.delivery_status)?;
        let attempts = u32::try_from(row.delivery_attempts)
            .map_err(|error| StoreError::corrupt("event delivery", error))?;
        let delivery =
            DeliveryState::rehydrate(status, attempts, row.last_attempt_at, row.failure_reason)
                .map_err(|error| StoreError::corrupt("event delivery", error))?;
        let digest: [u8; 32] = row
            .request_digest
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::corrupt("event", "invalid request digest length"))?;

        Ok(EventRecord::rehydrate(EventRecordSnapshot {
            id: row.id.into(),
            organization_id: OrganizationId::new(row.org_id)
                .map_err(|error| StoreError::corrupt("event", error))?,
            silicon_id: SiliconId::new(row.silicon_id)
                .map_err(|error| StoreError::corrupt("event", error))?,
            hook_id: row.hook_id.into(),
            envelope,
            request_digest: RequestDigest::from_bytes(digest),
            received_at: row.received_at,
            delivery,
        }))
    }
}

async fn insert_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event: &EventRecord,
) -> Result<(), StoreError> {
    let envelope = event.envelope();
    sqlx::query(
        r"
        INSERT INTO hook.events (
            id,
            hook_id,
            org_id,
            silicon_id,
            event_type,
            source,
            subject,
            occurred_at,
            schema_version,
            trace_id,
            payload,
            request_digest,
            received_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ",
    )
    .bind(event.id().as_uuid())
    .bind(event.hook_id().as_uuid())
    .bind(event.organization_id().as_str())
    .bind(event.silicon_id().as_str())
    .bind(envelope.event_type().as_str())
    .bind(envelope.source())
    .bind(envelope.subject())
    .bind(envelope.occurred_at())
    .bind(envelope.schema_version().as_str())
    .bind(envelope.trace_id().as_str())
    .bind(Value::Object(envelope.payload().clone()))
    .bind(event.request_digest().as_bytes().as_slice())
    .bind(event.received_at())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_outbox_job(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    command: &NewEvent,
) -> Result<(), StoreError> {
    let event = &command.event;
    sqlx::query(
        r"
        INSERT INTO hook_private.dm_outbox (
            event_id,
            org_id,
            silicon_id,
            request_body,
            available_at,
            created_at,
            updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $5, $5)
        ",
    )
    .bind(event.id().as_uuid())
    .bind(event.organization_id().as_str())
    .bind(event.silicon_id().as_str())
    .bind(command.dm_request_body.as_bytes())
    .bind(event.received_at())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn parse_delivery_status(value: &str) -> Result<DeliveryStatus, StoreError> {
    match value {
        "pending" => Ok(DeliveryStatus::Pending),
        "delivered" => Ok(DeliveryStatus::Delivered),
        "retrying" => Ok(DeliveryStatus::Retrying),
        "failed" => Ok(DeliveryStatus::Failed),
        _ => Err(StoreError::corrupt(
            "event delivery",
            "unknown delivery status",
        )),
    }
}
