//! Verified and blocked request logs with keyset history.

use futures::TryStreamExt as _;
use sqlx::{PgPool, Postgres, postgres::PgArguments, query::QueryAs};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::{
    BlockedRequest, DeliverySequence, EventRecord, HOOK_RECOVERY_DAYS, HistoryCursor, HookId,
    request::CapturedRequest,
};

use super::{
    HISTORY_PAGE_BYTE_BUDGET, MAX_HISTORY_LIMIT, PostgresStore, StoreError,
    listener::DELIVERY_CHANNEL,
    models::{BlockedRequestRow, EventRow, capture_columns, encode_headers},
    types::{AcceptEvent, HistoryPage, HistoryPageRequest, RecordBlockedRequest},
};

impl PostgresStore {
    /// Appends a verified request to its hook's log and its Silicon's ordered
    /// delivery stream, then wakes listening delivery sessions.
    ///
    /// The hook row is exclusively locked for the duration so a concurrent
    /// disable or delete cannot race a successful acceptance, and the
    /// Silicon's sequence counter is locked so positions are dense.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when the hook is no longer active or a
    /// PostgreSQL failure.
    pub async fn accept_event(&self, command: AcceptEvent) -> Result<EventRecord, StoreError> {
        let received_at = command.request.received_at();
        let mut transaction = self.pool.begin().await?;
        let still_active = sqlx::query(
            "UPDATE hook.hooks
             SET last_received_at = GREATEST(COALESCE(last_received_at, $2), $2),
                 updated_at = GREATEST(updated_at, $2)
             WHERE id = $1 AND disabled_at IS NULL AND deleted_at IS NULL",
        )
        .bind(command.hook.id().as_uuid())
        .bind(received_at)
        .execute(&mut *transaction)
        .await?;
        if still_active.rows_affected() != 1 {
            return Err(StoreError::NotFound { entity: "hook" });
        }
        let sequence = sqlx::query_scalar::<_, i64>(
            "INSERT INTO hook_private.delivery_sequences (silicon_id, last_sequence)
             VALUES ($1, 1)
             ON CONFLICT (silicon_id) DO UPDATE
             SET last_sequence = hook_private.delivery_sequences.last_sequence + 1
             RETURNING last_sequence",
        )
        .bind(command.hook.silicon_id().as_str())
        .fetch_one(&mut *transaction)
        .await?;
        let sequence =
            DeliverySequence::new(sequence).map_err(|error| StoreError::corrupt("event", error))?;
        let event = EventRecord::accept(command.event_id, &command.hook, command.request, sequence);
        insert_event(&mut transaction, &event).await?;
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(DELIVERY_CHANNEL)
            .bind(event.silicon_id().as_str())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(event)
    }

    /// Appends an unverified request to its hook's blocked log.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] when the hook is no longer active or a
    /// PostgreSQL failure.
    pub async fn record_blocked_request(
        &self,
        command: RecordBlockedRequest,
    ) -> Result<BlockedRequest, StoreError> {
        let received_at = command.request.received_at();
        let mut transaction = self.pool.begin().await?;
        let still_active = sqlx::query(
            "UPDATE hook.hooks
             SET last_blocked_at = GREATEST(COALESCE(last_blocked_at, $2), $2),
                 updated_at = GREATEST(updated_at, $2)
             WHERE id = $1 AND disabled_at IS NULL AND deleted_at IS NULL",
        )
        .bind(command.hook.id().as_uuid())
        .bind(received_at)
        .execute(&mut *transaction)
        .await?;
        if still_active.rows_affected() != 1 {
            return Err(StoreError::NotFound { entity: "hook" });
        }
        let blocked =
            BlockedRequest::record(command.id, &command.hook, command.request, command.reason);
        insert_blocked_request(&mut transaction, &blocked).await?;
        transaction.commit().await?;
        Ok(blocked)
    }

    /// Reads an authenticated descending keyset over retained verified requests.
    ///
    /// # Errors
    ///
    /// Returns an error for a limit outside `1..=10_000`, a PostgreSQL failure,
    /// or persisted rows that no longer satisfy domain invariants.
    pub async fn list_events(
        &self,
        request: &HistoryPageRequest,
    ) -> Result<HistoryPage<EventRecord>, StoreError> {
        validate_limit(request.limit)?;
        let query = history_query::<EventRow>(EVENT_HISTORY_SQL, request);
        collect_page(&self.pool, query, request.limit, |row: &EventRow| {
            (
                row.capture.estimated_response_bytes(),
                row.capture.received_at,
                row.id,
            )
        })
        .await
    }

    /// Reads an authenticated descending keyset over retained blocked requests.
    ///
    /// # Errors
    ///
    /// Returns an error for a limit outside `1..=10_000`, a PostgreSQL failure,
    /// or persisted rows that no longer satisfy domain invariants.
    pub async fn list_blocked_requests(
        &self,
        request: &HistoryPageRequest,
    ) -> Result<HistoryPage<BlockedRequest>, StoreError> {
        validate_limit(request.limit)?;
        let query = history_query::<BlockedRequestRow>(BLOCKED_HISTORY_SQL, request);
        collect_page(
            &self.pool,
            query,
            request.limit,
            |row: &BlockedRequestRow| {
                (
                    row.capture.estimated_response_bytes(),
                    row.capture.received_at,
                    row.id,
                )
            },
        )
        .await
    }
}

fn validate_limit(limit: u32) -> Result<(), StoreError> {
    if limit == 0 || limit > MAX_HISTORY_LIMIT {
        return Err(StoreError::InvalidArgument {
            field: "limit",
            reason: "must be between 1 and 10000",
        });
    }
    Ok(())
}

type HistoryQuery<'query, Row> = QueryAs<'query, Postgres, Row, PgArguments>;

fn history_query<'request, Row>(
    sql: &'static str,
    request: &'request HistoryPageRequest,
) -> HistoryQuery<'request, Row>
where
    Row: for<'row> sqlx::FromRow<'row, sqlx::postgres::PgRow> + Send + Unpin,
{
    let hook_id = request.filter.hook_id().map(HookId::as_uuid);
    sqlx::query_as::<_, Row>(sql)
        .bind(request.organization_id.as_str())
        .bind(request.silicon_id.as_str())
        .bind(hook_id)
        .bind(request.cursor.map(HistoryCursor::received_at))
        .bind(request.cursor.map(HistoryCursor::id))
        .bind(i64::from(request.limit) + 1)
        .bind(HOOK_RECOVERY_DAYS)
}

async fn collect_page<Row, Record>(
    pool: &PgPool,
    query: HistoryQuery<'_, Row>,
    limit: u32,
    describe: impl Fn(&Row) -> (usize, OffsetDateTime, Uuid),
) -> Result<HistoryPage<Record>, StoreError>
where
    Row: for<'row> sqlx::FromRow<'row, sqlx::postgres::PgRow> + Send + Unpin,
    Record: TryFrom<Row, Error = StoreError>,
{
    let mut stream = query.fetch(pool);
    let mut items = Vec::with_capacity(limit.min(128) as usize);
    let mut estimated_bytes = 0_usize;
    let mut last_boundary = None;
    let mut has_more = false;
    while let Some(row) = stream.try_next().await? {
        if items.len() == limit as usize {
            has_more = true;
            break;
        }
        let (row_bytes, received_at, id) = describe(&row);
        if !items.is_empty() && estimated_bytes.saturating_add(row_bytes) > HISTORY_PAGE_BYTE_BUDGET
        {
            has_more = true;
            break;
        }
        estimated_bytes = estimated_bytes.saturating_add(row_bytes);
        items.push(Record::try_from(row)?);
        last_boundary = Some(HistoryCursor::new(received_at, id));
    }
    Ok(HistoryPage {
        items,
        next_cursor: if has_more { last_boundary } else { None },
    })
}

const EVENT_HISTORY_SQL: &str = "
    WITH history_clock AS MATERIALIZED (SELECT clock_timestamp() AS now)
    SELECT event.id, event.hook_id, event.org_id, event.silicon_id, event.provider,
           event.summary, event.delivery_sequence,
           event.method, event.url, event.path, event.query_string, event.headers,
           event.body, event.remote_ip, event.received_at
    FROM hook.events AS event
    JOIN hook.hooks AS hook
      ON hook.id = event.hook_id
     AND hook.org_id = event.org_id
     AND hook.silicon_id = event.silicon_id
    CROSS JOIN history_clock
    WHERE event.org_id = $1
      AND event.silicon_id = $2
      AND ($3::uuid IS NULL OR event.hook_id = $3)
      AND event.expires_at > history_clock.now
      AND (hook.deleted_at IS NULL
           OR hook.deleted_at >= history_clock.now - ($7 * INTERVAL '1 day'))
      AND ($4::timestamptz IS NULL OR (event.received_at, event.id) < ($4, $5))
    ORDER BY event.received_at DESC, event.id DESC
    LIMIT $6
";

const BLOCKED_HISTORY_SQL: &str = "
    WITH history_clock AS MATERIALIZED (SELECT clock_timestamp() AS now)
    SELECT blocked.id, blocked.hook_id, blocked.org_id, blocked.silicon_id, blocked.provider,
           blocked.reason_code, blocked.reason_detail,
           blocked.method, blocked.url, blocked.path, blocked.query_string, blocked.headers,
           blocked.body, blocked.remote_ip, blocked.received_at
    FROM hook.blocked_requests AS blocked
    JOIN hook.hooks AS hook
      ON hook.id = blocked.hook_id
     AND hook.org_id = blocked.org_id
     AND hook.silicon_id = blocked.silicon_id
    CROSS JOIN history_clock
    WHERE blocked.org_id = $1
      AND blocked.silicon_id = $2
      AND ($3::uuid IS NULL OR blocked.hook_id = $3)
      AND blocked.expires_at > history_clock.now
      AND (hook.deleted_at IS NULL
           OR hook.deleted_at >= history_clock.now - ($7 * INTERVAL '1 day'))
      AND ($4::timestamptz IS NULL OR (blocked.received_at, blocked.id) < ($4, $5))
    ORDER BY blocked.received_at DESC, blocked.id DESC
    LIMIT $6
";

async fn insert_event(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    event: &EventRecord,
) -> Result<(), StoreError> {
    let request = event.request();
    bind_capture(
        sqlx::query(concat!(
            "INSERT INTO hook.events (id, hook_id, org_id, silicon_id, provider, summary, ",
            "delivery_sequence, ",
            capture_columns!(),
            ", expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, ",
            "$14, $15, $16, $16 + INTERVAL '14 days')"
        ))
        .bind(event.id().as_uuid())
        .bind(event.hook_id().as_uuid())
        .bind(event.organization_id().as_str())
        .bind(event.silicon_id().as_str())
        .bind(event.provider().as_str())
        .bind(event.summary())
        .bind(event.delivery_sequence().get()),
        request,
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_blocked_request(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    blocked: &BlockedRequest,
) -> Result<(), StoreError> {
    let snapshot = blocked.snapshot();
    bind_capture(
        sqlx::query(concat!(
            "INSERT INTO hook.blocked_requests (id, hook_id, org_id, silicon_id, provider, ",
            "reason_code, reason_detail, ",
            capture_columns!(),
            ", expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, ",
            "$14, $15, $16, $16 + INTERVAL '14 days')"
        ))
        .bind(snapshot.id.as_uuid())
        .bind(snapshot.hook_id.as_uuid())
        .bind(snapshot.organization_id.as_str())
        .bind(snapshot.silicon_id.as_str())
        .bind(snapshot.provider.as_str())
        .bind(snapshot.reason.code())
        .bind(snapshot.reason.detail()),
        blocked.request(),
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn bind_capture<'q>(
    query: sqlx::query::Query<'q, Postgres, PgArguments>,
    request: &'q CapturedRequest,
) -> sqlx::query::Query<'q, Postgres, PgArguments> {
    query
        .bind(request.method())
        .bind(request.url().as_str())
        .bind(request.path())
        .bind(request.query_string())
        .bind(encode_headers(request.headers()))
        .bind(request.content_type())
        .bind(request.body().as_ref())
        .bind(request.remote_ip())
        .bind(request.received_at())
}
