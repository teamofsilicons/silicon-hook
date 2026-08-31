//! PostgreSQL 16 integration tests for Silicon Hook's durable invariants.

use std::{sync::Arc, time::Duration as StdDuration};

use anyhow::{Context as _, Result, bail};
use bytes::Bytes;
use serde_json::{Map, json};
use silicon_hook::{
    application::{
        AcceptEventCommand, ApplicationError, Clock, CreateHookCommand, HookApplication,
        ManagementContext,
    },
    domain::{
        ActorKind, ActorRef, AuthorizationContext, Capability, EncryptedSecret, EncryptionKeyId,
        EndpointKey, EventEnvelopeInput, EventFilter, EventId, EventRecord, EventType, Hook,
        HookDescription, HookId, HookName, HookStatus, NewHook, OrganizationId, OrganizationRole,
        RequestDigest, SchemaVersion, SiliconId, TraceId,
    },
    infrastructure::{
        crypto::{CursorCodec, SecretCipher, SecretKey, SecretKeyring, WebhookSignatureVerifier},
        postgres::{
            AuditContext, CreateHook, CreateHookOutcome, EVENT_HISTORY_PAGE_BYTE_BUDGET,
            EventPageRequest, HookMutation, IdempotencyScope, IngressAcceptance, NewEvent,
            PersistedResponse, PostgresStore, RestoreHook, RestoreHookOutcome, RotateSecret,
            RotateSecretOutcome, RuntimeDatabaseRole, SECRET_REPLAY_WINDOW, StoreError, migrate,
        },
    },
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;
use time::{OffsetDateTime, macros::datetime};

const POSTGRES_PORT: u16 = 5432;
const DATABASE_WAIT_TIMEOUT: StdDuration = StdDuration::from_secs(10);
const ROTATION_GATE: i64 = 73_191;

struct TestDatabase {
    store: PostgresStore,
    _container: ContainerAsync<Postgres>,
}

impl TestDatabase {
    async fn start_unmigrated() -> Result<Self> {
        let container = Postgres::default()
            .with_tag("16-alpine")
            .start()
            .await
            .context("start PostgreSQL 16 test container")?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(POSTGRES_PORT).await?;
        let database_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .connect(&database_url)
            .await
            .context("connect to PostgreSQL test container")?;

        Ok(Self {
            store: PostgresStore::new(pool),
            _container: container,
        })
    }

    async fn start() -> Result<Self> {
        let database = Self::start_unmigrated().await?;
        migrate(database.store.pool()).await?;
        Ok(database)
    }
}

#[derive(Debug)]
struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

#[derive(Clone)]
struct FixtureIdentity {
    organization_id: OrganizationId,
    silicon_id: SiliconId,
    actor: ActorRef,
}

impl FixtureIdentity {
    fn new() -> Result<Self> {
        let silicon_id = SiliconId::new("silicon:integration")?;
        Ok(Self {
            organization_id: OrganizationId::new("org:integration")?,
            actor: ActorRef::try_new(ActorKind::Silicon, silicon_id.as_str())?,
            silicon_id,
        })
    }

    fn authorization(&self) -> AuthorizationContext {
        AuthorizationContext::new(
            self.organization_id.clone(),
            self.actor.clone(),
            OrganizationRole::Member,
            std::iter::empty::<Capability>(),
            std::iter::empty::<SiliconId>(),
            None,
        )
    }
}

fn encrypted_secret(key_id: &str, marker: u8) -> Result<EncryptedSecret> {
    Ok(EncryptedSecret::new(
        EncryptionKeyId::new(key_id)?,
        [marker; 12],
        vec![marker; 48],
    )?)
}

fn new_hook(
    identity: &FixtureIdentity,
    endpoint_key: &str,
    name: String,
    description: Option<String>,
    created_at: OffsetDateTime,
    encrypted_signing_secret: EncryptedSecret,
) -> Result<Hook> {
    Ok(Hook::create(NewHook {
        id: HookId::new(),
        organization_id: identity.organization_id.clone(),
        silicon_id: identity.silicon_id.clone(),
        name: HookName::new(name)?,
        description: HookDescription::optional(description)?,
        endpoint_key: EndpointKey::parse(endpoint_key)?,
        created_by: identity.actor.clone(),
        created_via_application: None,
        created_at,
        encrypted_signing_secret,
    }))
}

fn management_scope(
    identity: &FixtureIdentity,
    operation: &str,
    target_id: String,
    key: &str,
    digest_marker: u8,
) -> IdempotencyScope {
    IdempotencyScope {
        operation: operation.to_owned(),
        actor: identity.actor.clone(),
        calling_application_id: None,
        organization_id: identity.organization_id.clone(),
        target_id,
        key: key.to_owned(),
        request_digest: [digest_marker; 32],
    }
}

fn audit_context(identity: &FixtureIdentity, request_id: &str) -> AuditContext {
    AuditContext {
        actor: identity.actor.clone(),
        calling_application_id: None,
        request_id: Some(request_id.to_owned()),
    }
}

fn create_command(
    identity: &FixtureIdentity,
    hook: Hook,
    key: &str,
    digest_marker: u8,
) -> Result<CreateHook> {
    create_command_for(identity, hook, key, digest_marker, "hook.create", false)
}

fn iam_create_command(
    identity: &FixtureIdentity,
    hook: Hook,
    key: &str,
    digest_marker: u8,
) -> Result<CreateHook> {
    create_command_for(
        identity,
        hook,
        key,
        digest_marker,
        "hook.iam.provision",
        true,
    )
}

fn create_command_for(
    identity: &FixtureIdentity,
    hook: Hook,
    key: &str,
    digest_marker: u8,
    operation: &str,
    is_iam_default: bool,
) -> Result<CreateHook> {
    let recorded_at = hook.created_at();
    let hook_id = hook.id();
    let response_secret = hook.encrypted_signing_secret().clone();
    let replay_until = recorded_at
        .checked_add(SECRET_REPLAY_WINDOW)
        .context("test timestamp must admit the secret replay deadline")?;

    Ok(CreateHook {
        idempotency: management_scope(
            identity,
            operation,
            identity.silicon_id.as_str().to_owned(),
            key,
            digest_marker,
        ),
        response: PersistedResponse {
            status: 201,
            resource_id: Some(hook_id),
            encrypted_secret: Some(response_secret),
            secret_replay_until: Some(replay_until),
        },
        audit: audit_context(identity, "request:create"),
        hook,
        is_iam_default,
        recorded_at,
    })
}

async fn persist_hook(
    store: &PostgresStore,
    identity: &FixtureIdentity,
    endpoint_key: &str,
    encrypted_signing_secret: EncryptedSecret,
) -> Result<Hook> {
    let hook = new_hook(
        identity,
        endpoint_key,
        "Integration hook".to_owned(),
        Some("PostgreSQL integration fixture".to_owned()),
        datetime!(2026-08-31 12:00:00.123456 UTC),
        encrypted_signing_secret,
    )?;
    match store
        .create_hook(create_command(identity, hook, "create-key-0001", 1)?)
        .await?
    {
        CreateHookOutcome::Created(created) => Ok(created),
        CreateHookOutcome::Replayed { .. } => {
            bail!("a fresh integration database unexpectedly replayed hook creation")
        }
    }
}

async fn seed_full_hook_collection(
    store: &PostgresStore,
    identity: &FixtureIdentity,
) -> Result<()> {
    sqlx::query(
        r"
        INSERT INTO hook.hooks (
            id, org_id, silicon_id, endpoint_key, name, created_by_kind,
            created_by_id, encryption_key_id, secret_nonce,
            encrypted_signing_secret, created_at, updated_at
        )
        SELECT lpad(to_hex(sequence), 32, '0')::uuid,
               $1, $2, upper(lpad(to_hex(sequence), 6, '0')),
               'Bounded fixture', 'silicon', $2, 'integration-v1',
               decode(repeat('11', 12), 'hex'),
               decode(repeat('22', 48), 'hex'),
               TIMESTAMPTZ '2026-01-01 12:00:00 UTC',
               TIMESTAMPTZ '2026-01-01 12:00:00 UTC'
        FROM generate_series(1, 1000) AS sequence
        ",
    )
    .bind(identity.organization_id.as_str())
    .bind(identity.silicon_id.as_str())
    .execute(store.pool())
    .await?;
    Ok(())
}

async fn seed_retention_window(
    store: &PostgresStore,
    hook: &Hook,
    event_count: i32,
    protect_excess: bool,
) -> Result<()> {
    sqlx::query(
        r"
        WITH retention_clock AS MATERIALIZED (
            SELECT clock_timestamp() AS now
        ), inserted AS (
            INSERT INTO hook.events (
                id, hook_id, org_id, silicon_id, event_type, occurred_at,
                schema_version, trace_id, payload, request_digest, received_at,
                replay_protected_until
            )
            SELECT md5($1::text || ':' || sequence::text)::uuid,
                   $1, $2, $3, 'retention.event',
                   CASE
                       WHEN NOT $5 AND sequence <= 10
                       THEN retention_clock.now - INTERVAL '11 minutes'
                       ELSE retention_clock.now - INTERVAL '1 minute'
                            + sequence * INTERVAL '1 microsecond'
                   END,
                   '1.0', 'trace:retention', '{}'::jsonb,
                   decode(repeat('ab', 32), 'hex'),
                   CASE
                       WHEN NOT $5 AND sequence <= 10
                       THEN retention_clock.now - INTERVAL '11 minutes'
                       ELSE retention_clock.now - INTERVAL '1 minute'
                            + sequence * INTERVAL '1 microsecond'
                   END,
                   CASE
                       WHEN $5 OR sequence > 10
                       THEN retention_clock.now + INTERVAL '9 minutes'
                       ELSE retention_clock.now - INTERVAL '1 minute'
                   END
            FROM retention_clock, generate_series(1, $4) AS sequence
            RETURNING id, org_id, silicon_id, received_at
        )
        INSERT INTO hook_private.dm_outbox (
            event_id, org_id, silicon_id, request_body, status, attempts,
            available_at, created_at, updated_at
        )
        SELECT id, org_id, silicon_id, convert_to('{}', 'UTF8'), 'pending', 0,
               received_at, received_at, received_at
        FROM inserted
        ",
    )
    .bind(hook.id().as_uuid())
    .bind(hook.organization_id().as_str())
    .bind(hook.silicon_id().as_str())
    .bind(event_count)
    .bind(protect_excess)
    .execute(store.pool())
    .await?;
    Ok(())
}

async fn retention_state(store: &PostgresStore, hook: &Hook) -> Result<(i64, bool)> {
    sqlx::query_as::<_, (i64, bool)>(
        r"
        SELECT event_count, maintenance_due_at IS NOT NULL
        FROM hook_private.event_retention_state
        WHERE hook_id = $1
        ",
    )
    .bind(hook.id().as_uuid())
    .fetch_one(store.pool())
    .await
    .map_err(Into::into)
}

async fn mark_hook_deleted(
    store: &PostgresStore,
    hook_id: uuid::Uuid,
    deleted_at: OffsetDateTime,
    updated_at: OffsetDateTime,
) -> Result<()> {
    sqlx::query("UPDATE hook.hooks SET deleted_at = $2, updated_at = $3 WHERE id = $1")
        .bind(hook_id)
        .bind(deleted_at)
        .bind(updated_at)
        .execute(store.pool())
        .await?;
    Ok(())
}

fn event_record(
    hook: &Hook,
    event_id: EventId,
    request_digest: RequestDigest,
    received_at: OffsetDateTime,
    source: Option<String>,
    subject: Option<String>,
) -> Result<EventRecord> {
    let payload = Map::from_iter([("fixture".to_owned(), json!(true))]);
    event_record_with_payload(
        hook,
        event_id,
        request_digest,
        received_at,
        source,
        subject,
        payload,
    )
}

fn event_record_with_payload(
    hook: &Hook,
    event_id: EventId,
    request_digest: RequestDigest,
    received_at: OffsetDateTime,
    source: Option<String>,
    subject: Option<String>,
    payload: Map<String, serde_json::Value>,
) -> Result<EventRecord> {
    let envelope = EventEnvelopeInput::new(EventType::new("integration.event")?, payload)
        .with_context(source, subject)
        .with_metadata(
            Some(received_at),
            Some(SchemaVersion::new("1.0")?),
            Some(TraceId::new("trace:integration")?),
        )
        .normalize(received_at, TraceId::new("fallback:integration")?)?;

    Ok(EventRecord::accept(
        event_id,
        hook.organization_id().clone(),
        hook.silicon_id().clone(),
        hook.id(),
        envelope,
        request_digest,
        received_at,
    ))
}

fn ingress_command(
    hook: &Hook,
    event_id: EventId,
    idempotency_key: &str,
    request_digest: RequestDigest,
    authenticated_request_digest: RequestDigest,
) -> Result<NewEvent> {
    Ok(NewEvent::new(
        event_record(
            hook,
            event_id,
            request_digest,
            datetime!(2026-08-31 12:01:00.654321 UTC),
            Some("integration-source".to_owned()),
            Some("integration-subject".to_owned()),
        )?,
        hook.encrypted_signing_secret().clone(),
        authenticated_request_digest,
        idempotency_key.to_owned(),
    )?)
}

fn application(store: PostgresStore, now: OffsetDateTime) -> Result<HookApplication> {
    let encryption_key_id = EncryptionKeyId::new("integration-v1")?;
    let keyring = SecretKeyring::new(
        encryption_key_id.clone(),
        [(encryption_key_id, SecretKey::from_bytes([17; 32]))],
    )?;
    Ok(HookApplication::new(
        store,
        Arc::new(SecretCipher::new(keyring)),
        Arc::new(CursorCodec::new(SecretKey::from_bytes([29; 32]))),
        WebhookSignatureVerifier::default(),
        Arc::new(FixedClock(now)),
    ))
}

async fn wait_for_blocked_query(pool: &PgPool, query_fragment: &str) -> Result<()> {
    tokio::time::timeout(DATABASE_WAIT_TIMEOUT, async {
        loop {
            let is_waiting = sqlx::query_scalar::<_, bool>(
                r"
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_stat_activity
                    WHERE pid <> pg_backend_pid()
                      AND wait_event_type = 'Lock'
                      AND query ILIKE '%' || $1 || '%'
                )
                ",
            )
            .bind(query_fragment)
            .fetch_one(pool)
            .await?;
            if is_waiting {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .with_context(|| format!("query containing {query_fragment:?} did not block in time"))??;
    Ok(())
}

async fn assert_schema_not_ready_contains(store: &PostgresStore, expected: &str) -> Result<()> {
    match store.ready().await {
        Err(StoreError::SchemaNotReady { reason }) if reason.contains(expected) => Ok(()),
        outcome => {
            bail!("expected schema-not-ready reason containing {expected:?}, got {outcome:?}")
        }
    }
}

#[tokio::test]
async fn migrations_apply_to_a_fresh_postgresql_16_database() -> Result<()> {
    let database = TestDatabase::start_unmigrated().await?;
    let pool = database.store.pool();
    let version =
        sqlx::query_scalar::<_, i32>("SELECT current_setting('server_version_num')::integer")
            .fetch_one(pool)
            .await?;
    let absent_before = sqlx::query_scalar::<_, bool>("SELECT to_regclass('hook.hooks') IS NULL")
        .fetch_one(pool)
        .await?;

    assert!(version >= 160_000, "container must run PostgreSQL 16+");
    assert!(
        absent_before,
        "fresh database unexpectedly contained Hook tables"
    );
    let empty_readiness = database.store.ready().await;
    assert!(matches!(
        empty_readiness,
        Err(StoreError::SchemaNotReady { ref reason })
            if reason.contains("hook-migrate")
    ));

    migrate(pool).await?;
    migrate(pool).await?;
    database.store.ready().await?;
    database.store.ready_for(RuntimeDatabaseRole::Api).await?;
    database
        .store
        .ready_for(RuntimeDatabaseRole::Worker)
        .await?;

    let tables_exist = sqlx::query_scalar::<_, bool>(
        r"
        SELECT to_regclass('hook.hooks') IS NOT NULL
           AND to_regclass('hook.events') IS NOT NULL
           AND to_regclass('hook_private.dm_outbox') IS NOT NULL
           AND to_regclass('hook_private.management_idempotency') IS NOT NULL
        ",
    )
    .fetch_one(pool)
    .await?;
    let applied_migrations = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(pool)
        .await?;

    assert!(tables_exist);
    assert_eq!(applied_migrations, 1);

    let (migration_version, checksum) = sqlx::query_as::<_, (i64, Vec<u8>)>(
        "SELECT version, checksum FROM _sqlx_migrations ORDER BY version DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await?;
    sqlx::query("UPDATE _sqlx_migrations SET checksum = decode(repeat('00', 48), 'hex')")
        .execute(pool)
        .await?;
    assert_schema_not_ready_contains(&database.store, "checksum").await?;

    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2")
        .bind(checksum)
        .bind(migration_version)
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE hook.hooks DROP CONSTRAINT hooks_name_length")
        .execute(pool)
        .await?;
    assert_schema_not_ready_contains(&database.store, "hook.hooks.hooks_name_length").await?;
    sqlx::query(
        "ALTER TABLE hook.hooks ADD CONSTRAINT hooks_name_length \
         CHECK (char_length(name) BETWEEN 1 AND 200)",
    )
    .execute(pool)
    .await?;

    sqlx::query("DROP TRIGGER events_are_immutable ON hook.events")
        .execute(pool)
        .await?;
    assert_schema_not_ready_contains(&database.store, "hook.events.events_are_immutable").await?;
    sqlx::query(
        "CREATE TRIGGER events_are_immutable BEFORE UPDATE ON hook.events \
         FOR EACH ROW EXECUTE FUNCTION hook_private.reject_row_mutation()",
    )
    .execute(pool)
    .await?;

    sqlx::query("ALTER TABLE hook.events DROP COLUMN trace_id CASCADE")
        .execute(pool)
        .await?;
    assert_schema_not_ready_contains(&database.store, "hook.events.trace_id").await?;
    Ok(())
}

#[tokio::test]
async fn event_history_page_budget_preserves_keyset_continuation() -> Result<()> {
    const EVENT_COUNT: usize = 20;
    const PAYLOAD_BYTES: usize = 900_000;

    const _: () = assert!(EVENT_COUNT * PAYLOAD_BYTES > EVENT_HISTORY_PAGE_BYTE_BUDGET);

    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let secret = encrypted_secret("history-v1", 9)?;
    let hook = persist_hook(&database.store, &identity, "FEDCBA", secret.clone()).await?;
    let first_received_at = datetime!(2026-08-31 13:00:00 UTC);
    let mut expected_ids = Vec::with_capacity(EVENT_COUNT);

    for index in 0..EVENT_COUNT {
        let event_id = EventId::new();
        let marker = index.to_be_bytes();
        let timestamp_offset = i64::try_from(index).context("history fixture index overflow")?;
        let received_at = first_received_at
            .checked_add(time::Duration::microseconds(timestamp_offset))
            .context("history fixture timestamp overflow")?;
        let payload = Map::from_iter([("blob".to_owned(), json!("x".repeat(PAYLOAD_BYTES)))]);
        let event = event_record_with_payload(
            &hook,
            event_id,
            RequestDigest::sha256_parts(&[b"history-body", &marker]),
            received_at,
            None,
            None,
            payload,
        )?;
        let acceptance = database
            .store
            .accept_event(&NewEvent::new(
                event,
                secret.clone(),
                RequestDigest::sha256_parts(&[b"history-authenticated", &marker]),
                format!("history-key-{index:04}"),
            )?)
            .await?;
        assert!(matches!(
            acceptance,
            IngressAcceptance::Accepted { event_id: accepted } if accepted == event_id
        ));
        expected_ids.push(event_id);
    }

    let first_page = database
        .store
        .list_events(&EventPageRequest {
            organization_id: identity.organization_id.clone(),
            silicon_id: identity.silicon_id.clone(),
            filter: EventFilter::new(Some(hook.id()), None),
            cursor: None,
            limit: 10_000,
        })
        .await?;
    assert!(!first_page.items.is_empty());
    assert!(first_page.items.len() < EVENT_COUNT);
    let next_cursor = first_page
        .next_cursor
        .context("a byte-limited page must have a continuation cursor")?;

    let second_page = database
        .store
        .list_events(&EventPageRequest {
            organization_id: identity.organization_id,
            silicon_id: identity.silicon_id,
            filter: EventFilter::new(Some(hook.id()), None),
            cursor: Some(next_cursor),
            limit: 10_000,
        })
        .await?;
    assert_eq!(second_page.next_cursor, None);

    let actual_ids = first_page
        .items
        .into_iter()
        .chain(second_page.items)
        .map(|event| event.id())
        .collect::<Vec<_>>();
    expected_ids.reverse();
    assert_eq!(actual_ids, expected_ids);
    Ok(())
}

#[tokio::test]
async fn unicode_scalar_boundaries_round_trip_for_hooks_and_events() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let name = "界".repeat(200);
    let description = "🦀".repeat(2_000);
    let source = "界".repeat(500);
    let subject = "🦀".repeat(500);
    let secret = encrypted_secret("unicode-v1", 3)?;
    let hook = new_hook(
        &identity,
        "A0B1C2",
        name.clone(),
        Some(description.clone()),
        datetime!(2026-08-31 12:00:00 UTC),
        secret.clone(),
    )?;
    let hook = match database
        .store
        .create_hook(create_command(&identity, hook, "unicode-key-0001", 2)?)
        .await?
    {
        CreateHookOutcome::Created(created) => created,
        CreateHookOutcome::Replayed { .. } => bail!("fresh Unicode create replayed"),
    };
    let event = event_record(
        &hook,
        EventId::new(),
        RequestDigest::sha256(b"unicode-event"),
        datetime!(2026-08-31 12:01:00 UTC),
        Some(source.clone()),
        Some(subject.clone()),
    )?;
    let event_id = event.id();
    let acceptance = database
        .store
        .accept_event(&NewEvent::new(
            event,
            secret,
            RequestDigest::sha256(b"unicode-authenticated"),
            "unicode-event-key".to_owned(),
        )?)
        .await?;

    assert!(matches!(
        acceptance,
        IngressAcceptance::Accepted { event_id: accepted } if accepted == event_id
    ));

    let unicode_failure_reason = "界".repeat(2_000);
    sqlx::query(
        r"
        UPDATE hook_private.dm_outbox
        SET failure_reason = $2
        WHERE event_id = $1
        ",
    )
    .bind(event_id.as_uuid())
    .bind(&unicode_failure_reason)
    .execute(database.store.pool())
    .await?;
    let rejected = sqlx::query(
        r"
        UPDATE hook_private.dm_outbox
        SET failure_reason = $2
        WHERE event_id = $1
        ",
    )
    .bind(event_id.as_uuid())
    .bind("界".repeat(2_001))
    .execute(database.store.pool())
    .await;
    assert!(rejected.is_err(), "2,001 Unicode scalars must be rejected");

    let reloaded = database
        .store
        .get_hook(&identity.organization_id, &identity.silicon_id, hook.id())
        .await?
        .context("persisted Unicode hook was not found")?;
    assert_eq!(reloaded.name().as_str(), name);
    assert_eq!(
        reloaded.description().map(HookDescription::as_str),
        Some(description.as_str())
    );

    let page = database
        .store
        .list_events(&EventPageRequest {
            organization_id: identity.organization_id,
            silicon_id: identity.silicon_id,
            filter: EventFilter::new(Some(hook.id()), None),
            cursor: None,
            limit: 1,
        })
        .await?;
    assert_eq!(page.items.len(), 1);
    let persisted_event = page.items.first().context("event page was empty")?;
    assert_eq!(persisted_event.envelope().source(), Some(source.as_str()));
    assert_eq!(persisted_event.envelope().subject(), Some(subject.as_str()));
    Ok(())
}

#[tokio::test]
async fn retained_hook_limit_bounds_creation_and_listing() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let retained_at = datetime!(2026-08-31 12:01:00 UTC);
    seed_full_hook_collection(&database.store, &identity).await?;

    let expired_hook_id = uuid::Uuid::from_u128(1);
    let recovery_cutoff = retained_at - time::Duration::days(45);
    mark_hook_deleted(
        &database.store,
        expired_hook_id,
        recovery_cutoff,
        retained_at,
    )
    .await?;

    let listed = database
        .store
        .list_hooks(
            &identity.organization_id,
            &identity.silicon_id,
            true,
            retained_at,
        )
        .await?;
    assert_eq!(listed.len(), 1_000);

    let boundary_hook = new_hook(
        &identity,
        "FFF001",
        "Over limit".to_owned(),
        None,
        retained_at,
        encrypted_secret("integration-v1", 7)?,
    )?;
    let result = database
        .store
        .create_hook(create_command(
            &identity,
            boundary_hook,
            "quota-boundary-key",
            7,
        )?)
        .await;
    assert!(matches!(result, Err(StoreError::HookLimitReached)));

    mark_hook_deleted(
        &database.store,
        expired_hook_id,
        recovery_cutoff - time::Duration::microseconds(1),
        retained_at,
    )
    .await?;

    let replacement = new_hook(
        &identity,
        "FFF002",
        "Replacement after recovery".to_owned(),
        None,
        retained_at,
        encrypted_secret("integration-v1", 8)?,
    )?;
    let outcome = database
        .store
        .create_hook(create_command(
            &identity,
            replacement,
            "quota-expired-key",
            8,
        )?)
        .await?;
    assert!(matches!(outcome, CreateHookOutcome::Created(_)));

    let listed = database
        .store
        .list_hooks(
            &identity.organization_id,
            &identity.silicon_id,
            true,
            retained_at,
        )
        .await?;
    assert_eq!(listed.len(), 1_000);
    assert!(
        listed
            .iter()
            .all(|hook| hook.id().as_uuid() != expired_hook_id)
    );
    let physical_rows = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM hook.hooks WHERE org_id = $1 AND silicon_id = $2",
    )
    .bind(identity.organization_id.as_str())
    .bind(identity.silicon_id.as_str())
    .fetch_one(database.store.pool())
    .await?;
    assert_eq!(physical_rows, 1_001);
    Ok(())
}

#[tokio::test]
async fn iam_default_registration_survives_permanent_hook_purge() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let database_now = sqlx::query_scalar::<_, OffsetDateTime>("SELECT clock_timestamp()")
        .fetch_one(database.store.pool())
        .await?;
    let created_at = database_now - time::Duration::days(50);
    let first = new_hook(
        &identity,
        "1A2B3C",
        "Silicon IAM".to_owned(),
        None,
        created_at,
        encrypted_secret("iam-ledger-v1", 9)?,
    )?;
    let first_id = first.id();
    let outcome = database
        .store
        .create_hook(iam_create_command(&identity, first, "iam-ledger-first", 9)?)
        .await?;
    assert!(matches!(outcome, CreateHookOutcome::Created(_)));

    mark_hook_deleted(
        &database.store,
        first_id.as_uuid(),
        database_now - time::Duration::days(46),
        database_now - time::Duration::days(46),
    )
    .await?;
    let maintenance = database.store.run_maintenance_pass(100).await?;
    assert_eq!(maintenance.hooks_purged, 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook.hooks WHERE id = $1")
            .bind(first_id.as_uuid())
            .fetch_one(database.store.pool())
            .await?,
        0
    );

    let replacement = new_hook(
        &identity,
        "4D5E6F",
        "Silicon IAM replacement".to_owned(),
        None,
        database_now,
        encrypted_secret("iam-ledger-v2", 10)?,
    )?;
    let result = database
        .store
        .create_hook(iam_create_command(
            &identity,
            replacement,
            "iam-ledger-second",
            10,
        )?)
        .await;
    assert!(matches!(result, Err(StoreError::IamDefaultExists)));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook_private.iam_hook_registrations")
            .fetch_one(database.store.pool())
            .await?,
        1
    );
    Ok(())
}

#[tokio::test]
async fn create_replay_is_exact_with_a_sub_microsecond_clock_value() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let raw_time = datetime!(2026-08-31 12:00:00.123456789 UTC);
    let application = application(database.store.clone(), raw_time)?;
    let command = CreateHookCommand {
        context: ManagementContext {
            authorization: identity.authorization(),
            idempotency_key: "application-create-key".to_owned(),
            request_id: Some("request:create:application".to_owned()),
        },
        silicon_id: identity.silicon_id,
        name: HookName::new("Sub-microsecond hook")?,
        description: HookDescription::optional(Some("Exact replay fixture".to_owned()))?,
    };

    let first = application.create_hook(command.clone()).await?;
    let replay = application.create_hook(command).await?;
    let canonical_time = datetime!(2026-08-31 12:00:00.123456 UTC);

    assert_eq!(first.hook.id(), replay.hook.id());
    assert_eq!(first.hook.endpoint_key(), replay.hook.endpoint_key());
    assert_eq!(first.hook.created_at(), canonical_time);
    assert_eq!(replay.hook.created_at(), canonical_time);
    assert_eq!(
        first.hook.snapshot().created_at,
        replay.hook.snapshot().created_at
    );
    assert_eq!(
        first.signing_secret.as_bytes(),
        replay.signing_secret.as_bytes()
    );
    assert_eq!(
        first.hook.encrypted_signing_secret(),
        replay.hook.encrypted_signing_secret()
    );
    Ok(())
}

#[tokio::test]
async fn ingress_uses_database_time_even_when_the_process_clock_is_wrong() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let application = application(database.store.clone(), datetime!(2000-01-01 0:00 UTC))?;
    let created = application
        .create_hook(CreateHookCommand {
            context: ManagementContext {
                authorization: identity.authorization(),
                idempotency_key: "database-clock-hook".to_owned(),
                request_id: Some("request:database-clock-create".to_owned()),
            },
            silicon_id: identity.silicon_id.clone(),
            name: HookName::new("Database clock")?,
            description: None,
        })
        .await?;
    let body = Bytes::from_static(br#"{"type":"clock.test","payload":{"ok":true}}"#);
    let before = sqlx::query_scalar::<_, OffsetDateTime>("SELECT clock_timestamp()")
        .fetch_one(database.store.pool())
        .await?;
    let timestamp = before.unix_timestamp();
    let signature = WebhookSignatureVerifier::sign(&created.signing_secret, timestamp, &body)?;

    let event_id = application
        .accept_event(AcceptEventCommand {
            silicon_id: identity.silicon_id,
            endpoint_key: created.hook.endpoint_key().clone(),
            timestamp: timestamp.to_string(),
            signature,
            idempotency_key: "database-clock-event".to_owned(),
            body,
            request_id: "request:database-clock-ingress".to_owned(),
        })
        .await?;
    let after = sqlx::query_scalar::<_, OffsetDateTime>("SELECT clock_timestamp()")
        .fetch_one(database.store.pool())
        .await?;
    let received_at = sqlx::query_scalar::<_, OffsetDateTime>(
        "SELECT received_at FROM hook.events WHERE id = $1",
    )
    .bind(event_id.as_uuid())
    .fetch_one(database.store.pool())
    .await?;

    assert!((before..=after).contains(&received_at));
    Ok(())
}

#[tokio::test]
async fn normalized_dm_overflow_is_rejected_before_any_ingress_rows_are_committed() -> Result<()> {
    const NUMBER_COUNT: usize = 100_000;

    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let application = application(database.store.clone(), datetime!(2026-08-31 12:00 UTC))?;
    let created = application
        .create_hook(CreateHookCommand {
            context: ManagementContext {
                authorization: identity.authorization(),
                idempotency_key: "normalized-overflow-hook".to_owned(),
                request_id: Some("request:normalized-overflow-create".to_owned()),
            },
            silicon_id: identity.silicon_id.clone(),
            name: HookName::new("Normalized overflow")?,
            description: None,
        })
        .await?;
    let numbers = std::iter::repeat_n("1e10", NUMBER_COUNT)
        .collect::<Vec<_>>()
        .join(",");
    let body = Bytes::from(format!(
        r#"{{"type":"size.test","payload":{{"numbers":[{numbers}]}}}}"#
    ));
    assert!(body.len() <= 1024 * 1024);
    let database_now = sqlx::query_scalar::<_, OffsetDateTime>("SELECT clock_timestamp()")
        .fetch_one(database.store.pool())
        .await?;
    let timestamp = database_now.unix_timestamp();
    let signature = WebhookSignatureVerifier::sign(&created.signing_secret, timestamp, &body)?;

    let result = application
        .accept_event(AcceptEventCommand {
            silicon_id: identity.silicon_id,
            endpoint_key: created.hook.endpoint_key().clone(),
            timestamp: timestamp.to_string(),
            signature,
            idempotency_key: "normalized-overflow-event".to_owned(),
            body,
            request_id: "request:normalized-overflow-ingress".to_owned(),
        })
        .await;

    assert!(matches!(result, Err(ApplicationError::PayloadTooLarge)));
    let counts = sqlx::query_as::<_, (i64, i64, i64, i64)>(
        r"
        SELECT
            (SELECT count(*) FROM hook.events),
            (SELECT count(*) FROM hook_private.dm_outbox),
            (SELECT count(*) FROM hook_private.ingress_idempotency),
            (SELECT count(*) FROM hook_private.ingress_authenticated_requests)
        ",
    )
    .fetch_one(database.store.pool())
    .await?;
    assert_eq!(counts, (0, 0, 0, 0));
    Ok(())
}

#[tokio::test]
async fn restore_replays_identically_and_rejects_changed_or_new_active_requests() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let hook = persist_hook(
        &database.store,
        &identity,
        "D0E1F2",
        encrypted_secret("restore-v1", 4)?,
    )
    .await?;
    let deleted_at = datetime!(2026-08-31 12:02:00 UTC);
    database
        .store
        .delete_hook(&HookMutation {
            organization_id: identity.organization_id.clone(),
            silicon_id: identity.silicon_id.clone(),
            hook_id: hook.id(),
            audit: audit_context(&identity, "request:delete"),
            occurred_at: deleted_at,
        })
        .await?;

    let restore = RestoreHook {
        organization_id: identity.organization_id.clone(),
        silicon_id: identity.silicon_id.clone(),
        hook_id: hook.id(),
        idempotency: management_scope(
            &identity,
            "hook.restore",
            hook.id().to_string(),
            "restore-key-0001",
            5,
        ),
        response: PersistedResponse {
            status: 200,
            resource_id: Some(hook.id()),
            encrypted_secret: None,
            secret_replay_until: None,
        },
        audit: audit_context(&identity, "request:restore"),
        occurred_at: datetime!(2026-08-31 12:03:00 UTC),
    };

    let first = database.store.restore_hook(&restore).await?;
    let replay = database.store.restore_hook(&restore).await?;
    let (first_hook, replay_hook, replay_response) = match (first, replay) {
        (
            RestoreHookOutcome::Restored(first_hook),
            RestoreHookOutcome::Replayed {
                hook: replay_hook,
                response,
            },
        ) => (first_hook, replay_hook, response),
        outcomes => bail!("unexpected restore outcomes: {outcomes:?}"),
    };

    assert_eq!(first_hook.id(), replay_hook.id());
    assert_eq!(first_hook.status(), HookStatus::Active);
    assert_eq!(replay_hook.status(), HookStatus::Active);
    assert_eq!(first_hook.deleted_at(), None);
    assert_eq!(replay_hook.deleted_at(), None);
    assert_eq!(replay_response, restore.response);

    let mut changed_digest = restore.clone();
    changed_digest.idempotency.request_digest = [6; 32];
    assert!(matches!(
        database.store.restore_hook(&changed_digest).await,
        Err(StoreError::IdempotencyConflict)
    ));

    let mut new_key = restore;
    new_key.idempotency.key = "restore-key-0002".to_owned();
    new_key.idempotency.request_digest = [7; 32];
    assert!(matches!(
        database.store.restore_hook(&new_key).await,
        Err(StoreError::StateConflict { entity: "hook" })
    ));
    Ok(())
}

#[tokio::test]
async fn ingress_same_key_replays_identical_content_and_conflicts_on_change() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let hook = persist_hook(
        &database.store,
        &identity,
        "123ABC",
        encrypted_secret("ingress-v1", 5)?,
    )
    .await?;
    let request_digest = RequestDigest::sha256(b"same request body");
    let authenticated_digest = RequestDigest::sha256(b"1700000000.same request body");
    let first_event_id = EventId::new();

    let first = database
        .store
        .accept_event(&ingress_command(
            &hook,
            first_event_id,
            "ingress-key-0001",
            request_digest,
            authenticated_digest,
        )?)
        .await?;
    let replay = database
        .store
        .accept_event(&ingress_command(
            &hook,
            EventId::new(),
            "ingress-key-0001",
            request_digest,
            authenticated_digest,
        )?)
        .await?;

    assert!(matches!(
        first,
        IngressAcceptance::Accepted { event_id } if event_id == first_event_id
    ));
    assert!(matches!(
        replay,
        IngressAcceptance::Replayed { event_id } if event_id == first_event_id
    ));

    let conflict = database
        .store
        .accept_event(&ingress_command(
            &hook,
            EventId::new(),
            "ingress-key-0001",
            RequestDigest::sha256(b"changed request body"),
            RequestDigest::sha256(b"1700000001.changed request body"),
        )?)
        .await;
    assert!(matches!(conflict, Err(StoreError::IdempotencyConflict)));

    let event_count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook.events")
        .fetch_one(database.store.pool())
        .await?;
    let outbox_count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook_private.dm_outbox")
        .fetch_one(database.store.pool())
        .await?;
    assert_eq!(event_count, 1);
    assert_eq!(outbox_count, 1);
    Ok(())
}

#[tokio::test]
async fn authenticated_request_fingerprint_replays_under_a_changed_key() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let hook = persist_hook(
        &database.store,
        &identity,
        "456DEF",
        encrypted_secret("fingerprint-v1", 6)?,
    )
    .await?;
    let request_digest = RequestDigest::sha256(b"fingerprinted request body");
    let authenticated_digest = RequestDigest::sha256(b"1700000002.fingerprinted request body");
    let first_event_id = EventId::new();

    let accepted = database
        .store
        .accept_event(&ingress_command(
            &hook,
            first_event_id,
            "fingerprint-key-a",
            request_digest,
            authenticated_digest,
        )?)
        .await?;
    let replayed = database
        .store
        .accept_event(&ingress_command(
            &hook,
            EventId::new(),
            "fingerprint-key-b",
            request_digest,
            authenticated_digest,
        )?)
        .await?;

    assert!(matches!(
        accepted,
        IngressAcceptance::Accepted { event_id } if event_id == first_event_id
    ));
    assert!(matches!(
        replayed,
        IngressAcceptance::Replayed { event_id } if event_id == first_event_id
    ));

    let reused_alias = database
        .store
        .accept_event(&ingress_command(
            &hook,
            EventId::new(),
            "fingerprint-key-b",
            RequestDigest::sha256(b"different request body"),
            RequestDigest::sha256(b"1700000003.different request body"),
        )?)
        .await;
    assert!(matches!(reused_alias, Err(StoreError::IdempotencyConflict)));

    let key_rows =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook_private.ingress_idempotency")
            .fetch_one(database.store.pool())
            .await?;
    let replay_guard_rows = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM hook_private.ingress_authenticated_requests",
    )
    .fetch_one(database.store.pool())
    .await?;
    assert_eq!(key_rows, 2, "each observed caller key must remain bound");
    assert_eq!(replay_guard_rows, 1, "signed bytes have one replay guard");
    Ok(())
}

#[tokio::test]
async fn terminal_outbox_receipts_follow_event_retention_without_erasing_retry_work() -> Result<()>
{
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let hook = persist_hook(
        &database.store,
        &identity,
        "654FED",
        encrypted_secret("retention-v1", 9)?,
    )
    .await?;
    let delivered_id = EventId::new();
    let failed_id = EventId::new();
    let retrying_id = EventId::new();

    for (event_id, key, digest) in [
        (delivered_id, "retention-delivered", b"delivered".as_slice()),
        (failed_id, "retention-failed", b"failed".as_slice()),
        (retrying_id, "retention-retrying", b"retrying".as_slice()),
    ] {
        database
            .store
            .accept_event(&ingress_command(
                &hook,
                event_id,
                key,
                RequestDigest::sha256(digest),
                RequestDigest::sha256(&[b"authenticated:".as_slice(), digest].concat()),
            )?)
            .await?;
    }

    let terminal_at = datetime!(2026-08-31 12:05:00 UTC);
    sqlx::query(
        r"
        UPDATE hook_private.dm_outbox
        SET status = CASE
                WHEN event_id = $1 THEN 'delivered'
                WHEN event_id = $2 THEN 'failed'
                ELSE 'retrying'
            END,
            attempts = 1,
            available_at = CASE
                WHEN event_id = $3 THEN $4 + INTERVAL '1 minute'
                ELSE available_at
            END,
            last_attempt_at = $4,
            delivered_at = CASE WHEN event_id = $1 THEN $4 ELSE NULL END,
            failed_at = CASE WHEN event_id = $2 THEN $4 ELSE NULL END,
            failure_reason = CASE
                WHEN event_id = $2 THEN 'dm_http_422'
                WHEN event_id = $3 THEN 'dm_timeout'
                ELSE NULL
            END,
            last_http_status = CASE
                WHEN event_id = $1 THEN 202
                WHEN event_id = $2 THEN 422
                ELSE NULL
            END,
            updated_at = $4
        WHERE event_id IN ($1, $2, $3)
        ",
    )
    .bind(delivered_id.as_uuid())
    .bind(failed_id.as_uuid())
    .bind(retrying_id.as_uuid())
    .bind(terminal_at)
    .execute(database.store.pool())
    .await?;
    sqlx::query("DELETE FROM hook.events WHERE id IN ($1, $2, $3)")
        .bind(delivered_id.as_uuid())
        .bind(failed_id.as_uuid())
        .bind(retrying_id.as_uuid())
        .execute(database.store.pool())
        .await?;

    let result = database.store.run_maintenance_pass(100).await?;
    assert_eq!(result.outbox_rows_purged, 2);

    let remaining = sqlx::query_as::<_, (uuid::Uuid, String)>(
        r"
        SELECT event_id, status
        FROM hook_private.dm_outbox
        ORDER BY event_id
        ",
    )
    .fetch_all(database.store.pool())
    .await?;
    assert_eq!(
        remaining,
        vec![(retrying_id.as_uuid(), "retrying".to_owned())]
    );
    Ok(())
}

#[tokio::test]
async fn retention_queue_is_fair_replay_safe_and_exact_for_history() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let young_hook = persist_hook(
        &database.store,
        &identity,
        "135ACE",
        encrypted_secret("retention-young", 4)?,
    )
    .await?;
    let prunable = new_hook(
        &identity,
        "246BDF",
        "Prunable history".to_owned(),
        None,
        datetime!(2026-08-31 12:00:01 UTC),
        encrypted_secret("retention-old", 5)?,
    )?;
    let prunable_hook = match database
        .store
        .create_hook(create_command(&identity, prunable, "create-key-0002", 2)?)
        .await?
    {
        CreateHookOutcome::Created(hook) => hook,
        CreateHookOutcome::Replayed { .. } => bail!("fresh retention hook replayed"),
    };

    seed_retention_window(&database.store, &young_hook, 10_001, true).await?;
    seed_retention_window(&database.store, &prunable_hook, 10_020, false).await?;
    assert_eq!(
        retention_state(&database.store, &young_hook).await?,
        (10_001, true)
    );
    assert_eq!(
        retention_state(&database.store, &prunable_hook).await?,
        (10_020, true)
    );

    let first = database.store.run_maintenance_pass(2).await?;
    let second = database.store.run_maintenance_pass(2).await?;
    assert_eq!((first.events_purged, second.events_purged), (1, 1));
    assert_eq!(
        retention_state(&database.store, &young_hook).await?.0,
        10_001
    );
    assert_eq!(
        retention_state(&database.store, &prunable_hook).await?,
        (10_018, true)
    );

    let page = database
        .store
        .list_events(&EventPageRequest {
            organization_id: identity.organization_id.clone(),
            silicon_id: identity.silicon_id.clone(),
            filter: EventFilter::new(Some(young_hook.id()), None),
            cursor: None,
            limit: 10_000,
        })
        .await?;
    assert_eq!(page.items.len(), 10_000);
    assert_eq!(page.next_cursor, None);

    sqlx::query(
        r"
        UPDATE hook.hooks
        SET created_at = clock_timestamp() - INTERVAL '50 days',
            updated_at = clock_timestamp() - INTERVAL '46 days',
            deleted_at = clock_timestamp() - INTERVAL '46 days'
        WHERE id = $1
        ",
    )
    .bind(prunable_hook.id().as_uuid())
    .execute(database.store.pool())
    .await?;
    let expired_page = database
        .store
        .list_events(&EventPageRequest {
            organization_id: identity.organization_id,
            silicon_id: identity.silicon_id,
            filter: EventFilter::new(Some(prunable_hook.id()), None),
            cursor: None,
            limit: 10,
        })
        .await?;
    assert!(expired_page.items.is_empty());
    Ok(())
}

#[tokio::test]
async fn queued_rotation_prevents_old_secret_ingress_from_committing_after_it() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let old_secret = encrypted_secret("race-v1", 7)?;
    let hook = persist_hook(&database.store, &identity, "789ABC", old_secret).await?;
    let rotation_time = datetime!(2026-08-31 12:04:00 UTC);
    let rotated_secret = encrypted_secret("race-v2", 8)?;
    let rotation = RotateSecret {
        organization_id: identity.organization_id.clone(),
        silicon_id: identity.silicon_id.clone(),
        hook_id: hook.id(),
        encrypted_secret: rotated_secret.clone(),
        idempotency: management_scope(
            &identity,
            "hook.secret.rotate",
            hook.id().to_string(),
            "rotation-key-0001",
            8,
        ),
        response: PersistedResponse {
            status: 200,
            resource_id: Some(hook.id()),
            encrypted_secret: Some(rotated_secret.clone()),
            secret_replay_until: Some(
                rotation_time
                    .checked_add(SECRET_REPLAY_WINDOW)
                    .context("rotation deadline overflow")?,
            ),
        },
        audit: audit_context(&identity, "request:rotation"),
        occurred_at: rotation_time,
    };
    let ingress = ingress_command(
        &hook,
        EventId::new(),
        "rotation-race-event",
        RequestDigest::sha256(b"old-secret request"),
        RequestDigest::sha256(b"1700000003.old-secret request"),
    )?;

    // The test-only trigger pauses rotation after its row update, while the
    // transaction still owns the hook's exclusive row lock. This gives the
    // test a deterministic linearization point without adding production hooks.
    sqlx::query(
        r"
        CREATE FUNCTION hook_private.wait_at_rotation_gate()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $function$
        BEGIN
            IF NEW.secret_generation > OLD.secret_generation THEN
                PERFORM pg_advisory_xact_lock(73191);
            END IF;
            RETURN NEW;
        END;
        $function$
        ",
    )
    .execute(database.store.pool())
    .await?;
    sqlx::query(
        r"
        CREATE TRIGGER integration_rotation_gate
        AFTER UPDATE ON hook.hooks
        FOR EACH ROW
        EXECUTE FUNCTION hook_private.wait_at_rotation_gate()
        ",
    )
    .execute(database.store.pool())
    .await?;

    let mut gate_connection = database.store.pool().acquire().await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(ROTATION_GATE)
        .execute(&mut *gate_connection)
        .await?;

    let rotation_store = database.store.clone();
    let rotation_task =
        tokio::spawn(async move { rotation_store.rotate_hook_secret(&rotation).await });
    wait_for_blocked_query(database.store.pool(), "UPDATE hook.hooks").await?;

    let ingress_store = database.store.clone();
    let ingress_task = tokio::spawn(async move { ingress_store.accept_event(&ingress).await });
    wait_for_blocked_query(database.store.pool(), "FOR SHARE").await?;

    let gate_was_owned = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
        .bind(ROTATION_GATE)
        .fetch_one(&mut *gate_connection)
        .await?;
    assert!(gate_was_owned, "test did not own the rotation gate");

    let rotation_outcome = rotation_task.await.context("rotation task panicked")??;
    let ingress_outcome = ingress_task.await.context("ingress task panicked")?;
    assert!(matches!(
        rotation_outcome,
        RotateSecretOutcome::Rotated(rotated)
            if rotated.encrypted_signing_secret() == &rotated_secret
    ));
    assert!(matches!(ingress_outcome, Err(StoreError::SecretSuperseded)));

    let event_count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook.events")
        .fetch_one(database.store.pool())
        .await?;
    let outbox_count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook_private.dm_outbox")
        .fetch_one(database.store.pool())
        .await?;
    assert_eq!(event_count, 0);
    assert_eq!(outbox_count, 0);
    Ok(())
}
