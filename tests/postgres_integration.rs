//! PostgreSQL 16 integration tests for Silicon Hook's durable invariants.

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration as StdDuration,
};

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use silicon_hook::{
    application::{
        AcknowledgeDeliveriesCommand, ApplicationError, BindIamHookSecretCommand, Clock,
        ConnectIamHookCommand, CreateHookCommand, DeleteHookCommand, HookApplication,
        HookMutationCommand, HookWithSecret, ListHistoryCommand, ManagementContext,
        PullDeliveriesCommand, ReceiveOutcome, ReceiveRequestCommand, SigningPatch,
    },
    domain::{
        ActorKind, ActorRef, AuthorizationContext, EncryptionKeyId, EndpointKey, EventRecord,
        HookName, HookStatus, HookTimeZone, OrganizationId, OrganizationRole, SigningSecret,
        SiliconId,
        safety::UNVERIFIED_REQUESTS_PER_BLOCK,
        signature::{Expression, SignatureEncoding},
    },
    infrastructure::{
        crypto::{CursorCodec, SecretCipher, SecretKey, SecretKeyring},
        postgres::{
            EndpointResolution, HISTORY_PAGE_BYTE_BUDGET, PostgresStore, RuntimeDatabaseRole,
            StoreError, migrate,
        },
    },
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;
use time::{OffsetDateTime, macros::datetime};
use url::Url;

const POSTGRES_PORT: u16 = 5432;
const DATABASE_WAIT_TIMEOUT: StdDuration = StdDuration::from_secs(10);
const PUBLIC_BASE_URL: &str = "https://hook.integration.test/";
const PROVIDER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
const OTHER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));

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
            std::iter::empty::<SiliconId>(),
        )
    }

    fn context(&self, idempotency_key: &str) -> ManagementContext {
        ManagementContext {
            authorization: self.authorization(),
            idempotency_key: idempotency_key.to_owned(),
            request_id: Some(format!("request:{idempotency_key}")),
        }
    }
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
        Arc::new(FixedClock(now)),
        Url::parse(PUBLIC_BASE_URL)?,
    ))
}

async fn database_now(pool: &PgPool) -> Result<OffsetDateTime> {
    Ok(
        sqlx::query_scalar::<_, OffsetDateTime>("SELECT clock_timestamp()")
            .fetch_one(pool)
            .await?,
    )
}

async fn create_hook(
    application: &HookApplication,
    identity: &FixtureIdentity,
    name: &str,
    signing: SigningPatch,
    idempotency_key: &str,
) -> Result<HookWithSecret> {
    Ok(application
        .create_hook(CreateHookCommand {
            context: identity.context(idempotency_key),
            silicon_id: identity.silicon_id.clone(),
            name: HookName::new(name)?,
            description: None,
            time_zone: HookTimeZone::new("Asia/Kolkata")?,
            signing,
        })
        .await?)
}

fn standard_webhook_headers(
    secret: &SigningSecret,
    message_id: &str,
    timestamp: &str,
    body: &[u8],
) -> Result<Vec<(String, String)>> {
    let payload = [
        message_id.as_bytes(),
        b".",
        timestamp.as_bytes(),
        b".",
        body,
    ]
    .concat();
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(secret.as_str().as_bytes())
        .context("HMAC accepts any key length")?;
    mac.update(&payload);
    let signature = STANDARD.encode(mac.finalize().into_bytes());
    Ok(vec![
        ("content-type".to_owned(), "application/json".to_owned()),
        ("webhook-id".to_owned(), message_id.to_owned()),
        ("webhook-timestamp".to_owned(), timestamp.to_owned()),
        ("webhook-signature".to_owned(), format!("v1,{signature}")),
    ])
}

async fn receive(
    application: &HookApplication,
    identity: &FixtureIdentity,
    endpoint_key: &EndpointKey,
    headers: Vec<(String, String)>,
    body: &'static [u8],
    remote_ip: IpAddr,
) -> Result<ReceiveOutcome, ApplicationError> {
    application
        .receive_request(ReceiveRequestCommand {
            silicon_id: identity.silicon_id.clone(),
            endpoint_key: endpoint_key.clone(),
            method: "POST".to_owned(),
            path: format!(
                "/silicon/{}/{}",
                identity.silicon_id.as_str(),
                endpoint_key.as_str()
            ),
            query: None,
            headers,
            body: Bytes::from_static(body),
            remote_ip,
        })
        .await
}

fn secret_of(result: &HookWithSecret) -> Result<SigningSecret> {
    result
        .signing_secret
        .clone()
        .context("hook creation must return its generated secret")
}

async fn assert_schema_not_ready_contains(store: &PostgresStore, expected: &str) -> Result<()> {
    match store.ready().await {
        Err(StoreError::SchemaNotReady { reason }) if reason.contains(expected) => Ok(()),
        outcome => {
            bail!("expected schema-not-ready reason containing {expected:?}, got {outcome:?}")
        }
    }
}

async fn wait_for_blocked_query(pool: &PgPool, query_fragment: &str) -> Result<()> {
    tokio::time::timeout(DATABASE_WAIT_TIMEOUT, async {
        loop {
            let is_waiting = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (
                     SELECT 1 FROM pg_stat_activity
                     WHERE pid <> pg_backend_pid()
                       AND wait_event_type = 'Lock'
                       AND query ILIKE '%' || $1 || '%'
                 )",
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

#[tokio::test]
async fn migrations_apply_and_readiness_proves_the_schema_contract() -> Result<()> {
    let database = TestDatabase::start_unmigrated().await?;
    let pool = database.store.pool();
    let version =
        sqlx::query_scalar::<_, i32>("SELECT current_setting('server_version_num')::integer")
            .fetch_one(pool)
            .await?;
    assert!(version >= 160_000, "container must run PostgreSQL 16+");
    assert!(matches!(
        database.store.ready().await,
        Err(StoreError::SchemaNotReady { ref reason }) if reason.contains("hook-migrate")
    ));

    migrate(pool).await?;
    migrate(pool).await?;
    database.store.ready().await?;
    database.store.ready_for(RuntimeDatabaseRole::Api).await?;
    database
        .store
        .ready_for(RuntimeDatabaseRole::Worker)
        .await?;
    let applied = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(pool)
        .await?;
    assert_eq!(applied, 1);

    sqlx::query("ALTER TABLE hook.hooks DROP CONSTRAINT hooks_time_zone_format")
        .execute(pool)
        .await?;
    assert_schema_not_ready_contains(&database.store, "hook.hooks.hooks_time_zone_format").await?;
    sqlx::query(
        "ALTER TABLE hook.hooks ADD CONSTRAINT hooks_time_zone_format \
         CHECK (char_length(time_zone) BETWEEN 1 AND 64 AND time_zone ~ '^[A-Za-z0-9/_+-]+$')",
    )
    .execute(pool)
    .await?;

    sqlx::query("DROP TRIGGER blocked_requests_are_immutable ON hook.blocked_requests")
        .execute(pool)
        .await?;
    assert_schema_not_ready_contains(
        &database.store,
        "hook.blocked_requests.blocked_requests_are_immutable",
    )
    .await?;
    sqlx::query(
        "CREATE TRIGGER blocked_requests_are_immutable BEFORE UPDATE ON hook.blocked_requests \
         FOR EACH ROW EXECUTE FUNCTION hook_private.reject_row_mutation()",
    )
    .execute(pool)
    .await?;

    sqlx::query("ALTER TABLE hook.events DROP COLUMN summary CASCADE")
        .execute(pool)
        .await?;
    assert_schema_not_ready_contains(&database.store, "hook.events.summary").await?;
    Ok(())
}

#[tokio::test]
async fn verified_requests_join_the_delivery_stream_and_history() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let application = application(database.store.clone(), datetime!(2026-09-02 10:00 UTC))?;
    let created = create_hook(
        &application,
        &identity,
        "GitHub",
        SigningPatch::default(),
        "create-github-0001",
    )
    .await?;
    let secret = secret_of(&created)?;
    assert!(secret.as_str().starts_with("v1."));
    assert_eq!(secret.as_str().len(), 35);
    assert!(created.hook.signing().is_required());
    assert_eq!(created.hook.endpoint_key().as_str().len(), 8);

    let mut sequences = Vec::new();
    for (index, body) in [
        br#"{"action":"opened"}"#.as_slice(),
        br#"{"action":"closed"}"#.as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let headers =
            standard_webhook_headers(&secret, &format!("msg_{index}"), "1700000000", body)?;
        let outcome = receive(
            &application,
            &identity,
            created.hook.endpoint_key(),
            headers,
            body,
            PROVIDER_IP,
        )
        .await?;
        let ReceiveOutcome::Accepted(event) = outcome else {
            bail!("signed request was not accepted");
        };
        assert!(event.summary().starts_with("GitHub triggered at "));
        assert!(event.summary().ends_with(" Asia/Kolkata"));
        assert_eq!(event.request().body().as_ref(), body);
        sequences.push(event.delivery_sequence().get());
    }
    assert_eq!(sequences, vec![1, 2]);

    assert_hook_activity_and_history(&application, &identity, created.hook.id()).await?;
    assert_deliveries_are_ordered_and_acknowledged(&application, &identity).await
}

async fn assert_hook_activity_and_history(
    application: &HookApplication,
    identity: &FixtureIdentity,
    hook_id: silicon_hook::domain::HookId,
) -> Result<()> {
    let hooks = application
        .list_hooks(&identity.authorization(), &identity.silicon_id, false)
        .await?;
    assert_eq!(hooks.len(), 1);
    assert!(hooks[0].last_received_at().is_some());
    assert_eq!(hooks[0].last_blocked_at(), None);

    let history = application
        .list_events(ListHistoryCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            hook_id: Some(hook_id),
            limit: 10,
            cursor: None,
        })
        .await?;
    assert_eq!(
        history
            .items
            .iter()
            .map(|event| event.delivery_sequence().get())
            .collect::<Vec<_>>(),
        vec![2, 1],
        "history is newest first"
    );
    assert_eq!(history.next_cursor, None);
    Ok(())
}

async fn assert_deliveries_are_ordered_and_acknowledged(
    application: &HookApplication,
    identity: &FixtureIdentity,
) -> Result<()> {
    let backlog = application
        .pull_deliveries(PullDeliveriesCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            after_sequence: None,
            limit: 100,
        })
        .await?;
    assert_eq!(backlog.items.len(), 2);
    assert_eq!(backlog.cursor.acknowledged_through, 0);
    assert_eq!(backlog.latest_sequence, 2);

    let cursor = application
        .acknowledge_deliveries(AcknowledgeDeliveriesCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            through_sequence: 1,
        })
        .await?;
    assert_eq!(cursor.acknowledged_through, 1);
    let regressed = application
        .acknowledge_deliveries(AcknowledgeDeliveriesCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            through_sequence: 0,
        })
        .await?;
    assert_eq!(regressed.acknowledged_through, 1, "cursors never move back");

    let remaining = application
        .pull_deliveries(PullDeliveriesCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            after_sequence: None,
            limit: 100,
        })
        .await?;
    assert_eq!(remaining.items.len(), 1);
    assert_eq!(remaining.items[0].delivery_sequence().get(), 2);
    Ok(())
}

async fn assert_unsigned_hooks_accept_everything(
    application: &HookApplication,
    identity: &FixtureIdentity,
) -> Result<()> {
    let unsigned_hook = create_hook(
        application,
        identity,
        "Legacy",
        SigningPatch {
            required: Some(false),
            ..SigningPatch::default()
        },
        "create-legacy-0001",
    )
    .await?;
    let outcome = receive(
        application,
        identity,
        unsigned_hook.hook.endpoint_key(),
        vec![("content-type".to_owned(), "text/plain".to_owned())],
        b"plain text",
        PROVIDER_IP,
    )
    .await?;
    assert!(matches!(outcome, ReceiveOutcome::Accepted(_)));
    Ok(())
}

async fn assert_blocked_log_and_history(
    application: &HookApplication,
    identity: &FixtureIdentity,
    hook_id: silicon_hook::domain::HookId,
) -> Result<()> {
    let blocked_log = application
        .list_blocked_requests(ListHistoryCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            hook_id: None,
            limit: 100,
            cursor: None,
        })
        .await?;
    assert_eq!(
        blocked_log.items.len(),
        usize::try_from(UNVERIFIED_REQUESTS_PER_BLOCK)?
    );
    let events = application
        .list_events(ListHistoryCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            hook_id: None,
            limit: 100,
            cursor: None,
        })
        .await?;
    assert_eq!(
        events.items.len(),
        1,
        "only the verified request is history"
    );
    let hook = application
        .get_hook(&identity.authorization(), &identity.silicon_id, hook_id)
        .await?;
    assert!(hook.last_blocked_at().is_some());
    Ok(())
}

#[tokio::test]
async fn unverified_requests_are_logged_and_block_the_address_after_twenty() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let application = application(database.store.clone(), datetime!(2026-09-02 10:00 UTC))?;
    let created = create_hook(
        &application,
        &identity,
        "Stripe",
        SigningPatch::default(),
        "create-stripe-0001",
    )
    .await?;
    let secret = secret_of(&created)?;
    let body = br#"{"type":"charge.succeeded"}"#;
    let forged = vec![
        ("content-type".to_owned(), "application/json".to_owned()),
        ("webhook-id".to_owned(), "msg_forged".to_owned()),
        ("webhook-timestamp".to_owned(), "1700000000".to_owned()),
        (
            "webhook-signature".to_owned(),
            "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
        ),
    ];

    for attempt in 1..=UNVERIFIED_REQUESTS_PER_BLOCK {
        let outcome = receive(
            &application,
            &identity,
            created.hook.endpoint_key(),
            forged.clone(),
            body,
            PROVIDER_IP,
        )
        .await
        .with_context(|| format!("forged attempt {attempt} must still be receipted"))?;
        let ReceiveOutcome::Blocked(blocked) = outcome else {
            bail!("forged request {attempt} was accepted");
        };
        assert_eq!(blocked.reason().code(), "signature_mismatch");
    }

    let blocked_now = receive(
        &application,
        &identity,
        created.hook.endpoint_key(),
        forged.clone(),
        body,
        PROVIDER_IP,
    )
    .await;
    assert!(
        matches!(blocked_now, Err(ApplicationError::IpBlocked { .. })),
        "the twenty-first request from the address is refused"
    );
    let rejected = sqlx::query_scalar::<_, i64>(
        "SELECT rejected_requests FROM hook_private.ip_blocks WHERE hook_id = $1",
    )
    .bind(created.hook.id().as_uuid())
    .fetch_one(database.store.pool())
    .await?;
    assert_eq!(rejected, 1);

    let signed = standard_webhook_headers(&secret, "msg_ok", "1700000000", body)?;
    let from_other_address = receive(
        &application,
        &identity,
        created.hook.endpoint_key(),
        signed,
        body,
        OTHER_IP,
    )
    .await?;
    assert!(matches!(from_other_address, ReceiveOutcome::Accepted(_)));

    assert_blocked_log_and_history(&application, &identity, created.hook.id()).await?;
    assert_unsigned_hooks_accept_everything(&application, &identity).await
}

#[tokio::test]
async fn provider_specific_expressions_verify_github_style_signatures() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let application = application(database.store.clone(), datetime!(2026-09-02 10:00 UTC))?;
    let created = create_hook(
        &application,
        &identity,
        "GitHub",
        SigningPatch {
            payload: Some(Expression::parse("request.raw_body")?),
            signature: Some(Expression::parse(
                r#"request.headers["x-hub-signature-256"]"#,
            )?),
            signature_encoding: Some(SignatureEncoding::Hex),
            secret: Some(SigningSecret::from_text("gh-provider-secret")?),
            ..SigningPatch::default()
        },
        "create-github-hex",
    )
    .await?;
    assert_eq!(
        created.signing_secret.as_ref().map(SigningSecret::as_str),
        Some("gh-provider-secret"),
        "a supplied secret is echoed once"
    );
    let body = br#"{"ref":"refs/heads/main"}"#;
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(b"gh-provider-secret")
        .context("HMAC accepts any key length")?;
    mac.update(body);
    let signature = hex::encode(mac.finalize().into_bytes());
    let outcome = receive(
        &application,
        &identity,
        created.hook.endpoint_key(),
        vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            (
                "x-hub-signature-256".to_owned(),
                format!("sha256={signature}"),
            ),
        ],
        body,
        PROVIDER_IP,
    )
    .await?;
    assert!(matches!(outcome, ReceiveOutcome::Accepted(_)));
    Ok(())
}

#[tokio::test]
async fn endpoint_rotation_retires_the_previous_key_forever() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let application = application(database.store.clone(), datetime!(2026-09-02 10:00 UTC))?;
    let created = create_hook(
        &application,
        &identity,
        "Linear",
        SigningPatch::default(),
        "create-linear-0001",
    )
    .await?;
    let secret = secret_of(&created)?;
    let original_key = created.hook.endpoint_key().clone();

    let rotated = application
        .rotate_hook_endpoint(HookMutationCommand {
            context: identity.context("rotate-endpoint-0001"),
            silicon_id: identity.silicon_id.clone(),
            hook_id: created.hook.id(),
        })
        .await?;
    assert_ne!(rotated.endpoint_key(), &original_key);
    assert!(rotated.endpoint_rotated_at().is_some());
    let replay = application
        .rotate_hook_endpoint(HookMutationCommand {
            context: identity.context("rotate-endpoint-0001"),
            silicon_id: identity.silicon_id.clone(),
            hook_id: created.hook.id(),
        })
        .await?;
    assert_eq!(replay.endpoint_key(), rotated.endpoint_key());

    let body = br#"{"event":"issue.created"}"#;
    let headers = standard_webhook_headers(&secret, "msg_1", "1700000000", body)?;
    let retired = receive(
        &application,
        &identity,
        &original_key,
        headers.clone(),
        body,
        PROVIDER_IP,
    )
    .await;
    assert!(matches!(retired, Err(ApplicationError::EndpointRetired)));
    let accepted = receive(
        &application,
        &identity,
        rotated.endpoint_key(),
        headers,
        body,
        PROVIDER_IP,
    )
    .await?;
    assert!(matches!(accepted, ReceiveOutcome::Accepted(_)));

    sqlx::query(
        "UPDATE hook.hooks SET created_at = clock_timestamp() - INTERVAL '50 days', \
         disabled_at = NULL, deleted_at = clock_timestamp() - INTERVAL '46 days', \
         updated_at = clock_timestamp() WHERE id = $1",
    )
    .bind(created.hook.id().as_uuid())
    .execute(database.store.pool())
    .await?;
    let maintenance = database.store.run_maintenance_pass(100).await?;
    assert_eq!(maintenance.hooks_purged, 1);
    assert!(matches!(
        database
            .store
            .resolve_endpoint(&identity.silicon_id, &original_key)
            .await?,
        EndpointResolution::Retired
    ));
    assert!(matches!(
        database
            .store
            .resolve_endpoint(&identity.silicon_id, rotated.endpoint_key())
            .await?,
        EndpointResolution::Unknown
    ));
    Ok(())
}

#[tokio::test]
async fn secret_rotation_invalidates_the_previous_secret_immediately() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let application = application(database.store.clone(), datetime!(2026-09-02 10:00 UTC))?;
    let created = create_hook(
        &application,
        &identity,
        "Svix",
        SigningPatch::default(),
        "create-svix-0001",
    )
    .await?;
    let old_secret = secret_of(&created)?;

    let rotated = application
        .rotate_hook_secret(HookMutationCommand {
            context: identity.context("rotate-secret-0001"),
            silicon_id: identity.silicon_id.clone(),
            hook_id: created.hook.id(),
        })
        .await?;
    let new_secret = secret_of(&rotated)?;
    assert_ne!(new_secret.as_str(), old_secret.as_str());
    let replayed = application
        .rotate_hook_secret(HookMutationCommand {
            context: identity.context("rotate-secret-0001"),
            silicon_id: identity.silicon_id.clone(),
            hook_id: created.hook.id(),
        })
        .await?;
    assert_eq!(secret_of(&replayed)?.as_str(), new_secret.as_str());

    let body = br#"{"event":"ping"}"#;
    let stale = receive(
        &application,
        &identity,
        created.hook.endpoint_key(),
        standard_webhook_headers(&old_secret, "msg_old", "1700000000", body)?,
        body,
        PROVIDER_IP,
    )
    .await?;
    assert!(matches!(stale, ReceiveOutcome::Blocked(_)));
    let fresh = receive(
        &application,
        &identity,
        created.hook.endpoint_key(),
        standard_webhook_headers(&new_secret, "msg_new", "1700000000", body)?,
        body,
        PROVIDER_IP,
    )
    .await?;
    assert!(matches!(fresh, ReceiveOutcome::Accepted(_)));
    Ok(())
}

#[tokio::test]
async fn retention_purges_logs_after_fourteen_days_and_forgets_stale_blocks() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let application = application(database.store.clone(), datetime!(2026-09-02 10:00 UTC))?;
    let created = create_hook(
        &application,
        &identity,
        "Shopify",
        SigningPatch::default(),
        "create-shopify-0001",
    )
    .await?;
    let pool = database.store.pool();
    for (sequence, age_days) in [(1_i64, 15_i64), (2, 13), (3, 15)] {
        sqlx::query(
            "INSERT INTO hook.events (id, hook_id, org_id, silicon_id, provider, summary, \
             delivery_sequence, method, url, path, query_string, headers, body, remote_ip, \
             received_at, expires_at) \
             VALUES (gen_random_uuid(), $1, $2, $3, 'Shopify', 'summary', $5, 'POST', $4, \
             '/silicon/x/A', '', '[]'::jsonb, ''::bytea, '203.0.113.10'::inet, \
             now() - ($6 * INTERVAL '1 day'), \
             now() - ($6 * INTERVAL '1 day') + INTERVAL '14 days')",
        )
        .bind(created.hook.id().as_uuid())
        .bind(identity.organization_id.as_str())
        .bind(identity.silicon_id.as_str())
        .bind(format!("{PUBLIC_BASE_URL}silicon/x/A"))
        .bind(sequence)
        .bind(age_days)
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO hook.blocked_requests (id, hook_id, org_id, silicon_id, provider, \
             reason_code, reason_detail, method, url, path, query_string, headers, body, \
             remote_ip, received_at, expires_at) \
             VALUES (gen_random_uuid(), $1, $2, $3, 'Shopify', 'signature_mismatch', \
             'signature mismatch', 'POST', $4, '/silicon/x/A', '', '[]'::jsonb, ''::bytea, \
             '203.0.113.10'::inet, now() - ($5 * INTERVAL '1 day'), \
             now() - ($5 * INTERVAL '1 day') + INTERVAL '14 days')",
        )
        .bind(created.hook.id().as_uuid())
        .bind(identity.organization_id.as_str())
        .bind(identity.silicon_id.as_str())
        .bind(format!("{PUBLIC_BASE_URL}silicon/x/A"))
        .bind(age_days)
        .execute(pool)
        .await?;
    }
    sqlx::query(
        "INSERT INTO hook_private.ip_blocks (hook_id, remote_ip, strikes, blocked_until, \
         first_seen_at, updated_at) VALUES \
         ($1, '203.0.113.1'::inet, 3, NULL, clock_timestamp() - INTERVAL '40 days', \
          clock_timestamp() - INTERVAL '40 days'), \
         ($1, '203.0.113.2'::inet, 0, clock_timestamp() - INTERVAL '39 days', \
          clock_timestamp() - INTERVAL '40 days', clock_timestamp() - INTERVAL '40 days'), \
         ($1, '203.0.113.3'::inet, 5, NULL, clock_timestamp(), clock_timestamp())",
    )
    .bind(created.hook.id().as_uuid())
    .execute(pool)
    .await?;

    let result = database.store.run_maintenance_pass(10).await?;
    assert_eq!(result.events_purged, 2);
    assert_eq!(result.blocked_requests_purged, 2);
    assert_eq!(
        result.ip_blocks_purged, 2,
        "stale counters and expired blocks are forgotten"
    );
    let remaining_blocks =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook_private.ip_blocks")
            .fetch_one(pool)
            .await?;
    assert_eq!(remaining_blocks, 1, "a recent counter is kept");
    let history = application
        .list_events(ListHistoryCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            hook_id: None,
            limit: 10,
            cursor: None,
        })
        .await?;
    assert_eq!(history.items.len(), 1);
    Ok(())
}

#[tokio::test]
async fn history_page_budget_preserves_keyset_continuation() -> Result<()> {
    const EVENT_COUNT: usize = 20;
    const BODY_BYTES: usize = 900_000;
    const _: () = assert!(EVENT_COUNT * BODY_BYTES > HISTORY_PAGE_BYTE_BUDGET);

    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let application = application(database.store.clone(), datetime!(2026-09-02 10:00 UTC))?;
    let created = create_hook(
        &application,
        &identity,
        "Bulk",
        SigningPatch {
            required: Some(false),
            ..SigningPatch::default()
        },
        "create-bulk-0001",
    )
    .await?;
    let body: &'static [u8] = Box::leak(vec![b'x'; BODY_BYTES].into_boxed_slice());
    let mut expected = Vec::with_capacity(EVENT_COUNT);
    for _ in 0..EVENT_COUNT {
        let ReceiveOutcome::Accepted(event) = receive(
            &application,
            &identity,
            created.hook.endpoint_key(),
            vec![(
                "content-type".to_owned(),
                "application/octet-stream".to_owned(),
            )],
            body,
            PROVIDER_IP,
        )
        .await?
        else {
            bail!("unsigned hook must accept every request");
        };
        expected.push(event.id());
    }
    expected.reverse();

    let mut actual = Vec::new();
    let mut cursor = None;
    let mut first_cursor = None;
    let mut pages = 0_usize;
    loop {
        let page = application
            .list_events(ListHistoryCommand {
                authorization: identity.authorization(),
                silicon_id: identity.silicon_id.clone(),
                hook_id: Some(created.hook.id()),
                limit: 10_000,
                cursor: cursor.clone(),
            })
            .await?;
        pages += 1;
        assert!(
            !page.items.is_empty(),
            "every page carries at least one record"
        );
        assert!(
            page.items.len() < EVENT_COUNT,
            "the byte budget splits the history"
        );
        actual.extend(page.items.iter().map(EventRecord::id));
        if first_cursor.is_none() {
            first_cursor.clone_from(&page.next_cursor);
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert!(
        pages >= 2,
        "a budget-limited history needs continuation pages"
    );
    assert_eq!(actual, expected);
    let cursor = first_cursor.context("a byte-limited page must have a continuation cursor")?;

    let wrong_collection = application
        .list_blocked_requests(ListHistoryCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            hook_id: Some(created.hook.id()),
            limit: 10,
            cursor: Some(cursor),
        })
        .await;
    assert!(matches!(
        wrong_collection,
        Err(ApplicationError::Validation { field: "cursor" })
    ));
    Ok(())
}

#[tokio::test]
async fn create_replay_is_exact_with_a_sub_microsecond_clock_value() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let raw_time = datetime!(2026-08-31 12:00:00.123456789 UTC);
    let application = application(database.store.clone(), raw_time)?;

    let first = create_hook(
        &application,
        &identity,
        "Replay",
        SigningPatch::default(),
        "application-create-key",
    )
    .await?;
    let replay = create_hook(
        &application,
        &identity,
        "Replay",
        SigningPatch::default(),
        "application-create-key",
    )
    .await?;
    assert_eq!(first.hook.id(), replay.hook.id());
    assert_eq!(first.hook.endpoint_key(), replay.hook.endpoint_key());
    assert_eq!(
        first.hook.created_at(),
        datetime!(2026-08-31 12:00:00.123456 UTC)
    );
    assert_eq!(secret_of(&first)?.as_str(), secret_of(&replay)?.as_str());

    let changed = create_hook(
        &application,
        &identity,
        "Different",
        SigningPatch::default(),
        "application-create-key",
    )
    .await;
    let conflict = changed
        .err()
        .and_then(|error| error.downcast::<ApplicationError>().ok());
    assert!(matches!(
        conflict,
        Some(ApplicationError::IdempotencyConflict)
    ));
    Ok(())
}

#[tokio::test]
async fn ingress_uses_database_time_even_when_the_process_clock_is_wrong() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let application = application(database.store.clone(), datetime!(2000-01-01 0:00 UTC))?;
    let created = create_hook(
        &application,
        &identity,
        "Clock",
        SigningPatch {
            required: Some(false),
            ..SigningPatch::default()
        },
        "database-clock-hook",
    )
    .await?;
    let before = database_now(database.store.pool()).await?;
    let ReceiveOutcome::Accepted(event) = receive(
        &application,
        &identity,
        created.hook.endpoint_key(),
        Vec::new(),
        b"{}",
        PROVIDER_IP,
    )
    .await?
    else {
        bail!("unsigned hook must accept the request");
    };
    let after = database_now(database.store.pool()).await?;
    assert!((before..=after).contains(&event.received_at()));
    assert!(
        event.summary().contains("-20"),
        "summary uses the database year, not 2000"
    );
    Ok(())
}

#[tokio::test]
async fn connecting_the_iam_hook_is_idempotent_and_verifies_iam_signing() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let application = application(database.store.clone(), datetime!(2026-09-02 10:00 UTC))?;
    let context = |key: &str| ManagementContext {
        authorization: identity.authorization(),
        idempotency_key: key.to_owned(),
        request_id: None,
    };

    let prepared = application
        .prepare_iam_hook(ConnectIamHookCommand {
            context: context("iam-connect-0001"),
            silicon_id: identity.silicon_id.clone(),
        })
        .await?;
    assert_eq!(prepared.name().as_str(), "Silicon IAM");
    let again = application
        .prepare_iam_hook(ConnectIamHookCommand {
            context: context("iam-connect-0002"),
            silicon_id: identity.silicon_id.clone(),
        })
        .await?;
    assert_eq!(
        again.id(),
        prepared.id(),
        "a Silicon has exactly one IAM hook"
    );

    let iam_secret = format!("swhs_{}", "F".repeat(43));
    let bound = application
        .bind_iam_hook_secret(BindIamHookSecretCommand {
            context: context("iam-bind-0001"),
            silicon_id: identity.silicon_id.clone(),
            hook_id: prepared.id(),
            signing_secret: SigningSecret::from_text(iam_secret.clone())?,
        })
        .await?;
    assert_eq!(bound.id(), prepared.id());

    let body = br#"{"spec_version":"1.0","event_type":"organization.silicon.updated.v1"}"#;
    let timestamp = "1700000000";
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(iam_secret.as_bytes())
        .context("HMAC accepts any key length")?;
    mac.update(format!("{timestamp}.").as_bytes());
    mac.update(body);
    let signature = format!("v1={}", hex::encode(mac.finalize().into_bytes()));
    let outcome = receive(
        &application,
        &identity,
        bound.endpoint_key(),
        vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            ("X-Silicon-IAM-Timestamp".to_owned(), timestamp.to_owned()),
            ("X-Silicon-IAM-Key-Version".to_owned(), "1".to_owned()),
            ("X-Silicon-IAM-Signature".to_owned(), signature),
        ],
        body,
        PROVIDER_IP,
    )
    .await?;
    assert!(
        matches!(outcome, ReceiveOutcome::Accepted(_)),
        "the IAM hook verifies IAM's own signing convention with the IAM-issued secret"
    );

    application
        .delete_hook(DeleteHookCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            hook_id: prepared.id(),
            request_id: None,
        })
        .await?;
    let restored = application
        .prepare_iam_hook(ConnectIamHookCommand {
            context: context("iam-connect-0003"),
            silicon_id: identity.silicon_id.clone(),
        })
        .await?;
    assert_eq!(
        restored.id(),
        prepared.id(),
        "connecting again restores the deleted IAM hook"
    );
    assert_eq!(restored.status(), HookStatus::Active);
    Ok(())
}

#[tokio::test]
async fn concurrent_disable_wins_before_event_acceptance_commits() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let application = application(database.store.clone(), datetime!(2026-09-02 10:00 UTC))?;
    let created = create_hook(
        &application,
        &identity,
        "Race",
        SigningPatch {
            required: Some(false),
            ..SigningPatch::default()
        },
        "create-race-0001",
    )
    .await?;

    let mut disabling = database.store.pool().begin().await?;
    sqlx::query("SELECT id FROM hook.hooks WHERE id = $1 FOR UPDATE")
        .bind(created.hook.id().as_uuid())
        .execute(&mut *disabling)
        .await?;
    let ingress_application = application.clone();
    let ingress_identity = identity.clone();
    let endpoint_key = created.hook.endpoint_key().clone();
    let ingress_task = tokio::spawn(async move {
        receive(
            &ingress_application,
            &ingress_identity,
            &endpoint_key,
            Vec::new(),
            b"{}",
            PROVIDER_IP,
        )
        .await
    });
    wait_for_blocked_query(database.store.pool(), "last_received_at").await?;
    sqlx::query("UPDATE hook.hooks SET disabled_at = clock_timestamp(), updated_at = clock_timestamp() WHERE id = $1")
        .bind(created.hook.id().as_uuid())
        .execute(&mut *disabling)
        .await?;
    disabling.commit().await?;

    let outcome = ingress_task.await.context("ingress task panicked")?;
    assert!(matches!(outcome, Err(ApplicationError::NotFound)));
    let counts = sqlx::query_as::<_, (i64, i64)>(
        "SELECT (SELECT count(*) FROM hook.events), \
                (SELECT count(*) FROM hook_private.delivery_sequences)",
    )
    .fetch_one(database.store.pool())
    .await?;
    assert_eq!(counts, (0, 0));
    let hook = database
        .store
        .get_hook(
            &identity.organization_id,
            &identity.silicon_id,
            created.hook.id(),
        )
        .await?
        .context("hook disappeared")?;
    assert_eq!(hook.status(), HookStatus::Disabled);
    Ok(())
}
