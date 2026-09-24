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
        HookMutationCommand, HookPatch, HookWithSecret, ListHistoryCommand, ManagementContext,
        PullDeliveriesCommand, ReceiveOutcome, ReceiveRequestCommand, SigningPatch,
        UpdateHookCommand,
    },
    domain::{
        ActorKind, ActorRef, AuthorizationContext, EncryptionKeyId, EndpointKey, EventRecord,
        HookName, HookStatus, HookTimeZone, OrganizationId, OrganizationRole, SigningSecret,
        SiliconId,
        safety::UNVERIFIED_REQUESTS_PER_BLOCK,
        signature::{Expression, SecretEncoding, SignatureEncoding},
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
use testcontainers::{ContainerAsync, ImageExt as _, core::ExecCommand, runners::AsyncRunner as _};
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
    container: ContainerAsync<Postgres>,
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
            container,
        })
    }

    async fn start() -> Result<Self> {
        let database = Self::start_unmigrated().await?;
        migrate(database.store.pool()).await?;
        Ok(database)
    }

    /// Migrates as the owner, creates the two restricted runtime logins, and
    /// applies the real grant manifest through `psql` inside the container.
    /// Returns the owner store plus stores connected as the API and worker
    /// roles, so tests exercise the exact privileges production runs with.
    async fn start_with_runtime_roles() -> Result<(Self, PostgresStore, PostgresStore)> {
        let manifest = std::fs::read("deploy/postgres/grant-runtime.sql")
            .context("read the runtime grant manifest")?;
        let container = Postgres::default()
            .with_tag("16-alpine")
            .with_copy_to("/opt/grant-runtime.sql", manifest)
            .start()
            .await
            .context("start PostgreSQL 16 test container")?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(POSTGRES_PORT).await?;
        let owner_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let owner = PgPoolOptions::new()
            .max_connections(12)
            .connect(&owner_url)
            .await
            .context("connect to PostgreSQL test container")?;
        migrate(&owner).await?;
        sqlx::raw_sql(
            "CREATE ROLE silicon_hook_api LOGIN PASSWORD 'api-secret' \
                 NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION; \
             CREATE ROLE silicon_hook_worker LOGIN PASSWORD 'worker-secret' \
                 NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;",
        )
        .execute(&owner)
        .await?;
        let mut grants = container
            .exec(ExecCommand::new([
                "psql",
                "--username=postgres",
                "--dbname=postgres",
                "--set=api_role=silicon_hook_api",
                "--set=worker_role=silicon_hook_worker",
                "--file=/opt/grant-runtime.sql",
            ]))
            .await
            .context("apply the runtime grant manifest")?;
        // The exit code is only known once the process has finished, which
        // draining its output guarantees.
        let stdout = grants.stdout_to_vec().await?;
        let stderr = grants.stderr_to_vec().await?;
        let exit_code = grants.exit_code().await?;
        if exit_code != Some(0) {
            bail!(
                "grant manifest failed with {exit_code:?}: {}{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
        }
        let api = PgPoolOptions::new()
            .max_connections(8)
            .connect(&format!(
                "postgres://silicon_hook_api:api-secret@{host}:{port}/postgres"
            ))
            .await
            .context("connect as the API role")?;
        let worker = PgPoolOptions::new()
            .max_connections(4)
            .connect(&format!(
                "postgres://silicon_hook_worker:worker-secret@{host}:{port}/postgres"
            ))
            .await
            .context("connect as the worker role")?;
        Ok((
            Self {
                store: PostgresStore::new(owner),
                container,
            },
            PostgresStore::new(api),
            PostgresStore::new(worker),
        ))
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
    assert_eq!(applied, 17);

    let mut absent_environment = pool.begin().await?;
    sqlx::query("SELECT set_config('hook.environment_id', $1, true)")
        .bind(uuid::Uuid::now_v7().to_string())
        .execute(&mut *absent_environment)
        .await?;
    let available: bool = sqlx::query_scalar("SELECT hook_private.environment_is_available()")
        .fetch_one(&mut *absent_environment)
        .await?;
    assert!(
        !available,
        "an absent environment must return false, never NULL"
    );
    absent_environment.rollback().await?;

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

    let future_ack = application
        .acknowledge_deliveries(AcknowledgeDeliveriesCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            through_sequence: 9999,
        })
        .await;
    assert!(matches!(
        future_ack,
        Err(ApplicationError::Validation {
            field: "through_sequence"
        })
    ));

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

/// The API and worker roles hold exactly the grants in the reviewed manifest,
/// so every statement each process runs must work under those grants. The
/// owner-connected tests cannot see a privilege defect; this one can.
#[tokio::test]
async fn runtime_roles_operate_within_their_grants() -> Result<()> {
    let (database, api_store, worker_store) = TestDatabase::start_with_runtime_roles().await?;
    api_store.ready_for(RuntimeDatabaseRole::Api).await?;
    worker_store.ready_for(RuntimeDatabaseRole::Worker).await?;

    let identity = FixtureIdentity::new()?;
    let application = application(api_store.clone(), time::OffsetDateTime::now_utc())?;
    let (signed, open) = exercise_api_role(&application, &identity).await?;
    age_records(database.store.pool(), &identity, &signed, &open).await?;

    let result = worker_store.run_maintenance_pass(100).await?;
    assert_eq!(result.events_purged, 1);
    assert_eq!(result.blocked_requests_purged, 1);
    assert_eq!(result.hooks_purged, 1);
    assert_eq!(result.idempotency_rows_purged, 1);
    assert_eq!(result.ip_blocks_purged, 1);
    Ok(())
}

/// Runs every mutating and reading use case as the API role.
async fn exercise_api_role(
    application: &HookApplication,
    identity: &FixtureIdentity,
) -> Result<(HookWithSecret, HookWithSecret)> {
    let signed = create_hook(
        application,
        identity,
        "GitHub",
        SigningPatch::default(),
        "roles-create-0001",
    )
    .await?;
    let open = create_hook(
        application,
        identity,
        "Open",
        SigningPatch {
            required: Some(false),
            ..SigningPatch::default()
        },
        "roles-create-0002",
    )
    .await?;
    exercise_ingress_and_delivery(application, identity, &signed, &open).await?;
    application
        .rotate_hook_secret(HookMutationCommand {
            context: identity.context("roles-rotate-secret"),
            silicon_id: identity.silicon_id.clone(),
            hook_id: signed.hook.id(),
        })
        .await?;
    application
        .rotate_hook_endpoint(HookMutationCommand {
            context: identity.context("roles-rotate-endpoint"),
            silicon_id: identity.silicon_id.clone(),
            hook_id: signed.hook.id(),
        })
        .await?;
    application
        .delete_hook(DeleteHookCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            hook_id: open.hook.id(),
            request_id: None,
        })
        .await?;
    application
        .restore_hook(HookMutationCommand {
            context: identity.context("roles-restore"),
            silicon_id: identity.silicon_id.clone(),
            hook_id: open.hook.id(),
        })
        .await?;
    let iam = application
        .prepare_iam_hook(ConnectIamHookCommand {
            context: identity.context("roles-iam-connect"),
            silicon_id: identity.silicon_id.clone(),
        })
        .await?;
    application
        .bind_iam_hook_secret(BindIamHookSecretCommand {
            context: identity.context("roles-iam-bind"),
            silicon_id: identity.silicon_id.clone(),
            hook_id: iam.id(),
            signing_secret: SigningSecret::from_text(format!("swhs_{}", "G".repeat(43)))?,
        })
        .await?;

    Ok((signed, open))
}

/// Receives one accepted and one withheld request, then reads history and
/// consumes the delivery stream, all as the API role.
async fn exercise_ingress_and_delivery(
    application: &HookApplication,
    identity: &FixtureIdentity,
    signed: &HookWithSecret,
    open: &HookWithSecret,
) -> Result<()> {
    let accepted = receive(
        application,
        identity,
        open.hook.endpoint_key(),
        vec![],
        b"{\"event\":\"open\"}",
        PROVIDER_IP,
    )
    .await?;
    assert!(matches!(accepted, ReceiveOutcome::Accepted(_)));
    let withheld = receive(
        application,
        identity,
        signed.hook.endpoint_key(),
        vec![],
        b"{\"event\":\"unsigned\"}",
        PROVIDER_IP,
    )
    .await?;
    assert!(matches!(withheld, ReceiveOutcome::Blocked(_)));

    let history = ListHistoryCommand {
        authorization: identity.authorization(),
        silicon_id: identity.silicon_id.clone(),
        hook_id: None,
        limit: 10,
        cursor: None,
    };
    assert_eq!(
        application.list_events(history.clone()).await?.items.len(),
        1
    );
    assert_eq!(
        application
            .list_blocked_requests(history)
            .await?
            .items
            .len(),
        1
    );
    let backlog = application
        .pull_deliveries(PullDeliveriesCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            after_sequence: None,
            limit: 10,
        })
        .await?;
    assert_eq!(backlog.items.len(), 1);
    application
        .acknowledge_deliveries(AcknowledgeDeliveriesCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            through_sequence: 1,
        })
        .await?;
    Ok(())
}

/// Ages one record of every retained kind as the owner so the worker has
/// something to purge from each table.
async fn age_records(
    pool: &PgPool,
    identity: &FixtureIdentity,
    signed: &HookWithSecret,
    open: &HookWithSecret,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO hook.events (id, hook_id, org_id, silicon_id, provider, summary, \
         delivery_sequence, method, url, path, query_string, headers, body, remote_ip, \
         received_at, expires_at) \
         VALUES (gen_random_uuid(), $1, $2, $3, 'GitHub', 'summary', 99, 'POST', $4, \
         '/silicon/x/A', '', '[]'::jsonb, ''::bytea, '203.0.113.10'::inet, \
         now() - INTERVAL '15 days', now() - INTERVAL '1 day')",
    )
    .bind(signed.hook.id().as_uuid())
    .bind(identity.organization_id.as_str())
    .bind(identity.silicon_id.as_str())
    .bind(format!("{PUBLIC_BASE_URL}silicon/x/A"))
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO hook.blocked_requests (id, hook_id, org_id, silicon_id, provider, \
         reason_code, reason_detail, method, url, path, query_string, headers, body, \
         remote_ip, received_at, expires_at) \
         VALUES (gen_random_uuid(), $1, $2, $3, 'GitHub', 'signature_missing', 'missing', \
         'POST', $4, '/silicon/x/A', '', '[]'::jsonb, ''::bytea, '203.0.113.10'::inet, \
         now() - INTERVAL '15 days', now() - INTERVAL '1 day')",
    )
    .bind(signed.hook.id().as_uuid())
    .bind(identity.organization_id.as_str())
    .bind(identity.silicon_id.as_str())
    .bind(format!("{PUBLIC_BASE_URL}silicon/x/A"))
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO hook_private.ip_blocks (hook_id, remote_ip, strikes, blocked_until, \
         first_seen_at, updated_at) VALUES ($1, '198.51.100.99'::inet, 2, NULL, \
         clock_timestamp() - INTERVAL '40 days', clock_timestamp() - INTERVAL '40 days')",
    )
    .bind(signed.hook.id().as_uuid())
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO hook_private.management_idempotency (operation, actor_kind, actor_id, \
         org_id, target_id, idempotency_key, request_digest, created_at, expires_at) \
         VALUES ('hook.create', 'silicon', $1, $2, $1, 'expired-key-0001', \
         decode(repeat('00', 32), 'hex'), now() - INTERVAL '2 days', now() - INTERVAL '1 day')",
    )
    .bind(identity.silicon_id.as_str())
    .bind(identity.organization_id.as_str())
    .execute(pool)
    .await?;
    sqlx::query(
        "UPDATE hook.hooks SET created_at = clock_timestamp() - INTERVAL '50 days', \
         disabled_at = NULL, deleted_at = clock_timestamp() - INTERVAL '46 days', \
         updated_at = clock_timestamp() WHERE id = $1",
    )
    .bind(open.hook.id().as_uuid())
    .execute(pool)
    .await?;

    Ok(())
}

#[tokio::test]
async fn byos_can_be_set_after_creation_and_replaced_without_changing_the_endpoint() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let application = application(database.store.clone(), datetime!(2026-09-02 10:00 UTC))?;
    let created = create_hook(
        &application,
        &identity,
        "BYOS",
        SigningPatch::default(),
        "byos-create-0001",
    )
    .await?;
    let body = br#"{"event":"byos"}"#;
    let mut previous = secret_of(&created)?;
    for (index, supplied) in [" provider secret with spaces ", "replacement-secret"]
        .iter()
        .enumerate()
    {
        let updated = application
            .update_hook(UpdateHookCommand {
                authorization: identity.authorization(),
                silicon_id: identity.silicon_id.clone(),
                hook_id: created.hook.id(),
                patch: HookPatch {
                    signing: Some(SigningPatch {
                        secret: Some(SigningSecret::from_text(*supplied)?),
                        ..SigningPatch::default()
                    }),
                    ..HookPatch::default()
                },
                request_id: None,
            })
            .await?;
        assert_eq!(updated.endpoint_key(), created.hook.endpoint_key());
        assert_eq!(updated.signing().config, created.hook.signing().config);
        let rejected = receive(
            &application,
            &identity,
            updated.endpoint_key(),
            standard_webhook_headers(&previous, &format!("old-{index}"), "1700000000", body)?,
            body,
            PROVIDER_IP,
        )
        .await?;
        assert!(!matches!(rejected, ReceiveOutcome::Accepted(_)));
        previous = SigningSecret::from_text(*supplied)?;
        let accepted = receive(
            &application,
            &identity,
            updated.endpoint_key(),
            standard_webhook_headers(&previous, &format!("new-{index}"), "1700000000", body)?,
            body,
            PROVIDER_IP,
        )
        .await?;
        assert!(matches!(accepted, ReceiveOutcome::Accepted(_)));
    }
    // Reject an incompatible encoding before applying even the activation change.
    let invalid = application
        .update_hook(UpdateHookCommand {
            authorization: identity.authorization(),
            silicon_id: identity.silicon_id.clone(),
            hook_id: created.hook.id(),
            patch: HookPatch {
                enabled: Some(false),
                signing: Some(SigningPatch {
                    secret_encoding: Some(SecretEncoding::Hex),
                    ..SigningPatch::default()
                }),
                ..HookPatch::default()
            },
            request_id: None,
        })
        .await;
    assert!(matches!(
        invalid,
        Err(ApplicationError::ValidationDetailed { .. })
    ));
    let stored = database
        .store
        .get_hook(
            &identity.organization_id,
            &identity.silicon_id,
            created.hook.id(),
        )
        .await?
        .context("hook exists")?;
    assert_eq!(stored.status(), HookStatus::Active);
    Ok(())
}

#[tokio::test]
async fn encoded_secrets_verify_after_creation_and_rotation() -> Result<()> {
    let database = TestDatabase::start().await?;
    let identity = FixtureIdentity::new()?;
    let application = application(database.store.clone(), datetime!(2026-09-02 10:00 UTC))?;
    let body = br#"{"event":"encoded"}"#;
    for (index, encoding) in [
        SecretEncoding::Hex,
        SecretEncoding::Base64,
        SecretEncoding::Base64Url,
    ]
    .into_iter()
    .enumerate()
    {
        let created = create_hook(
            &application,
            &identity,
            "Encoded",
            SigningPatch {
                secret_encoding: Some(encoding),
                ..SigningPatch::default()
            },
            &format!("encoded-create-{index}"),
        )
        .await?;
        let rotated = application
            .rotate_hook_secret(HookMutationCommand {
                context: identity.context(&format!("encoded-rotate-{index}")),
                silicon_id: identity.silicon_id.clone(),
                hook_id: created.hook.id(),
            })
            .await?;
        for (label, result, accepted) in [("old", &created, false), ("new", &rotated, true)] {
            let key = encoding.decode(secret_of(result)?.as_str())?;
            let decoded = SigningSecret::from_text(String::from_utf8(key.to_vec())?)?;
            let outcome = receive(
                &application,
                &identity,
                created.hook.endpoint_key(),
                standard_webhook_headers(
                    &decoded,
                    &format!("{label}-{index}"),
                    "1700000000",
                    body,
                )?,
                body,
                PROVIDER_IP,
            )
            .await?;
            assert_eq!(matches!(outcome, ReceiveOutcome::Accepted(_)), accepted);
        }
    }
    Ok(())
}

#[tokio::test]
async fn deprecated_contract_sunsets_only_after_seven_request_free_days() -> Result<()> {
    let database = TestDatabase::start().await?;
    let pool = database.store.pool();
    let status: String =
        sqlx::query_scalar("SELECT status FROM hook_private.contract_status('v1',true)")
            .fetch_one(pool)
            .await?;
    assert_eq!(status, "deprecated");
    sqlx::query("UPDATE hook_private.contract_versions SET status='deprecated', deprecated_at=clock_timestamp()-INTERVAL '8 days', last_requested_at=clock_timestamp()-INTERVAL '6 days' WHERE major='v1'").execute(pool).await?;
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM hook_private.contract_status('v1',false)"
        )
        .fetch_one(pool)
        .await?,
        "deprecated"
    );
    sqlx::query("SELECT * FROM hook_private.contract_status('v1',true)")
        .execute(pool)
        .await?;
    let recent: bool = sqlx::query_scalar("SELECT last_requested_at > clock_timestamp()-INTERVAL '1 minute' FROM hook_private.contract_versions WHERE major='v1'").fetch_one(pool).await?;
    assert!(recent);
    sqlx::query("UPDATE hook_private.contract_versions SET last_requested_at=clock_timestamp()-INTERVAL '7 days' WHERE major='v1'").execute(pool).await?;
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM hook_private.contract_status('v1',true)"
        )
        .fetch_one(pool)
        .await?,
        "sunset"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT request_count FROM hook_private.contract_versions WHERE major='v1'",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(count, 2, "rejected calls cannot revive a sunset contract");
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one background worker scenario checks idle scheduling and stale-lease recovery together"
)]
async fn assert_idle_test_publisher_avoids_iam(
    service: &silicon_hook::application::environments::EnvironmentService,
    context: &silicon_hook::application::environments::EnvironmentContext,
    issuer: &wiremock::MockServer,
    owner: &PgPool,
) -> Result<()> {
    use silicon_hook::{delivery::publisher, infrastructure::ting::TingClient};
    let app = application(context.store.clone(), OffsetDateTime::now_utc())?.for_test_environment(
        context.store.clone(),
        context.environment.id,
        context.environment.generation,
    );
    let identity = FixtureIdentity::new()?;
    let hook = create_hook(
        &app,
        &identity,
        "idle-publisher",
        SigningPatch::default(),
        "idle-publisher-create",
    )
    .await?;
    let headers = standard_webhook_headers(&secret_of(&hook)?, "idle-event", "1700000000", b"{}")?;
    let ReceiveOutcome::Accepted(event) = receive(
        &app,
        &identity,
        hook.hook.endpoint_key(),
        headers,
        b"{}",
        PROVIDER_IP,
    )
    .await?
    else {
        bail!("fixture event was not accepted");
    };
    let event_id = event.id().as_uuid();
    let bytes: Vec<u8> =
        sqlx::query_scalar("SELECT request_body FROM hook_private.ting_outbox WHERE event_id=$1")
            .bind(event_id)
            .fetch_one(owner)
            .await?;
    sqlx::query("UPDATE hook_private.ting_outbox SET next_attempt_at=clock_timestamp()+INTERVAL '1 hour' WHERE event_id=$1")
        .bind(event_id).execute(owner).await?;
    let calls = issuer
        .received_requests()
        .await
        .context("IAM requests")?
        .len();
    let receiver = wiremock::MockServer::start().await;
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(publisher::run_tests(
        app,
        service.clone(),
        TingClient::new(&receiver.uri(), StdDuration::from_secs(1))?,
        StdDuration::from_millis(5),
        shutdown,
    ));
    tokio::time::sleep(StdDuration::from_millis(100)).await;
    assert_eq!(
        issuer
            .received_requests()
            .await
            .context("IAM requests")?
            .len(),
        calls,
        "future retries must not revalidate idle IAM contexts"
    );
    sqlx::query("UPDATE hook_private.ting_outbox SET next_attempt_at=clock_timestamp(), lease_id=gen_random_uuid(), lease_until=clock_timestamp()+INTERVAL '1 hour' WHERE event_id=$1")
        .bind(event_id).execute(owner).await?;
    tokio::time::sleep(StdDuration::from_millis(100)).await;
    assert_eq!(
        issuer
            .received_requests()
            .await
            .context("IAM requests")?
            .len(),
        calls,
        "a current lease is not due work"
    );
    // Rotation makes that old lease reclaimable; the hint must preserve this path.
    sqlx::query("UPDATE hook_control.environments SET generation=generation+1 WHERE id=$1")
        .bind(context.environment.id)
        .execute(owner)
        .await?;
    tokio::time::timeout(StdDuration::from_secs(3), async {
        loop {
            let attempts: i64 = sqlx::query_scalar(
                "SELECT attempts FROM hook_private.ting_outbox WHERE event_id=$1",
            )
            .bind(event_id)
            .fetch_one(owner)
            .await?;
            if attempts > 0 {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await??;
    assert!(
        issuer
            .received_requests()
            .await
            .context("IAM requests")?
            .len()
            > calls,
        "actual sends still revalidate IAM"
    );
    // No publisher is configured: the real sender must defer, never contact Ting.
    assert!(
        receiver
            .received_requests()
            .await
            .context("Ting requests")?
            .is_empty()
    );
    sqlx::query("UPDATE hook_private.ting_outbox SET accepted_at=clock_timestamp(),ting_id='msg_fixture',silent=false,last_error_code=NULL,lease_id=NULL,lease_until=NULL WHERE event_id=$1")
        .bind(event_id).execute(owner).await?;
    let calls = issuer
        .received_requests()
        .await
        .context("IAM requests")?
        .len();
    tokio::time::sleep(StdDuration::from_millis(100)).await;
    assert_eq!(
        issuer
            .received_requests()
            .await
            .context("IAM requests")?
            .len(),
        calls,
        "accepted sends must not poll IAM"
    );
    stop.send(true)?;
    task.await?;
    assert_eq!(
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT request_body FROM hook_private.ting_outbox WHERE event_id=$1"
        )
        .bind(event_id)
        .fetch_one(owner)
        .await?,
        bytes
    );
    // Leave the enclosing lifecycle scenario at its original generation.
    sqlx::query("DELETE FROM hook.hooks WHERE id=$1")
        .bind(hook.hook.id().as_uuid())
        .execute(owner)
        .await?;
    sqlx::query("UPDATE hook_control.environments SET generation=$2 WHERE id=$1")
        .bind(context.environment.id)
        .bind(context.environment.generation)
        .execute(owner)
        .await?;
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one lifecycle fixture checks selection, reset and revocation together"
)]
async fn application_secret_selects_empty_isolated_storage_and_revalidates_lifecycle() -> Result<()>
{
    use silicon_hook::{
        application::environments::EnvironmentService,
        config::{DatabaseSettings, IamSettings},
        infrastructure::iam::IamClient,
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };
    let (database, _, _) = TestDatabase::start_with_runtime_roles().await?;
    let server = MockServer::start().await;
    Mock::given(method("GET")).and(path("/api/version")).respond_with(ResponseTemplate::new(200).insert_header("silicon-iam-api-version","v1").insert_header("vary","Silicon-IAM-Supported-API-Versions").set_body_json(serde_json::json!({"service":"silicon-iam","selected_api_version":"v1","supported_api_versions":["v1"],"build":"test","commit":"test"}))).mount(&server).await;
    let secret = format!("ask_{}", "A".repeat(43));
    let selector = format!("Basic {}", STANDARD.encode(format!("hook:{secret}")));
    let id = uuid::Uuid::now_v7();
    let context = |version, cleaned: Option<&str>| {
        serde_json::json!({
            "environment_id":id,"webhook_key_digest":"ab".repeat(32),
            "environment":{"environment_id":id,"org_id":"tos","name":"SDK sandbox","description":null,"version":version,"key_generation":1,"cleaned_at":cleaned,"created_at":"2026-09-13T00:00:00Z","creator_type":"carbon","creator_id":"c:alice"},
            "application":{"app_id":"hook","base_url":"https://backend.hook.teamofsilicons.com","app_scope":{"iam":[],"external":[]},"webhook_scope":[],"testing_idle_days":15}
        })
    };
    let selected = Mock::given(method("GET"))
        .and(path("/api/v1/application/testing-context"))
        .and(header("x-testing-application", selector.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(context(1, None)))
        .mount_as_scoped(&server)
        .await;
    let iam = IamClient::connect(&IamSettings {
        base_url: Url::parse(&server.uri())?,
        app_id: Some("hook".into()),
        app_secret: Some(secrecy::SecretString::from(format!(
            "ask_{}",
            "P".repeat(43)
        ))),
        connect_timeout: StdDuration::from_secs(2),
        request_timeout: StdDuration::from_secs(2),
        max_response_bytes: 1024 * 1024,
        allow_insecure_local_http: true,
        local_auth: false,
        webhook: None,
    })
    .await?;
    let db = DatabaseSettings {
        url: secrecy::SecretString::from(format!(
            "postgres://silicon_hook_api:api-secret@{}:{}/postgres",
            database.container.get_host().await?,
            database.container.get_host_port_ipv4(5432).await?
        )),
        max_connections: std::num::NonZeroU32::new(4).context("pool size")?,
        min_connections: 0,
        acquire_timeout: StdDuration::from_secs(3),
        statement_timeout: StdDuration::from_secs(10),
    };
    let key = EncryptionKeyId::new("1")?;
    let cipher = Arc::new(SecretCipher::new(SecretKeyring::new(
        key.clone(),
        [(key, SecretKey::from_bytes([7; 32]))],
    )?));
    let service = EnvironmentService::connect(db, cipher, iam).await?;
    let first = service.resolve_app_secret(&secret).await?;
    assert_eq!(first.environment.id, id);
    assert_eq!(first.environment.generation, 1);
    assert!(first.iam.is_testing());
    let again = service.resolve_app_secret(&secret).await?;
    assert_eq!(again.environment.id, id);
    assert_idle_test_publisher_avoids_iam(&service, &first, &server, database.store.pool()).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM hook_control.environments")
        .fetch_one(database.store.pool())
        .await?;
    assert_eq!(count, 1, "repeated selection does not fork storage");
    sqlx::query("INSERT INTO hook_private.telemetry_events(environment_id,event_id,source,step,trace_id,data) VALUES($1,$2,'client','command',$3,'{}')")
        .bind(id).bind(uuid::Uuid::now_v7()).bind(uuid::Uuid::now_v7()).execute(database.store.pool()).await?;
    let stored: String = sqlx::query_scalar(
        "SELECT encrypted_credentials::text FROM hook_control.environments WHERE id=$1",
    )
    .bind(id)
    .fetch_one(database.store.pool())
    .await?;
    assert!(!stored.contains(&secret));
    drop(selected);
    let cleaned = Mock::given(method("GET"))
        .and(path("/api/v1/application/testing-context"))
        .and(header("x-testing-application", selector.as_str()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(context(2, Some("2026-09-13T01:00:00Z"))),
        )
        .mount_as_scoped(&server)
        .await;
    let after_clean = service.resolve_app_secret(&secret).await?;
    assert_eq!(after_clean.environment.generation, 2);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM hook_private.telemetry_events WHERE environment_id=$1"
        )
        .bind(id)
        .fetch_one(database.store.pool())
        .await?,
        0,
        "sandbox clean purges telemetry"
    );
    assert_eq!(
        service
            .resolve_app_secret(&secret)
            .await?
            .environment
            .generation,
        2,
        "clean is applied once"
    );
    drop(cleaned);
    assert!(
        service.resolve_app_secret(&secret).await.is_err(),
        "cached pools cannot bypass revoked selectors"
    );
    let service = service.with_honeycomb_control(
        secrecy::SecretString::from("dedicated-hook-honeycomb-service-token"),
        "hook".into(),
        Url::parse(&server.uri())?,
    )?;
    let mut current = context(3, Some("2026-09-13T01:00:00Z"));
    current["webhook_key_digest"] =
        hex::encode(<Sha256 as sha2::Digest>::digest("A".repeat(32))).into();
    let ready = Mock::given(method("GET"))
        .and(path("/api/v1/application/testing-context"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&current))
        .mount_as_scoped(&server)
        .await;
    let operation = |action: &str,
                     revision,
                     generation|
     -> Result<
        silicon_hook::application::environments::lifecycle::LifecycleOperation,
    > {
        Ok(serde_json::from_value(
            serde_json::json!({"operation_id":uuid::Uuid::now_v7(),"environment_id":id,"org_id":"tos","app_id":"hook","environment_revision":revision,"generation":generation,"key_version":1,"action":action,"testing_key":"A".repeat(32)}),
        )?)
    };
    assert_eq!(
        service.lifecycle(&operation("prepare", 1, 1)?).await?["state"],
        "completed"
    );
    let managed = service.resolve_app_secret(&secret).await?;
    assert_eq!(managed.environment.id, id);
    let clean = operation("clean", 2, 2)?;
    assert_eq!(service.lifecycle(&clean).await?["state"], "completed");
    let cleaned_generation = service.selected_metadata(id).await?.generation;
    assert_eq!(
        service
            .resolve_app_secret(&secret)
            .await?
            .environment
            .generation,
        cleaned_generation,
        "IAM snapshots cannot repeat coordinator cleanup"
    );
    assert_eq!(
        service.lifecycle(&operation("disable", 3, 2)?).await?["state"],
        "completed"
    );
    assert!(
        service.resolve_app_secret(&secret).await.is_err(),
        "an IAM response cannot override Hook disable"
    );
    assert_eq!(
        service.lifecycle(&operation("restore", 4, 2)?).await?["state"],
        "completed"
    );
    drop(ready);
    let unavailable = Mock::given(method("GET"))
        .and(path("/api/v1/application/testing-context"))
        .respond_with(ResponseTemplate::new(403))
        .mount_as_scoped(&server)
        .await;
    assert!(
        service.resolve_app_secret(&secret).await.is_err(),
        "local restore cannot bypass shared IAM readiness"
    );
    drop(unavailable);
    current["environment_id"] = uuid::Uuid::now_v7().to_string().into();
    current["environment"]["environment_id"] = current["environment_id"].clone();
    current["webhook_key_digest"] =
        hex::encode(<Sha256 as sha2::Digest>::digest("C".repeat(32))).into();
    let _unprepared = Mock::given(method("GET"))
        .and(path("/api/v1/application/testing-context"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&current))
        .mount_as_scoped(&server)
        .await;
    assert!(
        service.resolve_app_secret(&secret).await.is_err(),
        "selection cannot create an unprepared shared environment"
    );
    Ok(())
}

#[tokio::test]
async fn telemetry_runtime_grants_deduplicate_and_keep_payloads_private() -> Result<()> {
    let (owner, api, worker) = TestDatabase::start_with_runtime_roles().await?;
    let id = uuid::Uuid::now_v7();
    for _ in 0..2 {
        sqlx::query("INSERT INTO hook_private.telemetry_events(event_id,source,step,trace_id,data) VALUES($1,'cli','command',$1,'{}') ON CONFLICT DO NOTHING")
            .bind(id).execute(api.pool()).await?;
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook_private.telemetry_events")
            .fetch_one(owner.store.pool())
            .await?,
        1
    );
    assert!(
        sqlx::query("SELECT data FROM hook_private.telemetry_events")
            .execute(api.pool())
            .await
            .is_err()
    );
    assert!(
        sqlx::query("SELECT data FROM hook_private.telemetry_events")
            .execute(worker.pool())
            .await
            .is_ok()
    );
    assert!(
        sqlx::query("DELETE FROM hook_private.telemetry_events")
            .execute(api.pool())
            .await
            .is_err()
    );
    assert!(sqlx::query("INSERT INTO hook_private.telemetry_events(environment_id,event_id,source,step,trace_id,data) VALUES($1,$2,'cli','command',$2,'{}')")
        .bind(uuid::Uuid::now_v7()).bind(uuid::Uuid::now_v7()).execute(api.pool()).await.is_err());
    sqlx::query(
        "UPDATE hook_private.telemetry_events SET recorded_at=clock_timestamp()-INTERVAL '31 days'",
    )
    .execute(owner.store.pool())
    .await?;
    let deleted = sqlx::query("DELETE FROM hook_private.telemetry_events WHERE environment_id=hook_private.environment_id() AND event_id IN (SELECT event_id FROM hook_private.telemetry_events WHERE recorded_at < clock_timestamp()-INTERVAL '30 days' LIMIT 1000)").execute(worker.pool()).await?;
    assert_eq!(deleted.rows_affected(), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicit HOOK_TELEMETRY_TABLE_KEY and sends a synthetic diagnostic"]
async fn telemetry_reaches_configured_space_station_table() -> Result<()> {
    anyhow::ensure!(
        std::env::var("HOOK_TELEMETRY_TABLE_KEY").is_ok(),
        "configure the Hook table key explicitly"
    );
    let (owner, api, worker) = TestDatabase::start_with_runtime_roles().await?;
    let id = uuid::Uuid::now_v7();
    let event = serde_json::json!({"event_id":id,"trace_id":id,"source":"backend","step":"verification","outcome":"succeeded","version":"0.5.0","operation":"telemetry_integration_check","progress":1});
    sqlx::query("INSERT INTO hook_private.telemetry_events(event_id,source,step,trace_id,data) VALUES($1,'backend','verification',$1,$2)")
        .bind(id).bind(event).execute(api.pool()).await?;
    silicon_hook::telemetry::flush_events(worker.pool()).await?;
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT exported_at IS NOT NULL FROM hook_private.telemetry_events WHERE event_id=$1"
        )
        .bind(id)
        .fetch_one(owner.store.pool())
        .await?
    );
    println!("Space Station accepted synthetic Hook diagnostic {id}");
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "end-to-end participant state machine with restricted database roles"
)]
async fn honeycomb_lifecycle_fences_cleanup_retries_and_retains_binding() -> Result<()> {
    use secrecy::SecretString;
    use silicon_hook::{
        application::environments::{EnvironmentService, lifecycle::LifecycleOperation},
        config::{DatabaseSettings, IamSettings},
        infrastructure::iam::IamClient,
    };
    use tower::ServiceExt as _;
    use uuid::Uuid;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };
    let (database, api, _) = TestDatabase::start_with_runtime_roles().await?;
    let coordinator = MockServer::start().await;
    let iam = IamClient::connect(&IamSettings {
        base_url: Url::parse("http://127.0.0.1:9")?,
        app_id: None,
        app_secret: None,
        connect_timeout: StdDuration::from_millis(10),
        request_timeout: StdDuration::from_millis(10),
        max_response_bytes: 1024,
        allow_insecure_local_http: true,
        local_auth: true,
        webhook: None,
    })
    .await?;
    let url = format!(
        "postgres://silicon_hook_api:api-secret@{}:{}/postgres",
        database.container.get_host().await?,
        database.container.get_host_port_ipv4(5432).await?
    );
    let db = DatabaseSettings {
        url: SecretString::from(url.clone()),
        max_connections: std::num::NonZeroU32::new(4).context("pool size")?,
        min_connections: 0,
        acquire_timeout: StdDuration::from_secs(3),
        statement_timeout: StdDuration::from_secs(10),
    };
    let key = EncryptionKeyId::new("1")?;
    let cipher = Arc::new(SecretCipher::new(SecretKeyring::new(
        key.clone(),
        [(key, SecretKey::from_bytes([7; 32]))],
    )?));
    let service = EnvironmentService::connect(db, cipher, iam.clone())
        .await?
        .with_honeycomb_control(
            SecretString::from("dedicated-hook-honeycomb-service-credential"),
            "hook".into(),
            Url::parse(&coordinator.uri())?,
        )?;
    assert!(service.authorize_honeycomb("user-token").is_err());
    service.authorize_honeycomb("dedicated-hook-honeycomb-service-credential")?;
    let id = Uuid::now_v7();
    let operation = |action: &str,
                     revision,
                     generation,
                     key_version|
     -> Result<LifecycleOperation> {
        Ok(serde_json::from_value(
            serde_json::json!({"operation_id":Uuid::now_v7(),"environment_id":id,"org_id":"org:integration","app_id":"hook","environment_revision":revision,"generation":generation,"key_version":key_version,"action":action,"testing_key":"A".repeat(32),"snapshot":{}}),
        )?)
    };
    let prepare = operation("prepare", 1, 1, 1)?;
    // The protected route bypasses test headers, but never service authentication.
    let router = silicon_hook::api::router(
        silicon_hook::api::ApiDependencies {
            ting: silicon_hook::infrastructure::ting::TingClient::new(
                "http://127.0.0.1:1",
                StdDuration::from_secs(1),
            )?,
            application: application(api.clone(), database_now(api.pool()).await?)?,
            environments: Some(service.clone()),
            iam: iam.clone(),
            trusted_proxy_hops: 0,
            realtime: silicon_hook::config::RealtimeSettings {
                heartbeat_interval: StdDuration::from_secs(30),
                heartbeat_timeout: StdDuration::from_secs(120),
                replay_batch_size: std::num::NonZeroU32::MIN,
                poll_interval: StdDuration::from_secs(1),
                max_silicons_per_connection: std::num::NonZeroUsize::MIN,
            },
            wakeups: silicon_hook::infrastructure::postgres::DeliveryWakeups::new(),
        },
        &silicon_hook::config::ServerSettings {
            bind_addr: "127.0.0.1:0".parse()?,
            public_base_url: Url::parse(PUBLIC_BASE_URL)?,
            request_timeout: StdDuration::from_secs(5),
            max_ingress_body_bytes: 4096,
            max_management_body_bytes: 65536,
            concurrency_limit: 8,
            trusted_proxy_hops: 0,
        },
    );
    let endpoint = format!(
        "/internal/honeycomb/organizations/org:integration/testing-environments/{id}/operations/{}",
        prepare.operation_id
    );
    for (token, expected) in [
        ("user-token", http::StatusCode::UNAUTHORIZED),
        (
            "dedicated-hook-honeycomb-service-credential",
            http::StatusCode::OK,
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                http::Request::put(&endpoint)
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-hook-test-app-secret", "disabled-test-secret")
                    .body(axum::body::Body::from(serde_json::to_vec(&prepare)?))?,
            )
            .await?;
        assert_eq!(response.status(), expected);
    }
    let receipt = service.lifecycle(&prepare).await?;
    assert_eq!(receipt["state"], "completed");
    assert_eq!(receipt, service.lifecycle(&prepare).await?);
    assert!(!receipt.to_string().contains(&"A".repeat(32)));
    let mut changed: LifecycleOperation = serde_json::from_value(serde_json::to_value(&prepare)?)?;
    changed.action = "clean".into();
    assert!(service.lifecycle(&changed).await.is_err());
    let generation = service.selected_metadata(id).await?.generation;
    let scoped = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(url.parse::<sqlx::postgres::PgConnectOptions>()?.options([
            ("hook.environment_id", id.to_string()),
            ("hook.environment_generation", generation.to_string()),
        ]))
        .await?;
    let app = application(api.clone(), database_now(api.pool()).await?)?.for_test_environment(
        PostgresStore::new(scoped.clone()),
        id,
        generation,
    );
    let identity = FixtureIdentity::new()?;
    let hook = create_hook(
        &app,
        &identity,
        "before-clean",
        SigningPatch {
            required: Some(false),
            ..SigningPatch::default()
        },
        "before-clean",
    )
    .await?;
    service.touch(id, generation).await?;
    Mock::given(method("POST"))
        .and(path(format!(
            "/api/v1/environments/{id}/apps/hook/activity"
        )))
        .and(header("x-testing-environment-key", "A".repeat(32)))
        .respond_with(ResponseTemplate::new(503))
        .mount(&coordinator)
        .await;
    service.report_activity().await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook_control.activity_reports")
            .fetch_one(database.store.pool())
            .await?,
        1
    );
    coordinator.reset().await;
    Mock::given(method("POST"))
        .and(header("x-testing-environment-key", "A".repeat(32)))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&coordinator)
        .await;
    service.report_activity().await?;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook_control.activity_reports")
            .fetch_one(database.store.pool())
            .await?,
        0
    );
    // An in-flight transport owns a shared fence. Clean cannot complete until it sends.
    sqlx::raw_sql("CREATE FUNCTION public.fail_hook_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected cleanup failure'; END $$; CREATE TRIGGER fail_hook_cleanup BEFORE DELETE ON hook.events FOR EACH STATEMENT EXECUTE FUNCTION public.fail_hook_cleanup();").execute(database.store.pool()).await?;
    let guard = app.delivery_guard().await?.context("test delivery fence")?;
    let clean = operation("clean", 2, 2, 1)?;
    let cloned = service.clone();
    let clean_json = serde_json::to_value(&clean)?;
    let cleanup = tokio::spawn(async move {
        cloned
            .lifecycle(
                &serde_json::from_value(clean_json)
                    .map_err(silicon_hook::error::AppError::internal)?,
            )
            .await
    });
    wait_for_blocked_query(database.store.pool(), "FOR UPDATE").await?;
    assert!(!cleanup.is_finished());
    guard.commit().await?;
    assert_eq!(cleanup.await??["state"], "failed");
    assert_eq!(
        service
            .lifecycle_status("org:integration", id, clean.operation_id)
            .await?["state"],
        "failed"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook.hooks WHERE environment_id=$1")
            .bind(id)
            .fetch_one(database.store.pool())
            .await?,
        1,
        "failed cleanup rolls back deletion"
    );
    sqlx::raw_sql(
        "DROP TRIGGER fail_hook_cleanup ON hook.events; DROP FUNCTION public.fail_hook_cleanup();",
    )
    .execute(database.store.pool())
    .await?;
    assert_eq!(service.lifecycle(&clean).await?["state"], "completed");
    assert!(!app.environment_is_available().await?);
    assert!(app.delivery_guard().await.is_err());
    assert!(
        create_hook(
            &app,
            &identity,
            "stale-write",
            SigningPatch {
                required: Some(false),
                ..SigningPatch::default()
            },
            "stale-write"
        )
        .await
        .is_err()
    );
    assert!(
        sqlx::query(
            "INSERT INTO hook_private.delivery_sequences(silicon_id,last_sequence) VALUES('late',1)"
        )
        .execute(&scoped)
        .await
        .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook.hooks WHERE environment_id=$1")
            .bind(id)
            .fetch_one(database.store.pool())
            .await?,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM hook_control.endpoint_routes WHERE environment_id=$1"
        )
        .bind(id)
        .fetch_one(database.store.pool())
        .await?,
        1
    );
    assert_eq!(service.lifecycle(&clean).await?["state"], "completed");
    let after = service.selected_metadata(id).await?.generation;
    assert!(after > generation);
    assert_eq!(after, service.selected_metadata(id).await?.generation);
    assert!(
        service
            .lifecycle(&operation("disable", 1, 1, 1)?)
            .await
            .is_err()
    );
    assert!(
        service
            .lifecycle(&operation("restore", 3, 3, 1)?)
            .await
            .is_err()
    );
    assert_eq!(
        service.lifecycle(&operation("disable", 3, 2, 1)?).await?["state"],
        "completed"
    );
    assert!(
        service
            .resolve_endpoint(
                identity.silicon_id.as_str(),
                hook.hook.endpoint_key().as_str()
            )
            .await
            .is_err()
    );
    assert_eq!(
        service.lifecycle(&operation("restore", 4, 2, 1)?).await?["state"],
        "completed"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook.hooks WHERE environment_id=$1")
            .bind(id)
            .fetch_one(database.store.pool())
            .await?,
        0
    );
    let mut rotate = operation("rotate-key", 5, 2, 2)?;
    rotate.testing_key = "B".repeat(32);
    let (first_rotation, repeated_rotation) =
        tokio::join!(service.lifecycle(&rotate), service.lifecycle(&rotate));
    assert_eq!(first_rotation?, repeated_rotation?);
    let mut purge = operation("purge", 6, 2, 2)?;
    purge.testing_key = "B".repeat(32);
    assert_eq!(service.lifecycle(&purge).await?["state"], "completed");
    assert_eq!(service.lifecycle(&purge).await?["state"], "completed");
    assert_eq!(
        service
            .lifecycle_status("org:integration", id, purge.operation_id)
            .await?["state"],
        "completed"
    );
    assert!(
        service
            .lifecycle(&operation("prepare", 7, 2, 2)?)
            .await
            .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT encrypted_credentials FROM hook_control.environments WHERE id=$1"
        )
        .bind(id)
        .fetch_one(database.store.pool())
        .await?,
        serde_json::json!({})
    );
    Ok(())
}

#[tokio::test]
async fn public_identifier_cutover_preserves_hook_credentials_and_history_keys() -> Result<()> {
    let db = TestDatabase::start_unmigrated().await?;
    let pool = db.store.pool();
    sqlx::migrate!("./migrations").run_to(16, pool).await?;
    let id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO hook.hooks(id,org_id,silicon_id,endpoint_key,name,signature_config,created_by_kind,created_by_id,created_at,updated_at,encryption_key_id,secret_nonce,encrypted_signing_secret) VALUES($1,'tos','assistant:tos','A1B2C3D4','Retained hook','{}','carbon','alice',now(),now(),'key-1',$2,$3)")
        .bind(id).bind(vec![7_u8;12]).bind(vec![9_u8;32]).execute(pool).await?;
    let before: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(h)-'silicon_id'-'created_by_id' FROM hook.hooks h WHERE id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    sqlx::raw_sql("CREATE FUNCTION schema_trigger_probe() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$; CREATE TRIGGER schema_disabled AFTER UPDATE ON hook.hooks FOR EACH ROW EXECUTE FUNCTION schema_trigger_probe(); ALTER TABLE hook.hooks DISABLE TRIGGER schema_disabled; CREATE TRIGGER schema_replica AFTER UPDATE ON hook.hooks FOR EACH ROW EXECUTE FUNCTION schema_trigger_probe(); ALTER TABLE hook.hooks ENABLE REPLICA TRIGGER schema_replica; CREATE TRIGGER schema_always AFTER UPDATE ON hook.hooks FOR EACH ROW EXECUTE FUNCTION schema_trigger_probe(); ALTER TABLE hook.hooks ENABLE ALWAYS TRIGGER schema_always; ").execute(pool).await?;
    migrate(pool).await?;
    let after: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(h)-'silicon_id'-'created_by_id' FROM hook.hooks h WHERE id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    assert_eq!(
        before, after,
        "UUID, endpoint key, ciphertext, nonce, version and timestamps must remain exact"
    );
    let ids: (String, String) =
        sqlx::query_as("SELECT silicon_id,created_by_id FROM hook.hooks WHERE id=$1")
            .bind(id)
            .fetch_one(pool)
            .await?;
    assert_eq!(ids, ("si:assistant".into(), "c:alice".into()));
    let modes: Vec<(String,String)> = sqlx::query_as("SELECT tgname,tgenabled::text FROM pg_trigger WHERE tgrelid='hook.hooks'::regclass AND tgname LIKE 'schema_%' ORDER BY tgname").fetch_all(pool).await?;
    assert_eq!(
        modes,
        vec![
            ("schema_always".into(), "A".into()),
            ("schema_disabled".into(), "D".into()),
            ("schema_replica".into(), "R".into())
        ]
    );
    sqlx::raw_sql("DROP TRIGGER schema_disabled ON hook.hooks; DROP TRIGGER schema_replica ON hook.hooks; DROP TRIGGER schema_always ON hook.hooks; DROP FUNCTION schema_trigger_probe();").execute(pool).await?;
    let disabled:i64=sqlx::query_scalar("SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN('hook','hook_private','hook_control') AND NOT t.tgisinternal AND t.tgenabled='D'")
        .fetch_one(pool).await?;
    assert_eq!(disabled, 0);
    db.store.ready().await?;
    Ok(())
}

#[tokio::test]
async fn public_identifier_collision_aborts_without_changing_owners() -> Result<()> {
    let db = TestDatabase::start_unmigrated().await?;
    let pool = db.store.pool();
    sqlx::migrate!("./migrations").run_to(16, pool).await?;
    for org in ["alpha", "other"] {
        sqlx::query("INSERT INTO hook.hooks(id,org_id,silicon_id,endpoint_key,name,signature_config,created_by_kind,created_by_id,created_at,updated_at) VALUES($1,$2,$3,'A1B2C3D4','Collision hook','{}','carbon','alice',now(),now())")
            .bind(uuid::Uuid::new_v4()).bind(org).bind(format!("assistant:{org}")).execute(pool).await?;
    }
    assert!(migrate(pool).await.is_err());
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT silicon_id FROM hook.hooks ORDER BY silicon_id")
            .fetch_all(pool)
            .await?;
    assert_eq!(ids, vec!["assistant:alpha", "assistant:other"]);
    Ok(())
}
