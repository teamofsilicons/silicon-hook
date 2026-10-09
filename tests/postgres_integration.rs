//! PostgreSQL 16 integration tests for Silicon Hook's durable invariants.

mod support;

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
        ApplicationError, BindIamHookSecretCommand, Clock, ConnectIamHookCommand,
        CreateHookCommand, DeleteHookCommand, HookApplication, HookMutationCommand, HookPatch,
        HookWithSecret, ListHistoryCommand, ManagementContext, ReceiveOutcome,
        ReceiveRequestCommand, SigningPatch, UpdateHookCommand,
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
use sqlx::PgPool;
use time::{OffsetDateTime, macros::datetime};
use url::Url;

const DATABASE_WAIT_TIMEOUT: StdDuration = StdDuration::from_secs(10);
const PUBLIC_BASE_URL: &str = "https://hook.integration.test/";
const PROVIDER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
const OTHER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));

struct TestDatabase {
    store: PostgresStore,
    /// Keeps the throwaway database alive; dropping it drops the database.
    handle: support::postgres::TestDatabase,
}

impl TestDatabase {
    async fn start_unmigrated() -> Result<Option<Self>> {
        let Some(handle) = support::postgres::TestDatabase::create().await? else {
            return Ok(None);
        };
        let pool = handle.connect(12).await?;
        Ok(Some(Self {
            store: PostgresStore::new(pool),
            handle,
        }))
    }

    async fn start() -> Result<Option<Self>> {
        let Some(database) = Self::start_unmigrated().await? else {
            return Ok(None);
        };
        migrate(database.store.pool()).await?;
        Ok(Some(database))
    }

    /// Migrates as the owner, creates the two restricted runtime logins, and
    /// applies the real grant manifest through `psql`. Returns the owner store
    /// plus stores connected as the API and worker roles, so tests exercise
    /// the exact privileges production runs with.
    async fn start_with_runtime_roles() -> Result<Option<(Self, PostgresStore, PostgresStore)>> {
        let Some(mut database) = Self::start().await? else {
            return Ok(None);
        };
        let roles = database.handle.runtime_roles().await?;
        let api = support::postgres::TestDatabase::connect_as(&roles.api, 8).await?;
        let worker = support::postgres::TestDatabase::connect_as(&roles.worker, 4).await?;
        Ok(Some((
            database,
            PostgresStore::new(api),
            PostgresStore::new(worker),
        )))
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
    let Some(database) = TestDatabase::start_unmigrated().await? else {
        return Ok(());
    };
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
    assert_eq!(applied, 18);

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
    let Some(database) = TestDatabase::start().await? else {
        return Ok(());
    };
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

    assert_hook_activity_and_history(&application, &identity, created.hook.id()).await
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
    let Some(database) = TestDatabase::start().await? else {
        return Ok(());
    };
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
    let Some(database) = TestDatabase::start().await? else {
        return Ok(());
    };
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
    let Some(database) = TestDatabase::start().await? else {
        return Ok(());
    };
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
    let Some(database) = TestDatabase::start().await? else {
        return Ok(());
    };
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
    let Some(database) = TestDatabase::start().await? else {
        return Ok(());
    };
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

    let Some(database) = TestDatabase::start().await? else {
        return Ok(());
    };
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
    let Some(database) = TestDatabase::start().await? else {
        return Ok(());
    };
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
    let Some(database) = TestDatabase::start().await? else {
        return Ok(());
    };
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
    let Some(database) = TestDatabase::start().await? else {
        return Ok(());
    };
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
    let Some(database) = TestDatabase::start().await? else {
        return Ok(());
    };
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
    let Some((database, api_store, worker_store)) =
        TestDatabase::start_with_runtime_roles().await?
    else {
        return Ok(());
    };
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
    let Some(database) = TestDatabase::start().await? else {
        return Ok(());
    };
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
    let Some(database) = TestDatabase::start().await? else {
        return Ok(());
    };
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
    let Some(database) = TestDatabase::start().await? else {
        return Ok(());
    };
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

#[tokio::test]
async fn telemetry_runtime_grants_deduplicate_and_keep_payloads_private() -> Result<()> {
    let Some((owner, api, worker)) = TestDatabase::start_with_runtime_roles().await? else {
        return Ok(());
    };
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
    let Some((owner, api, worker)) = TestDatabase::start_with_runtime_roles().await? else {
        return Ok(());
    };
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
async fn public_identifier_cutover_preserves_hook_credentials_and_history_keys() -> Result<()> {
    let Some(db) = TestDatabase::start_unmigrated().await? else {
        return Ok(());
    };
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
    let Some(db) = TestDatabase::start_unmigrated().await? else {
        return Ok(());
    };
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
