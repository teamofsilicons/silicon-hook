//! Retained Ting references survive authority rotation; clean still destroys them.

use std::{sync::Arc, time::Duration};

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use hmac::{Hmac, Mac as _};
use serde_json::Value;
use sha2::Sha256;
use silicon_hook::{
    application::{
        ApplicationError, Clock, CreateHookCommand, HookApplication, HookWithSecret,
        ManagementContext, ReceiveOutcome, ReceiveRequestCommand, SigningPatch,
    },
    delivery::EventReference,
    domain::{
        ActorKind, ActorRef, AuthorizationContext, EncryptionKeyId, EventRecord, HookName,
        HookTimeZone, OrganizationId, OrganizationRole, SigningSecret, SiliconId,
    },
    infrastructure::{
        crypto::{CursorCodec, SecretCipher, SecretKey, SecretKeyring},
        postgres::{PostgresStore, TingOutboxClaim, migrate},
    },
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{ContainerAsync, ImageExt as _, core::ExecCommand, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

const ORG: &str = "org:ting-integration";
const SILICON: &str = "silicon:ting-integration";
const MESSAGE_ID: &str = "provider-event-1";
const TIMESTAMP: &str = "1700000000";

struct Database {
    owner: PgPool,
    store: PostgresStore,
    api_url: String,
    _container: ContainerAsync<Postgres>,
}

impl Database {
    async fn start() -> Result<Self> {
        let grants = std::fs::read("deploy/postgres/grant-runtime.sql")?;
        let container = Postgres::default()
            .with_tag("16-alpine")
            .with_copy_to("/opt/grant-runtime.sql", grants)
            .start()
            .await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let owner = PgPoolOptions::new()
            .max_connections(4)
            .connect(&format!(
                "postgres://postgres:postgres@{host}:{port}/postgres"
            ))
            .await?;
        migrate(&owner).await?;
        sqlx::raw_sql(
            "CREATE ROLE ting_delivery_api LOGIN PASSWORD 'test-api' NOSUPERUSER NOINHERIT;
             CREATE ROLE ting_delivery_worker LOGIN PASSWORD 'test-worker' NOSUPERUSER NOINHERIT;",
        )
        .execute(&owner)
        .await?;
        let mut result = container
            .exec(ExecCommand::new([
                "psql",
                "--username=postgres",
                "--dbname=postgres",
                "--set=api_role=ting_delivery_api",
                "--set=worker_role=ting_delivery_worker",
                "--file=/opt/grant-runtime.sql",
            ]))
            .await?;
        let _stdout = result.stdout_to_vec().await?;
        let stderr = result.stderr_to_vec().await?;
        if result.exit_code().await? != Some(0) {
            bail!(
                "runtime grants failed: {}",
                String::from_utf8_lossy(&stderr)
            );
        }
        let api_url = format!("postgres://ting_delivery_api:test-api@{host}:{port}/postgres");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&api_url)
            .await?;
        Ok(Self {
            owner,
            store: PostgresStore::new(pool),
            api_url,
            _container: container,
        })
    }

    async fn scoped_store(&self, environment: Uuid, generation: i64) -> Result<PostgresStore> {
        let options = self
            .api_url
            .parse::<sqlx::postgres::PgConnectOptions>()?
            .options([
                ("hook.environment_id", environment.to_string()),
                ("hook.environment_generation", generation.to_string()),
            ]);
        Ok(PostgresStore::new(
            PgPoolOptions::new()
                .max_connections(4)
                .connect_with(options)
                .await?,
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

fn authorization(org: &str, actor: &str) -> Result<AuthorizationContext> {
    Ok(AuthorizationContext::new(
        OrganizationId::new(org)?,
        ActorRef::try_new(ActorKind::Silicon, actor)?,
        OrganizationRole::Member,
        std::iter::empty::<SiliconId>(),
    ))
}

fn application(store: PostgresStore) -> Result<HookApplication> {
    let key_id = EncryptionKeyId::new("ting-test-key")?;
    let keyring = SecretKeyring::new(key_id.clone(), [(key_id, SecretKey::from_bytes([17; 32]))])?;
    Ok(HookApplication::new(
        store,
        Arc::new(SecretCipher::new(keyring)),
        Arc::new(CursorCodec::new(SecretKey::from_bytes([29; 32]))),
        Arc::new(FixedClock(OffsetDateTime::now_utc())),
        Url::parse("https://hook.ting-integration.test/")?,
    ))
}

async fn create_hook(app: &HookApplication, key: &str) -> Result<HookWithSecret> {
    Ok(app
        .create_hook(CreateHookCommand {
            context: ManagementContext {
                authorization: authorization(ORG, SILICON)?,
                idempotency_key: key.to_owned(),
                request_id: None,
            },
            silicon_id: SiliconId::new(SILICON)?,
            name: HookName::new("Provider")?,
            description: None,
            time_zone: HookTimeZone::new("UTC")?,
            signing: SigningPatch::default(),
        })
        .await?)
}

fn signed_headers(secret: &SigningSecret, body: &[u8]) -> Result<Vec<(String, String)>> {
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(secret.as_str().as_bytes())
        .context("valid HMAC key")?;
    mac.update(MESSAGE_ID.as_bytes());
    mac.update(b".");
    mac.update(TIMESTAMP.as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(vec![
        (
            "content-type".to_owned(),
            "application/octet-stream".to_owned(),
        ),
        ("webhook-id".to_owned(), MESSAGE_ID.to_owned()),
        ("webhook-timestamp".to_owned(), TIMESTAMP.to_owned()),
        (
            "webhook-signature".to_owned(),
            format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes())),
        ),
    ])
}

fn request(
    created: &HookWithSecret,
    headers: Vec<(String, String)>,
    body: Bytes,
) -> Result<ReceiveRequestCommand> {
    Ok(ReceiveRequestCommand {
        silicon_id: SiliconId::new(SILICON)?,
        endpoint_key: created.hook.endpoint_key().clone(),
        method: "POST".to_owned(),
        path: format!("/silicon/{SILICON}/{}", created.hook.endpoint_key()),
        query: None,
        headers,
        body,
        remote_ip: "203.0.113.42".parse()?,
    })
}

async fn accept(app: &HookApplication, hook: &HookWithSecret, body: Bytes) -> Result<EventRecord> {
    let secret = hook.signing_secret.as_ref().context("generated secret")?;
    let command = request(hook, signed_headers(secret, &body)?, body)?;
    match app.receive_request(command).await? {
        ReceiveOutcome::Accepted(event) => Ok(event),
        ReceiveOutcome::Blocked(_) => bail!("valid signature was rejected"),
    }
}

async fn claim_one(store: &PostgresStore) -> Result<TingOutboxClaim> {
    let mut claims = store.claim_ting(10, Duration::from_secs(60)).await?;
    assert_eq!(claims.len(), 1);
    claims.pop().context("one queued notification")
}

fn reference(claim: &TingOutboxClaim) -> Result<(Value, EventReference)> {
    let envelope: Value = serde_json::from_slice(&claim.request_body)?;
    let reference = serde_json::from_value(envelope["data"]["data"]["metadata"].clone())?;
    Ok((envelope, reference))
}

async fn insert_environment(database: &Database, id: Uuid) -> Result<()> {
    sqlx::query(
        "INSERT INTO hook_control.environments
             (id,org_id,creator_kind,creator_id,name,key_hash,iam_key_hash,
              creation_request_hash,creation_input_hash,encrypted_credentials,honeycomb_state)
         VALUES ($1,$2,'carbon','carbon:owner','Ting integration',$3,$4,$5,$6,'{}'::jsonb,'ready')",
    )
    .bind(id)
    .bind(ORG)
    .bind([1_u8; 32].as_slice())
    .bind([2_u8; 32].as_slice())
    .bind([3_u8; 32].as_slice())
    .bind([4_u8; 32].as_slice())
    .execute(&database.owner)
    .await?;
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one retained lifecycle exercises rotation, disable, restore and destructive clean"
)]
async fn retained_events_keep_source_identity_while_pending_sends_adopt_current_authority()
-> Result<()> {
    let database = Database::start().await?;
    let production = application(database.store.clone())?;
    let environment = Uuid::now_v7();
    insert_environment(&database, environment).await?;
    let original_store = database.scoped_store(environment, 1).await?;
    let original_app = production.for_test_environment(original_store.clone(), environment, 1);
    let hook = create_hook(&original_app, "generation-hook-create").await?;
    let event = accept(
        &original_app,
        &hook,
        Bytes::from_static(b"retained before rotation"),
    )
    .await?;
    let original = claim_one(&original_store).await?;
    let (_, pointer) = reference(&original)?;
    assert_eq!(pointer.environment_generation, 1);
    assert_eq!(original.environment_generation, 1);
    let original_bytes = original.request_body.clone();
    let auth = authorization(ORG, SILICON)?;
    let silicon = SiliconId::new(SILICON)?;

    // A key rotation invalidates current authority but deliberately keeps data.
    sqlx::query("UPDATE hook_control.environments SET generation=2, key_hash=$2 WHERE id=$1")
        .bind(environment)
        .bind([9_u8; 32].as_slice())
        .execute(&database.owner)
        .await?;
    assert!(
        original_store
            .claim_ting(1, Duration::from_secs(60))
            .await
            .is_err()
    );
    assert!(!original_store.ting_claim_is_current(&original).await?);
    assert!(
        original_store
            .complete_ting(&original, "msg_stale", false)
            .await
            .is_err()
    );
    assert!(matches!(
        original_app
            .get_event(&auth, &silicon, event.id(), Some((environment, 1)))
            .await,
        Err(ApplicationError::StateConflict)
    ));
    let rotated_store = database.scoped_store(environment, 2).await?;
    let rotated_app = production.for_test_environment(rotated_store.clone(), environment, 2);
    assert!(!rotated_store.ting_claim_is_current(&original).await?);
    assert!(
        !rotated_store
            .complete_ting(&original, "msg_stale", false)
            .await?
    );
    let adopted = claim_one(&rotated_store).await?;
    assert_eq!(adopted.id, original.id);
    assert_eq!(adopted.environment_generation, 2);
    assert_eq!(adopted.idempotency_key, original.idempotency_key);
    assert_eq!(adopted.request_body, original_bytes);
    assert_eq!(adopted.attempts, original.attempts + 1);
    assert_ne!(adopted.lease_id, original.lease_id);
    assert!(rotated_store.ting_claim_is_current(&adopted).await?);
    assert_eq!(
        rotated_app
            .get_event(&auth, &silicon, event.id(), Some((environment, 1)))
            .await?
            .request()
            .body()
            .as_ref(),
        b"retained before rotation"
    );
    assert!(matches!(
        rotated_app
            .get_event(&auth, &silicon, event.id(), Some((environment, 2)))
            .await,
        Err(ApplicationError::NotFound)
    ));
    assert!(matches!(
        rotated_app
            .get_event(&auth, &silicon, event.id(), Some((Uuid::new_v4(), 1)))
            .await,
        Err(ApplicationError::NotFound)
    ));
    assert!(
        sqlx::query("UPDATE hook.events SET source_generation=2 WHERE id=$1")
            .bind(event.id().as_uuid())
            .execute(&database.owner)
            .await
            .is_err()
    );
    assert!(
        rotated_store
            .complete_ting(&adopted, "msg_retained", false)
            .await?
    );

    // A newer event gets its own original generation; disabled authority cannot
    // claim it, and restore can reclaim its invalidated lease immediately.
    let second = accept(
        &rotated_app,
        &hook,
        Bytes::from_static(b"retained before disable"),
    )
    .await?;
    let pending = claim_one(&rotated_store).await?;
    assert_eq!(reference(&pending)?.1.environment_generation, 2);
    sqlx::query(
        "UPDATE hook_control.environments SET generation=3,honeycomb_state='disabled' WHERE id=$1",
    )
    .bind(environment)
    .execute(&database.owner)
    .await?;
    let disabled_store = database.scoped_store(environment, 3).await?;
    let disabled_app = production.for_test_environment(disabled_store.clone(), environment, 3);
    assert!(
        disabled_store
            .claim_ting(1, Duration::from_secs(60))
            .await
            .is_err()
    );
    assert!(!disabled_store.ting_claim_is_current(&pending).await?);
    assert!(matches!(
        disabled_app
            .get_event(&auth, &silicon, event.id(), Some((environment, 1)))
            .await,
        Err(ApplicationError::StateConflict)
    ));
    sqlx::query(
        "UPDATE hook_control.environments SET generation=4,honeycomb_state='ready' WHERE id=$1",
    )
    .bind(environment)
    .execute(&database.owner)
    .await?;
    let restored_store = database.scoped_store(environment, 4).await?;
    let restored_app = production.for_test_environment(restored_store.clone(), environment, 4);
    let restored = claim_one(&restored_store).await?;
    assert_eq!(restored.id, pending.id);
    assert_eq!(restored.environment_generation, 4);
    assert_eq!(restored.request_body, pending.request_body);
    assert_eq!(restored.idempotency_key, pending.idempotency_key);
    for (id, generation) in [(event.id(), 1), (second.id(), 2)] {
        assert_eq!(
            restored_app
                .get_event(&auth, &silicon, id, Some((environment, generation)))
                .await?
                .id(),
            id
        );
    }

    // Destructive clean removes event/outbox rows, so adopting authority never
    // recreates an old event or makes a cleaned reference visible.
    let generation: i64 = sqlx::query_scalar("SELECT hook_control.clean_environment($1)")
        .bind(environment)
        .fetch_one(&database.owner)
        .await?;
    assert_eq!(generation, 5);
    let cleaned_store = database.scoped_store(environment, 5).await?;
    let cleaned_app = production.for_test_environment(cleaned_store.clone(), environment, 5);
    assert!(
        cleaned_store
            .claim_ting(10, Duration::from_secs(60))
            .await?
            .is_empty()
    );
    assert!(
        !cleaned_store
            .complete_ting(&restored, "msg_after_clean", false)
            .await?
    );
    for (id, source_generation) in [(event.id(), 1), (second.id(), 2)] {
        assert!(matches!(
            cleaned_app
                .get_event(&auth, &silicon, id, Some((environment, source_generation)))
                .await,
            Err(ApplicationError::NotFound)
        ));
    }
    Ok(())
}

#[tokio::test]
async fn migration_recovers_queued_source_generation_instead_of_current_authority() -> Result<()> {
    let database = Database::start().await?;
    let production = application(database.store.clone())?;
    let environment = Uuid::now_v7();
    insert_environment(&database, environment).await?;
    let original_store = database.scoped_store(environment, 1).await?;
    let original_app = production.for_test_environment(original_store, environment, 1);
    let hook = create_hook(&original_app, "backfill-hook-create").await?;
    let event = accept(
        &original_app,
        &hook,
        Bytes::from_static(b"legacy retained event"),
    )
    .await?;

    // Recreate the pre-0013 schema with a retained generation-one event while
    // lifecycle authority has already moved on, then apply the real migration.
    sqlx::raw_sql("ALTER TABLE hook.events DROP COLUMN source_generation")
        .execute(&database.owner)
        .await?;
    sqlx::query("UPDATE hook_control.environments SET generation=2 WHERE id=$1")
        .bind(environment)
        .execute(&database.owner)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0013_ting_retained_generation.sql"
    ))
    .execute(&database.owner)
    .await?;
    let current_store = database.scoped_store(environment, 2).await?;
    let current_app = production.for_test_environment(current_store.clone(), environment, 2);
    let auth = authorization(ORG, SILICON)?;
    let silicon = SiliconId::new(SILICON)?;
    assert_eq!(
        current_app
            .get_event(&auth, &silicon, event.id(), Some((environment, 1)))
            .await?
            .id(),
        event.id()
    );
    assert!(matches!(
        current_app
            .get_event(&auth, &silicon, event.id(), Some((environment, 2)))
            .await,
        Err(ApplicationError::NotFound)
    ));
    let adopted = claim_one(&current_store).await?;
    assert_eq!(adopted.environment_generation, 2);
    assert_eq!(reference(&adopted)?.1.environment_generation, 1);
    Ok(())
}
