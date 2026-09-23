//! Application and PostgreSQL invariants for Hook's Ting delivery boundary.

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
        request::MAX_BODY_BYTES,
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

#[tokio::test]
async fn signature_rejection_never_queues_and_outbox_failure_rolls_back_acceptance() -> Result<()> {
    let database = Database::start().await?;
    let app = application(database.store.clone())?;
    let hook = create_hook(&app, "atomic-create-0001").await?;
    let body = Bytes::from_static(b"verified provider payload");
    let secret = hook.signing_secret.as_ref().context("generated secret")?;
    let wrong_signature = signed_headers(secret, b"different content")?;
    let rejected = app
        .receive_request(request(&hook, wrong_signature, body.clone())?)
        .await?;
    assert!(matches!(rejected, ReceiveOutcome::Blocked(_)));
    assert_eq!(
        sqlx::query_as::<_, (i64, i64, i64)>(
            "SELECT (SELECT count(*) FROM hook.events),
                    (SELECT count(*) FROM hook_private.ting_outbox),
                    (SELECT count(*) FROM hook.blocked_requests)",
        )
        .fetch_one(&database.owner)
        .await?,
        (0, 0, 1)
    );

    // A storage failure after the event INSERT must roll back the complete
    // acceptance, including its sequence and hook activity timestamp.
    sqlx::raw_sql(
        "CREATE FUNCTION hook_private.reject_test_ting() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'injected outbox failure' USING ERRCODE='23514'; END $$;
         CREATE TRIGGER reject_test_ting BEFORE INSERT ON hook_private.ting_outbox
             FOR EACH ROW EXECUTE FUNCTION hook_private.reject_test_ting();",
    )
    .execute(&database.owner)
    .await?;
    assert!(accept(&app, &hook, body.clone()).await.is_err());
    assert_eq!(
        sqlx::query_as::<_, (i64, i64, i64)>(
            "SELECT (SELECT count(*) FROM hook.events),
                    (SELECT count(*) FROM hook_private.ting_outbox),
                    (SELECT count(*) FROM hook_private.delivery_sequences)",
        )
        .fetch_one(&database.owner)
        .await?,
        (0, 0, 0)
    );
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT last_received_at IS NULL FROM hook.hooks WHERE id=$1"
        )
        .bind(hook.hook.id().as_uuid())
        .fetch_one(&database.owner)
        .await?
    );
    sqlx::raw_sql(
        "DROP TRIGGER reject_test_ting ON hook_private.ting_outbox;
         DROP FUNCTION hook_private.reject_test_ting();",
    )
    .execute(&database.owner)
    .await?;
    let event = accept(&app, &hook, body).await?;
    assert_eq!(event.delivery_sequence().get(), 1);
    let claim = claim_one(&database.store).await?;
    let (envelope, reference) = reference(&claim)?;
    assert_eq!(reference.id, event.id());
    assert_eq!(envelope["for"], SILICON);
    assert_eq!(envelope["type"], "hook.webhook.received");
    assert_eq!(claim.event_id, event.id().as_uuid());
    Ok(())
}

#[tokio::test]
async fn maximum_provider_payload_uses_compact_ting_and_current_authorized_hydration() -> Result<()>
{
    let database = Database::start().await?;
    let app = application(database.store.clone())?;
    let hook = create_hook(&app, "large-create-0001").await?;
    let marker = b"provider-private-payload-must-stay-in-hook";
    let mut bytes = vec![b'x'; MAX_BODY_BYTES];
    bytes[..marker.len()].copy_from_slice(marker);
    let body = Bytes::from(bytes);
    let secret = hook.signing_secret.as_ref().context("generated secret")?;
    let mut headers = signed_headers(secret, &body)?;
    headers.push((
        "authorization".to_owned(),
        "Bearer provider-only-secret".to_owned(),
    ));
    let outcome = app
        .receive_request(request(&hook, headers, body.clone())?)
        .await?;
    let ReceiveOutcome::Accepted(event) = outcome else {
        bail!("maximum-size signed body was rejected");
    };
    let claim = claim_one(&database.store).await?;
    assert!(
        claim.request_body.len() < 4_096,
        "notification must stay compact"
    );
    let text = std::str::from_utf8(&claim.request_body)?;
    assert!(!text.contains(std::str::from_utf8(marker)?));
    assert!(!text.contains("provider-only-secret"));
    assert!(!text.contains("webhook-signature"));
    let (envelope, pointer) = reference(&claim)?;
    assert_eq!(envelope["data"]["type"], "new_event");
    assert_eq!(pointer.id, event.id());
    assert_eq!(pointer.environment_id, Uuid::nil());
    assert_eq!(pointer.environment_generation, 0);
    let silicon = SiliconId::new(SILICON)?;
    let expected = Some((pointer.environment_id, pointer.environment_generation));
    let hydrated = app
        .get_event(
            &authorization(ORG, SILICON)?,
            &silicon,
            pointer.id,
            expected,
        )
        .await?;
    assert_eq!(hydrated.request().body(), &body);
    assert_eq!(hydrated.request().body().len(), MAX_BODY_BYTES);
    assert!(matches!(
        app.get_event(
            &authorization("org:foreign", SILICON)?,
            &silicon,
            pointer.id,
            expected
        )
        .await,
        Err(ApplicationError::NotFound)
    ));
    assert!(matches!(
        app.get_event(
            &authorization(ORG, "silicon:foreign")?,
            &silicon,
            pointer.id,
            expected
        )
        .await,
        Err(ApplicationError::NotFound)
    ));
    assert!(matches!(
        app.get_event(
            &authorization(ORG, SILICON)?,
            &silicon,
            pointer.id,
            Some((Uuid::new_v4(), 1))
        )
        .await,
        Err(ApplicationError::NotFound)
    ));
    let visible_carbon = AuthorizationContext::new(
        OrganizationId::new(ORG)?,
        ActorRef::try_new(ActorKind::Carbon, "carbon:observer")?,
        OrganizationRole::Member,
        [silicon.clone()],
    );
    assert_eq!(
        app.get_event(&visible_carbon, &silicon, pointer.id, expected)
            .await?
            .request()
            .body(),
        &body
    );
    let carbon_without_visibility = AuthorizationContext::new(
        OrganizationId::new(ORG)?,
        ActorRef::try_new(ActorKind::Carbon, "carbon:observer")?,
        OrganizationRole::Member,
        std::iter::empty::<SiliconId>(),
    );
    assert!(matches!(
        app.get_event(&carbon_without_visibility, &silicon, pointer.id, expected)
            .await,
        Err(ApplicationError::NotFound)
    ));
    Ok(())
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
    reason = "one clean must invalidate old claims and preserve production"
)]
async fn clean_fences_old_claims_and_references_without_touching_production() -> Result<()> {
    let database = Database::start().await?;
    let production = application(database.store.clone())?;
    let production_hook = create_hook(&production, "production-create-0001").await?;
    let production_event = accept(
        &production,
        &production_hook,
        Bytes::from_static(b"production"),
    )
    .await?;
    let environment = Uuid::now_v7();
    insert_environment(&database, environment).await?;
    let old_store = database.scoped_store(environment, 1).await?;
    let old_app = production.for_test_environment(old_store.clone(), environment, 1);
    let old_hook = create_hook(&old_app, "test-create-0001").await?;
    let old_event = accept(&old_app, &old_hook, Bytes::from_static(b"before clean")).await?;
    let old_claim = claim_one(&old_store).await?;
    let (_, old_pointer) = reference(&old_claim)?;
    assert_eq!(old_pointer.environment_id, environment);
    assert_eq!(old_pointer.environment_generation, 1);
    assert_eq!(old_claim.environment_generation, 1);
    let current_generation: i64 = sqlx::query_scalar("SELECT hook_control.clean_environment($1)")
        .bind(environment)
        .fetch_one(&database.owner)
        .await?;
    assert_eq!(current_generation, 2);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM hook_private.ting_outbox WHERE environment_id=$1"
        )
        .bind(environment)
        .fetch_one(&database.owner)
        .await?,
        0
    );
    assert!(!old_store.ting_claim_is_current(&old_claim).await?);
    assert!(
        old_store
            .claim_ting(1, Duration::from_secs(60))
            .await
            .is_err()
    );
    assert!(
        old_store
            .complete_ting(&old_claim, "msg_stale", false)
            .await
            .is_err()
    );
    let auth = authorization(ORG, SILICON)?;
    let silicon = SiliconId::new(SILICON)?;
    assert!(matches!(
        old_app
            .get_event(&auth, &silicon, old_event.id(), Some((environment, 1)))
            .await,
        Err(ApplicationError::StateConflict)
    ));

    let current_store = database
        .scoped_store(environment, current_generation)
        .await?;
    let current_app =
        production.for_test_environment(current_store.clone(), environment, current_generation);
    assert!(matches!(
        current_app
            .get_event(&auth, &silicon, old_pointer.id, Some((environment, 1)))
            .await,
        Err(ApplicationError::NotFound)
    ));
    assert!(
        !current_store
            .complete_ting(&old_claim, "msg_stale", false)
            .await?
    );
    let new_hook = create_hook(&current_app, "test-create-0001").await?;
    let new_event = accept(&current_app, &new_hook, Bytes::from_static(b"after clean")).await?;
    assert_eq!(new_event.delivery_sequence().get(), 1);
    assert_ne!(new_event.id(), old_event.id());
    let new_claim = claim_one(&current_store).await?;
    let (_, new_pointer) = reference(&new_claim)?;
    assert_eq!(new_pointer.environment_generation, 2);
    assert_eq!(new_claim.environment_generation, 2);
    assert_ne!(new_claim.idempotency_key, old_claim.idempotency_key);
    assert_eq!(
        current_app
            .get_event(&auth, &silicon, new_pointer.id, Some((environment, 2)))
            .await?
            .request()
            .body()
            .as_ref(),
        b"after clean"
    );
    assert_eq!(
        production
            .get_event(
                &auth,
                &silicon,
                production_event.id(),
                Some((Uuid::nil(), 0))
            )
            .await?
            .request()
            .body()
            .as_ref(),
        b"production"
    );
    let production_claim = claim_one(&database.store).await?;
    assert_eq!(production_claim.environment_id, Uuid::nil());
    assert_eq!(production_claim.event_id, production_event.id().as_uuid());
    Ok(())
}
