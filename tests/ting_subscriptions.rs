//! Carbon receiving interest, isolated fanout, cancellation, and current authorization.

use std::{
    num::{NonZeroU32, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use axum::{
    Router,
    body::{Body, to_bytes},
};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode};
use secrecy::SecretString;
use serde_json::{Value, json};
use silicon_hook::{
    api::{ApiDependencies, router},
    application::{
        ApplicationError, CreateHookCommand, HookApplication, ManagementContext, SigningPatch,
        SystemClock,
    },
    config::{IamSettings, RealtimeSettings, ServerSettings},
    delivery::{
        publisher::Publisher,
        subscriptions::{self, SubscriptionError},
    },
    domain::{
        ActorKind, ActorRef, AuthorizationContext, EncryptionKeyId, EventRecord, Hook, HookName,
        HookTimeZone, OrganizationId, OrganizationRole, SiliconId,
        request::{CapturedRequest, CapturedRequestParts},
    },
    infrastructure::{
        crypto::{CursorCodec, SecretCipher, SecretKey, SecretKeyring},
        iam::IamClient,
        postgres::{AcceptEvent, DeliveryWakeups, PostgresStore, RuntimeDatabaseRole, migrate},
        ting::TingClient,
    },
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{ContainerAsync, ImageExt as _, core::ExecCommand, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const ORG: &str = "tos";
const SILICON: &str = "cos:tos";
const CARBON: &str = "alice";
const ACCESS: &str = "oat_carbon_fixture_token_abcdefghijklmnopqrstuvwxyz";
const RENEWED_ACCESS: &str = "oat_carbon_fixture_token_renewed_abcdefghijklmnopqrstuvwxyz";
const PUBLISHER_ACCESS: &str = "oat_observer_publisher_fixture_abcdefghijklmnopqrstuvwxyz";

struct Database {
    owner: PgPool,
    store: PostgresStore,
    api_url: String,
    _container: ContainerAsync<Postgres>,
}

impl Database {
    async fn start() -> Result<Self> {
        let container = Postgres::default()
            .with_tag("16-alpine")
            .with_copy_to(
                "/opt/grants.sql",
                std::fs::read("deploy/postgres/grant-runtime.sql")?,
            )
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
            "CREATE ROLE observer_api LOGIN PASSWORD 'fixture' NOSUPERUSER NOINHERIT;
            CREATE ROLE observer_worker LOGIN PASSWORD 'fixture' NOSUPERUSER NOINHERIT;",
        )
        .execute(&owner)
        .await?;
        let mut granted = container
            .exec(ExecCommand::new([
                "psql",
                "--username=postgres",
                "--dbname=postgres",
                "--set=api_role=observer_api",
                "--set=worker_role=observer_worker",
                "--file=/opt/grants.sql",
            ]))
            .await?;
        let _ = granted.stdout_to_vec().await?;
        let error = granted.stderr_to_vec().await?;
        if granted.exit_code().await? != Some(0) {
            bail!("grant fixture failed: {}", String::from_utf8_lossy(&error));
        }
        let api_url = format!("postgres://observer_api:fixture@{host}:{port}/postgres");
        let store = PostgresStore::new(
            PgPoolOptions::new()
                .max_connections(6)
                .connect(&api_url)
                .await?,
        );
        store.ready_for(RuntimeDatabaseRole::Api).await?;
        Ok(Self {
            owner,
            store,
            api_url,
            _container: container,
        })
    }

    async fn scoped(&self, id: Uuid, generation: i64) -> Result<PostgresStore> {
        let options = self
            .api_url
            .parse::<sqlx::postgres::PgConnectOptions>()?
            .options([
                ("hook.environment_id", id.to_string()),
                ("hook.environment_generation", generation.to_string()),
            ]);
        Ok(PostgresStore::new(
            PgPoolOptions::new()
                .max_connections(4)
                .connect_with(options)
                .await?,
        ))
    }

    async fn environment(&self, id: Uuid) -> Result<()> {
        sqlx::query(
            "INSERT INTO hook_control.environments
            (id,org_id,creator_kind,creator_id,name,key_hash,iam_key_hash,
             creation_request_hash,creation_input_hash,encrypted_credentials,honeycomb_state)
            VALUES ($1,$2,'carbon','alice','Observers',$3,$4,$5,$6,'{}'::jsonb,'ready')",
        )
        .bind(id)
        .bind(ORG)
        .bind([1_u8; 32].as_slice())
        .bind([2_u8; 32].as_slice())
        .bind([3_u8; 32].as_slice())
        .bind([4_u8; 32].as_slice())
        .execute(&self.owner)
        .await?;
        Ok(())
    }
}

fn carbon(actor: &str, visible: bool) -> Result<AuthorizationContext> {
    let visibility = if visible {
        vec![SiliconId::new(SILICON)?]
    } else {
        Vec::new()
    };
    Ok(AuthorizationContext::new(
        OrganizationId::new(ORG)?,
        ActorRef::try_new(ActorKind::Carbon, actor)?,
        OrganizationRole::Member,
        visibility,
    ))
}

fn silicon() -> Result<AuthorizationContext> {
    Ok(AuthorizationContext::new(
        OrganizationId::new(ORG)?,
        ActorRef::try_new(ActorKind::Silicon, SILICON)?,
        OrganizationRole::Member,
        [],
    ))
}

fn application(store: PostgresStore) -> Result<HookApplication> {
    let key = EncryptionKeyId::new("observer-key")?;
    Ok(HookApplication::new(
        store,
        Arc::new(SecretCipher::new(SecretKeyring::new(
            key.clone(),
            [(key, SecretKey::from_bytes([9; 32]))],
        )?)),
        Arc::new(CursorCodec::new(SecretKey::from_bytes([13; 32]))),
        Arc::new(SystemClock),
        Url::parse("https://hook.observer.test/")?,
    ))
}

async fn create(app: &HookApplication) -> Result<Hook> {
    Ok(app
        .create_hook(CreateHookCommand {
            context: ManagementContext {
                authorization: silicon()?,
                idempotency_key: "observer-fixture-hook".to_owned(),
                request_id: None,
            },
            silicon_id: SiliconId::new(SILICON)?,
            name: HookName::new("Provider")?,
            description: None,
            time_zone: HookTimeZone::new("UTC")?,
            signing: SigningPatch::default(),
        })
        .await?
        .hook)
}

async fn accept(store: &PostgresStore, hook: &Hook) -> Result<EventRecord> {
    Ok(store
        .accept_event(AcceptEvent {
            delivery_app_id: "tos>hook".to_owned(),
            event_id: Uuid::now_v7().into(),
            hook: hook.clone(),
            request: CapturedRequest::new(CapturedRequestParts {
                method: "POST".to_owned(),
                url: Url::parse("https://hook.observer.test/provider")?,
                headers: vec![(
                    "authorization".to_owned(),
                    "provider-private-token".to_owned(),
                )],
                body: Bytes::from_static(b"original private provider payload"),
                remote_ip: "203.0.113.42".parse()?,
                received_at: OffsetDateTime::now_utc(),
            })?,
        })
        .await?)
}

fn assert_delivery_policies(observer_body: &[u8], primary_body: &[u8]) -> Result<Value> {
    let observer: Value = serde_json::from_slice(observer_body)?;
    let primary: Value = serde_json::from_slice(primary_body)?;
    assert!(
        observer.get("delivery").is_none(),
        "Carbon observer remains ordinary"
    );
    assert_eq!(primary["delivery"], "required");
    Ok(observer)
}

#[tokio::test]
async fn observers_start_at_bind_and_unsubscribe_only_cancels_their_own_sends() -> Result<()> {
    let db = Database::start().await?;
    let app = application(db.store.clone())?;
    let hook = create(&app).await?;
    let target = SiliconId::new(SILICON)?;
    let actor = carbon(CARBON, true)?;
    let before = accept(&db.store, &hook).await?;
    let binding = subscriptions::subscribe(&db.store, &actor, &target).await?;
    assert_eq!(
        subscriptions::subscribe(&db.store, &actor, &target)
            .await?
            .id,
        binding.id
    );
    assert!(
        subscriptions::get(&db.store, &carbon("bob", true)?, &target)
            .await?
            .is_none()
    );
    assert!(
        db.store
            .ting_status(&OrganizationId::new(ORG)?, &target, before.id(), CARBON)
            .await?
            .is_none()
    );

    let event = accept(&db.store, &hook).await?;
    let claims = db.store.claim_ting(10, Duration::from_secs(60)).await?;
    assert_eq!(claims.len(), 3);
    let observer = claims
        .iter()
        .find(|claim| claim.recipient_id == CARBON)
        .context("observer send")?;
    let primary = claims
        .iter()
        .find(|claim| claim.event_id == event.id().as_uuid() && claim.recipient_id == SILICON)
        .context("primary send")?;
    let envelope = assert_delivery_policies(&observer.request_body, &primary.request_body)?;
    assert_eq!(envelope["for"], CARBON);
    assert_eq!(
        envelope["data"]["data"]["metadata"]["id"],
        event.id().as_uuid().to_string()
    );
    let encoded = std::str::from_utf8(&observer.request_body)?;
    assert!(!encoded.contains("provider-private-token"));
    assert!(!encoded.contains("original private provider payload"));
    assert_eq!(
        app.get_event(&actor, &target, event.id(), Some((Uuid::nil(), 0)))
            .await?
            .request()
            .body(),
        event.request().body()
    );
    assert!(matches!(
        app.get_event(
            &carbon(CARBON, false)?,
            &target,
            event.id(),
            Some((Uuid::nil(), 0))
        )
        .await,
        Err(ApplicationError::NotFound)
    ));
    assert!(matches!(
        subscriptions::get(&db.store, &carbon(CARBON, false)?, &target).await,
        Err(SubscriptionError::NotVisible)
    ));
    assert!(matches!(
        subscriptions::subscribe(&db.store, &silicon()?, &target).await,
        Err(SubscriptionError::CarbonRequired)
    ));

    subscriptions::unsubscribe(&db.store, &carbon("bob", false)?, &target).await?;
    assert!(db.store.ting_claim_is_current(observer).await?);
    subscriptions::unsubscribe(&db.store, &carbon(CARBON, false)?, &target).await?;
    subscriptions::unsubscribe(&db.store, &carbon(CARBON, false)?, &target).await?;
    assert!(!db.store.ting_claim_is_current(observer).await?);
    assert!(
        !db.store
            .complete_ting(observer, "msg_unsubscribed", false)
            .await?
    );
    assert!(db.store.ting_claim_is_current(primary).await?);
    let rebound = subscriptions::subscribe(&db.store, &actor, &target).await?;
    assert_ne!(rebound.id, binding.id);
    assert!(
        db.store
            .ting_status(&OrganizationId::new(ORG)?, &target, event.id(), CARBON)
            .await?
            .is_none()
    );
    let after = accept(&db.store, &hook).await?;
    assert!(
        db.store
            .ting_status(&OrganizationId::new(ORG)?, &target, after.id(), CARBON)
            .await?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn observer_failure_rolls_back_primary_event_and_sequence_together() -> Result<()> {
    let db = Database::start().await?;
    let app = application(db.store.clone())?;
    let hook = create(&app).await?;
    subscriptions::subscribe(&db.store, &carbon(CARBON, true)?, &SiliconId::new(SILICON)?).await?;
    sqlx::raw_sql("CREATE FUNCTION hook_private.reject_observer_fixture() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.recipient_binding_id IS NOT NULL THEN RAISE EXCEPTION 'observer write failed' USING ERRCODE='23514'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_observer_fixture BEFORE INSERT ON hook_private.ting_outbox
        FOR EACH ROW EXECUTE FUNCTION hook_private.reject_observer_fixture();")
        .execute(&db.owner).await?;
    assert!(accept(&db.store, &hook).await.is_err());
    assert_eq!(sqlx::query_as::<_,(i64,i64,i64)>("SELECT (SELECT count(*) FROM hook.events),
        (SELECT count(*) FROM hook_private.ting_outbox), (SELECT last_sequence FROM hook_private.delivery_sequences)")
        .fetch_one(&db.owner).await?, (0,0,0));
    sqlx::raw_sql(
        "DROP TRIGGER reject_observer_fixture ON hook_private.ting_outbox;
        DROP FUNCTION hook_private.reject_observer_fixture();",
    )
    .execute(&db.owner)
    .await?;
    assert_eq!(accept(&db.store, &hook).await?.delivery_sequence().get(), 1);
    assert_eq!(
        db.store
            .claim_ting(10, Duration::from_secs(60))
            .await?
            .len(),
        2
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_bindings_cannot_exceed_fanout_limit() -> Result<()> {
    let db = Database::start().await?;
    let target = SiliconId::new(SILICON)?;
    for index in 0..99 {
        subscriptions::subscribe(
            &db.store,
            &carbon(&format!("observer-{index}"), true)?,
            &target,
        )
        .await?;
    }
    let first = carbon("last-first", true)?;
    let second = carbon("last-second", true)?;
    let (first, second) = tokio::join!(
        subscriptions::subscribe(&db.store, &first, &target),
        subscriptions::subscribe(&db.store, &second, &target),
    );
    assert!(matches!(
        (&first, &second),
        (Ok(_), Err(SubscriptionError::LimitReached))
            | (Err(SubscriptionError::LimitReached), Ok(_))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook_private.ting_recipient_bindings")
            .fetch_one(&db.owner)
            .await?,
        100
    );
    assert!(
        subscriptions::subscribe(&db.store, &carbon("observer-0", true)?, &target)
            .await
            .is_ok()
    );
    Ok(())
}

#[tokio::test]
async fn bindings_are_environment_scoped_retained_by_rotation_and_erased_by_clean() -> Result<()> {
    let db = Database::start().await?;
    let production = application(db.store.clone())?;
    let actor = carbon(CARBON, true)?;
    let target = SiliconId::new(SILICON)?;
    let production_binding = subscriptions::subscribe(&db.store, &actor, &target).await?;
    let environment = Uuid::now_v7();
    db.environment(environment).await?;
    let original = db.scoped(environment, 1).await?;
    assert!(
        subscriptions::get(&original, &actor, &target)
            .await?
            .is_none()
    );
    let binding = subscriptions::subscribe(&original, &actor, &target).await?;
    let app = production.for_test_environment(original.clone(), environment, 1);
    let hook = create(&app).await?;
    accept(&original, &hook).await?;
    sqlx::query("UPDATE hook_control.environments SET generation=2 WHERE id=$1")
        .bind(environment)
        .execute(&db.owner)
        .await?;
    assert!(
        subscriptions::unsubscribe(&original, &actor, &target)
            .await
            .is_err()
    );
    let rotated = db.scoped(environment, 2).await?;
    assert_eq!(
        subscriptions::get(&rotated, &actor, &target)
            .await?
            .context("retained binding")?
            .id,
        binding.id
    );
    assert_eq!(
        rotated.claim_ting(10, Duration::from_secs(60)).await?.len(),
        2
    );
    sqlx::query("SELECT hook_control.clean_environment($1)")
        .bind(environment)
        .execute(&db.owner)
        .await?;
    let clean = db.scoped(environment, 3).await?;
    assert!(subscriptions::get(&clean, &actor, &target).await?.is_none());
    assert!(
        clean
            .claim_ting(10, Duration::from_secs(60))
            .await?
            .is_empty()
    );
    assert_eq!(
        subscriptions::get(&db.store, &actor, &target)
            .await?
            .context("production retained")?
            .id,
        production_binding.id
    );
    Ok(())
}

struct Remote {
    iam: IamClient,
    iam_server: MockServer,
    ting_server: MockServer,
    visible: Arc<AtomicBool>,
    grant_status: Arc<AtomicU16>,
    token_active: Arc<AtomicBool>,
}

impl Remote {
    async fn start() -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let iam_server = MockServer::start().await;
        let ting_server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/api/version")).respond_with(ResponseTemplate::new(200)
            .insert_header("silicon-iam-api-version", "v1")
            .insert_header("vary", "Silicon-IAM-Supported-API-Versions")
            .set_body_json(json!({"service":"silicon-iam","selected_api_version":"v1","supported_api_versions":["v1"],"build":"test","commit":"test"})))
            .mount(&iam_server).await;
        let token_active = Arc::new(AtomicBool::new(true));
        let active = Arc::clone(&token_active);
        Mock::given(method("POST")).and(path("/api/v1/oauth/introspect"))
            .respond_with(move |request: &wiremock::Request| {
                let token = url::form_urlencoded::parse(&request.body)
                    .find(|(key, _)| key == "token").map(|(_, value)| value.into_owned()).unwrap_or_default();
                if token == ACCESS && !active.load(Ordering::SeqCst) {
                    return ResponseTemplate::new(200).set_body_json(json!({"active":false}));
                }
                let (actor, kind) = if token == PUBLISHER_ACCESS { ("publisher:tos", "silicon") } else { (CARBON, "carbon") };
                let now = OffsetDateTime::now_utc().unix_timestamp();
                ResponseTemplate::new(200).set_body_json(json!({
                    "active":true,"public_id":actor,"actor_type":kind,"client_id":"tos>hook","org_id":ORG,
                    "membership_id":Uuid::now_v7(),"session_id":Uuid::now_v7(),"scope":"profile roles.read memberships.read",
                    "audience":"tos>hook","issued_at":now,"expires_at":now+1800,"authorization_epoch":1,
                    "authorization":{"actor_type":kind,"public_id":actor,"organization_id":Uuid::now_v7(),"org_id":ORG,
                        "membership_id":format!("{actor}[{ORG}]"),"membership_version":1,"authorization_epoch":1,"audience":"tos>hook",
                        "testing_environment_id":null,"scopes":["profile","roles.read","memberships.read"],"org_role":"member","tags":[]}
                }))
            }).mount(&iam_server).await;
        Mock::given(method("POST")).and(path("/api/v1/app-auth/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token":PUBLISHER_ACCESS,"refresh_token":"ort_observer_publisher_family_abcdefghijklmnopqrstuvwxyz",
                "token_type":"Bearer","expires_in":1800,"scope":"profile roles.read memberships.read","org_id":ORG,
                "actor":{"principal_id":Uuid::now_v7(),"type":"silicon","public_id":"publisher:tos"}
            }))).mount(&iam_server).await;
        let visible = Arc::new(AtomicBool::new(true));
        let visibility = Arc::clone(&visible);
        Mock::given(method("GET")).and(path("/api/v1/organizations/tos/directory/members"))
            .respond_with(move |_: &wiremock::Request| ResponseTemplate::new(200).set_body_json(json!({
                "items": if visibility.load(Ordering::SeqCst) { vec![json!({"id":SILICON,"org":{"id":ORG,"name":"Team"}})] } else { vec![] },
                "page":{"has_more":false,"next_cursor":null}
            }))).mount(&iam_server).await;
        Mock::given(method("GET")).and(path("/api/v1/obo-access/applications/tos%3Eting/endpoints"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"application":{"app_id":"tos>ting","org_id":ORG},
                "endpoints":[{"endpoint_id":"subscriptions.register","path":"/v1/subscriptions","metadata":{},"critical":true,"ttl_seconds":60},
                {"endpoint_id":"tings.send","path":"/v1/tings","metadata":{},"critical":true,"ttl_seconds":60}]})))
            .mount(&iam_server).await;
        Mock::given(method("POST")).and(path("/api/v1/obo-access/exchanges"))
            .respond_with(|_: &wiremock::Request| ResponseTemplate::new(200).set_body_json(json!({
                "access_proof":format!("proof_{}",Uuid::new_v4()),"proof_id":Uuid::new_v4(),"expires_in":30,
                "expires_at":(OffsetDateTime::now_utc()+time::Duration::seconds(30)).format(&Rfc3339).unwrap_or_default()
            }))).mount(&iam_server).await;
        let grant_status = Arc::new(AtomicU16::new(200));
        let grant = Arc::clone(&grant_status);
        Mock::given(method("POST"))
            .and(path("/v1/tings"))
            .respond_with(|request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
                let mut accepted = json!({"id":format!("msg_{}",Uuid::new_v4()),
                    "key":body["key"],"status":"accepted","silent":false,"created_at":"2026-09-22T10:00:00Z"});
                if let Some(mode) = body.get("delivery") { accepted["delivery"] = mode.clone(); }
                ResponseTemplate::new(202).set_body_json(accepted)
            }).mount(&ting_server).await;
        Mock::given(method("POST"))
            .and(path("/v1/subscriptions"))
            .respond_with(move |request: &wiremock::Request| {
                let status = grant.load(Ordering::SeqCst);
                let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
                ResponseTemplate::new(status).set_body_json(if status == 200 {
                    json!({"id":"sub_fixture","app_id":"tos>hook","for":body["for"],"active":true})
                } else {
                    json!({"error":{"code":"consent_required","message":"consent required"}})
                })
            })
            .mount(&ting_server)
            .await;
        let iam = IamClient::connect(&IamSettings {
            base_url: Url::parse(&iam_server.uri())?,
            app_id: Some("tos>hook".to_owned()),
            app_secret: Some(SecretString::from("ask_observer_fixture")),
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(2),
            max_response_bytes: 65_536,
            allow_insecure_local_http: true,
            local_auth: false,
            webhook: None,
        })
        .await?;
        Ok(Self {
            iam,
            iam_server,
            ting_server,
            visible,
            grant_status,
            token_active,
        })
    }
}

fn api(app: HookApplication, remote: &Remote) -> Result<Router> {
    let server = ServerSettings {
        bind_addr: "127.0.0.1:0".parse()?,
        public_base_url: Url::parse("https://hook.observer.test/")?,
        request_timeout: Duration::from_secs(5),
        max_ingress_body_bytes: 1024 * 1024,
        max_management_body_bytes: 65_536,
        concurrency_limit: 8,
        trusted_proxy_hops: 0,
    };
    Ok(router(
        ApiDependencies {
            application: app,
            environments: None,
            iam: remote.iam.clone(),
            ting: TingClient::new(&remote.ting_server.uri(), Duration::from_secs(2))?,
            trusted_proxy_hops: 0,
            realtime: RealtimeSettings {
                heartbeat_interval: Duration::from_secs(30),
                heartbeat_timeout: Duration::from_secs(120),
                replay_batch_size: NonZeroU32::MIN,
                poll_interval: Duration::from_secs(1),
                max_silicons_per_connection: NonZeroUsize::MIN,
            },
            wakeups: DeliveryWakeups::new(),
        },
        &server,
    ))
}

async fn call(
    api: &Router,
    verb: Method,
    body: &'static str,
) -> Result<(StatusCode, HeaderMap, Value)> {
    call_as(api, verb, body, ACCESS).await
}

async fn call_as(
    api: &Router,
    verb: Method,
    body: &'static str,
    token: &str,
) -> Result<(StatusCode, HeaderMap, Value)> {
    let response = api
        .clone()
        .oneshot(
            Request::builder()
                .method(verb)
                .uri(format!("/api/v2/silicons/{SILICON}/delivery/subscription"))
                .header("authorization", format!("Bearer {token}"))
                .header("x-org-id", ORG)
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 65_536).await?;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, headers, body))
}

#[tokio::test]
async fn api_binds_only_the_live_caller_after_ting_consent_and_rechecks_visibility() -> Result<()> {
    let db = Database::start().await?;
    let remote = Remote::start().await?;
    let api = api(application(db.store.clone())?, &remote)?;
    let (status, headers, body) = call(&api, Method::GET, "").await?;
    assert_eq!(status, StatusCode::OK);
    assert!(headers["cache-control"].to_str()?.contains("no-store"));
    assert_eq!(body, json!({"receiving":false,"subscription":null}));
    assert_eq!(
        call(&api, Method::POST, r#"{"for":"bob"}"#).await?.0,
        StatusCode::BAD_REQUEST
    );
    remote.grant_status.store(403, Ordering::SeqCst);
    assert_eq!(call(&api, Method::POST, "").await?.0, StatusCode::FORBIDDEN);
    assert!(
        !call(&api, Method::GET, "").await?.2["receiving"]
            .as_bool()
            .context("boolean receiving")?
    );
    remote.grant_status.store(200, Ordering::SeqCst);
    let (status, _, body) = call(&api, Method::POST, "").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["subscription"]["recipient_id"], CARBON);
    assert_eq!(body["subscription"]["silicon_id"], SILICON);
    let id = body["subscription"]["id"].clone();
    assert_eq!(
        call(&api, Method::POST, "").await?.2["subscription"]["id"],
        id
    );
    for request in remote
        .ting_server
        .received_requests()
        .await
        .context("Ting requests")?
    {
        let body: Value = serde_json::from_slice(&request.body)?;
        assert_eq!(body, json!({"org_id":ORG,"app_id":"tos>hook","for":CARBON}));
        assert!(
            !request
                .body
                .windows(ACCESS.len())
                .any(|window| window == ACCESS.as_bytes())
        );
    }
    assert!(
        remote
            .iam_server
            .received_requests()
            .await
            .context("IAM requests")?
            .iter()
            .any(|request| request.url.path() == "/api/v1/obo-access/exchanges")
    );
    remote.visible.store(false, Ordering::SeqCst);
    for verb in [Method::GET, Method::POST] {
        assert_eq!(call(&api, verb, "").await?.0, StatusCode::NOT_FOUND);
    }
    let (status, headers, body) = call(&api, Method::DELETE, "").await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(headers["cache-control"].to_str()?.contains("no-store"));
    assert_eq!(body, Value::Null);
    remote.visible.store(true, Ordering::SeqCst);
    assert_eq!(
        call(&api, Method::GET, "").await?.2,
        json!({"receiving":false,"subscription":null})
    );
    Ok(())
}

async fn publish_due(publisher: &Publisher) -> Result<()> {
    for _ in 0..8 {
        if !publisher.publish_one().await? {
            return Ok(());
        }
    }
    bail!("fixture publication did not drain its due claims")
}

async fn sent(remote: &Remote) -> Result<Vec<Value>> {
    remote
        .ting_server
        .received_requests()
        .await
        .context("Ting requests")?
        .into_iter()
        .filter(|request| request.url.path() == "/v1/tings")
        .map(|request| serde_json::from_slice(&request.body).map_err(Into::into))
        .collect()
}

#[tokio::test]
async fn observer_send_waits_for_renewal_then_stops_after_current_visibility_is_lost() -> Result<()>
{
    let db = Database::start().await?;
    let remote = Remote::start().await?;
    let app = application(db.store.clone())?;
    let hook = create(&app).await?;
    let target = SiliconId::new(SILICON)?;
    let api = api(app.clone(), &remote)?;
    let ting = TingClient::new(&remote.ting_server.uri(), Duration::from_secs(2))?;
    let publisher = Publisher::new(app.clone(), remote.iam.clone(), ting);
    app.publisher_credentials(remote.iam.clone())
        .provision(
            &OrganizationId::new(ORG)?,
            "slt_owned_observer_publisher_fixture",
            "observer-publisher-bootstrap-01",
        )
        .await?;

    // Legacy bindings have no retained token: their copies remain pending, while
    // the owning Silicon still receives its own event normally.
    let legacy = subscriptions::subscribe(&db.store, &carbon(CARBON, true)?, &target).await?;
    let first = accept(&db.store, &hook).await?;
    publish_due(&publisher).await?;
    assert_eq!(sent(&remote).await?.len(), 1);
    let pending = db
        .store
        .ting_status(&OrganizationId::new(ORG)?, &target, first.id(), CARBON)
        .await?
        .context("legacy copy remains pending")?;
    assert_eq!(
        pending.last_error_code.as_deref(),
        Some("observer_authority_refresh_required")
    );
    assert!(pending.accepted_at.is_none());

    let renewed = call(&api, Method::POST, "").await?;
    assert_eq!(renewed.0, StatusCode::OK);
    assert_eq!(renewed.2["subscription"]["id"], legacy.id.to_string());
    let sealed: String = sqlx::query_scalar(
        "SELECT encrypted_authority::text FROM hook_private.ting_recipient_bindings WHERE id=$1",
    )
    .bind(legacy.id)
    .fetch_one(&db.owner)
    .await?;
    assert!(!sealed.contains(ACCESS));
    assert!(!renewed.2.to_string().contains("encrypted_authority"));

    // An expired Carbon token does not become publisher authority. Renewing the
    // same interest with a fresh current token resumes its original queued copy.
    remote.token_active.store(false, Ordering::SeqCst);
    let denied_renewal = call(&api, Method::POST, "").await?;
    assert_eq!(denied_renewal.0, StatusCode::UNAUTHORIZED);
    assert_eq!(denied_renewal.2["error"]["code"], "unauthenticated");
    sqlx::query("UPDATE hook_private.ting_outbox SET next_attempt_at=clock_timestamp()")
        .execute(&db.owner)
        .await?;
    publish_due(&publisher).await?;
    assert_eq!(sent(&remote).await?.len(), 1);
    let response = call_as(&api, Method::POST, "", RENEWED_ACCESS).await?;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(response.2["subscription"]["id"], legacy.id.to_string());
    sqlx::query("UPDATE hook_private.ting_outbox SET next_attempt_at=clock_timestamp()")
        .execute(&db.owner)
        .await?;
    publish_due(&publisher).await?;
    let sends = sent(&remote).await?;
    assert_eq!(sends.len(), 2);
    assert!(sends.iter().any(|send| send["for"] == CARBON
        && send["data"]["data"]["metadata"]["id"] == first.id().to_string()));

    // Loss of current target visibility cancels observer interest before its new
    // compact event metadata reaches Ting, without cancelling the primary send.
    remote.visible.store(false, Ordering::SeqCst);
    let second = accept(&db.store, &hook).await?;
    publish_due(&publisher).await?;
    let sends = sent(&remote).await?;
    assert_eq!(sends.len(), 3);
    assert!(!sends.iter().any(|send| send["for"] == CARBON
        && send["data"]["data"]["metadata"]["id"] == second.id().to_string()));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM hook_private.ting_recipient_bindings")
            .fetch_one(&db.owner)
            .await?,
        0
    );
    assert!(
        db.store
            .ting_status(&OrganizationId::new(ORG)?, &target, second.id(), SILICON)
            .await?
            .context("primary send")?
            .accepted_at
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn stale_observer_denial_cannot_remove_renewed_authority() -> Result<()> {
    use silicon_hook::delivery::observer_authority::ObserverFailure;
    let db = Database::start().await?;
    let remote = Remote::start().await?;
    let app = application(db.store.clone())?;
    let hook = create(&app).await?;
    let target = SiliconId::new(SILICON)?;
    let authority = app.observer_authorities(remote.iam.clone());
    let auth = carbon(CARBON, true)?;
    let binding = authority
        .subscribe(&auth, &target, &SecretString::from(ACCESS))
        .await?;
    accept(&db.store, &hook).await?;
    let claim = db
        .store
        .claim_ting(10, Duration::from_secs(60))
        .await?
        .into_iter()
        .find(|claim| claim.recipient_id == CARBON)
        .context("observer claim")?;
    remote.visible.store(false, Ordering::SeqCst);
    let Err(ObserverFailure::Revoked(stale)) = authority.authorize(&claim).await else {
        bail!("target revocation was not recognized");
    };
    remote.visible.store(true, Ordering::SeqCst);
    assert_eq!(
        authority
            .subscribe(&auth, &target, &SecretString::from(RENEWED_ACCESS))
            .await?
            .id,
        binding.id
    );
    authority.revoke(&stale).await?;
    assert!(!authority.is_current(&stale).await?);
    let fresh = authority
        .authorize(&claim)
        .await
        .map_err(|_| anyhow::anyhow!("renewed authority rejected"))?;
    assert!(authority.is_current(&fresh).await?);
    assert!(db.store.ting_claim_is_current(&claim).await?);
    Ok(())
}
