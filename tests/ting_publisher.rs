//! Provider HTTP ingress through durable publication, with only IAM/Ting mocked.

use std::{
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac as _};
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use silicon_hook::{
    api::{ApiDependencies, router},
    application::{
        CreateHookCommand, HookApplication, HookWithSecret, ManagementContext, SigningPatch,
        SystemClock,
    },
    config::{IamSettings, RealtimeSettings, ServerSettings},
    delivery::publisher::Publisher,
    domain::{
        ActorKind, ActorRef, AuthorizationContext, EncryptionKeyId, EventId, HookName,
        HookTimeZone, OrganizationId, OrganizationRole, SiliconId,
    },
    infrastructure::{
        crypto::{CursorCodec, SecretCipher, SecretKey, SecretKeyring},
        iam::IamClient,
        postgres::{DeliveryWakeups, PostgresStore, TingOutboxStatus, migrate},
        ting::{TingClient, TingDeliveryMode},
    },
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use uuid::Uuid;
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path},
};

const ORG: &str = "tos";
const SILICON: &str = "si:cos";
const PUBLISHER: &str = "si:publisher";
const ACCESS_V1: &str = "oat_publisher_fixture_access_token_aaaaaaaaaaaa";
const ACCESS_V2: &str = "oat_publisher_fixture_access_token_bbbbbbbbbbbb";
const REFRESH_V1: &str = "ort_publisher_fixture_refresh_token_aaaaaaaaaaaa";
const REFRESH_V2: &str = "ort_publisher_fixture_refresh_token_bbbbbbbbbbbb";
const READER_ACCESS: &str = "oat_reader_fixture_access_token_aaaaaaaaaaaa";
const PAYLOAD: &str = r#"{"private_provider_payload":"kept exclusively in Hook"}"#;

struct Harness {
    application: HookApplication,
    iam: IamClient,
    ting: TingClient,
    issuer: MockServer,
    receiver: MockServer,
    pool: PgPool,
    server: tokio::task::JoinHandle<()>,
    _container: ContainerAsync<Postgres>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Harness {
    async fn start(reject_first_subject: bool) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let container = Postgres::default().with_tag("16-alpine").start().await?;
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&format!(
                "postgres://postgres:postgres@{}:{}/postgres",
                container.get_host().await?,
                container.get_host_port_ipv4(5432).await?,
            ))
            .await?;
        migrate(&pool).await?;
        let (issuer, iam) = iam_fixture(reject_first_subject).await?;
        let receiver = MockServer::start().await;
        let ting = TingClient::new(&receiver.uri(), Duration::from_secs(2))?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let public_base_url = Url::parse(&format!("http://{address}/"))?;
        let key_id = EncryptionKeyId::new("publisher-test-key")?;
        let application = HookApplication::new(
            PostgresStore::new(pool.clone()),
            Arc::new(SecretCipher::new(SecretKeyring::new(
                key_id.clone(),
                [(key_id, SecretKey::from_bytes([17; 32]))],
            )?)),
            Arc::new(CursorCodec::new(SecretKey::from_bytes([29; 32]))),
            Arc::new(SystemClock),
            public_base_url.clone(),
        );
        let routes = router(
            ApiDependencies {
                application: application.clone(),
                environments: None,
                iam: iam.clone(),
                ting: ting.clone(),
                trusted_proxy_hops: 0,
                wakeups: DeliveryWakeups::new(),
                realtime: RealtimeSettings {
                    heartbeat_interval: Duration::from_secs(30),
                    heartbeat_timeout: Duration::from_secs(120),
                    replay_batch_size: NonZeroU32::new(100).context("nonzero batch")?,
                    poll_interval: Duration::from_millis(250),
                    max_silicons_per_connection: NonZeroUsize::new(4)
                        .context("nonzero capacity")?,
                },
            },
            &ServerSettings {
                bind_addr: address,
                public_base_url,
                request_timeout: Duration::from_secs(5),
                max_ingress_body_bytes: 1024 * 1024,
                max_management_body_bytes: 64 * 1024,
                concurrency_limit: 64,
                trusted_proxy_hops: 0,
            },
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                routes.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        Ok(Self {
            application,
            iam,
            ting,
            issuer,
            receiver,
            pool,
            server,
            _container: container,
        })
    }

    fn publisher(&self) -> Publisher {
        Publisher::new(
            self.application.clone(),
            self.iam.clone(),
            self.ting.clone(),
        )
    }

    async fn provision(&self) -> Result<()> {
        self.application
            .publisher_credentials(self.iam.clone())
            .provision(
                &OrganizationId::new(ORG)?,
                "slt_dedicated_publisher_fixture",
                "publisher-provision-0001",
            )
            .await?;
        Ok(())
    }

    async fn create_hook(&self) -> Result<HookWithSecret> {
        Ok(self
            .application
            .create_hook(CreateHookCommand {
                context: ManagementContext {
                    authorization: AuthorizationContext::new(
                        OrganizationId::new(ORG)?,
                        ActorRef::try_new(ActorKind::Silicon, SILICON)?,
                        OrganizationRole::Member,
                        std::iter::empty::<SiliconId>(),
                    ),
                    idempotency_key: "publisher-create-0001".to_owned(),
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

    async fn receive(&self, hook: &HookWithSecret, message_id: &str) -> Result<EventId> {
        let secret = hook
            .signing_secret
            .as_ref()
            .context("generated signing secret")?;
        let timestamp = "1700000000";
        let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(secret.as_str().as_bytes())?;
        mac.update(format!("{message_id}.{timestamp}.{PAYLOAD}").as_bytes());
        let url = self
            .application
            .endpoint_url(&SiliconId::new(SILICON)?, hook.hook.endpoint_key())?;
        let response = reqwest::Client::new()
            .post(url)
            .header("content-type", "application/json")
            .header("webhook-id", message_id)
            .header("webhook-timestamp", timestamp)
            .header(
                "webhook-signature",
                format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes())),
            )
            .body(PAYLOAD)
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let receipt: Value = response.json().await?;
        assert_eq!(receipt["status"], "webhook.ok");
        Ok(serde_json::from_value(receipt["receipt_id"].clone())?)
    }

    async fn status(&self, event: EventId) -> Result<TingOutboxStatus> {
        self.application
            .store()
            .ting_status(
                &OrganizationId::new(ORG)?,
                &SiliconId::new(SILICON)?,
                event,
                SILICON,
            )
            .await?
            .context("durable event publication")
    }

    async fn body(&self, event: EventId) -> Result<Vec<u8>> {
        Ok(sqlx::query_scalar(
            "SELECT request_body FROM hook_private.ting_outbox WHERE event_id=$1",
        )
        .bind(event.as_uuid())
        .fetch_one(&self.pool)
        .await?)
    }

    async fn make_due(&self, event: EventId) -> Result<()> {
        // Advance only this isolated fixture's retry schedule, without sleeping.
        sqlx::query("UPDATE hook_private.ting_outbox SET next_attempt_at=clock_timestamp() WHERE event_id=$1")
            .bind(event.as_uuid()).execute(&self.pool).await?;
        Ok(())
    }
}

fn token_response(refreshed: bool) -> Value {
    json!({
        "access_token": if refreshed { ACCESS_V2 } else { ACCESS_V1 },
        "refresh_token": if refreshed { REFRESH_V2 } else { REFRESH_V1 },
        "token_type":"Bearer", "expires_in":1800, "scope":"profile roles.read memberships.read",
        "org_id":ORG,
        "actor":{"principal_id":Uuid::now_v7(), "type":"silicon", "public_id":PUBLISHER}
    })
}

fn introspection() -> Value {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    json!({
        "active":true, "public_id":PUBLISHER, "actor_type":"silicon", "client_id":"hook",
        "org_id":ORG, "membership_id":Uuid::now_v7(), "session_id":Uuid::now_v7(),
        "scope":"profile roles.read memberships.read", "audience":"hook",
        "issued_at":now, "expires_at":now+1800, "authorization_epoch":1,
        "authorization":{
            "actor_type":"silicon", "public_id":PUBLISHER, "organization_id":Uuid::now_v7(),
            "org_id":ORG, "membership_id":"si:publisher[tos]", "membership_version":1,
            "authorization_epoch":1, "audience":"hook", "testing_environment_id":null,
            "scopes":["profile", "roles.read", "memberships.read"], "org_role":"member", "tags":[]
        }
    })
}

async fn iam_fixture(reject_first_subject: bool) -> Result<(MockServer, IamClient)> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/version"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("silicon-iam-api-version", "v1")
                .insert_header("vary", "Silicon-IAM-Supported-API-Versions")
                .set_body_json(json!({"service":"silicon-iam", "selected_api_version":"v1",
                "supported_api_versions":["v1"], "build":"test", "commit":"test"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/app-auth/tokens"))
        .respond_with(|request: &Request| {
            let refreshed = url::form_urlencoded::parse(&request.body)
                .any(|(key, value)| key == "refresh_token" && value == REFRESH_V1);
            ResponseTemplate::new(200).set_body_json(token_response(refreshed))
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/oauth/introspect"))
        .respond_with(|request: &Request| {
            let reader = url::form_urlencoded::parse(&request.body)
                .any(|(key, value)| key == "token" && value == READER_ACCESS);
            let mut snapshot = introspection();
            if reader {
                snapshot["public_id"] = json!(SILICON);
                snapshot["authorization"]["public_id"] = json!(SILICON);
                snapshot["authorization"]["membership_id"] = json!(format!("{SILICON}[{ORG}]"));
            }
            ResponseTemplate::new(200).set_body_json(snapshot)
        })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/obo-access/applications/ting/endpoints"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "application":{"app_id":"ting", "org_id":ORG},
            "endpoints":[{"endpoint_id":"tings.send", "path":"/v1/tings", "metadata":{},
                "critical":true, "ttl_seconds":60},
                {"endpoint_id":"sent.query","path":"/v1/sent/query","metadata":{},"critical":true,"ttl_seconds":60}]
        })))
        .mount(&server)
        .await;
    let attempts = AtomicUsize::new(0);
    Mock::given(method("POST"))
        .and(path("/api/v1/obo-access/exchanges"))
        .respond_with(move |_: &Request| {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 && reject_first_subject {
                return ResponseTemplate::new(401).set_body_json(json!({"error":{
                    "code":"invalid_subject_token", "message":"Subject is no longer active",
                    "request_id":Uuid::now_v7()
                }}));
            }
            let expiry = OffsetDateTime::now_utc() + time::Duration::seconds(30);
            ResponseTemplate::new(200).set_body_json(json!({
                "access_proof":format!("proof_{}", Uuid::new_v4()), "proof_id":Uuid::new_v4(),
                "expires_in":30, "expires_at":expiry.format(&Rfc3339).unwrap_or_default()
            }))
        })
        .mount(&server)
        .await;
    let iam = IamClient::connect(&IamSettings {
        base_url: Url::parse(&server.uri())?,
        app_id: Some("hook".to_owned()),
        app_secret: Some(SecretString::from("ask_fixture_signing_secret")),
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        max_response_bytes: 65_536,
        allow_insecure_local_http: true,
        local_auth: false,
        webhook: None,
    })
    .await?;
    Ok((server, iam))
}

fn acceptance(request: &Request, silent: bool) -> Value {
    let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
    let mut accepted = json!({"id":"msg_publisher_fixture", "key":body["key"], "status":"accepted", "silent":silent,
        "created_at":"2026-09-22T10:00:00Z"});
    if let Some(mode) = body.get("delivery") {
        accepted["delivery"] = mode.clone();
    }
    accepted
}

async fn requests(server: &MockServer, route: &str) -> Result<Vec<Request>> {
    Ok(server
        .received_requests()
        .await
        .context("recorded HTTP requests")?
        .into_iter()
        .filter(|request| request.url.path() == route)
        .collect())
}

fn assert_proof_binding(exchange: &Request, body: &[u8]) -> Result<()> {
    let value: Value = serde_json::from_slice(&exchange.body)?;
    assert_eq!(
        value["request"]["body_sha256"],
        hex::encode(Sha256::digest(body))
    );
    assert_eq!(value["request"]["method"], "POST");
    assert_eq!(value["audience"], "ting");
    assert_eq!(value["endpoint_id"], "tings.send");
    assert_eq!(value["org_id"], ORG);
    Ok(())
}

#[tokio::test]
async fn missing_publisher_stays_pending_then_records_normal_and_silent_acceptance() -> Result<()> {
    let harness = Harness::start(false).await?;
    let hook = harness.create_hook().await?;
    let event = harness.receive(&hook, "provider-normal").await?;
    assert!(harness.publisher().publish_one().await?);
    let pending = harness.status(event).await?;
    assert_eq!(
        pending.last_error_code.as_deref(),
        Some("publisher_not_configured")
    );
    assert!(pending.accepted_at.is_none());
    assert!(pending.lease_until.is_none());
    assert!(requests(&harness.receiver, "/v1/tings").await?.is_empty());
    assert!(
        !harness.publisher().publish_one().await?,
        "retry honors its due time"
    );

    harness.provision().await?;
    let sends = AtomicUsize::new(0);
    Mock::given(method("POST"))
        .and(path("/v1/tings"))
        .respond_with(move |request: &Request| {
            ResponseTemplate::new(202).set_body_json(acceptance(
                request,
                sends.fetch_add(1, Ordering::SeqCst) > 0,
            ))
        })
        .expect(2)
        .mount(&harness.receiver)
        .await;
    harness.make_due(event).await?;
    assert!(harness.publisher().publish_one().await?);
    let normal = harness.status(event).await?;
    assert!(normal.accepted_at.is_some());
    assert_eq!(normal.silent, Some(false));
    assert_eq!(normal.delivery, TingDeliveryMode::Required);
    assert_eq!(normal.attempts, 2);
    assert!(normal.last_error_code.is_none());
    let silent_event = harness.receive(&hook, "provider-muted").await?;
    assert!(harness.publisher().publish_one().await?);
    let silent = harness.status(silent_event).await?;
    assert!(silent.accepted_at.is_some());
    assert_eq!(silent.silent, Some(true));
    assert_eq!(silent.delivery, TingDeliveryMode::Required);
    assert!(!harness.publisher().publish_one().await?);

    let sent = requests(&harness.receiver, "/v1/tings").await?;
    let proofs = requests(&harness.issuer, "/api/v1/obo-access/exchanges").await?;
    assert_eq!(sent.len(), 2);
    assert_eq!(proofs.len(), 2);
    assert_ne!(
        sent[0].headers.get("authorization"),
        sent[1].headers.get("authorization")
    );
    for (send, proof) in sent.iter().zip(&proofs) {
        assert_proof_binding(proof, &send.body)?;
        assert!(!String::from_utf8_lossy(&send.body).contains("private_provider_payload"));
        let envelope: Value = serde_json::from_slice(&send.body)?;
        assert_eq!(envelope["for"], SILICON);
        assert_eq!(envelope["type"], "hook.webhook.received");
        assert_eq!(envelope["delivery"], "required");
    }
    Ok(())
}

#[tokio::test]
async fn uncertain_acceptance_replays_persisted_bytes_with_a_fresh_proof_after_restart()
-> Result<()> {
    let harness = Harness::start(false).await?;
    harness.provision().await?;
    let hook = harness.create_hook().await?;
    let event = harness.receive(&hook, "provider-uncertain").await?;
    let prepared = harness.body(event).await?;
    let accepted_body = Mutex::new(None::<Vec<u8>>);
    Mock::given(method("POST"))
        .and(path("/v1/tings"))
        .respond_with(move |request: &Request| {
            let Ok(mut accepted) = accepted_body.lock() else {
                return ResponseTemplate::new(500);
            };
            match accepted.as_ref() {
                None => {
                    // The remote service saved it, but its response is unusable.
                    *accepted = Some(request.body.clone());
                    ResponseTemplate::new(202).set_body_string("{truncated acceptance")
                }
                Some(body) if body == &request.body => {
                    ResponseTemplate::new(200).set_body_json(acceptance(request, false))
                }
                Some(_) => ResponseTemplate::new(409),
            }
        })
        .expect(2)
        .mount(&harness.receiver)
        .await;
    assert!(harness.publisher().publish_one().await?);
    let pending = harness.status(event).await?;
    assert_eq!(pending.last_error_code.as_deref(), Some("invalid_response"));
    assert!(pending.accepted_at.is_none());
    assert!(pending.lease_until.is_none());
    harness.make_due(event).await?;
    // A new publisher instance must rely on the committed outbox/session state.
    assert!(harness.publisher().publish_one().await?);
    let completed = harness.status(event).await?;
    assert!(completed.accepted_at.is_some());
    assert_eq!(completed.ting_id.as_deref(), Some("msg_publisher_fixture"));
    assert_eq!(completed.attempts, 2);
    assert!(completed.last_error_code.is_none());
    assert!(!harness.publisher().publish_one().await?);
    let sent = requests(&harness.receiver, "/v1/tings").await?;
    let proofs = requests(&harness.issuer, "/api/v1/obo-access/exchanges").await?;
    assert_eq!(sent.len(), 2);
    assert_eq!(proofs.len(), 2);
    for (send, proof) in sent.iter().zip(&proofs) {
        assert_eq!(send.body, prepared);
        assert_proof_binding(proof, &prepared)?;
    }
    assert_ne!(
        sent[0].headers.get("authorization"),
        sent[1].headers.get("authorization")
    );
    assert_ne!(
        proofs[0].headers.get("idempotency-key"),
        proofs[1].headers.get("idempotency-key")
    );
    assert_eq!(
        requests(&harness.issuer, "/api/v1/app-auth/tokens")
            .await?
            .len(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn required_send_waits_for_recipient_opt_in_then_accepts_muted_without_downgrading()
-> Result<()> {
    let harness = Harness::start(false).await?;
    harness.provision().await?;
    let hook = harness.create_hook().await?;
    let event = harness.receive(&hook, "required-before-consent").await?;
    let prepared = harness.body(event).await?;
    let parsed: Value = serde_json::from_slice(&prepared)?;
    assert_eq!(parsed["delivery"], "required");
    let calls = AtomicUsize::new(0);
    Mock::given(method("POST"))
        .and(path("/v1/tings"))
        .respond_with(move |request: &Request| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(403)
                    .set_body_json(json!({"error":{"code":"required_delivery_not_enabled"}}))
            } else {
                ResponseTemplate::new(202).set_body_json(acceptance(request, true))
            }
        })
        .expect(2)
        .mount(&harness.receiver)
        .await;
    assert!(harness.publisher().publish_one().await?);
    let pending = harness.status(event).await?;
    assert_eq!(pending.delivery, TingDeliveryMode::Required);
    assert_eq!(
        pending.last_error_code.as_deref(),
        Some("required_delivery_not_enabled")
    );
    assert!(pending.accepted_at.is_none());
    assert!(pending.silent.is_none());
    assert!(pending.lease_until.is_none());
    assert!(
        !harness.publisher().publish_one().await?,
        "consent failure must respect its retry delay"
    );

    // Model the recipient explicitly consenting; only advance this fixture's retry clock.
    harness.make_due(event).await?;
    assert!(harness.publisher().publish_one().await?);
    let accepted = harness.status(event).await?;
    assert!(accepted.accepted_at.is_some());
    assert_eq!(accepted.delivery, TingDeliveryMode::Required);
    assert_eq!(accepted.silent, Some(true));
    assert!(accepted.last_error_code.is_none());
    for request in requests(&harness.receiver, "/v1/tings").await? {
        assert_eq!(request.body, prepared);
    }
    assert_eq!(harness.body(event).await?, prepared);
    assert!(
        requests(&harness.receiver, "/v1/subscriptions")
            .await?
            .is_empty(),
        "publisher cannot enable or manufacture recipient consent"
    );
    Mock::given(method("POST"))
        .and(path("/v1/sent/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id":"msg_publisher_fixture","type":"hook.webhook.received","for":SILICON,
            "silent":true,"read":false,"delivery":"required","deliveries":[]
        })))
        .mount(&harness.receiver)
        .await;
    let url = harness
        .application
        .endpoint_url(&SiliconId::new(SILICON)?, hook.hook.endpoint_key())?
        .join(&format!(
            "/api/v2/silicons/{SILICON}/events/{event}/publication"
        ))?;
    let status: Value = reqwest::Client::new()
        .get(url)
        .bearer_auth(READER_ACCESS)
        .header("x-org-id", ORG)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(status["state"], "accepted_by_ting");
    assert_eq!(status["delivery"], "required");
    assert_eq!(status["silent"], true);
    assert_eq!(status["recipient_receipt"]["delivery"], "required");
    assert_eq!(status["recipient_receipt"]["silent"], true);
    assert_eq!(status["recipient_receipt"]["read"], false);
    Ok(())
}

#[tokio::test]
async fn legacy_ordinary_body_survives_uncertain_acceptance_and_new_publisher_restart() -> Result<()>
{
    let harness = Harness::start(false).await?;
    harness.provision().await?;
    let hook = harness.create_hook().await?;
    let event = harness.receive(&hook, "legacy-ordinary").await?;
    // Seed a pre-upgrade outbox record, before any publisher sees it. Production
    // code must never perform this rewrite or reinterpret it as a required send.
    let mut legacy: Value = serde_json::from_slice(&harness.body(event).await?)?;
    legacy
        .as_object_mut()
        .context("body object")?
        .remove("delivery");
    let bytes = serde_json::to_vec(&legacy)?;
    sqlx::query("UPDATE hook_private.ting_outbox SET request_body=$2 WHERE event_id=$1")
        .bind(event.as_uuid())
        .bind(&bytes)
        .execute(&harness.pool)
        .await?;
    assert_eq!(
        harness.status(event).await?.delivery,
        TingDeliveryMode::Ordinary
    );
    let calls = AtomicUsize::new(0);
    Mock::given(method("POST"))
        .and(path("/v1/tings"))
        .respond_with(move |request: &Request| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(202).set_body_string("{lost ordinary acceptance")
            } else {
                ResponseTemplate::new(200).set_body_json(acceptance(request, true))
            }
        })
        .expect(2)
        .mount(&harness.receiver)
        .await;
    assert!(harness.publisher().publish_one().await?);
    assert_eq!(
        harness.status(event).await?.last_error_code.as_deref(),
        Some("invalid_response")
    );
    harness.make_due(event).await?;
    assert!(harness.publisher().publish_one().await?);
    let status = harness.status(event).await?;
    assert_eq!(status.delivery, TingDeliveryMode::Ordinary);
    assert_eq!(status.silent, Some(true));
    assert!(status.accepted_at.is_some());
    assert_eq!(harness.body(event).await?, bytes);
    let sends = requests(&harness.receiver, "/v1/tings").await?;
    let proofs = requests(&harness.issuer, "/api/v1/obo-access/exchanges").await?;
    assert_eq!(sends.len(), 2);
    assert_eq!(proofs.len(), 2);
    for (send, proof) in sends.iter().zip(&proofs) {
        assert_eq!(send.body, bytes);
        assert_proof_binding(proof, &bytes)?;
    }
    let url = harness
        .application
        .endpoint_url(&SiliconId::new(SILICON)?, hook.hook.endpoint_key())?
        .join(&format!(
            "/api/v2/silicons/{SILICON}/events/{event}/publication"
        ))?;
    let response: Value = reqwest::Client::new()
        .get(url)
        .bearer_auth(READER_ACCESS)
        .header("x-org-id", ORG)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(response["state"], "accepted_silently");
    assert_eq!(response["delivery"], "ordinary");
    assert_eq!(response["silent"], true);
    Ok(())
}

#[tokio::test]
async fn rejected_subject_refreshes_owned_family_before_retrying_the_same_send() -> Result<()> {
    let harness = Harness::start(true).await?;
    harness.provision().await?;
    let hook = harness.create_hook().await?;
    let event = harness.receive(&hook, "provider-revoked-access").await?;
    let prepared = harness.body(event).await?;
    Mock::given(method("POST"))
        .and(path("/v1/tings"))
        .respond_with(|request: &Request| {
            ResponseTemplate::new(202).set_body_json(acceptance(request, false))
        })
        .expect(1)
        .mount(&harness.receiver)
        .await;
    assert!(harness.publisher().publish_one().await?);
    let pending = harness.status(event).await?;
    assert_eq!(
        pending.last_error_code.as_deref(),
        Some("publisher_unauthorized")
    );
    assert!(pending.accepted_at.is_none());
    assert!(requests(&harness.receiver, "/v1/tings").await?.is_empty());
    let expired: bool = sqlx::query_scalar(
        "SELECT expires_at <= clock_timestamp() FROM hook_private.ting_publisher_credentials WHERE org_id=$1",
    ).bind(ORG).fetch_one(&harness.pool).await?;
    assert!(
        expired,
        "early IAM rejection invalidates the exact cached access token"
    );
    harness.make_due(event).await?;
    assert!(harness.publisher().publish_one().await?);
    assert!(harness.status(event).await?.accepted_at.is_some());
    let exchanges = requests(&harness.issuer, "/api/v1/obo-access/exchanges").await?;
    assert_eq!(exchanges.len(), 2);
    let first: Value = serde_json::from_slice(&exchanges[0].body)?;
    let second: Value = serde_json::from_slice(&exchanges[1].body)?;
    assert_eq!(first["subject_token"], ACCESS_V1);
    assert_eq!(second["subject_token"], ACCESS_V2);
    for exchange in &exchanges {
        assert_proof_binding(exchange, &prepared)?;
    }
    let token_calls = requests(&harness.issuer, "/api/v1/app-auth/tokens").await?;
    assert_eq!(token_calls.len(), 2);
    let refresh: std::collections::HashMap<_, _> =
        url::form_urlencoded::parse(&token_calls[1].body).collect();
    assert_eq!(
        refresh.get("refresh_token").map(AsRef::as_ref),
        Some(REFRESH_V1)
    );
    assert!(!refresh.contains_key("slt"));
    assert_ne!(
        token_calls[0].headers.get("idempotency-key"),
        token_calls[1].headers.get("idempotency-key")
    );
    assert_eq!(
        requests(&harness.issuer, "/api/v1/oauth/introspect")
            .await?
            .len(),
        2
    );
    let sent = requests(&harness.receiver, "/v1/tings").await?;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].body, prepared);
    Ok(())
}

#[tokio::test]
async fn receipt_lookup_refreshes_an_early_rejected_publisher_without_a_pending_send() -> Result<()>
{
    let harness = Harness::start(true).await?;
    harness.provision().await?;
    let hook = harness.create_hook().await?;
    let event = harness.receive(&hook, "receipt-only-recovery").await?;
    // Model a previously accepted publication; no pending sender can perform
    // credential recovery on behalf of this subsequent status request.
    let claim = harness
        .application
        .store()
        .claim_ting(1, Duration::from_secs(60))
        .await?
        .pop()
        .context("prior publication")?;
    assert!(
        harness
            .application
            .store()
            .complete_ting(&claim, "msg_prior", false)
            .await?
    );
    Mock::given(method("POST")).and(path("/v1/sent/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id":"msg_prior","type":"hook.webhook.received","for":SILICON,"silent":false,"read":false,"delivery":"required",
            "deliveries":[{"webhook_id":"destination_fixture","delivery_acked":true,"read_acked":false}],
            "deliveries_next_cursor":null
        }))).expect(1).mount(&harness.receiver).await;
    let url = harness
        .application
        .endpoint_url(&SiliconId::new(SILICON)?, hook.hook.endpoint_key())?
        .join(&format!(
            "/api/v2/silicons/{SILICON}/events/{event}/publication"
        ))?;
    let response = reqwest::Client::new()
        .get(url)
        .bearer_auth(READER_ACCESS)
        .header("x-org-id", ORG)
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: Value = response.json().await?;
    assert_eq!(body["state"], "accepted_by_ting");
    assert_eq!(body["delivery"], "required");
    assert_eq!(body["silent"], false);
    assert_eq!(body["recipient_receipt"]["delivery"], "required");
    assert_eq!(body["recipient_status_error"], Value::Null);
    assert_eq!(
        body["recipient_receipt"]["deliveries"][0]["delivery_acked"],
        true
    );
    let exchanges = requests(&harness.issuer, "/api/v1/obo-access/exchanges").await?;
    assert_eq!(exchanges.len(), 2);
    let first: Value = serde_json::from_slice(&exchanges[0].body)?;
    let second: Value = serde_json::from_slice(&exchanges[1].body)?;
    assert_eq!(first["subject_token"], ACCESS_V1);
    assert_eq!(second["subject_token"], ACCESS_V2);
    assert_eq!(first["endpoint_id"], "sent.query");
    assert_eq!(second["endpoint_id"], "sent.query");
    assert_eq!(
        requests(&harness.issuer, "/api/v1/app-auth/tokens")
            .await?
            .len(),
        2
    );
    assert!(requests(&harness.receiver, "/v1/tings").await?.is_empty());
    Ok(())
}
