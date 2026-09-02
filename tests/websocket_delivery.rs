//! End-to-end WebSocket delivery: replay, live events, acknowledgments, and
//! the heartbeat timeout, exercised over a real listener and PostgreSQL 16.

use std::{
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::{SinkExt as _, StreamExt as _};
use hmac::{Hmac, Mac as _};
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::Sha256;
use silicon_hook::{
    api::{ApiDependencies, HEARTBEAT_CLOSE_CODE, router},
    application::{HookApplication, SystemClock},
    config::{DatabaseSettings, IamSettings, LocalAuthSettings, RealtimeSettings, ServerSettings},
    domain::EncryptionKeyId,
    infrastructure::{
        crypto::{CursorCodec, SecretCipher, SecretKey, SecretKeyring},
        iam::IamClient,
        postgres::{
            DeliveryWakeups, PostgresStore, connect_options, migrate, spawn_delivery_listener,
        },
    },
};
use sqlx::postgres::PgPoolOptions;
use testcontainers::{ContainerAsync, ImageExt as _, runners::AsyncRunner as _};
use testcontainers_modules::postgres::Postgres;
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};
use url::Url;

const SILICON_ID: &str = "cos:tos";
const ORG_ID: &str = "tos";
const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

struct Harness {
    base_url: String,
    client: reqwest::Client,
    _container: ContainerAsync<Postgres>,
    _shutdown: tokio::sync::watch::Sender<bool>,
}

impl Harness {
    async fn start(realtime: RealtimeSettings) -> Result<Self> {
        let container = Postgres::default()
            .with_tag("16-alpine")
            .start()
            .await
            .context("start PostgreSQL 16 test container")?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(5432).await?;
        let database_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await?;
        migrate(&pool).await?;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;
        let base_url = format!("http://{local_addr}");
        let public_base_url = Url::parse(&format!("{base_url}/"))?;

        let key_id = EncryptionKeyId::new("1")?;
        let cipher = SecretCipher::new(SecretKeyring::new(
            key_id.clone(),
            [(key_id, SecretKey::from_bytes([7_u8; 32]))],
        )?);
        let application = HookApplication::new(
            PostgresStore::new(pool),
            Arc::new(cipher),
            Arc::new(CursorCodec::new(SecretKey::from_bytes([8_u8; 32]))),
            Arc::new(SystemClock),
            public_base_url.clone(),
        );
        let iam = IamClient::new(&IamSettings {
            base_url: Url::parse("http://127.0.0.1:9")?,
            app_id: None,
            app_secret: None,
            audience: "silicon-hook".to_owned(),
            connect_timeout: Duration::from_millis(50),
            request_timeout: Duration::from_millis(50),
            max_response_bytes: 1_024,
            local_auth: Some(LocalAuthSettings {
                iam_service_token: SecretString::from("local-service-token".to_owned()),
            }),
        })?;
        let wakeups = DeliveryWakeups::new();
        let (shutdown, shutdown_receiver) = tokio::sync::watch::channel(false);
        let database_settings = DatabaseSettings {
            url: SecretString::from(database_url),
            max_connections: NonZeroU32::MIN,
            min_connections: 0,
            acquire_timeout: Duration::from_secs(3),
            statement_timeout: Duration::from_secs(10),
        };
        tokio::spawn(spawn_delivery_listener(
            connect_options(&database_settings, "websocket-test-listener")?,
            wakeups.clone(),
            shutdown_receiver,
        ));
        let server = ServerSettings {
            bind_addr: local_addr,
            public_base_url,
            request_timeout: Duration::from_secs(5),
            max_ingress_body_bytes: 1024 * 1024,
            max_management_body_bytes: 64 * 1024,
            concurrency_limit: 64,
            trusted_proxy_hops: 0,
        };
        let app = router(
            ApiDependencies {
                application,
                iam,
                allow_local_credentials: true,
                trusted_proxy_hops: 0,
                realtime,
                wakeups,
            },
            &server,
        );
        tokio::spawn(async move {
            let _served = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });

        Ok(Self {
            base_url,
            client: reqwest::Client::new(),
            _container: container,
            _shutdown: shutdown,
        })
    }

    async fn create_hook(&self) -> Result<Value> {
        let response = self
            .client
            .post(format!(
                "{}/api/v1/silicons/{SILICON_ID}/hooks",
                self.base_url
            ))
            .header(
                "authorization",
                format!("Bearer local:silicon:member:{SILICON_ID}"),
            )
            .header("x-org-id", ORG_ID)
            .header("idempotency-key", "websocket-create-0001")
            .json(&json!({"name": "GitHub"}))
            .send()
            .await?;
        let status = response.status();
        let body: Value = response.json().await?;
        if status != reqwest::StatusCode::CREATED {
            bail!("hook creation failed with {status}: {body}");
        }
        Ok(body)
    }

    async fn send_webhook(&self, hook: &Value, message_id: &str, body: &str) -> Result<Value> {
        let secret = hook["signing_secret"]
            .as_str()
            .context("creation returns a signing secret")?;
        let endpoint_url = hook["endpoint_url"]
            .as_str()
            .context("creation returns the endpoint url")?;
        let timestamp = "1700000000";
        let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(secret.as_bytes())
            .context("HMAC accepts any key length")?;
        mac.update(format!("{message_id}.{timestamp}.{body}").as_bytes());
        let signature = STANDARD.encode(mac.finalize().into_bytes());
        let response = self
            .client
            .post(endpoint_url)
            .header("content-type", "application/json")
            .header("webhook-id", message_id)
            .header("webhook-timestamp", timestamp)
            .header("webhook-signature", format!("v1,{signature}"))
            .body(body.to_owned())
            .send()
            .await?;
        let status = response.status();
        let receipt: Value = response.json().await?;
        if status != reqwest::StatusCode::OK {
            bail!("webhook delivery failed with {status}: {receipt}");
        }
        assert_eq!(receipt["status"], "webhook.ok");
        Ok(receipt)
    }

    async fn connect(&self) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
        let url = format!(
            "{}/api/v1/ws?silicon_id={SILICON_ID}",
            self.base_url.replacen("http://", "ws://", 1)
        );
        let mut request =
            tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url)?;
        request.headers_mut().insert(
            "authorization",
            format!("Bearer local:silicon:member:{SILICON_ID}").parse()?,
        );
        request.headers_mut().insert("x-org-id", ORG_ID.parse()?);
        let (socket, _response) = tokio_tungstenite::connect_async(request).await?;
        Ok(socket)
    }
}

async fn next_frame(socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>) -> Result<Message> {
    tokio::time::timeout(FRAME_TIMEOUT, socket.next())
        .await
        .context("timed out waiting for a frame")?
        .context("socket closed")?
        .map_err(Into::into)
}

async fn next_json(socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>) -> Result<Value> {
    loop {
        match next_frame(socket).await? {
            Message::Text(text) => return Ok(serde_json::from_str(text.as_str())?),
            Message::Ping(_) | Message::Pong(_) => {}
            other => bail!("unexpected frame {other:?}"),
        }
    }
}

/// Reads frames until one with the wanted `type`, answering pings on the way.
async fn expect_type(
    socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    wanted: &str,
) -> Result<Value> {
    for _ in 0..32 {
        let frame = next_json(socket).await?;
        if frame["type"] == "ping" {
            socket
                .send(Message::Text(
                    json!({"type": "pong", "ping_id": frame["ping_id"]})
                        .to_string()
                        .into(),
                ))
                .await?;
            continue;
        }
        if frame["type"] == wanted {
            return Ok(frame);
        }
        bail!("expected a {wanted} frame, received {frame}");
    }
    bail!("gave up waiting for a {wanted} frame")
}

fn realtime(heartbeat_interval: Duration, heartbeat_timeout: Duration) -> Result<RealtimeSettings> {
    Ok(RealtimeSettings {
        heartbeat_interval,
        heartbeat_timeout,
        replay_batch_size: NonZeroU32::new(100).context("non-zero")?,
        poll_interval: Duration::from_millis(250),
        max_silicons_per_connection: NonZeroUsize::new(4).context("non-zero")?,
    })
}

#[tokio::test]
async fn events_are_delivered_live_acknowledged_and_replayed_on_reconnect() -> Result<()> {
    let harness =
        Harness::start(realtime(Duration::from_secs(30), Duration::from_secs(120))?).await?;
    let hook = harness.create_hook().await?;

    let mut socket = harness.connect().await?;
    let ready = expect_type(&mut socket, "ready").await?;
    assert_eq!(ready["protocol_version"], 1);
    assert_eq!(ready["silicon_ids"], json!([SILICON_ID]));
    assert_eq!(ready["acknowledged_through"][SILICON_ID], 0);
    assert_eq!(ready["heartbeat_interval_seconds"], 30);
    assert_eq!(ready["heartbeat_timeout_seconds"], 120);

    harness
        .send_webhook(&hook, "msg_1", r#"{"action":"opened"}"#)
        .await?;
    let event = expect_type(&mut socket, "event").await?;
    assert_eq!(event["silicon_id"], SILICON_ID);
    assert_eq!(event["delivery_sequence"], 1);
    assert_eq!(event["event"]["provider"], "GitHub");
    assert_eq!(event["event"]["request"]["body"], r#"{"action":"opened"}"#);
    assert_eq!(event["event"]["request"]["method"], "POST");
    let summary = event["event"]["summary"]
        .as_str()
        .context("events carry a summary line")?;
    assert!(summary.starts_with("GitHub triggered at "));
    assert!(summary.ends_with(" UTC"));

    socket
        .send(Message::Text(
            json!({"type": "ack", "silicon_id": SILICON_ID, "through_sequence": 1})
                .to_string()
                .into(),
        ))
        .await?;
    let acknowledged = expect_type(&mut socket, "ack_recorded").await?;
    assert_eq!(acknowledged["acknowledged_through"], 1);

    harness
        .send_webhook(&hook, "msg_2", r#"{"action":"closed"}"#)
        .await?;
    let second = expect_type(&mut socket, "event").await?;
    assert_eq!(second["delivery_sequence"], 2);
    socket.close(None).await?;

    let mut reconnected = harness.connect().await?;
    let ready = expect_type(&mut reconnected, "ready").await?;
    assert_eq!(ready["acknowledged_through"][SILICON_ID], 1);
    let replayed = expect_type(&mut reconnected, "event").await?;
    assert_eq!(
        replayed["delivery_sequence"], 2,
        "the unacknowledged event is attached to the next connection"
    );

    let pulled: Value = harness
        .client
        .get(format!(
            "{}/api/v1/silicons/{SILICON_ID}/deliveries",
            harness.base_url
        ))
        .header(
            "authorization",
            format!("Bearer local:silicon:member:{SILICON_ID}"),
        )
        .header("x-org-id", ORG_ID)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(pulled["cursor"]["acknowledged_through"], 1);
    assert_eq!(pulled["latest_sequence"], 2);
    assert_eq!(pulled["items"].as_array().map(Vec::len), Some(1));
    Ok(())
}

#[tokio::test]
async fn missing_pongs_close_the_connection_with_heartbeat_timeout() -> Result<()> {
    let harness = Harness::start(realtime(
        Duration::from_millis(500),
        Duration::from_secs(2),
    )?)
    .await?;
    harness.create_hook().await?;
    let mut socket = harness.connect().await?;
    expect_type(&mut socket, "ready").await?;

    let first_ping = next_json(&mut socket).await?;
    assert_eq!(first_ping["type"], "ping");
    assert!(first_ping["ping_id"].is_string());

    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        let frame = tokio::time::timeout_at(deadline, socket.next())
            .await
            .context("heartbeat timeout never closed the socket")?;
        match frame {
            Some(Ok(Message::Close(Some(close)))) => {
                assert_eq!(u16::from(close.code), HEARTBEAT_CLOSE_CODE);
                assert_eq!(close.reason, "heartbeat-timeout");
                return Ok(());
            }
            Some(Ok(Message::Text(_) | Message::Ping(_))) => {}
            None | Some(Err(_) | Ok(_)) => bail!("socket ended without a heartbeat close"),
        }
    }
}
