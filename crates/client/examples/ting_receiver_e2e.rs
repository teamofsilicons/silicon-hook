//! Controlled integration-test host for the stateless Hook SDK.
//!
//! Run with one private configuration-file path. The host, rather than the SDK,
//! owns the HTTP listener, durable event acceptance, deduplication, and HTTP204.
//! This is a fixture driver, not a general-purpose application server.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use silicon_hook_client::{
    Client, Secret,
    delivery::{DeliveryContext, DeliveryOutcome, ReceivedEvent, Receiver, UnavailableEvent},
};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    hook_url: String,
    hook_token: String,
    app_id: String,
    org_id: String,
    recipient_id: String,
    environment_id: Uuid,
    webhook_id: String,
    callback_secret: String,
    listen_addr: SocketAddr,
    output: PathBuf,
    ack_gate: Option<PathBuf>,
}

struct Host {
    client: Client,
    receiver: Receiver,
    output: PathBuf,
    ack_gate: Option<PathBuf>,
    acceptance: Mutex<()>,
}

#[derive(Default, Deserialize, Serialize)]
struct Evidence {
    requests: u64,
    new_events: u64,
    #[serde(default)]
    unavailable: u64,
    duplicates: u64,
    last_status: u16,
    event_ids: Vec<Uuid>,
    ting_ids: Vec<String>,
    callback_sha256: String,
    callback_bytes: usize,
}

fn private_json(path: &Path, value: &impl Serialize) -> Result<(), ()> {
    let parent = path.parent().ok_or(())?;
    let temporary = parent.join(format!(".{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|_| ())?;
    let bytes = serde_json::to_vec(value).map_err(|_| ())?;
    file.write_all(&bytes).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    fs::rename(&temporary, path).map_err(|_| ())?;
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ())?;
    Ok(())
}

fn accept(output: &Path, received: &ReceivedEvent) -> Result<bool, ()> {
    let path = output
        .join("accepted")
        .join(format!("{}.json", received.event.id));
    let incoming = serde_json::to_value(received).map_err(|_| ())?;
    if path.exists() {
        let saved: Value =
            serde_json::from_slice(&fs::read(path).map_err(|_| ())?).map_err(|_| ())?;
        // Another delivery ID can refer to the same provider event. Dedupe the
        // durable application work by event ID, verifying the original payload.
        if saved["event"] != incoming["event"] {
            return Err(());
        }
        return Ok(false);
    }
    private_json(&path, &incoming)?;
    Ok(true)
}

fn record_unavailable(output: &Path, received: &UnavailableEvent) -> Result<bool, ()> {
    let incoming = serde_json::to_value(received).map_err(|_| ())?;
    let accepted = output
        .join("accepted")
        .join(format!("{}.json", received.reference.id));
    if accepted.exists() {
        let saved: Value =
            serde_json::from_slice(&fs::read(accepted).map_err(|_| ())?).map_err(|_| ())?;
        // The payload can expire after an earlier durable acceptance whose
        // HTTP204 was lost. That retry is still already accepted work.
        if saved["key"] != incoming["key"]
            || [
                "id",
                "org_id",
                "silicon_id",
                "hook_id",
                "delivery_sequence",
                "received_at",
                "summary",
            ]
            .iter()
            .any(|&field| saved["event"][field] != incoming["reference"][field])
        {
            return Err(());
        }
        return Ok(false);
    }
    let path = output
        .join("unavailable")
        .join(format!("{}.json", received.reference.id));
    if path.exists() {
        let saved: Value =
            serde_json::from_slice(&fs::read(path).map_err(|_| ())?).map_err(|_| ())?;
        if saved["reference"] != incoming["reference"] {
            return Err(());
        }
        return Ok(false);
    }
    // Persist a terminal delivery result separately from accepted application
    // work. The upstream payload is unavailable, so no work is manufactured.
    private_json(&path, &incoming)?;
    Ok(true)
}

fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

async fn callback(State(host): State<Arc<Host>>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let Some(authorization) = one_header(&headers, "authorization") else {
        return StatusCode::UNAUTHORIZED;
    };
    let Some(webhook) = one_header(&headers, "ting-webhook-id") else {
        return StatusCode::UNAUTHORIZED;
    };
    let records = match host.receiver.decode(authorization, webhook, &body) {
        Ok(records) => records,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let events = match host.receiver.resolve(&host.client, &records).await {
        Ok(events) => events,
        Err(_) => {
            let _ = private_json(&host.output.join("error.json"), &json!({"stage":"resolve"}));
            return StatusCode::SERVICE_UNAVAILABLE;
        }
    };
    // The fixture uses a single writer and atomic, fsynced files. A real host
    // can use its durable job store with a unique event-ID key instead.
    let _guard = host.acceptance.lock().await;
    let evidence_path = host.output.join("evidence.json");
    let mut evidence: Evidence = match fs::read(&evidence_path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(saved) => saved,
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE,
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Evidence::default(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE,
    };
    for event in &events {
        match event {
            DeliveryOutcome::Event(event) => match accept(&host.output, event) {
                Ok(true) => evidence.new_events += 1,
                Ok(false) => evidence.duplicates += 1,
                Err(()) => return StatusCode::SERVICE_UNAVAILABLE,
            },
            DeliveryOutcome::Unavailable(event) => match record_unavailable(&host.output, event) {
                Ok(true) => evidence.unavailable += 1,
                Ok(false) => evidence.duplicates += 1,
                Err(()) => return StatusCode::SERVICE_UNAVAILABLE,
            },
        }
    }
    let status = if host.ack_gate.as_ref().is_some_and(|path| !path.is_file()) {
        // Deliberately model a lost/failed HTTP acknowledgment after durable
        // acceptance. The retry must find the existing event without redoing it.
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::NO_CONTENT
    };
    evidence.requests += 1;
    evidence.last_status = status.as_u16();
    evidence.event_ids = events
        .iter()
        .map(|event| match event {
            DeliveryOutcome::Event(event) => event.event.id,
            DeliveryOutcome::Unavailable(event) => event.reference.id,
        })
        .collect();
    evidence.ting_ids = events
        .iter()
        .map(|event| match event {
            DeliveryOutcome::Event(event) => event.ting_id.clone(),
            DeliveryOutcome::Unavailable(event) => event.ting_id.clone(),
        })
        .collect();
    evidence.callback_sha256 = hex::encode(Sha256::digest(&body));
    evidence.callback_bytes = body.len();
    if private_json(&evidence_path, &evidence).is_err() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    status
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        // Neither configuration nor HTTP errors are printed: both can contain
        // fixture tokens or provider data.
        eprintln!("Hook SDK receiving fixture failed; inspect its private evidence.");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), ()> {
    let config_path = std::env::args_os().nth(1).ok_or(())?;
    let config: Config =
        serde_json::from_slice(&fs::read(config_path).map_err(|_| ())?).map_err(|_| ())?;
    fs::create_dir_all(config.output.join("accepted")).map_err(|_| ())?;
    fs::create_dir_all(config.output.join("unavailable")).map_err(|_| ())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for path in [
            &config.output,
            &config.output.join("accepted"),
            &config.output.join("unavailable"),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| ())?;
        }
    }
    let client = Client::new(&config.hook_url)
        .map_err(|_| ())?
        .with_telemetry(false)
        .with_token(config.hook_token)
        .with_organization(&config.org_id);
    let receiver = Receiver::new(
        DeliveryContext {
            app_id: config.app_id,
            org_id: config.org_id,
            recipient_id: config.recipient_id,
            environment_id: config.environment_id,
        },
        &config.webhook_id,
        Secret::new(config.callback_secret),
    )
    .map_err(|_| ())?;
    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .map_err(|_| ())?;
    private_json(
        &config.output.join("ready.json"),
        &json!({"pid": std::process::id(), "address":listener.local_addr().map_err(|_| ())?}),
    )?;
    let host = Arc::new(Host {
        client,
        receiver,
        output: config.output,
        ack_gate: config.ack_gate,
        acceptance: Mutex::new(()),
    });
    let router = Router::new()
        .route("/ting", post(callback))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(host);
    axum::serve(listener, router).await.map_err(|_| ())
}
