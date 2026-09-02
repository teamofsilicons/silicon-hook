//! HTTP API composition root: management, ingress, history, and realtime.

mod dto;
mod extractors;
mod handlers;
mod middleware;
mod routes;
mod state;
mod ws;

use std::{net::SocketAddr, sync::Arc};

use anyhow::Context as _;
use secrecy::ExposeSecret as _;

use self::state::ApiState;
use crate::{
    application::{HookApplication, SystemClock},
    config::{ApiSettings, CryptoSettings},
    domain::EncryptionKeyId,
    infrastructure::{
        crypto::{CursorCodec, SecretCipher, SecretKey, SecretKeyring},
        iam::IamClient,
        postgres::{
            DeliveryWakeups, PostgresStore, connect, connect_options, spawn_delivery_listener,
        },
    },
    shutdown,
};

pub use dto::{CapturedRequestResponse, EventResponse};
pub use ws::{
    ClientFrame, HEARTBEAT_CLOSE_CODE, HEARTBEAT_CLOSE_REASON, PROTOCOL_VERSION, ServerFrame,
};

use crate::config::{RealtimeSettings, ServerSettings};

/// Everything the HTTP router needs, so embedders and end-to-end tests can
/// build it without a running process.
#[derive(Clone, Debug)]
pub struct ApiDependencies {
    /// Application services over PostgreSQL.
    pub application: HookApplication,
    /// Online IAM adapter.
    pub iam: IamClient,
    /// Whether deterministic `local:` credentials are accepted.
    pub allow_local_credentials: bool,
    /// Trusted reverse-proxy hops for client address resolution.
    pub trusted_proxy_hops: u8,
    /// WebSocket delivery policy.
    pub realtime: RealtimeSettings,
    /// Local fan-out of delivery notifications.
    pub wakeups: DeliveryWakeups,
}

/// Builds the complete HTTP router.
pub fn router(dependencies: ApiDependencies, server: &ServerSettings) -> axum::Router {
    routes::router(
        ApiState {
            application: dependencies.application,
            iam: dependencies.iam,
            allow_local_credentials: dependencies.allow_local_credentials,
            trusted_proxy_hops: dependencies.trusted_proxy_hops,
            realtime: dependencies.realtime,
            wakeups: dependencies.wakeups,
        },
        server,
    )
}

/// Connects dependencies and serves HTTP until graceful shutdown.
///
/// # Errors
///
/// Returns an error when a required dependency or listener cannot start.
pub async fn serve(settings: ApiSettings) -> anyhow::Result<()> {
    let pool = connect(&settings.database, "silicon-hook-api")
        .await
        .context("failed to connect API database pool")?;
    let store = PostgresStore::new(pool.clone());
    let wakeups = DeliveryWakeups::new();
    let dependencies = ApiDependencies {
        application: HookApplication::new(
            store,
            Arc::new(build_secret_cipher(&settings.crypto)?),
            Arc::new(CursorCodec::new(SecretKey::from_base64url(
                settings.crypto.cursor_signing_key.expose_secret(),
            )?)),
            Arc::new(SystemClock),
            settings.server.public_base_url.clone(),
        ),
        iam: IamClient::new(&settings.iam).context("failed to construct IAM client")?,
        allow_local_credentials: settings.iam.local_auth_enabled(),
        trusted_proxy_hops: settings.server.trusted_proxy_hops,
        realtime: settings.realtime,
        wakeups: wakeups.clone(),
    };
    let app = router(dependencies, &settings.server);
    let listener = tokio::net::TcpListener::bind(settings.server.bind_addr)
        .await
        .with_context(|| {
            format!(
                "failed to bind HTTP listener at {}",
                settings.server.bind_addr
            )
        })?;
    let local_addr = listener
        .local_addr()
        .context("failed to read HTTP listener address")?;
    tracing::info!(%local_addr, "Silicon Hook API listening");

    let (shutdown_sender, shutdown_receiver) = tokio::sync::watch::channel(false);
    let listener_options = connect_options(&settings.database, "silicon-hook-listener")?;
    let mut notification_task = tokio::spawn(spawn_delivery_listener(
        listener_options,
        wakeups,
        shutdown_receiver.clone(),
    ));
    let mut server_shutdown = shutdown_receiver;
    let mut server_task = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            while !*server_shutdown.borrow_and_update() {
                if server_shutdown.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
    });

    let result = tokio::select! {
        result = &mut server_task => flatten_server_result(result, "HTTP server failed"),
        () = shutdown::signal() => {
            let _receiver_was_alive = shutdown_sender.send(true).is_ok();
            if let Ok(result) =
                tokio::time::timeout(settings.shutdown.timeout, &mut server_task).await
            {
                flatten_server_result(
                    result,
                    "HTTP server failed during graceful shutdown",
                )
            } else {
                server_task.abort();
                let _aborted = server_task.await;
                Err(anyhow::anyhow!(
                    "graceful shutdown exceeded {:?}",
                    settings.shutdown.timeout
                ))
            }
        }
    };

    let _stopped = shutdown_sender.send(true);
    if tokio::time::timeout(settings.shutdown.timeout, &mut notification_task)
        .await
        .is_err()
    {
        notification_task.abort();
    }
    pool.close().await;
    result
}

fn flatten_server_result(
    result: Result<std::io::Result<()>, tokio::task::JoinError>,
    context: &'static str,
) -> anyhow::Result<()> {
    match result {
        Ok(result) => result.context(context),
        Err(error) => Err(anyhow::Error::new(error).context(context)),
    }
}

fn build_secret_cipher(settings: &CryptoSettings) -> anyhow::Result<SecretCipher> {
    let current_key_id =
        EncryptionKeyId::new(settings.current_encryption_version.get().to_string())?;
    let entries = settings
        .encryption_keys
        .iter()
        .map(|(version, encoded)| {
            Ok((
                EncryptionKeyId::new(version.get().to_string())?,
                SecretKey::from_base64url(encoded.expose_secret())?,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let keyring = SecretKeyring::new(current_key_id, entries)?;
    Ok(SecretCipher::new(keyring))
}
