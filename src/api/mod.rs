//! HTTP API composition root: management, ingress, history, and realtime.

mod contracts;
mod delivery;
mod dto;
mod extractors;
mod handlers;
mod middleware;
mod routes;
mod scope;
mod state;
mod subscriptions;
mod telemetry_events;
mod version;

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
        postgres::{PostgresStore, connect},
    },
    shutdown,
};

pub use dto::{CapturedRequestResponse, EventResponse};
pub use version::{API_VERSION_HEADER, SUPPORTED_API_VERSIONS, SUPPORTED_API_VERSIONS_HEADER};

use crate::config::ServerSettings;

/// Everything the HTTP router needs, so embedders and end-to-end tests can
/// build it without a running process.
#[derive(Clone, Debug)]
pub struct ApiDependencies {
    /// Application services over PostgreSQL.
    pub application: HookApplication,
    /// Online IAM adapter.
    pub iam: IamClient,
    /// Internal Ting HTTP boundary; never accepts a caller-selected origin.
    pub ting: crate::infrastructure::ting::TingClient,
    /// Trusted reverse-proxy hops for client address resolution.
    pub trusted_proxy_hops: u8,
}

/// Builds the complete HTTP router.
pub fn router(mut dependencies: ApiDependencies, server: &ServerSettings) -> axum::Router {
    dependencies.iam = dependencies.application.ting_iam(dependencies.iam);
    routes::router(
        ApiState {
            application: dependencies.application,
            iam: dependencies.iam,
            ting: dependencies.ting,
            trusted_proxy_hops: dependencies.trusted_proxy_hops,
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
    let dependencies = build_dependencies(&settings, store).await?;
    let publisher = crate::delivery::publisher::Publisher::new(
        dependencies.application.clone(),
        dependencies.iam.clone(),
        dependencies.ting.clone(),
    );
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
    let mut publisher_task = tokio::spawn(crate::delivery::publisher::run(
        publisher,
        settings.ting.poll_interval,
        shutdown_receiver.clone(),
    ));
    let mut server_task = spawn_server(listener, app, shutdown_receiver);

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
    stop_task(settings.shutdown.timeout, &mut publisher_task).await;
    pool.close().await;
    result
}

fn spawn_server(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<std::io::Result<()>> {
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            while !*shutdown.borrow_and_update() {
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
    })
}

async fn stop_task<T>(timeout: std::time::Duration, task: &mut tokio::task::JoinHandle<T>) {
    if tokio::time::timeout(timeout, &mut *task).await.is_err() {
        task.abort();
        let _ = task.await;
    }
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

async fn build_dependencies(
    settings: &ApiSettings,
    store: PostgresStore,
) -> anyhow::Result<ApiDependencies> {
    let cipher = Arc::new(build_secret_cipher(&settings.crypto)?);
    let iam = IamClient::connect(&settings.iam)
        .await
        .context("failed to connect to Silicon IAM")?
        .with_ting_grants(store.clone(), cipher.clone());
    Ok(ApiDependencies {
        application: HookApplication::new(
            store,
            cipher,
            Arc::new(CursorCodec::new(SecretKey::from_base64url(
                settings.crypto.cursor_signing_key.expose_secret(),
            )?)),
            Arc::new(SystemClock),
            settings.server.public_base_url.clone(),
        )
        .with_delivery_application(iam.application_id().unwrap_or("hook")),
        ting: crate::infrastructure::ting::TingClient::new(
            settings.ting.base_url.as_str(),
            settings.ting.request_timeout,
        )?,
        iam,
        trusted_proxy_hops: settings.server.trusted_proxy_hops,
    })
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
