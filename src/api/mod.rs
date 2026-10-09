//! HTTP API composition root: management, ingress, history, and realtime.

mod accounts;
mod auth;
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
    delivery::adapter::TingAdapter,
    domain::EncryptionKeyId,
    infrastructure::{
        accounts::AccountsGateway,
        crypto::{CursorCodec, SecretCipher, SecretKey, SecretKeyring},
        postgres::{PostgresStore, connect},
        ting::TingClient,
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
    /// Application services over PostgreSQL, Silicon Accounts and (optionally) Ting.
    pub application: HookApplication,
    /// Trusted reverse-proxy hops for client address resolution.
    pub trusted_proxy_hops: u8,
}

/// Builds the complete HTTP router.
pub fn router(dependencies: ApiDependencies, server: &ServerSettings) -> axum::Router {
    routes::router(
        ApiState {
            application: dependencies.application,
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
    for warning in &settings.obsolete_variables {
        tracing::warn!("{warning}");
    }
    let pool = connect(&settings.database, "silicon-hook-api")
        .await
        .context("failed to connect API database pool")?;
    let store = PostgresStore::new(pool.clone());
    let dependencies = build_dependencies(&settings, store.clone())?;
    let publisher = dependencies
        .application
        .delivery()
        .cloned()
        .map(|ting| crate::delivery::publisher::Publisher::new(store, ting));
    if publisher.is_some() {
        tracing::info!("delivery through Ting is enabled");
    } else {
        tracing::warn!(
            "HOOK_TING_URL is not set: delivery through Ting is disabled. Hook still receives, verifies and stores every event, and queues nothing for Ting."
        );
    }
    if !dependencies.application.accounts().webhook_configured() {
        tracing::warn!(
            "HOOK_ACCOUNTS_WEBHOOK_SECRET is not set: Silicon Accounts webhook deliveries will be refused"
        );
    }
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
    let mut publisher_task = publisher.map(|publisher| {
        tokio::spawn(crate::delivery::publisher::run(
            publisher,
            settings.ting.poll_interval,
            shutdown_receiver.clone(),
        ))
    });
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
    if let Some(task) = &mut publisher_task {
        stop_task(settings.shutdown.timeout, task).await;
    }
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

fn build_dependencies(
    settings: &ApiSettings,
    store: PostgresStore,
) -> anyhow::Result<ApiDependencies> {
    let cipher = Arc::new(build_secret_cipher(&settings.crypto)?);
    let accounts = AccountsGateway::new(&settings.accounts)
        .map_err(|error| anyhow::anyhow!("failed to configure Silicon Accounts: {error}"))?;
    let mut application = HookApplication::new(
        store,
        cipher,
        Arc::new(CursorCodec::new(SecretKey::from_base64url(
            settings.crypto.cursor_signing_key.expose_secret(),
        )?)),
        Arc::new(SystemClock),
        settings.server.public_base_url.clone(),
        accounts.clone(),
    );
    if let Some(origin) = &settings.ting.base_url {
        let client = TingClient::new(origin.as_str(), settings.ting.request_timeout)
            .map_err(|error| anyhow::anyhow!("failed to configure Ting delivery: {error}"))?;
        application = application.with_delivery(TingAdapter::new(client, accounts));
    }
    Ok(ApiDependencies {
        application,
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
