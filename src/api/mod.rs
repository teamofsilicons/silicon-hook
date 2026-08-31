//! HTTP API composition root and route handlers.

mod dto;
mod extractors;
mod handlers;
mod middleware;
mod routes;
mod state;

use std::sync::Arc;

use anyhow::Context as _;
use secrecy::ExposeSecret as _;

use self::state::ApiState;
use crate::{
    application::{HookApplication, SystemClock},
    config::{ApiSettings, CryptoSettings},
    domain::EncryptionKeyId,
    infrastructure::{
        crypto::{CursorCodec, SecretCipher, SecretKey, SecretKeyring, WebhookSignatureVerifier},
        iam::IamClient,
        postgres::{PostgresStore, connect},
    },
    shutdown,
};

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
    let state = ApiState {
        application: HookApplication::new(
            store,
            Arc::new(build_secret_cipher(&settings.crypto)?),
            Arc::new(CursorCodec::new(SecretKey::from_base64url(
                settings.crypto.cursor_signing_key.expose_secret(),
            )?)),
            WebhookSignatureVerifier::new(settings.policy.signature_tolerance),
            Arc::new(SystemClock),
        ),
        iam: IamClient::new(&settings.iam).context("failed to construct IAM client")?,
        allow_local_credentials: settings.iam.local_auth_enabled(),
        public_base_url: settings.server.public_base_url.clone(),
    };
    let app = routes::router(state, &settings.server);
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

    let (shutdown_sender, mut shutdown_receiver) = tokio::sync::watch::channel(false);
    let mut server_task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                while !*shutdown_receiver.borrow_and_update() {
                    if shutdown_receiver.changed().await.is_err() {
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
