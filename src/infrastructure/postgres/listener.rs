//! Cross-replica delivery wake-ups over PostgreSQL `LISTEN`/`NOTIFY`.
//!
//! Event acceptance notifies the Silicon's identifier on one channel. Every
//! API replica runs one listener that fans notifications out to its local
//! WebSocket sessions. Sessions also poll on a slow timer, so a missed or
//! lagged notification only delays a delivery rather than losing it.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use sqlx::postgres::{PgConnectOptions, PgListener, PgPoolOptions};
use tokio::sync::{broadcast, watch};

use crate::domain::SiliconId;

/// Channel carrying Silicon identifiers whose streams gained an event.
pub const DELIVERY_CHANNEL: &str = "hook_delivery";
/// IAM notification fan-out; carries no credentials or event payload.
pub const AUTHORIZATION_CHANNEL: &str = "hook_authorization_changed";
const RECONNECT_DELAY: Duration = Duration::from_secs(2);
const BROADCAST_CAPACITY: usize = 4_096;

/// Local fan-out of delivery notifications.
#[derive(Clone, Debug)]
pub struct DeliveryWakeups {
    sender: broadcast::Sender<SiliconId>,
    authorization_epoch: Arc<AtomicU64>,
}

impl DeliveryWakeups {
    /// Creates a fan-out with a bounded per-subscriber backlog.
    #[must_use]
    pub fn new() -> Self {
        let (sender, _receiver) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            sender,
            authorization_epoch: Arc::default(),
        }
    }

    /// Observes the current cross-replica IAM invalidation generation.
    #[must_use]
    pub fn authorization_epoch(&self) -> u64 {
        self.authorization_epoch.load(Ordering::Acquire)
    }

    /// Invalidates retained WebSocket authorization after a verified IAM event.
    pub fn invalidate_authorization(&self) {
        self.authorization_epoch.fetch_add(1, Ordering::AcqRel);
    }

    /// Subscribes to every Silicon notification; callers filter locally.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<SiliconId> {
        self.sender.subscribe()
    }

    /// Publishes a wake-up to local subscribers.
    pub fn publish(&self, silicon_id: SiliconId) {
        // A send only fails when nobody is subscribed, which is not an error.
        let _subscribers = self.sender.send(silicon_id);
    }
}

impl Default for DeliveryWakeups {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs a resilient `LISTEN` loop until shutdown, republishing each
/// notification to the local fan-out.
pub async fn spawn_delivery_listener(
    options: PgConnectOptions,
    wakeups: DeliveryWakeups,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options.clone())
            .await;
        let listener = match pool {
            Ok(pool) => PgListener::connect_with(&pool).await,
            Err(error) => Err(error),
        };
        match listener {
            Ok(mut listener) => {
                if let Err(error) = listener
                    .listen_all([DELIVERY_CHANNEL, AUTHORIZATION_CHANNEL])
                    .await
                {
                    tracing::warn!(error = %error, "delivery listener failed to subscribe");
                } else {
                    tracing::info!("delivery listener subscribed");
                    run_listener(&mut listener, &wakeups, &mut shutdown).await;
                    if *shutdown.borrow() {
                        return;
                    }
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "delivery listener failed to connect");
            }
        }
        tokio::select! {
            () = tokio::time::sleep(RECONNECT_DELAY) => {}
            _ = shutdown.changed() => return,
        }
    }
}

async fn run_listener(
    listener: &mut PgListener,
    wakeups: &DeliveryWakeups,
    shutdown: &mut watch::Receiver<bool>,
) {
    loop {
        let notification = tokio::select! {
            notification = listener.try_recv() => notification,
            _ = shutdown.changed() => return,
        };
        match notification {
            Ok(Some(notification)) => {
                if notification.channel() == AUTHORIZATION_CHANNEL {
                    wakeups.invalidate_authorization();
                    continue;
                }
                if notification.channel() != DELIVERY_CHANNEL {
                    continue;
                }
                if let Ok(silicon_id) = SiliconId::new(notification.payload()) {
                    wakeups.publish(silicon_id);
                } else {
                    tracing::warn!("delivery notification carried an invalid payload");
                }
            }
            Ok(None) => {
                // The connection dropped and will reconnect; sessions poll in
                // the meantime, so nothing is lost.
                tracing::warn!("delivery listener connection was lost");
            }
            Err(error) => {
                tracing::warn!(error = %error, "delivery listener failed");
                return;
            }
        }
    }
}
