//! Application composition root and helpers shared by every use case.

use std::sync::Arc;

use time::OffsetDateTime;
use url::Url;

use super::{ApplicationError, Clock};
use crate::{
    domain::{
        Action, AuthorizationContext, AuthorizationDecision, EndpointKey, SiliconId, authorize,
    },
    infrastructure::{
        crypto::{CursorCodec, SecretCipher},
        postgres::{
            AuditContext, IdempotencyScope, PostgresStore, SECRET_REPLAY_WINDOW, StoreError,
        },
    },
};

/// Coordinates validated domain behavior with durable persistence.
#[derive(Clone)]
pub struct HookApplication {
    pub(super) store: PostgresStore,
    pub(super) secret_cipher: Arc<SecretCipher>,
    pub(super) cursor_codec: Arc<CursorCodec>,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) public_base_url: Url,
    pub(super) delivery_app_id: String,
}

impl std::fmt::Debug for HookApplication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HookApplication")
            .field("store", &self.store)
            .field("secret_cipher", &"[REDACTED]")
            .field("cursor_codec", &"[REDACTED]")
            .field("public_base_url", &self.public_base_url.as_str())
            .finish_non_exhaustive()
    }
}

impl HookApplication {
    /// Composes the application from its durable, cryptographic, and time boundaries.
    #[must_use]
    pub fn new(
        store: PostgresStore,
        secret_cipher: Arc<SecretCipher>,
        cursor_codec: Arc<CursorCodec>,
        clock: Arc<dyn Clock>,
        public_base_url: Url,
    ) -> Self {
        Self {
            store,
            secret_cipher,
            cursor_codec,
            clock,
            public_base_url,
            delivery_app_id: "hook".to_owned(),
        }
    }

    /// Selects the IAM application that owns outgoing Ting event types.
    #[must_use]
    pub fn with_delivery_application(mut self, app_id: &str) -> Self {
        app_id.clone_into(&mut self.delivery_app_id);
        self
    }

    /// Exposes the store for readiness without leaking it into handlers.
    #[must_use]
    pub const fn store(&self) -> &PostgresStore {
        &self.store
    }

    /// Attach the dedicated grant store to this exact data plane.
    #[must_use]
    pub fn ting_iam(
        &self,
        iam: crate::infrastructure::iam::IamClient,
    ) -> crate::infrastructure::iam::IamClient {
        iam.with_ting_grants(self.store.clone(), self.secret_cipher.clone())
    }

    /// Creates the scoped, exclusively server-owned publishing session manager.
    #[must_use]
    pub fn publisher_credentials(
        &self,
        iam: crate::infrastructure::iam::IamClient,
    ) -> crate::delivery::credentials::PublisherCredentials {
        crate::delivery::credentials::PublisherCredentials::new(
            self.store.clone(),
            self.secret_cipher.clone(),
            iam,
        )
    }

    /// Uses the selected store and encryption key to check Carbon publication authority.
    #[must_use]
    pub fn observer_authorities(
        &self,
        iam: crate::infrastructure::iam::IamClient,
    ) -> crate::delivery::observer_authority::ObserverAuthorities {
        crate::delivery::observer_authority::ObserverAuthorities::new(
            self.store.clone(),
            self.secret_cipher.clone(),
            iam,
        )
    }

    /// Builds the canonical public URL of an endpoint.
    ///
    /// # Errors
    ///
    /// Returns an internal error if the configured public origin cannot carry
    /// path segments.
    pub fn endpoint_url(
        &self,
        silicon_id: &SiliconId,
        endpoint_key: &EndpointKey,
    ) -> Result<Url, ApplicationError> {
        endpoint_url(&self.public_base_url, silicon_id, endpoint_key)
    }
}

/// Builds `{origin}/silicon/{silicon_id}/{endpoint_key}`.
///
/// # Errors
///
/// Returns an internal error if the origin cannot carry path segments.
pub fn endpoint_url(
    public_base_url: &Url,
    silicon_id: &SiliconId,
    endpoint_key: &EndpointKey,
) -> Result<Url, ApplicationError> {
    let mut url = public_base_url.clone();
    url.set_query(None);
    url.set_fragment(None);
    url.path_segments_mut()
        .map_err(|()| {
            ApplicationError::internal(anyhow::anyhow!(
                "public Hook URL cannot contain path segments"
            ))
        })?
        .clear()
        .push("silicon")
        .push(silicon_id.as_str())
        .push(endpoint_key.as_str());
    Ok(url)
}

pub(super) fn authorize_action(
    authorization: &AuthorizationContext,
    action: Action,
    silicon_id: &SiliconId,
) -> Result<(), ApplicationError> {
    match authorize(authorization, action, silicon_id) {
        AuthorizationDecision::Allowed => Ok(()),
        AuthorizationDecision::TargetNotVisible => Err(ApplicationError::NotFound),
        AuthorizationDecision::InsufficientPrivilege => Err(ApplicationError::Forbidden),
    }
}

pub(super) fn audit_context(
    authorization: &AuthorizationContext,
    request_id: Option<String>,
) -> AuditContext {
    AuditContext {
        actor: authorization.actor().clone(),
        request_id,
    }
}

pub(super) fn idempotency_scope(
    operation: &str,
    authorization: &AuthorizationContext,
    target_id: String,
    key: String,
    request_digest: [u8; 32],
) -> IdempotencyScope {
    IdempotencyScope {
        operation: operation.to_owned(),
        actor: authorization.actor().clone(),
        organization_id: authorization.organization_id().clone(),
        target_id,
        key,
        request_digest,
    }
}

pub(super) fn secret_replay_until(now: OffsetDateTime) -> Result<OffsetDateTime, ApplicationError> {
    now.checked_add(SECRET_REPLAY_WINDOW).ok_or_else(|| {
        ApplicationError::internal(anyhow::anyhow!("secret replay deadline overflow"))
    })
}

/// Normalizes a timestamp to the microsecond precision PostgreSQL stores so a
/// first response never differs from its database-rehydrated replay.
pub(super) fn database_time(value: OffsetDateTime) -> Result<OffsetDateTime, ApplicationError> {
    let nanosecond = value.nanosecond() / 1_000 * 1_000;
    value.replace_nanosecond(nanosecond).map_err(|error| {
        ApplicationError::internal(anyhow::anyhow!(
            "failed to normalize an authoritative timestamp: {error}"
        ))
    })
}

fn database_is_unavailable(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::WorkerCrashed => true,
        sqlx::Error::Database(database) => database.code().is_some_and(|code| {
            code.starts_with("08")
                || code.starts_with("53")
                || matches!(code.as_ref(), "57014" | "57P01" | "57P02" | "57P03")
        }),
        _ => false,
    }
}

pub(super) fn map_store_error(error: StoreError) -> ApplicationError {
    match error {
        StoreError::NotFound { .. } => ApplicationError::NotFound,
        StoreError::StateConflict { .. } | StoreError::IamDefaultExists => {
            ApplicationError::StateConflict
        }
        StoreError::IdempotencyConflict => ApplicationError::IdempotencyConflict,
        StoreError::SecretReplayExpired | StoreError::SecretSuperseded => {
            ApplicationError::SecretUnavailable
        }
        StoreError::HookLimitReached => ApplicationError::HookLimitReached,
        StoreError::InvalidArgument { field, .. } => ApplicationError::Validation { field },
        StoreError::Database(source) if database_is_unavailable(&source) => {
            ApplicationError::unavailable(source)
        }
        StoreError::Database(source) => ApplicationError::internal(source),
        StoreError::Migration(_)
        | StoreError::SchemaNotReady { .. }
        | StoreError::CorruptData { .. }
        | StoreError::EndpointKeyConflict
        | StoreError::NumericRange { .. } => ApplicationError::internal(error),
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::{database_is_unavailable, database_time, endpoint_url};
    use crate::domain::{EndpointKey, SiliconId};

    #[test]
    fn authoritative_timestamps_match_postgres_precision() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_eq!(
            database_time(datetime!(2026-08-31 12:00:00.123456789 UTC))?,
            datetime!(2026-08-31 12:00:00.123456 UTC)
        );
        Ok(())
    }

    #[test]
    fn only_transient_database_failures_are_unavailable() {
        assert!(database_is_unavailable(&sqlx::Error::PoolTimedOut));
        assert!(database_is_unavailable(&sqlx::Error::PoolClosed));
        assert!(!database_is_unavailable(&sqlx::Error::RowNotFound));
        assert!(!database_is_unavailable(&sqlx::Error::ColumnNotFound(
            "missing".to_owned()
        )));
    }

    #[test]
    fn endpoint_urls_follow_the_public_layout() -> Result<(), Box<dyn std::error::Error>> {
        let url = endpoint_url(
            &url::Url::parse("https://hook.teamofsilicons.com/")?,
            &SiliconId::new("si:cos")?,
            &EndpointKey::parse("402e2j2u")?,
        )?;
        assert_eq!(
            url.as_str(),
            "https://hook.teamofsilicons.com/silicon/si:cos/402E2J2U"
        );
        Ok(())
    }
}
