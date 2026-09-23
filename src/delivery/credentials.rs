//! Exclusive, encrypted IAM sessions for server-side Ting publication.
//!
//! Provisioning accepts a new Hook SLT, never an existing caller access/refresh
//! pair. Every IAM mutation has a durable key before the network call. Leases
//! serialize processes, and their random ownership tokens fence late replies.

use std::{fmt, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::FromRow;
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    domain::{ActorKind, EncryptedSecret, EncryptionKeyId, OrganizationId, SigningSecret},
    infrastructure::{
        crypto::SecretCipher,
        iam::{AuthorizationRequest, IamClient, IamError, IssuedTokens},
        postgres::PostgresStore,
    },
};

const NETWORK_TIMEOUT: Duration = Duration::from_secs(25);
const REFRESH_MARGIN: time::Duration = time::Duration::seconds(60);
const MAX_TRANSITIONS: usize = 6;

/// Non-secret metadata for an initialized publisher.
#[derive(Clone, Debug, Serialize)]
pub struct PublisherMetadata {
    /// Organization whose publication this dedicated session authorizes.
    pub org_id: OrganizationId,
    /// Dedicated Silicon identity, confirmed online with IAM.
    pub actor_id: String,
    /// Conservative access-token expiry, measured from the original IAM call.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// Safe credential failures: no upstream bodies, SQL arguments or secrets.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PublisherCredentialError {
    /// The bootstrap input does not meet the public contract.
    #[error("invalid publisher provisioning input")]
    InvalidInput,
    /// A different bootstrap operation already owns this organization.
    #[error("publisher provisioning conflicts with the existing operation")]
    Conflict,
    /// Another process currently owns the session transition.
    #[error("publisher credentials are being updated")]
    Busy,
    /// No dedicated publisher has been provisioned in this environment.
    #[error("publisher credentials are not configured")]
    NotConfigured,
    /// IAM did not confirm the dedicated Silicon in the selected organization.
    #[error("publisher is not authorized for this organization")]
    Forbidden,
    /// IAM permanently rejected the dedicated session or bootstrap.
    #[error("IAM rejected the dedicated publisher session")]
    SessionRejected,
    /// IAM failed transiently, or an expired replay needs another attempt.
    #[error("publisher authentication is temporarily unavailable")]
    Unavailable,
    /// Persistence failed; operation keys remain available for recovery.
    #[error("publisher credential storage is unavailable")]
    Storage,
    /// Stored secret material cannot be sealed or authenticated.
    #[error("publisher credentials could not be protected or authenticated")]
    Encryption,
    /// The lease or environment changed while an IAM call was in flight.
    #[error("publisher credential lease or environment changed")]
    Stale,
}

/// Owns an IAM refresh family solely for backend publication.
#[derive(Clone)]
pub struct PublisherCredentials {
    store: PostgresStore,
    cipher: Arc<SecretCipher>,
    iam: IamClient,
}

impl fmt::Debug for PublisherCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublisherCredentials")
            .finish_non_exhaustive()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
enum StoredCredentials {
    Bootstrap {
        slt: String,
    },
    Session {
        access_token: String,
        refresh_token: String,
    },
    Replacement {
        slt: String,
        refresh_token: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SealedCredentials {
    Bootstrap {
        slt: SealedSecret,
    },
    Session {
        access_token: SealedSecret,
        refresh_token: SealedSecret,
    },
    Replacement {
        slt: SealedSecret,
        refresh_token: Option<SealedSecret>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedSecret {
    key_id: String,
    nonce: [u8; 12],
    ciphertext: String,
}

#[derive(FromRow)]
struct CredentialRow {
    id: Uuid,
    provision_request_hash: Vec<u8>,
    provision_input_hash: Vec<u8>,
    encrypted_credentials: serde_json::Value,
    actor_id: Option<String>,
    expires_at: Option<OffsetDateTime>,
    validated: bool,
    rejected: bool,
    operation_key: Option<Uuid>,
    operation_started_at: Option<OffsetDateTime>,
    database_now: OffsetDateTime,
}

// Explicit scope predicates also protect test fixtures using a schema-owner
// connection, for which PostgreSQL can otherwise bypass row-level security.
macro_rules! scoped_sql {
    ($before:literal, $after:literal) => {
        concat!(
            $before,
            "environment_id = hook_private.environment_id()
    AND environment_generation = CASE
        WHEN hook_private.environment_id() = '00000000-0000-0000-0000-000000000000'::uuid
        THEN 0 ELSE current_setting('hook.environment_generation')::bigint END
    AND hook_private.environment_is_available()",
            $after
        )
    };
}

impl PublisherCredentials {
    /// Uses the already selected production or generation-pinned test context.
    #[must_use]
    pub fn new(store: PostgresStore, cipher: Arc<SecretCipher>, iam: IamClient) -> Self {
        Self { store, cipher, iam }
    }

    /// Takes ownership of a fresh, separately issued Hook SLT for a Silicon.
    ///
    /// The caller must authorize the configuring administrator before calling.
    /// Retrying requires the identical SLT and idempotency key. Replacing an
    /// established family is deliberately refused rather than orphaning it.
    ///
    /// # Errors
    /// Returns safe input, conflict, lease, IAM, encryption or storage failures.
    pub async fn provision(
        &self,
        org: &OrganizationId,
        slt: &str,
        idempotency_key: &str,
    ) -> Result<PublisherMetadata, PublisherCredentialError> {
        validate_input(slt, idempotency_key)?;
        let request_hash = digest(b"publisher-operation", org, idempotency_key);
        let input_hash = digest(b"publisher-bootstrap", org, slt);
        self.adopt_generation(org).await?;
        self.stage(org, slt, &request_hash, &input_hash).await?;
        let row = self
            .read(org)
            .await?
            .ok_or(PublisherCredentialError::Stale)?;
        if row.provision_request_hash != request_hash || row.provision_input_hash != input_hash {
            return Err(PublisherCredentialError::Conflict);
        }
        let _owned_token = self.access_token(org).await?;
        let row = self
            .read(org)
            .await?
            .ok_or(PublisherCredentialError::Stale)?;
        if !row.validated || row.rejected {
            return Err(PublisherCredentialError::SessionRejected);
        }
        Ok(PublisherMetadata {
            org_id: org.clone(),
            actor_id: row.actor_id.ok_or(PublisherCredentialError::Storage)?,
            expires_at: row.expires_at.ok_or(PublisherCredentialError::Storage)?,
        })
    }

    /// Explicitly replaces a rejected publisher using another dedicated SLT.
    ///
    /// The configuring administrator must explicitly request recovery. A usable
    /// family is never replaced; an already completed retry is idempotent. The
    /// old refresh family is revoked with a durable mutation key before its
    /// replacement can log in. A different in-progress replacement conflicts.
    ///
    /// # Errors
    /// Returns the same safe failures as provisioning, including conflicts when
    /// the current publisher is still usable or a replacement input changes.
    pub async fn reprovision(
        &self,
        org: &OrganizationId,
        slt: &str,
        idempotency_key: &str,
    ) -> Result<PublisherMetadata, PublisherCredentialError> {
        validate_input(slt, idempotency_key)?;
        let lease = Uuid::now_v7();
        let row = self.claim(org, lease).await?;
        let result = self
            .stage_replacement(org, lease, &row, slt, idempotency_key)
            .await;
        let released = self.release(org, lease).await;
        result?;
        released?;
        self.provision(org, slt, idempotency_key).await
    }

    async fn stage_replacement(
        &self,
        org: &OrganizationId,
        lease: Uuid,
        row: &CredentialRow,
        slt: &str,
        idempotency_key: &str,
    ) -> Result<(), PublisherCredentialError> {
        let request_hash = digest(b"publisher-operation", org, idempotency_key);
        let input_hash = digest(b"publisher-bootstrap", org, slt);
        if row.provision_request_hash == request_hash {
            return if row.provision_input_hash == input_hash {
                Ok(())
            } else {
                Err(PublisherCredentialError::Conflict)
            };
        }
        if !row.rejected {
            return Err(PublisherCredentialError::Conflict);
        }
        let previous = self.open(row.id, &row.encrypted_credentials)?;
        let refresh_token = match &previous {
            StoredCredentials::Bootstrap { .. } => None,
            StoredCredentials::Session { refresh_token, .. } => Some(refresh_token.clone()),
            StoredCredentials::Replacement { .. } => {
                return Err(PublisherCredentialError::Conflict);
            }
        };
        let encrypted = self.seal(
            row.id,
            &StoredCredentials::Replacement {
                slt: slt.to_owned(),
                refresh_token,
            },
        )?;
        let changed = sqlx::query(scoped_sql!(
            "UPDATE hook_private.ting_publisher_credentials
             SET encrypted_credentials=$3,provision_request_hash=$4,provision_input_hash=$5,
                 operation_key=$6,operation_started_at=clock_timestamp(),validated=false,
                 updated_at=clock_timestamp()
             WHERE org_id=$1 AND lease_id=$2 AND lease_until>clock_timestamp() AND rejected AND ",
            ""
        ))
        .bind(org.as_str())
        .bind(lease)
        .bind(encrypted)
        .bind(request_hash)
        .bind(input_hash)
        .bind(Uuid::now_v7())
        .execute(self.store.pool())
        .await
        .map_err(|_| PublisherCredentialError::Storage)?
        .rows_affected();
        changed_once(changed)
    }

    /// Gets this backend's access token, recovering pending login/refresh work.
    ///
    /// Only the encrypted family owned by this store is ever refreshed. A
    /// returned credential is validated for the selected organization and never
    /// belongs to an interactive caller's existing session.
    ///
    /// # Errors
    /// Returns safe absence, lease, IAM, encryption or persistence failures.
    pub async fn access_token(
        &self,
        org: &OrganizationId,
    ) -> Result<SecretString, PublisherCredentialError> {
        let lease = Uuid::now_v7();
        let row = self.claim(org, lease).await?;
        let result = self.advance(org, lease, row).await;
        // Preserve the original safe failure when release also fails. A crash or
        // failed release is recovered after the bounded database lease expires.
        let released = self.release(org, lease).await;
        match result {
            Ok(token) => {
                released?;
                Ok(token)
            }
            Err(error) => Err(error),
        }
    }

    /// Expires the exact access token IAM rejected so its owned family refreshes.
    ///
    /// A late rejection for an older token leaves a newer token unchanged. The
    /// comparison and mutation hold the same durable lease used for refresh;
    /// the lease-token condition prevents a late writer after lease takeover.
    /// Returns whether the rejected token was still current.
    ///
    /// # Errors
    /// Returns safe absence, lease, encryption or persistence failures.
    pub async fn invalidate_access_token(
        &self,
        org: &OrganizationId,
        rejected_token: &SecretString,
    ) -> Result<bool, PublisherCredentialError> {
        let lease = Uuid::now_v7();
        let row = self.claim(org, lease).await?;
        let result = self
            .invalidate_current(org, lease, &row, rejected_token)
            .await;
        let released = self.release(org, lease).await;
        match result {
            Ok(changed) => {
                released?;
                Ok(changed)
            }
            Err(error) => Err(error),
        }
    }

    async fn invalidate_current(
        &self,
        org: &OrganizationId,
        lease: Uuid,
        row: &CredentialRow,
        rejected_token: &SecretString,
    ) -> Result<bool, PublisherCredentialError> {
        let stored = self.open(row.id, &row.encrypted_credentials)?;
        let StoredCredentials::Session { access_token, .. } = &stored else {
            return Ok(false);
        };
        let current_hash: [u8; 32] = Sha256::digest(access_token.as_bytes()).into();
        let rejected_hash: [u8; 32] =
            Sha256::digest(rejected_token.expose_secret().as_bytes()).into();
        if row.rejected || !bool::from(current_hash.ct_eq(&rejected_hash)) {
            return Ok(false);
        }
        let changed = sqlx::query(scoped_sql!(
            "UPDATE hook_private.ting_publisher_credentials
             SET expires_at=clock_timestamp(),validated=false,updated_at=clock_timestamp()
             WHERE org_id=$1 AND lease_id=$2 AND lease_until>clock_timestamp() AND ",
            ""
        ))
        .bind(org.as_str())
        .bind(lease)
        .execute(self.store.pool())
        .await
        .map_err(|_| PublisherCredentialError::Storage)?
        .rows_affected();
        changed_once(changed)?;
        Ok(true)
    }

    async fn stage(
        &self,
        org: &OrganizationId,
        slt: &str,
        request_hash: &[u8],
        input_hash: &[u8],
    ) -> Result<(), PublisherCredentialError> {
        let id = Uuid::now_v7();
        let encrypted = self.seal(
            id,
            &StoredCredentials::Bootstrap {
                slt: slt.to_owned(),
            },
        )?;
        sqlx::query(
            "INSERT INTO hook_private.ting_publisher_credentials
            (org_id,id,provision_request_hash,provision_input_hash,encrypted_credentials,
             operation_key,operation_started_at)
            VALUES($1,$2,$3,$4,$5,$6,clock_timestamp())
            ON CONFLICT(environment_id,org_id) DO NOTHING",
        )
        .bind(org.as_str())
        .bind(id)
        .bind(request_hash)
        .bind(input_hash)
        .bind(encrypted)
        .bind(Uuid::now_v7())
        .execute(self.store.pool())
        .await
        .map_err(|_| PublisherCredentialError::Storage)?;
        Ok(())
    }

    async fn read(
        &self,
        org: &OrganizationId,
    ) -> Result<Option<CredentialRow>, PublisherCredentialError> {
        sqlx::query_as(scoped_sql!(
            "SELECT *,clock_timestamp() AS database_now
            FROM hook_private.ting_publisher_credentials WHERE org_id=$1 AND ",
            ""
        ))
        .bind(org.as_str())
        .fetch_optional(self.store.pool())
        .await
        .map_err(|_| PublisherCredentialError::Storage)
    }

    async fn claim(
        &self,
        org: &OrganizationId,
        lease: Uuid,
    ) -> Result<CredentialRow, PublisherCredentialError> {
        self.adopt_generation(org).await?;
        let row = sqlx::query_as(scoped_sql!(
            "UPDATE hook_private.ting_publisher_credentials
            SET lease_id=$2,lease_until=clock_timestamp()+INTERVAL '120 seconds'
            WHERE org_id=$1 AND ",
            "
              AND (lease_until IS NULL OR lease_until<=clock_timestamp())
            RETURNING *,clock_timestamp() AS database_now"
        ))
        .bind(org.as_str())
        .bind(lease)
        .fetch_optional(self.store.pool())
        .await
        .map_err(|_| PublisherCredentialError::Storage)?;
        if let Some(row) = row {
            return Ok(row);
        }
        Err(if self.read(org).await?.is_some() {
            PublisherCredentialError::Busy
        } else {
            PublisherCredentialError::NotConfigured
        })
    }

    async fn adopt_generation(&self, org: &OrganizationId) -> Result<(), PublisherCredentialError> {
        // Key rotation and disable/restore retain the owned IAM family. Only a
        // current, ready environment can adopt it; clean has deleted the row.
        // Clearing the previous lease fences replies from the old context,
        // while preserving its operation key recovers an uncertain exchange.
        sqlx::query("UPDATE hook_private.ting_publisher_credentials
            SET environment_generation=current_setting('hook.environment_generation')::bigint,
                validated=false,lease_id=NULL,lease_until=NULL,updated_at=clock_timestamp()
            WHERE org_id=$1 AND environment_id=hook_private.environment_id()
              AND environment_id<>'00000000-0000-0000-0000-000000000000'::uuid
              AND hook_private.environment_is_available()
              AND environment_generation<>NULLIF(current_setting('hook.environment_generation',true),'')::bigint")
            .bind(org.as_str()).execute(self.store.pool()).await
            .map_err(|_| PublisherCredentialError::Storage)?;
        Ok(())
    }

    async fn release(
        &self,
        org: &OrganizationId,
        lease: Uuid,
    ) -> Result<(), PublisherCredentialError> {
        let changed = sqlx::query(scoped_sql!(
            "UPDATE hook_private.ting_publisher_credentials
            SET lease_id=NULL,lease_until=NULL
            WHERE org_id=$1 AND lease_id=$2 AND lease_until>clock_timestamp() AND ",
            ""
        ))
        .bind(org.as_str())
        .bind(lease)
        .execute(self.store.pool())
        .await
        .map_err(|_| PublisherCredentialError::Storage)?
        .rows_affected();
        changed_once(changed)
    }

    async fn advance(
        &self,
        org: &OrganizationId,
        lease: Uuid,
        mut row: CredentialRow,
    ) -> Result<SecretString, PublisherCredentialError> {
        for _ in 0..MAX_TRANSITIONS {
            let stored = self.open(row.id, &row.encrypted_credentials)?;
            if row.rejected && !matches!(&stored, StoredCredentials::Replacement { .. }) {
                return Err(PublisherCredentialError::SessionRejected);
            }
            match &stored {
                StoredCredentials::Replacement { slt, refresh_token } => {
                    if let Some(refresh) = refresh_token {
                        let key = row
                            .operation_key
                            .ok_or(PublisherCredentialError::Storage)?
                            .to_string();
                        self.renew_lease(org, lease).await?;
                        let revoked =
                            tokio::time::timeout(NETWORK_TIMEOUT, self.iam.logout(refresh, &key))
                                .await
                                .map_err(|_| PublisherCredentialError::Unavailable)?;
                        // An invalid/revoked token has no usable family left.
                        match revoked {
                            Ok(()) | Err(IamError::InvalidCredential | IamError::NotFound) => {}
                            Err(_) => return Err(PublisherCredentialError::Unavailable),
                        }
                    }
                    row = self.finish_replacement(org, lease, row.id, slt).await?;
                }
                StoredCredentials::Bootstrap { slt } => {
                    let key = row
                        .operation_key
                        .ok_or(PublisherCredentialError::Storage)?
                        .to_string();
                    self.renew_lease(org, lease).await?;
                    let tokens = tokio::time::timeout(NETWORK_TIMEOUT, self.iam.login(slt, &key))
                        .await
                        .map_err(|_| PublisherCredentialError::Unavailable)?;
                    let tokens = self.iam_result(org, lease, tokens).await?;
                    row = self.save_issued(org, lease, &row, &tokens).await?;
                }
                StoredCredentials::Session {
                    access_token,
                    refresh_token,
                } => {
                    if let Some(operation) = row.operation_key {
                        let key = operation.to_string();
                        self.renew_lease(org, lease).await?;
                        let tokens = tokio::time::timeout(
                            NETWORK_TIMEOUT,
                            self.iam.refresh(refresh_token, &key),
                        )
                        .await
                        .map_err(|_| PublisherCredentialError::Unavailable)?;
                        let tokens = self.iam_result(org, lease, tokens).await?;
                        row = self.save_issued(org, lease, &row, &tokens).await?;
                    } else if row
                        .expires_at
                        .is_none_or(|expiry| expiry <= row.database_now + REFRESH_MARGIN)
                    {
                        row = self.begin_refresh(org, lease).await?;
                    } else {
                        if !row.validated {
                            self.validate(org, lease, &row, access_token).await?;
                        }
                        self.confirm_lease(org, lease).await?;
                        return Ok(SecretString::from(access_token.clone()));
                    }
                }
            }
        }
        Err(PublisherCredentialError::Unavailable)
    }

    async fn finish_replacement(
        &self,
        org: &OrganizationId,
        lease: Uuid,
        id: Uuid,
        slt: &str,
    ) -> Result<CredentialRow, PublisherCredentialError> {
        let encrypted = self.seal(
            id,
            &StoredCredentials::Bootstrap {
                slt: slt.to_owned(),
            },
        )?;
        sqlx::query_as(scoped_sql!(
            "UPDATE hook_private.ting_publisher_credentials
             SET encrypted_credentials=$3,actor_id=NULL,expires_at=NULL,validated=false,rejected=false,
                 operation_key=$4,operation_started_at=clock_timestamp(),updated_at=clock_timestamp()
             WHERE org_id=$1 AND lease_id=$2 AND lease_until>clock_timestamp() AND ",
            " RETURNING *,clock_timestamp() AS database_now"
        )).bind(org.as_str()).bind(lease).bind(encrypted).bind(Uuid::now_v7())
            .fetch_optional(self.store.pool()).await.map_err(|_|PublisherCredentialError::Storage)?
            .ok_or(PublisherCredentialError::Stale)
    }

    async fn iam_result<T>(
        &self,
        org: &OrganizationId,
        lease: Uuid,
        result: Result<T, IamError>,
    ) -> Result<T, PublisherCredentialError> {
        match result {
            Ok(value) => Ok(value),
            Err(IamError::InvalidCredential | IamError::Forbidden | IamError::NotFound) => {
                self.reject(org, lease).await?;
                Err(PublisherCredentialError::SessionRejected)
            }
            Err(_) => Err(PublisherCredentialError::Unavailable),
        }
    }

    async fn save_issued(
        &self,
        org: &OrganizationId,
        lease: Uuid,
        row: &CredentialRow,
        tokens: &IssuedTokens,
    ) -> Result<CredentialRow, PublisherCredentialError> {
        if tokens.access_token.is_empty() || tokens.refresh_token.is_empty() {
            self.reject(org, lease).await?;
            return Err(PublisherCredentialError::Forbidden);
        }
        let rejected = tokens.actor.kind() != ActorKind::Silicon
            || tokens
                .organization_id
                .as_ref()
                .is_some_and(|bound| bound != org)
            || row
                .actor_id
                .as_deref()
                .is_some_and(|actor| actor != tokens.actor.id().as_str());
        let started = row
            .operation_started_at
            .ok_or(PublisherCredentialError::Storage)?;
        let expires = conservative_expiry(started, tokens.expires_in)?;
        let encrypted = self.seal(
            row.id,
            &StoredCredentials::Session {
                access_token: tokens.access_token.to_string(),
                refresh_token: tokens.refresh_token.to_string(),
            },
        )?;
        // Preserve a rotated family before another fallible network call. It is
        // unusable until IAM's live authorization below marks it validated.
        let saved = sqlx::query_as(scoped_sql!(
            "UPDATE hook_private.ting_publisher_credentials
            SET encrypted_credentials=$3,actor_id=$4,expires_at=$5,validated=false,rejected=$6,
                operation_key=NULL,operation_started_at=NULL,updated_at=clock_timestamp()
            WHERE org_id=$1 AND lease_id=$2 AND lease_until>clock_timestamp() AND ",
            " RETURNING *,clock_timestamp() AS database_now"
        ))
        .bind(org.as_str())
        .bind(lease)
        .bind(encrypted)
        .bind(tokens.actor.id().as_str())
        .bind(expires)
        .bind(rejected)
        .fetch_optional(self.store.pool())
        .await
        .map_err(|_| PublisherCredentialError::Storage)?
        .ok_or(PublisherCredentialError::Stale)?;
        if rejected {
            Err(PublisherCredentialError::Forbidden)
        } else {
            Ok(saved)
        }
    }

    async fn begin_refresh(
        &self,
        org: &OrganizationId,
        lease: Uuid,
    ) -> Result<CredentialRow, PublisherCredentialError> {
        sqlx::query_as(scoped_sql!(
            "UPDATE hook_private.ting_publisher_credentials
            SET operation_key=$3,operation_started_at=clock_timestamp(),updated_at=clock_timestamp()
            WHERE org_id=$1 AND lease_id=$2 AND lease_until>clock_timestamp()
              AND operation_key IS NULL AND ",
            " RETURNING *,clock_timestamp() AS database_now"
        ))
        .bind(org.as_str())
        .bind(lease)
        .bind(Uuid::now_v7())
        .fetch_optional(self.store.pool())
        .await
        .map_err(|_| PublisherCredentialError::Storage)?
        .ok_or(PublisherCredentialError::Stale)
    }

    async fn validate(
        &self,
        org: &OrganizationId,
        lease: Uuid,
        row: &CredentialRow,
        access_token: &str,
    ) -> Result<(), PublisherCredentialError> {
        let request = AuthorizationRequest {
            token: SecretString::from(access_token),
            org_id: org.clone(),
            targets: Vec::new(),
        };
        self.renew_lease(org, lease).await?;
        let context = tokio::time::timeout(NETWORK_TIMEOUT, self.iam.authorize(&request))
            .await
            .map_err(|_| PublisherCredentialError::Unavailable)?;
        let context = self.iam_result(org, lease, context).await?;
        if context.organization_id() != org
            || context.actor().kind() != ActorKind::Silicon
            || Some(context.actor().id().as_str()) != row.actor_id.as_deref()
        {
            self.reject(org, lease).await?;
            return Err(PublisherCredentialError::Forbidden);
        }
        let changed = sqlx::query(scoped_sql!(
            "UPDATE hook_private.ting_publisher_credentials
            SET validated=true,updated_at=clock_timestamp()
            WHERE org_id=$1 AND lease_id=$2 AND lease_until>clock_timestamp() AND ",
            ""
        ))
        .bind(org.as_str())
        .bind(lease)
        .execute(self.store.pool())
        .await
        .map_err(|_| PublisherCredentialError::Storage)?
        .rows_affected();
        changed_once(changed)
    }

    async fn reject(
        &self,
        org: &OrganizationId,
        lease: Uuid,
    ) -> Result<(), PublisherCredentialError> {
        let changed = sqlx::query(scoped_sql!(
            "UPDATE hook_private.ting_publisher_credentials
            SET rejected=true,validated=false,updated_at=clock_timestamp()
            WHERE org_id=$1 AND lease_id=$2 AND lease_until>clock_timestamp() AND ",
            ""
        ))
        .bind(org.as_str())
        .bind(lease)
        .execute(self.store.pool())
        .await
        .map_err(|_| PublisherCredentialError::Storage)?
        .rows_affected();
        changed_once(changed)
    }

    async fn confirm_lease(
        &self,
        org: &OrganizationId,
        lease: Uuid,
    ) -> Result<(), PublisherCredentialError> {
        let current: bool = sqlx::query_scalar(scoped_sql!(
            "SELECT EXISTS(
            SELECT FROM hook_private.ting_publisher_credentials
            WHERE org_id=$1 AND lease_id=$2 AND lease_until>clock_timestamp()
              AND validated AND NOT rejected AND expires_at>clock_timestamp() AND ",
            ")"
        ))
        .bind(org.as_str())
        .bind(lease)
        .fetch_one(self.store.pool())
        .await
        .map_err(|_| PublisherCredentialError::Storage)?;
        if current {
            Ok(())
        } else {
            Err(PublisherCredentialError::Stale)
        }
    }

    async fn renew_lease(
        &self,
        org: &OrganizationId,
        lease: Uuid,
    ) -> Result<(), PublisherCredentialError> {
        let changed = sqlx::query(scoped_sql!(
            "UPDATE hook_private.ting_publisher_credentials
             SET lease_until=clock_timestamp()+INTERVAL '120 seconds'
             WHERE org_id=$1 AND lease_id=$2 AND lease_until>clock_timestamp() AND ",
            ""
        ))
        .bind(org.as_str())
        .bind(lease)
        .execute(self.store.pool())
        .await
        .map_err(|_| PublisherCredentialError::Storage)?
        .rows_affected();
        changed_once(changed)
    }

    fn seal(
        &self,
        id: Uuid,
        stored: &StoredCredentials,
    ) -> Result<serde_json::Value, PublisherCredentialError> {
        // Seal fields independently: IAM accepts a 4096-byte SLT, so wrapping
        // plaintext in JSON would exceed SecretCipher's 4096-byte bound. Each
        // field has a separate authenticated binding to prevent swapping it.
        let sealed = match stored {
            StoredCredentials::Bootstrap { slt } => SealedCredentials::Bootstrap {
                slt: self.seal_secret(id, b"bootstrap-slt", slt)?,
            },
            StoredCredentials::Session {
                access_token,
                refresh_token,
            } => SealedCredentials::Session {
                access_token: self.seal_secret(id, b"access-token", access_token)?,
                refresh_token: self.seal_secret(id, b"refresh-token", refresh_token)?,
            },
            StoredCredentials::Replacement { slt, refresh_token } => {
                SealedCredentials::Replacement {
                    slt: self.seal_secret(id, b"replacement-slt", slt)?,
                    refresh_token: refresh_token
                        .as_ref()
                        .map(|value| self.seal_secret(id, b"refresh-token", value))
                        .transpose()?,
                }
            }
        };
        serde_json::to_value(sealed).map_err(|_| PublisherCredentialError::Encryption)
    }

    fn seal_secret(
        &self,
        id: Uuid,
        field: &[u8],
        value: &str,
    ) -> Result<SealedSecret, PublisherCredentialError> {
        let plain = SigningSecret::from_zeroizing(Zeroizing::new(value.to_owned()))
            .map_err(|_| PublisherCredentialError::Encryption)?;
        let sealed = self
            .cipher
            .encrypt(secret_binding(id, field).into(), &plain)
            .map_err(|_| PublisherCredentialError::Encryption)?;
        Ok(SealedSecret {
            key_id: sealed.key_id().as_str().to_owned(),
            nonce: *sealed.nonce(),
            ciphertext: URL_SAFE_NO_PAD.encode(sealed.ciphertext()),
        })
    }

    fn open(
        &self,
        id: Uuid,
        sealed: &serde_json::Value,
    ) -> Result<StoredCredentials, PublisherCredentialError> {
        let sealed: SealedCredentials = serde_json::from_value(sealed.clone())
            .map_err(|_| PublisherCredentialError::Encryption)?;
        match sealed {
            SealedCredentials::Bootstrap { slt } => Ok(StoredCredentials::Bootstrap {
                slt: self
                    .open_secret(id, b"bootstrap-slt", slt)?
                    .as_str()
                    .to_owned(),
            }),
            SealedCredentials::Session {
                access_token,
                refresh_token,
            } => {
                let access = self.open_secret(id, b"access-token", access_token)?;
                let refresh = self.open_secret(id, b"refresh-token", refresh_token)?;
                Ok(StoredCredentials::Session {
                    access_token: access.as_str().to_owned(),
                    refresh_token: refresh.as_str().to_owned(),
                })
            }
            SealedCredentials::Replacement { slt, refresh_token } => {
                let slt = self.open_secret(id, b"replacement-slt", slt)?;
                let refresh = refresh_token
                    .map(|value| self.open_secret(id, b"refresh-token", value))
                    .transpose()?;
                Ok(StoredCredentials::Replacement {
                    slt: slt.as_str().to_owned(),
                    refresh_token: refresh.map(|value| value.as_str().to_owned()),
                })
            }
        }
    }

    fn open_secret(
        &self,
        id: Uuid,
        field: &[u8],
        sealed: SealedSecret,
    ) -> Result<SigningSecret, PublisherCredentialError> {
        let ciphertext = EncryptedSecret::new(
            EncryptionKeyId::new(sealed.key_id)
                .map_err(|_| PublisherCredentialError::Encryption)?,
            sealed.nonce,
            URL_SAFE_NO_PAD
                .decode(sealed.ciphertext)
                .map_err(|_| PublisherCredentialError::Encryption)?,
        )
        .map_err(|_| PublisherCredentialError::Encryption)?;
        self.cipher
            .decrypt(secret_binding(id, field).into(), &ciphertext)
            .map_err(|_| PublisherCredentialError::Encryption)
    }
}

fn secret_binding(id: Uuid, field: &[u8]) -> Uuid {
    let mut hash = Sha256::new();
    hash.update(b"silicon-hook/publisher-secret/v1\0");
    hash.update(id.as_bytes());
    hash.update(field);
    let digest = hash.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

fn validate_input(slt: &str, key: &str) -> Result<(), PublisherCredentialError> {
    if !(1..=4096).contains(&slt.len())
        || !slt.bytes().all(|byte| byte.is_ascii_graphic())
        || !(8..=255).contains(&key.len())
        || !key.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(PublisherCredentialError::InvalidInput);
    }
    Ok(())
}

fn digest(domain: &[u8], org: &OrganizationId, value: &str) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(org.as_str());
    hash.update([0]);
    hash.update(value);
    hash.finalize().to_vec()
}

fn conservative_expiry(
    started: OffsetDateTime,
    lifetime: Duration,
) -> Result<OffsetDateTime, PublisherCredentialError> {
    let seconds =
        i64::try_from(lifetime.as_secs()).map_err(|_| PublisherCredentialError::Unavailable)?;
    started
        .checked_add(time::Duration::seconds(seconds))
        .ok_or(PublisherCredentialError::Unavailable)
}

fn changed_once(changed: u64) -> Result<(), PublisherCredentialError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(PublisherCredentialError::Stale)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::IamSettings,
        domain::ActorRef,
        infrastructure::{
            crypto::{SecretKey, SecretKeyring},
            postgres::migrate,
        },
    };
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use testcontainers::{ImageExt as _, runners::AsyncRunner as _};
    use testcontainers_modules::postgres::Postgres;
    use url::Url;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    async fn credentials(store: PostgresStore) -> TestResult<PublisherCredentials> {
        let key = EncryptionKeyId::new("publisher-test")?;
        let cipher = Arc::new(SecretCipher::new(SecretKeyring::new(
            key.clone(),
            [(key, SecretKey::from_bytes([71; 32]))],
        )?));
        let iam = IamClient::connect(&IamSettings {
            base_url: Url::parse("http://127.0.0.1:9")?,
            app_id: None,
            app_secret: None,
            connect_timeout: Duration::from_millis(50),
            request_timeout: Duration::from_millis(50),
            max_response_bytes: 1024,
            allow_insecure_local_http: true,
            local_auth: true,
            webhook: None,
        })
        .await?;
        Ok(PublisherCredentials::new(store, cipher, iam))
    }

    #[tokio::test]
    async fn ciphertext_binds_row_and_field_and_supports_maximum_slt() -> TestResult {
        let pool =
            PgPoolOptions::new().connect_lazy("postgres://unused:unused@127.0.0.1:9/unused")?;
        let service = credentials(PostgresStore::new(pool)).await?;
        let id = Uuid::now_v7();
        let bootstrap = StoredCredentials::Bootstrap {
            slt: "x".repeat(4096),
        };
        let sealed = service.seal(id, &bootstrap)?;
        assert!(!sealed.to_string().contains(&"x".repeat(64)));
        assert!(matches!(
            service.open(Uuid::now_v7(), &sealed),
            Err(PublisherCredentialError::Encryption)
        ));
        let opened = service.open(id, &sealed)?;
        assert!(matches!(&opened, StoredCredentials::Bootstrap { slt } if slt.len() == 4096));
        let mut sealed = service.seal(
            id,
            &StoredCredentials::Session {
                access_token: "synthetic-access".into(),
                refresh_token: "synthetic-refresh".into(),
            },
        )?;
        let previous_access = sealed["access_token"].clone();
        sealed["access_token"] = sealed["refresh_token"].clone();
        sealed["refresh_token"] = previous_access;
        assert!(matches!(
            service.open(id, &sealed),
            Err(PublisherCredentialError::Encryption)
        ));
        assert!(!format!("{service:?}").contains("synthetic"));
        Ok(())
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one real-database fixture covers lease recovery and lifecycle fencing without sharing state"
    )]
    async fn durable_leases_preserve_retries_and_late_rejections_leave_new_tokens_alone()
    -> TestResult {
        let container = Postgres::default().with_tag("16-alpine").start().await?;
        let url = format!(
            "postgres://postgres:postgres@{}:{}/postgres",
            container.get_host().await?,
            container.get_host_port_ipv4(5432).await?
        );
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await?;
        migrate(&pool).await?;
        let service = credentials(PostgresStore::new(pool.clone())).await?;
        let org = OrganizationId::new("publisher-test")?;
        let request_hash = digest(b"publisher-operation", &org, "provision-1");
        let input_hash = digest(b"publisher-bootstrap", &org, "synthetic-slt");
        service
            .stage(&org, "synthetic-slt", &request_hash, &input_hash)
            .await?;
        let first = Uuid::now_v7();
        let row = service.claim(&org, first).await?;
        let operation = row.operation_key;
        assert!(operation.is_some());
        assert!(
            !row.encrypted_credentials
                .to_string()
                .contains("synthetic-slt")
        );
        assert!(matches!(
            service.claim(&org, Uuid::now_v7()).await,
            Err(PublisherCredentialError::Busy)
        ));
        // A process disappearing leaves a lease, not an ambiguous new IAM key.
        sqlx::query("UPDATE hook_private.ting_publisher_credentials SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE id=$1")
            .bind(row.id).execute(&pool).await?;
        let restarted = credentials(PostgresStore::new(pool.clone())).await?;
        let second = Uuid::now_v7();
        let row = restarted.claim(&org, second).await?;
        assert_eq!(row.operation_key, operation);
        assert_eq!(
            service.reject(&org, first).await,
            Err(PublisherCredentialError::Stale)
        );
        assert_eq!(
            service.release(&org, first).await,
            Err(PublisherCredentialError::Stale)
        );
        let tokens = IssuedTokens {
            access_token: Zeroizing::new("synthetic-access-v1".into()),
            refresh_token: Zeroizing::new("synthetic-refresh-v1".into()),
            expires_in: Duration::from_secs(3600),
            scopes: Vec::new(),
            actor: ActorRef::try_new(ActorKind::Silicon, "publisher:publisher-test")?,
            organization_id: Some(org.clone()),
        };
        let saved = restarted.save_issued(&org, second, &row, &tokens).await?;
        assert!(
            !saved.validated,
            "issuance alone must not enable the publisher"
        );
        let refresh = restarted.begin_refresh(&org, second).await?;
        assert!(refresh.operation_key.is_some());
        restarted.release(&org, second).await?;
        let third = Uuid::now_v7();
        let replay = service.claim(&org, third).await?;
        assert_eq!(replay.operation_key, refresh.operation_key);
        assert_eq!(replay.operation_started_at, refresh.operation_started_at);
        let renewed = IssuedTokens {
            access_token: Zeroizing::new("synthetic-access-v2".into()),
            refresh_token: Zeroizing::new("synthetic-refresh-v2".into()),
            ..tokens
        };
        let saved = service.save_issued(&org, third, &replay, &renewed).await?;
        service.release(&org, third).await?;
        assert!(
            !service
                .invalidate_access_token(&org, &SecretString::from("synthetic-access-v1"))
                .await?
        );
        let current = service.read(&org).await?.ok_or("missing publisher")?;
        assert_eq!(current.expires_at, saved.expires_at);
        assert!(
            service
                .invalidate_access_token(&org, &SecretString::from("synthetic-access-v2"))
                .await?
        );
        let current = service.read(&org).await?.ok_or("missing publisher")?;
        assert!(
            current
                .expires_at
                .is_some_and(|expiry| expiry <= current.database_now)
        );
        assert!(!current.validated);

        let recovery_lease = Uuid::now_v7();
        let current = service.claim(&org, recovery_lease).await?;
        assert_eq!(
            service
                .stage_replacement(
                    &org,
                    recovery_lease,
                    &current,
                    "replacement-slt",
                    "recovery-operation"
                )
                .await,
            Err(PublisherCredentialError::Conflict),
            "an administrator retry must not discard a usable family"
        );
        service.reject(&org, recovery_lease).await?;
        let rejected = service
            .read(&org)
            .await?
            .ok_or("missing rejected publisher")?;
        service
            .stage_replacement(
                &org,
                recovery_lease,
                &rejected,
                "replacement-slt",
                "recovery-operation",
            )
            .await?;
        let replacement = service.read(&org).await?.ok_or("missing replacement")?;
        let revocation_key = replacement.operation_key;
        let payload = service.open(replacement.id, &replacement.encrypted_credentials)?;
        assert!(
            matches!(&payload, StoredCredentials::Replacement { slt,refresh_token } if slt=="replacement-slt" && refresh_token.as_deref()==Some("synthetic-refresh-v2"))
        );
        service.release(&org, recovery_lease).await?;
        // An unavailable revocation endpoint leaves the exact old family and
        // durable operation intact; a restart must not invent another key.
        assert!(matches!(
            service
                .reprovision(&org, "replacement-slt", "recovery-operation")
                .await,
            Err(PublisherCredentialError::Unavailable)
        ));
        assert_eq!(
            service
                .read(&org)
                .await?
                .ok_or("missing replacement")?
                .operation_key,
            revocation_key
        );
        assert!(matches!(
            service
                .reprovision(&org, "different-slt", "different-operation")
                .await,
            Err(PublisherCredentialError::Conflict)
        ));
        let recovery_lease = Uuid::now_v7();
        let replacement = restarted.claim(&org, recovery_lease).await?;
        // Model the successful idempotent revocation response. Its next login
        // operation is committed before any attempt to exchange the new SLT.
        let staged = restarted
            .finish_replacement(&org, recovery_lease, replacement.id, "replacement-slt")
            .await?;
        assert_ne!(staged.operation_key, revocation_key);
        assert!(!staged.rejected);
        assert!(!staged.validated);
        assert!(staged.actor_id.is_none());
        let payload = restarted.open(staged.id, &staged.encrypted_credentials)?;
        assert!(matches!(&payload,StoredCredentials::Bootstrap { slt } if slt=="replacement-slt"));
        restarted.release(&org, recovery_lease).await?;

        // Cleaning a selected sandbox must erase its publisher while leaving
        // production untouched, and a stale generation must not recreate it.
        let environment = Uuid::now_v7();
        sqlx::query("INSERT INTO hook_control.environments(id,org_id,creator_kind,creator_id,name,key_hash,iam_key_hash,encrypted_credentials,creation_request_hash,creation_input_hash)
            VALUES($1,$2,'silicon','fixture','Publisher test',$3,$4,'{}',$3,$4)")
            .bind(environment).bind(org.as_str()).bind(vec![17_u8;32]).bind(vec![18_u8;32]).execute(&pool).await?;
        let scoped_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(url.parse::<PgConnectOptions>()?.options([
                ("hook.environment_id", environment.to_string()),
                ("hook.environment_generation", "1".into()),
            ]))
            .await?;
        let scoped = credentials(PostgresStore::new(scoped_pool.clone())).await?;
        scoped
            .stage(&org, "synthetic-slt", &request_hash, &input_hash)
            .await?;
        let old_lease = Uuid::now_v7();
        let bootstrap = scoped.claim(&org, old_lease).await?;
        let established = scoped
            .save_issued(&org, old_lease, &bootstrap, &renewed)
            .await?;
        sqlx::query(
            "UPDATE hook_private.ting_publisher_credentials SET validated=true WHERE id=$1",
        )
        .bind(established.id)
        .execute(&pool)
        .await?;
        sqlx::query("UPDATE hook_control.environments SET generation=2 WHERE id=$1")
            .bind(environment)
            .execute(&pool)
            .await?;
        let new_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(url.parse::<PgConnectOptions>()?.options([
                ("hook.environment_id", environment.to_string()),
                ("hook.environment_generation", "2".into()),
            ]))
            .await?;
        let rotated = credentials(PostgresStore::new(new_pool.clone())).await?;
        let new_lease = Uuid::now_v7();
        let adopted = rotated.claim(&org, new_lease).await?;
        assert_eq!(
            adopted.encrypted_credentials,
            established.encrypted_credentials
        );
        assert!(
            !adopted.validated,
            "a changed generation must reauthorize its retained family"
        );
        assert!(scoped.reject(&org, old_lease).await.is_err());
        rotated.release(&org, new_lease).await?;
        assert!(
            rotated.access_token(&org).await.is_err(),
            "an unconfigured IAM cannot revalidate the adopted family"
        );
        sqlx::query("SELECT hook_control.clean_environment($1)")
            .bind(environment)
            .execute(&pool)
            .await?;
        assert!(rotated.read(&org).await?.is_none());
        assert!(
            rotated
                .stage(&org, "synthetic-slt", &request_hash, &input_hash)
                .await
                .is_err()
        );
        let remaining: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM hook_private.ting_publisher_credentials WHERE environment_id=$1",
        )
        .bind(environment)
        .fetch_one(&pool)
        .await?;
        assert_eq!(remaining, 0);
        assert!(service.read(&org).await?.is_some());
        new_pool.close().await;
        scoped_pool.close().await;
        pool.close().await;
        Ok(())
    }

    #[test]
    fn expired_idempotent_iam_reply_does_not_gain_a_new_lifetime()
    -> Result<(), PublisherCredentialError> {
        let issued = OffsetDateTime::UNIX_EPOCH;
        let replayed_at = issued + time::Duration::hours(2);
        let expiry = conservative_expiry(issued, Duration::from_secs(3600))?;
        assert!(expiry < replayed_at);
        assert_eq!(expiry, issued + time::Duration::hours(1));
        Ok(())
    }

    #[test]
    fn bootstrap_hashes_bind_both_purpose_and_organization()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = OrganizationId::new("one")?;
        let second = OrganizationId::new("two")?;
        assert_ne!(
            digest(b"publisher-operation", &first, "same"),
            digest(b"publisher-operation", &second, "same")
        );
        assert_ne!(
            digest(b"publisher-operation", &first, "same"),
            digest(b"publisher-bootstrap", &first, "same")
        );
        assert!(validate_input("an-opaque-slt", "operation-key").is_ok());
        assert_eq!(
            validate_input("credential\nheader", "operation-key"),
            Err(PublisherCredentialError::InvalidInput)
        );
        Ok(())
    }
}
