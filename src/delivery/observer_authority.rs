//! Live recipient authorization for future Carbon event references.
//!
//! The enclosing runtime owns refresh. Hook retains only the encrypted current
//! access token and never substitutes the publisher's authority for the Carbon.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    domain::{
        Action, ActorKind, AuthorizationContext, EncryptedSecret, EncryptionKeyId, OrganizationId,
        SigningSecret, SiliconId, authorize,
    },
    infrastructure::{
        crypto::SecretCipher,
        iam::{AuthorizationRequest, IamClient, IamError},
        postgres::{PostgresStore, StoreError, TingOutboxClaim},
    },
};

use super::subscriptions::{ReceivingSubscription, SubscriptionError};

/// A checked binding version; it contains no credentials or event data.
#[derive(Clone, Debug)]
pub struct ObserverPermit {
    binding_id: Uuid,
    version: Uuid,
}

/// Safe reasons that a Carbon copy must not be published.
#[derive(Debug)]
pub enum ObserverFailure {
    /// The current actor no longer has access; revoke only this checked version.
    Revoked(ObserverPermit),
    /// Missing or expired actor authority; the runtime must subscribe again.
    RefreshRequired,
    /// IAM or the encrypted authority store could not be checked safely.
    Unavailable,
}

/// Encrypted current recipient credentials and current IAM visibility checks.
#[derive(Clone)]
pub struct ObserverAuthorities {
    store: PostgresStore,
    cipher: Arc<SecretCipher>,
    iam: IamClient,
}

impl std::fmt::Debug for ObserverAuthorities {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObserverAuthorities")
            .finish_non_exhaustive()
    }
}

impl ObserverAuthorities {
    /// Uses the already selected production or isolated environment context.
    #[must_use]
    pub fn new(store: PostgresStore, cipher: Arc<SecretCipher>, iam: IamClient) -> Self {
        Self { store, cipher, iam }
    }

    /// Atomically subscribes or renews the caller's encrypted access authority.
    /// The HTTP boundary must first verify this exact token and its Ting grant.
    ///
    /// # Errors
    /// Returns subscription, encryption or storage failures without credentials.
    pub async fn subscribe(
        &self,
        authorization: &AuthorizationContext,
        silicon: &SiliconId,
        token: &SecretString,
    ) -> Result<ReceivingSubscription, SubscriptionError> {
        super::subscriptions::subscribe_with_authority(
            &self.store,
            authorization,
            silicon,
            Some((&self.cipher, token)),
        )
        .await
    }

    /// Checks the exact Carbon's live identity and target access before sending.
    /// No state is inferred from the backend publisher's wider credentials.
    ///
    /// # Errors
    /// Distinguishes revoked target access from expired or unavailable authority.
    pub async fn authorize(
        &self,
        claim: &TingOutboxClaim,
    ) -> Result<ObserverPermit, ObserverFailure> {
        let binding_id = claim
            .recipient_binding_id
            .ok_or(ObserverFailure::Unavailable)?;
        let row = sqlx::query_as::<_, (Option<Uuid>, Option<serde_json::Value>)>(
            "SELECT authority_version, encrypted_authority FROM hook_private.ting_recipient_bindings
             WHERE id=$1 AND org_id=$2 AND silicon_id=$3 AND recipient_id=$4
               AND environment_id=$5 AND environment_id=hook_private.environment_id()
               AND hook_private.environment_is_available()",
        ).bind(binding_id).bind(&claim.org_id).bind(&claim.silicon_id).bind(&claim.recipient_id)
            .bind(claim.environment_id).fetch_optional(self.store.pool()).await
            .map_err(|_| ObserverFailure::Unavailable)?;
        let Some((Some(version), Some(sealed))) = row else {
            return Err(ObserverFailure::RefreshRequired);
        };
        let permit = ObserverPermit {
            binding_id,
            version,
        };
        let token =
            open(&self.cipher, binding_id, sealed).map_err(|()| ObserverFailure::Unavailable)?;
        let org_id =
            OrganizationId::new(claim.org_id.clone()).map_err(|_| ObserverFailure::Unavailable)?;
        let target =
            SiliconId::new(claim.silicon_id.clone()).map_err(|_| ObserverFailure::Unavailable)?;
        let request = AuthorizationRequest {
            token,
            org_id,
            targets: vec![target.clone()],
        };
        let authorization = self
            .iam
            .authorize(&request)
            .await
            .map_err(|error| match error {
                IamError::InvalidCredential | IamError::Forbidden | IamError::NotFound => {
                    ObserverFailure::RefreshRequired
                }
                _ => ObserverFailure::Unavailable,
            })?;
        if authorization.actor().kind() != ActorKind::Carbon
            || authorization.actor().id().as_str() != claim.recipient_id
            || authorization.organization_id().as_str() != claim.org_id
            || !authorize(&authorization, Action::ReadEvents, &target).is_allowed()
        {
            return Err(ObserverFailure::Revoked(permit));
        }
        Ok(permit)
    }

    /// Checks renewal/unsubscribe races immediately before external publication.
    ///
    /// # Errors
    /// Returns database failures.
    pub async fn is_current(&self, permit: &ObserverPermit) -> Result<bool, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM hook_private.ting_recipient_bindings
             WHERE id=$1 AND authority_version=$2 AND environment_id=hook_private.environment_id()
               AND hook_private.environment_is_available())",
        )
        .bind(permit.binding_id)
        .bind(permit.version)
        .fetch_one(self.store.pool())
        .await?)
    }

    /// Cancels only the denied version and its observer copies, never primary sends.
    /// Call after releasing any shared environment lifecycle guard.
    ///
    /// # Errors
    /// Returns database failures.
    pub async fn revoke(&self, permit: &ObserverPermit) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM hook_private.ting_recipient_bindings
            WHERE id=$1 AND authority_version=$2 AND environment_id=hook_private.environment_id()
              AND hook_private.environment_is_available()",
        )
        .bind(permit.binding_id)
        .bind(permit.version)
        .execute(self.store.pool())
        .await?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedAuthority {
    key_id: String,
    nonce: [u8; 12],
    ciphertext: String,
}

fn binding(id: Uuid) -> crate::domain::HookId {
    let mut hash = Sha256::new();
    hash.update(b"hook-ting-observer-access-v1\0");
    hash.update(id.as_bytes());
    let hash = hash.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    Uuid::from_bytes(bytes).into()
}

pub(super) fn seal(
    cipher: &SecretCipher,
    id: Uuid,
    token: &SecretString,
) -> Result<serde_json::Value, SubscriptionError> {
    let fail = || SubscriptionError::AuthorityUnavailable;
    let secret = SigningSecret::from_zeroizing(Zeroizing::new(token.expose_secret().to_owned()))
        .map_err(|_| fail())?;
    let sealed = cipher.encrypt(binding(id), &secret).map_err(|_| fail())?;
    serde_json::to_value(SealedAuthority {
        key_id: sealed.key_id().as_str().to_owned(),
        nonce: *sealed.nonce(),
        ciphertext: URL_SAFE_NO_PAD.encode(sealed.ciphertext()),
    })
    .map_err(|_| fail())
}

fn open(cipher: &SecretCipher, id: Uuid, value: serde_json::Value) -> Result<SecretString, ()> {
    let sealed: SealedAuthority = serde_json::from_value(value).map_err(|_| ())?;
    let secret = EncryptedSecret::new(
        EncryptionKeyId::new(sealed.key_id).map_err(|_| ())?,
        sealed.nonce,
        URL_SAFE_NO_PAD.decode(sealed.ciphertext).map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    let plain = cipher.decrypt(binding(id), &secret).map_err(|_| ())?;
    Ok(SecretString::from(plain.as_str()))
}
