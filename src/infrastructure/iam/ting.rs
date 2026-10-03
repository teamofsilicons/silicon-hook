//! Request-bound Ting proofs issued through the official IAM client.

use secrecy::{ExposeSecret as _, SecretString};
use silicon_iam_client::{EnvironmentKey, models};
use uuid::Uuid;

use super::{IamClient, IamError, sdk_error};
use crate::domain::{ActorKind, ActorRef, OrganizationId};
use crate::infrastructure::ting::{TingProof, TingTestingCredentials};

impl IamClient {
    /// Resolve Ting's organization UUID from current IAM authority, not response aliases.
    pub(crate) async fn ting_receiver_organization(
        &self,
        token: &SecretString,
        org: &OrganizationId,
        actor: &ActorRef,
        environment: Uuid,
    ) -> Result<Uuid, IamError> {
        if !self.is_testing() || environment.is_nil() {
            return Err(IamError::Forbidden);
        }
        let snapshot = self
            .sdk()?
            .oauth()
            .authorization(token.expose_secret(), Some(org.as_str()))
            .await
            .map_err(sdk_error)?
            .ok_or(IamError::InvalidCredential)?;
        let kind = match actor.kind() {
            ActorKind::Carbon => models::ApplicationAuthorizationActorType::Carbon,
            ActorKind::Silicon => models::ApplicationAuthorizationActorType::Silicon,
        };
        if snapshot.audience != self.app_id()?
            || snapshot.org_id != org.as_str()
            || snapshot.public_id.as_deref() != Some(actor.id().as_str())
            || snapshot.actor_type != Some(kind)
            || snapshot.testing_environment_id != Some(environment)
            || snapshot.organization_id.is_nil()
        {
            return Err(IamError::InvalidCredential);
        }
        Ok(snapshot.organization_id)
    }

    /// Loads only separately approved, renewable authority for one fixed endpoint.
    pub(crate) async fn ting_proof(
        &self,
        subject_token: &SecretString,
        org_id: &str,
        endpoint_id: &str,
        path: &str,
        _body: &[u8],
    ) -> Result<TingProof, IamError> {
        let expected = match endpoint_id {
            "tings.send" => "/v1/tings",
            "subscriptions.register" => "/v1/subscriptions",
            "sent.query" => "/v1/sent/query",
            "receivers.bootstrap" if self.is_testing() => "/v1/receivers/bootstrap",
            _ => return Err(IamError::InvalidInput("ting_endpoint")),
        };
        if path != expected {
            return Err(IamError::InvalidInput("ting_endpoint"));
        }
        self.ting_grants
            .as_ref()
            .ok_or(IamError::TingAuthorizationRequired)?
            .authority(self, subject_token, org_id, endpoint_id)
            .await
    }
}

pub(super) fn testing_credentials(
    app_secret: String,
    environment_key: String,
) -> Result<TingTestingCredentials, IamError> {
    if app_secret.is_empty()
        || app_secret.len() > 4096
        || !app_secret.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(IamError::InvalidResponse);
    }
    EnvironmentKey::new(environment_key.clone()).map_err(|_| IamError::InvalidResponse)?;
    Ok(TingTestingCredentials {
        app_secret: SecretString::from(app_secret),
        environment_key: SecretString::from(environment_key),
    })
}
