//! Request-bound Ting proofs issued through the official IAM client.

use secrecy::{ExposeSecret as _, SecretString};
use silicon_iam_client::{EnvironmentKey, Mutation, api::obo::body_sha256, models};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{IamClient, IamError, sdk_error};
use crate::domain::{ActorKind, ActorRef, OrganizationId};
use crate::infrastructure::ting::{TingProof, TingTestingCredentials};

const TING_APPLICATION: &str = "tos>ting";

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

    /// Issues a fresh single-use proof for one fixed Ting operation.
    ///
    /// The exact body is hashed without being reserialized. An uncertain IAM
    /// exchange is abandoned: the next attempt issues a different proof and
    /// retains the downstream operation's own idempotency key.
    pub(crate) async fn ting_proof(
        &self,
        subject_token: &SecretString,
        org_id: &str,
        endpoint_id: &str,
        path: &str,
        body: &[u8],
    ) -> Result<TingProof, IamError> {
        let expected_path = match endpoint_id {
            "tings.send" => "/v1/tings",
            "subscriptions.register" => "/v1/subscriptions",
            "sent.query" => "/v1/sent/query",
            "receivers.bootstrap" if self.is_testing() => "/v1/receivers/bootstrap",
            _ => return Err(IamError::InvalidInput("ting_endpoint")),
        };
        if path != expected_path
            || org_id.is_empty()
            || org_id.len() > 255
            || org_id.chars().any(char::is_control)
            || !(32..=4096).contains(&subject_token.expose_secret().len())
            || subject_token.expose_secret().starts_with("local:")
        {
            return Err(IamError::InvalidInput("ting_proof"));
        }
        let sdk = self.sdk()?;
        let catalog = sdk
            .obo()
            .endpoints(TING_APPLICATION)
            .await
            .map_err(sdk_error)?;
        let mut matching = catalog
            .endpoints
            .iter()
            .filter(|item| item.endpoint_id == endpoint_id);
        let endpoint = matching.next().ok_or(IamError::InvalidResponse)?;
        // IAM's catalog has no method field. The signed request binds POST;
        // only the exact, fixed Ting path from this catalog is permitted.
        if catalog.application.app_id != TING_APPLICATION
            || matching.next().is_some()
            || endpoint.path != expected_path
            || !endpoint.critical
            || !endpoint
                .metadata
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
            || endpoint
                .ttl_seconds
                .is_some_and(|ttl| !(1..=60).contains(&ttl))
        {
            return Err(IamError::InvalidResponse);
        }
        let response = sdk
            .obo()
            .exchange_signed(
                &models::OboExchangeRequest {
                    org_id: Some(org_id.to_owned()),
                    subject_token: subject_token.expose_secret().to_owned(),
                    audience: TING_APPLICATION.to_owned(),
                    endpoint_id: endpoint_id.to_owned(),
                    metadata: serde_json::json!({}),
                    request: models::OboExchangeRequestBinding {
                        method: "POST".to_owned(),
                        body_sha256: body_sha256(body),
                    },
                },
                &catalog,
                &Mutation::new(),
            )
            .await
            .map_err(|error| match error {
                silicon_iam_client::Error::Api(error) if error.code == "invalid_subject_token" => {
                    IamError::InvalidCredential
                }
                other => sdk_error(other),
            })?;
        let now = OffsetDateTime::now_utc();
        if response.expires_in <= 0
            || response.expires_in > 60
            || response.expires_at <= now
            || (response.expires_at - now).whole_seconds() > 60
            || response.access_proof.is_empty()
            || response.access_proof.len() > 16_384
            || !response
                .access_proof
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
        {
            return Err(IamError::InvalidResponse);
        }
        let testing = match (self.is_testing(), response.testing_context) {
            (false, None) => None,
            (true, Some(context)) if context.app_id == TING_APPLICATION => Some(
                testing_credentials(context.app_secret, context.iam_test_key)?,
            ),
            _ => return Err(IamError::InvalidResponse),
        };
        Ok(TingProof {
            token: SecretString::from(response.access_proof),
            testing,
            expires_at: response.expires_at,
        })
    }
}

fn testing_credentials(
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
