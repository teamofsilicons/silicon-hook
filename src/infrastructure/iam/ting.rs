//! Request-bound Ting proofs issued through the official IAM client.

use secrecy::SecretString;
use silicon_iam_client::EnvironmentKey;

use super::{IamClient, IamError};
use crate::infrastructure::ting::{TingProof, TingTestingCredentials};

impl IamClient {
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
