//! Testing-only scoped receiver capabilities; never general Ting sessions.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{IamClient, TingClient, TingError, identifier};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiverEnvironment {
    pub(crate) kind: String,
    pub(crate) id: Uuid,
    /// Shared Honeycomb generation, not Hook's internal credential generation.
    pub(crate) generation: i64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ReceiverScope {
    pub(crate) app_id: String,
    #[serde(rename = "for")]
    pub(crate) recipient: String,
    pub(crate) kind: String,
    /// IAM UUID verified from the selected Hook authorization snapshot.
    pub(crate) org_id: Uuid,
    /// Hook's canonical handle retained for event hydration.
    pub(crate) hook_org_id: String,
    pub(crate) environment: ReceiverEnvironment,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiverCapability {
    pub(crate) receiver_id: String,
    pub(crate) receiver_token: SecretString,
    #[serde(rename = "for")]
    recipient: String,
    kind: String,
    app_id: String,
    org_id: Uuid,
    pub(crate) environment: ReceiverEnvironment,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) expires_at: OffsetDateTime,
}

#[derive(Serialize)]
struct Bootstrap<'a> {
    org_id: Uuid,
    app_id: &'a str,
    #[serde(rename = "for")]
    recipient: &'a str,
    key: String,
    environment_id: Uuid,
    generation: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    receiver_id: Option<&'a str>,
}

impl TingClient {
    pub(crate) async fn bootstrap_receiver(
        &self,
        iam: &IamClient,
        token: &SecretString,
        scope: &ReceiverScope,
        key: &str,
        receiver_id: Option<&str>,
    ) -> Result<ReceiverCapability, TingError> {
        if !iam.is_testing()
            || iam.application_id() != Some(scope.app_id.as_str())
            || scope.environment.kind != "testing"
            || scope.environment.id.is_nil()
            || scope.environment.generation <= 0
            || scope.org_id.is_nil()
            || !matches!(scope.kind.as_str(), "carbon" | "silicon")
            || !identifier(&scope.recipient, 255)
            || !identifier(&scope.hook_org_id, 100)
            || !(8..=255).contains(&key.len())
            || !identifier(key, 255)
            || receiver_id.is_some_and(|id| !identifier(id, 255))
        {
            return Err(TingError::InvalidInput("invalid_receiver_context"));
        }
        // A fixed field order and bounded key preserve the exact proof body on
        // retries. Environment/generation come from the caller's pinned scope.
        let body = serde_json::to_vec(&Bootstrap {
            org_id: scope.org_id,
            app_id: &scope.app_id,
            recipient: &scope.recipient,
            key: format!("hook:{}", hex::encode(Sha256::digest(key.as_bytes()))),
            environment_id: scope.environment.id,
            generation: scope.environment.generation,
            receiver_id,
        })
        .map_err(|_| TingError::InvalidInput("invalid_receiver_request"))?;
        let proof = iam
            .ting_proof(
                token,
                &scope.hook_org_id,
                "receivers.bootstrap",
                "/v1/receivers/bootstrap",
                &body,
            )
            .await?;
        if proof.testing.is_none() {
            return Err(TingError::InvalidResponse);
        }
        let requested_at = OffsetDateTime::now_utc();
        let (status, body) = self.post("/v1/receivers/bootstrap", &body, &proof).await?;
        if !matches!(status, 200 | 201) {
            return Err(TingError::InvalidResponse);
        }
        let capability: ReceiverCapability =
            serde_json::from_slice(&body).map_err(|_| TingError::InvalidResponse)?;
        validate_capability(
            &capability,
            scope,
            receiver_id,
            status,
            requested_at,
            proof.expires_at,
        )?;
        Ok(capability)
    }
}

fn validate_capability(
    capability: &ReceiverCapability,
    scope: &ReceiverScope,
    receiver_id: Option<&str>,
    status: u16,
    requested_at: OffsetDateTime,
    proof_expiry: OffsetDateTime,
) -> Result<(), TingError> {
    use secrecy::ExposeSecret as _;
    if capability.recipient != scope.recipient
        || capability.kind != scope.kind
        || capability.app_id != scope.app_id
        || capability.org_id != scope.org_id
        || capability.environment != scope.environment
        || !identifier(&capability.receiver_id, 255)
        || receiver_id.is_some_and(|id| id != capability.receiver_id)
        || !capability
            .receiver_token
            .expose_secret()
            .strip_prefix("ting_recv_")
            .is_some_and(|token| token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()))
        || capability.expires_at > proof_expiry
        || capability.expires_at > OffsetDateTime::now_utc() + time::Duration::seconds(30)
        || (status == 201 && capability.expires_at < requested_at - time::Duration::seconds(1))
    {
        return Err(TingError::InvalidResponse);
    }
    // A 200 recovery can return an already-expired original capability. Keep
    // its original receiver ID/expiry so the caller can explicitly renew it;
    // recovering a receipt never extends authority or means receiving is ready.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{IamSettings, IamWebhookSettings},
        domain::{ActorId, ActorKind, ActorRef, OrganizationId},
    };
    use serde_json::{Value, json};
    use std::time::Duration;
    use time::format_description::well_known::Rfc3339;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const HOOK_KEY: &str = "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH";
    const TING_KEY: &str = "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT";
    const SUBJECT: &str = "oat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn scope() -> ReceiverScope {
        ReceiverScope {
            app_id: "hook".into(),
            recipient: "si:worker".into(),
            kind: "silicon".into(),
            org_id: Uuid::new_v4(),
            hook_org_id: "tos".into(),
            environment: ReceiverEnvironment {
                kind: "testing".into(),
                id: Uuid::new_v4(),
                generation: 7,
            },
        }
    }

    fn response(
        scope: &ReceiverScope,
        expiry: OffsetDateTime,
    ) -> Result<Value, time::error::Format> {
        Ok(
            json!({"receiver_id":"recv_fixture", "receiver_token":format!("ting_recv_{}", "a".repeat(64)),
            "for":scope.recipient,"kind":scope.kind,"app_id":scope.app_id,"org_id":scope.org_id,
            "environment":scope.environment,"expires_at":expiry.format(&Rfc3339)?}),
        )
    }

    async fn fixture(
        scope: &ReceiverScope,
    ) -> Result<(MockServer, IamClient, IamClient), Box<dyn std::error::Error>> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/api/version"))
            .respond_with(ResponseTemplate::new(200).insert_header("silicon-iam-api-version", "v1")
                    .insert_header("vary", "Silicon-IAM-Supported-API-Versions")
                .set_body_json(json!({"service":"silicon-iam","selected_api_version":"v1","supported_api_versions":["v1"],"build":"test","commit":"test"})))
            .mount(&server).await;
        Mock::given(method("POST")).and(path("/api/v1/oauth/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active":true,"authorization":{
                "actor_type":"silicon","public_id":scope.recipient,"organization_id":scope.org_id,"org_id":"tos",
                "membership_id":"si:worker[tos]","membership_version":1,"authorization_epoch":1,"audience":"hook",
                "testing_environment_id":scope.environment.id,"scopes":[],"org_role":null,"tags":null}})))
            .mount(&server).await;
        Mock::given(method("GET")).and(path("/api/v1/obo-access/applications/ting/endpoints"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"application":{"app_id":"ting","org_id":"tos"},
                "endpoints":[{"endpoint_id":"receivers.bootstrap","path":"/v1/receivers/bootstrap","metadata":{},"critical":true,"ttl_seconds":30}]})))
            .mount(&server).await;
        Mock::given(method("POST")).and(path("/api/v1/obo-access/exchanges"))
            .respond_with(|_: &wiremock::Request| ResponseTemplate::new(200).set_body_json(json!({
                "access_proof":format!("proof_{}",Uuid::new_v4()),"proof_id":Uuid::new_v4(),"expires_in":30,
                "expires_at":(OffsetDateTime::now_utc()+time::Duration::seconds(30)).format(&Rfc3339).unwrap_or_default(),
                "testing_context":{"app_id":"ting","app_secret":"ask_ting_audience_secret","iam_test_key":TING_KEY}})))
            .mount(&server).await;
        let iam = IamClient::connect(&IamSettings {
            base_url: Url::parse(&server.uri())?,
            app_id: Some("hook".into()),
            app_secret: Some(SecretString::from("ask_hook_source_secret")),
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(2),
            max_response_bytes: 65_536,
            allow_insecure_local_http: true,
            local_auth: false,
            webhook: None,
        })
        .await?;
        let testing = iam
            .for_environment(
                HOOK_KEY,
                "hook",
                "ask_hook_source_secret",
                &IamWebhookSettings {
                    secret: SecretString::from("whs_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
                    version: 1,
                    previous: None,
                },
            )
            .await?;
        Ok((server, testing, iam))
    }

    #[tokio::test]
    async fn receiver_retries_keep_exact_body_but_use_fresh_audience_scoped_proofs() -> TestResult {
        let scope = scope();
        let (issuer, iam, _) = fixture(&scope).await?;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/receivers/bootstrap"))
            .respond_with(ResponseTemplate::new(201).set_body_json(response(
                &scope,
                OffsetDateTime::now_utc() + time::Duration::seconds(20),
            )?))
            .expect(2)
            .mount(&server)
            .await;
        let client = TingClient::new(&server.uri(), Duration::from_secs(2))?;
        for _ in 0..2 {
            let result = client
                .bootstrap_receiver(
                    &iam,
                    &SecretString::from(SUBJECT),
                    &scope,
                    "stable-hook-operation",
                    None,
                )
                .await?;
            assert!(!format!("{result:?}").contains("ting_recv_"));
        }
        let requests = server
            .received_requests()
            .await
            .ok_or("missing Ting requests")?;
        assert_eq!(requests[0].body, requests[1].body);
        assert_ne!(
            requests[0].headers["authorization"],
            requests[1].headers["authorization"]
        );
        for request in &requests {
            assert_eq!(
                request.headers["iam_test_app_secret"],
                "ask_ting_audience_secret"
            );
            assert_eq!(request.headers["x-testing-environment-key"], TING_KEY);
            let body: Value = serde_json::from_slice(&request.body)?;
            assert_eq!(body["org_id"], scope.org_id.to_string());
            assert_eq!(body["generation"], 7);
            assert_eq!(
                body["key"],
                format!(
                    "hook:{}",
                    hex::encode(Sha256::digest(b"stable-hook-operation"))
                )
            );
        }
        let exchanges: Vec<_> = issuer
            .received_requests()
            .await
            .ok_or("missing IAM requests")?
            .into_iter()
            .filter(|r| r.url.path() == "/api/v1/obo-access/exchanges")
            .collect();
        assert_eq!(exchanges.len(), 2);
        assert_ne!(
            exchanges[0].headers["idempotency-key"],
            exchanges[1].headers["idempotency-key"]
        );
        for exchange in exchanges {
            let body: Value = serde_json::from_slice(&exchange.body)?;
            assert_eq!(body["endpoint_id"], "receivers.bootstrap");
            assert_eq!(body["org_id"], "tos");
            assert_eq!(
                body["request"]["body_sha256"],
                hex::encode(Sha256::digest(&requests[0].body))
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn receiver_organization_uses_current_iam_mapping_and_rejects_other_authority()
    -> TestResult {
        let scope = scope();
        let (_, iam, production) = fixture(&scope).await?;
        let token = SecretString::from(SUBJECT);
        let org = OrganizationId::new("tos")?;
        let actor = ActorRef::new(ActorKind::Silicon, ActorId::new("si:worker")?);
        assert_eq!(
            iam.ting_receiver_organization(&token, &org, &actor, scope.environment.id)
                .await?,
            scope.org_id
        );
        for (actor, environment) in [
            (
                ActorRef::new(ActorKind::Carbon, ActorId::new("si:worker")?),
                scope.environment.id,
            ),
            (
                ActorRef::new(ActorKind::Silicon, ActorId::new("si:other")?),
                scope.environment.id,
            ),
            (actor, Uuid::new_v4()),
        ] {
            assert!(
                iam.ting_receiver_organization(&token, &org, &actor, environment)
                    .await
                    .is_err()
            );
        }
        let client = TingClient::new("http://127.0.0.1:1", Duration::from_millis(10))?;
        assert!(matches!(
            client
                .bootstrap_receiver(&production, &token, &scope, "stable-operation", None)
                .await,
            Err(TingError::InvalidInput(_))
        ));
        assert!(
            production
                .ting_proof(
                    &token,
                    "tos",
                    "receivers.bootstrap",
                    "/v1/receivers/bootstrap",
                    b"{}"
                )
                .await
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn receiver_capability_rejects_cross_scope_and_excess_authority() -> TestResult {
        let scope = scope();
        let now = OffsetDateTime::now_utc();
        let value = response(&scope, now + time::Duration::seconds(20))?;
        for (field, bad) in [
            ("for", json!("si:other")),
            ("kind", json!("carbon")),
            ("app_id", json!("other")),
            ("org_id", json!(Uuid::new_v4())),
            ("receiver_token", json!("opaque_general_session")),
            (
                "expires_at",
                json!((now + time::Duration::seconds(31)).format(&Rfc3339)?),
            ),
            (
                "environment",
                json!({"kind":"production","id":scope.environment.id,"generation":7}),
            ),
            (
                "environment",
                json!({"kind":"testing","id":Uuid::new_v4(),"generation":7}),
            ),
            (
                "environment",
                json!({"kind":"testing","id":scope.environment.id,"generation":8}),
            ),
        ] {
            let mut bad_value = value.clone();
            bad_value[field] = bad;
            let capability = serde_json::from_value(bad_value)?;
            assert!(
                validate_capability(
                    &capability,
                    &scope,
                    None,
                    201,
                    now,
                    now + time::Duration::seconds(30)
                )
                .is_err(),
                "{field}"
            );
        }
        let capability = serde_json::from_value(value)?;
        assert!(
            validate_capability(
                &capability,
                &scope,
                Some("other_receiver"),
                201,
                now,
                now + time::Duration::seconds(30)
            )
            .is_err()
        );
        assert!(
            validate_capability(
                &capability,
                &scope,
                None,
                201,
                now,
                now + time::Duration::seconds(10)
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn receiver_expired_replay_preserves_original_receipt_without_extending_authority() -> TestResult
    {
        let scope = scope();
        let now = OffsetDateTime::now_utc();
        let expired = now - time::Duration::minutes(5);
        let capability = serde_json::from_value(response(&scope, expired)?)?;
        validate_capability(
            &capability,
            &scope,
            Some("recv_fixture"),
            200,
            now,
            now + time::Duration::seconds(30),
        )?;
        assert_eq!(capability.expires_at, expired);
        assert!(
            validate_capability(
                &capability,
                &scope,
                None,
                201,
                now,
                now + time::Duration::seconds(30)
            )
            .is_err()
        );
        Ok(())
    }
}
