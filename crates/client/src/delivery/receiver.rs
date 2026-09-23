//! Testing-only receiver acquisition for an enclosing app's internal transport.

use reqwest::Method;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{DeliveryContext, identifier};
use crate::{Client, Error, Mutation, Result, Secret};

fn receiver_error(error: Error) -> Error {
    match error {
        // Serde's invalid enum/value diagnostics may quote an upstream value.
        // A malformed secret-bearing response must not put it in an error log.
        Error::Json(_) => Error::Protocol("invalid scoped receiver response".into()),
        other => other,
    }
}

/// IAM actor kind attested by Hook for a scoped receiver.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverKind {
    Carbon,
    Silicon,
}

impl ReceiverKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Carbon => "carbon",
            Self::Silicon => "silicon",
        }
    }
}

/// Current shared test lifecycle; its generation differs from Hook credentials.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct ReceiverEnvironment {
    pub kind: String,
    pub id: Uuid,
    pub generation: i64,
}

/// Scope verified against the selected Hook actor, organization and environment.
/// Retain this exact scope with the mutation when a bootstrap outcome is uncertain.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct ReceiverScope {
    pub app_id: String,
    #[serde(rename = "for")]
    pub recipient: String,
    pub kind: ReceiverKind,
    /// Authoritative IAM organization UUID, used by Ting.
    pub org_id: Uuid,
    /// Hook's canonical handle, used when hydrating event references.
    pub hook_org_id: String,
    pub environment: ReceiverEnvironment,
}

impl ReceiverScope {
    /// Hydration routing retains the Hook handle and original event generation.
    pub fn delivery_context(&self) -> DeliveryContext {
        DeliveryContext {
            app_id: self.app_id.clone(),
            org_id: self.hook_org_id.clone(),
            recipient_id: self.recipient.clone(),
            environment_id: self.environment.id,
        }
    }

    fn validate(&self) -> Result<()> {
        if !identifier(&self.app_id, 255)
            || !identifier(&self.recipient, 255)
            || !identifier(&self.hook_org_id, 100)
            || self.org_id.is_nil()
            || self.environment.kind != "testing"
            || self.environment.id.is_nil()
            || self.environment.generation <= 0
        {
            return Err(Error::Protocol("invalid scoped receiver authority".into()));
        }
        Ok(())
    }
}

/// Short-lived authority for this actor's Hook inbox/watch only, never a general
/// Ting session, destination enrollment, grant change or acknowledgment.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiverCapability {
    #[serde(flatten)]
    pub scope: ReceiverScope,
    pub receiver_id: String,
    pub receiver_token: Secret,
    /// Exact replay retains the original expiry, including a historical one.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

impl Client {
    fn require_receiver_context(&self) -> Result<()> {
        if !self.is_testing()
            || self
                .token
                .as_ref()
                .is_none_or(|token| token.expose().is_empty())
            || self.org.as_deref().is_none_or(|org| !identifier(org, 100))
        {
            return Err(Error::Invalid(
                "scoped receiving requires a selected test environment, authenticated actor and organization".into(),
            ));
        }
        Ok(())
    }

    /// Read current receiver authority. Requires Ting 0.1.4 at the Hook backend.
    /// This issues no capability and changes no grant. Generation is the shared
    /// Honeycomb lifecycle generation, not `TestEnvironment::generation`.
    pub async fn receiver_scope(&self) -> Result<ReceiverScope> {
        self.require_receiver_context()?;
        let iam = self.iam().await?;
        let status = self.login_status().await?;
        let environment = self.selected_environment().await?;
        let scope: ReceiverScope = self
            .call(
                Method::GET,
                &["delivery", "receiver"],
                &[],
                None::<&()>,
                None,
            )
            .await
            .map_err(receiver_error)?;
        scope.validate()?;
        let actor = status
            .actor
            .ok_or_else(|| Error::Protocol("receiver actor missing".into()))?;
        if !iam.testing
            || !status.authenticated
            || iam.app_id.as_deref() != Some(&scope.app_id)
            || status.org_id.as_deref() != Some(&scope.hook_org_id)
            || self.org.as_deref() != Some(&scope.hook_org_id)
            || actor.id != scope.recipient
            || actor.kind != scope.kind.as_str()
            || environment.id != scope.environment.id
            || environment.org_id != scope.hook_org_id
        {
            return Err(Error::Protocol(
                "receiver differs from selected Hook authority".into(),
            ));
        }
        Ok(scope)
    }

    /// Acquire a testing-only receiver. Retain the scope and mutation before
    /// sending; repeat them unchanged after an uncertain response. This does not
    /// register a recipient, start receiving or acknowledge anything.
    pub async fn bootstrap_receiver(
        &self,
        scope: &ReceiverScope,
        mutation: &Mutation,
    ) -> Result<ReceiverCapability> {
        self.acquire_receiver(scope, None, mutation).await
    }

    /// Explicitly renew with the original receiver ID and a new caller-owned
    /// mutation. A replay returns its original result/expiry without extending
    /// authority. No replacement key or renewal is generated automatically.
    pub async fn renew_receiver(
        &self,
        scope: &ReceiverScope,
        receiver_id: &str,
        mutation: &Mutation,
    ) -> Result<ReceiverCapability> {
        if !identifier(receiver_id, 255) {
            return Err(Error::Invalid("invalid scoped receiver identifier".into()));
        }
        self.acquire_receiver(scope, Some(receiver_id), mutation)
            .await
    }

    async fn acquire_receiver(
        &self,
        scope: &ReceiverScope,
        receiver_id: Option<&str>,
        mutation: &Mutation,
    ) -> Result<ReceiverCapability> {
        self.require_receiver_context()?;
        scope.validate()?;
        if self.org.as_deref() != Some(&scope.hook_org_id) {
            return Err(Error::Invalid(
                "receiver differs from selected organization".into(),
            ));
        }
        #[derive(Serialize)]
        struct Request<'a> {
            environment_id: Uuid,
            generation: i64,
            #[serde(skip_serializing_if = "Option::is_none")]
            receiver_id: Option<&'a str>,
        }
        let result: ReceiverCapability = self
            .call(
                Method::POST,
                &["delivery", "receiver"],
                &[],
                Some(&Request {
                    environment_id: scope.environment.id,
                    generation: scope.environment.generation,
                    receiver_id,
                }),
                Some(mutation),
            )
            .await
            .map_err(receiver_error)?;
        if result.scope != *scope
            || !identifier(&result.receiver_id, 255)
            || receiver_id.is_some_and(|id| id != result.receiver_id)
            || !result
                .receiver_token
                .expose()
                .strip_prefix("ting_recv_")
                .is_some_and(|token| {
                    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
                })
            || result.expires_at > OffsetDateTime::now_utc() + time::Duration::seconds(30)
        {
            return Err(Error::Protocol("invalid scoped receiver response".into()));
        }
        // Historical success is intentionally preserved for explicit renewal;
        // callers must check expires_at before starting a transport.
        Ok(result)
    }
}
