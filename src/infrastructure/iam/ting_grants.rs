//! Dedicated, encrypted Ting endpoint grants. Login credentials only identify the caller.
use super::{IamClient, IamError, sdk_error};
use crate::infrastructure::{crypto::SecretCipher, postgres::PostgresStore, ting::TingProof};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use silicon_iam_client::{Credential, EnvironmentKey, IdempotencyKey, Mutation, models};
use sqlx::PgConnection;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

const ROOTS: [&str; 3] = ["subscriptions.register", "tings.send", "sent.query"];
#[derive(Clone)]
pub(super) struct TingGrants {
    store: PostgresStore,
    cipher: Arc<SecretCipher>,
}
struct Scope {
    environment: Uuid,
    generation: i64,
    app: String,
    org: String,
    kind: String,
    actor: String,
}
impl Scope {
    fn aad(&self, endpoint: &str, grant: Uuid) -> Vec<u8> {
        json!([
            "hook.ting.obo.v1",
            self.environment,
            self.generation,
            self.app,
            self.org,
            self.kind,
            self.actor,
            endpoint,
            grant
        ])
        .to_string()
        .into_bytes()
    }
}
fn unavailable<T>(_: T) -> IamError {
    IamError::InvalidResponse
}

fn retry_key(value: &str) -> Result<Mutation, IamError> {
    let digest = Sha256::digest(value.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Ok(Mutation::with_key(
        IdempotencyKey::parse(Uuid::from_bytes(bytes).to_string()).map_err(sdk_error)?,
    ))
}
fn token_error(error: silicon_iam_client::Error) -> IamError {
    match error {
        silicon_iam_client::Error::Api(ref e)
            if [400, 401, 403, 404, 410].contains(&e.status) && e.code != "invalid_client" =>
        {
            IamError::TingAuthorizationRequired
        }
        other => sdk_error(other),
    }
}
impl IamClient {
    /// Bind encrypted feature authority to the same pool as the current application.
    #[must_use]
    pub fn with_ting_grants(mut self, store: PostgresStore, cipher: Arc<SecretCipher>) -> Self {
        self.ting_grants = Some(TingGrants { store, cipher });
        self
    }
    /// Create an explicit Ting approval request for the authenticated account.
    /// # Errors
    /// Rejects mismatched identity, environment, or unavailable IAM/storage.
    pub async fn authorize_ting(
        &self,
        token: &SecretString,
        org: &str,
        key: &str,
    ) -> Result<Value, IamError> {
        self.ting_grants
            .as_ref()
            .ok_or(IamError::NotConfigured)?
            .begin(self, token, org, key)
            .await
    }
    /// Save dedicated credentials after the user approves the separate request.
    /// # Errors
    /// Rejects changed account, code replay, scope changes, and invalid provider credentials.
    pub async fn complete_ting(
        &self,
        token: &SecretString,
        org: &str,
        id: Uuid,
        code: &str,
    ) -> Result<Value, IamError> {
        self.ting_grants
            .as_ref()
            .ok_or(IamError::NotConfigured)?
            .complete(self, token, org, id, code)
            .await
    }
    /// Return local, non-secret grant status, or disconnect locally stored authority.
    /// # Errors
    /// Rejects invalid current identity and unavailable scoped storage.
    pub async fn ting_authorization_status(
        &self,
        token: &SecretString,
        org: &str,
        disconnect: bool,
    ) -> Result<Value, IamError> {
        self.ting_grants
            .as_ref()
            .ok_or(IamError::NotConfigured)?
            .status(self, token, org, disconnect)
            .await
    }
}
impl TingGrants {
    async fn scope(
        &self,
        iam: &IamClient,
        token: &SecretString,
        org: &str,
    ) -> Result<Scope, IamError> {
        if !token.expose_secret().starts_with("oat_") {
            return Err(IamError::InvalidCredential);
        }
        let snapshot = iam
            .sdk()?
            .oauth()
            .authorization(token.expose_secret(), Some(org))
            .await
            .map_err(sdk_error)?
            .ok_or(IamError::InvalidCredential)?;
        let (environment,generation):(Uuid,i64)=sqlx::query_as("SELECT hook_private.environment_id(), COALESCE(NULLIF(current_setting('hook.environment_generation',true),''),'0')::bigint").fetch_one(self.store.pool()).await.map_err(unavailable)?;
        let kind = match snapshot.actor_type {
            Some(models::ApplicationAuthorizationActorType::Carbon) => "carbon",
            Some(models::ApplicationAuthorizationActorType::Silicon) => "silicon",
            _ => return Err(IamError::Forbidden),
        };
        let actor = snapshot.public_id.ok_or(IamError::Forbidden)?;
        if snapshot.audience != iam.app_id()?
            || snapshot.org_id != org
            || snapshot.testing_environment_id != (!environment.is_nil()).then_some(environment)
            || iam.is_testing() == environment.is_nil()
            || iam.inner.testing_id.is_some_and(|id| id != environment)
            || (environment.is_nil() && generation != 0)
            || (!environment.is_nil() && generation <= 0)
            || !(actor.starts_with("c:") && kind == "carbon"
                || actor.starts_with("si:") && kind == "silicon")
        {
            return Err(IamError::Forbidden);
        }
        Ok(Scope {
            environment,
            generation,
            app: iam.app_id()?.into(),
            org: org.into(),
            kind: kind.into(),
            actor,
        })
    }
    async fn lock(&self, connection: &mut PgConnection, scope: &Scope) -> Result<(), IamError> {
        if !scope.environment.is_nil() {
            let active:Option<(i64,bool)>=sqlx::query_as("SELECT generation,deleted_at IS NULL AND (honeycomb_state IS NULL OR honeycomb_state='ready') FROM hook_control.environments WHERE id=$1 FOR SHARE").bind(scope.environment).fetch_optional(&mut *connection).await.map_err(unavailable)?;
            if active != Some((scope.generation, true)) {
                return Err(IamError::Forbidden);
            }
        }
        let hash = Sha256::digest(scope.aad("lock", Uuid::nil()));
        let mut b = [0; 8];
        b.copy_from_slice(&hash[..8]);
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(i64::from_be_bytes(b))
            .execute(connection)
            .await
            .map_err(unavailable)?;
        Ok(())
    }
    fn roots(iam: &IamClient) -> Vec<&'static str> {
        let mut roots = ROOTS.to_vec();
        if iam.is_testing() {
            roots.push("receivers.bootstrap");
        }
        roots
    }
    // Commit the immutable request before crossing the IAM boundary. Login rotation
    // only revalidates ownership of a retry; it must not change the retained body.
    async fn prepare_start(
        &self,
        iam: &IamClient,
        scope: &Scope,
        token: &SecretString,
        key: &str,
    ) -> Result<(), IamError> {
        let request = models::OboAuthorizationRequest {
            org_id: scope.org.clone(),
            subject_token: token.expose_secret().into(),
            endpoints: Self::roots(iam)
                .iter()
                .map(|id| models::OboAuthorizationEndpoint {
                    audience: "ting".into(),
                    endpoint_id: (*id).into(),
                })
                .collect(),
            redirect_uri: None,
            state: None,
        };
        let sealed = self
            .cipher
            .seal_credential(
                &scope.aad(&format!("start:{key}"), Uuid::nil()),
                &serde_json::to_value(request).map_err(unavailable)?,
            )
            .map_err(unavailable)?;
        let mut tx = self.store.pool().begin().await.map_err(unavailable)?;
        self.lock(&mut tx, scope).await?;
        sqlx::query("INSERT INTO hook_private.ting_authorizations(environment_id,generation,app_id,org_id,actor_kind,actor_id,authorization_id,expires_at,start_key,start_payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(environment_id,generation,app_id,org_id,actor_kind,actor_id,start_key) DO NOTHING")
            .bind(scope.environment).bind(scope.generation).bind(&scope.app).bind(&scope.org).bind(&scope.kind).bind(&scope.actor).bind(Uuid::new_v4()).bind(OffsetDateTime::now_utc()+time::Duration::minutes(10)).bind(key).bind(sealed).execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
    async fn begin(
        &self,
        iam: &IamClient,
        token: &SecretString,
        org: &str,
        key: &str,
    ) -> Result<Value, IamError> {
        let mutation = super::mutation(key)?;
        let scope = self.scope(iam, token, org).await?;
        self.prepare_start(iam, &scope, token, key).await?;
        let mut tx = self.store.pool().begin().await.map_err(unavailable)?;
        self.lock(&mut tx, &scope).await?;
        let (expires, sealed):(OffsetDateTime,Value)=sqlx::query_as("SELECT expires_at,start_payload FROM hook_private.ting_authorizations WHERE environment_id=$1 AND generation=$2 AND app_id=$3 AND org_id=$4 AND actor_kind=$5 AND actor_id=$6 AND start_key=$7 FOR UPDATE")
            .bind(scope.environment).bind(scope.generation).bind(&scope.app).bind(&scope.org).bind(&scope.kind).bind(&scope.actor).bind(key).fetch_one(&mut *tx).await.map_err(unavailable)?;
        if expires <= OffsetDateTime::now_utc() {
            return Err(IamError::TingAuthorizationRequired);
        }
        let request = serde_json::from_value(
            self.cipher
                .open_credential(&scope.aad(&format!("start:{key}"), Uuid::nil()), &sealed)
                .map_err(unavailable)?,
        )
        .map_err(unavailable)?;
        let detail = iam
            .sdk()?
            .obo()
            .authorize(&request, &mutation)
            .await
            .map_err(sdk_error)?;
        if detail.app_id != scope.app
            || detail.org_id != scope.org
            || detail.actor.public_id != scope.actor
            || actor_kind(&detail.actor) != scope.kind
            || detail.expires_at <= OffsetDateTime::now_utc()
        {
            return Err(IamError::Forbidden);
        }
        let url = detail
            .authorization_url
            .as_deref()
            .ok_or(IamError::InvalidResponse)?;
        let parsed = url::Url::parse(url).map_err(unavailable)?;
        if parsed.scheme() != "https"
            && !(parsed.scheme() == "http"
                && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
        {
            return Err(IamError::InvalidResponse);
        }
        sqlx::query("UPDATE hook_private.ting_authorizations SET authorization_id=$8,expires_at=$9 WHERE environment_id=$1 AND generation=$2 AND app_id=$3 AND org_id=$4 AND actor_kind=$5 AND actor_id=$6 AND start_key=$7")
            .bind(scope.environment).bind(scope.generation).bind(&scope.app).bind(&scope.org).bind(&scope.kind).bind(&scope.actor).bind(key).bind(detail.id).bind(detail.expires_at).execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(
            json!({"authorization_id":detail.id,"authorization_url":url,"expires_at":detail.expires_at.format(&time::format_description::well_known::Rfc3339).map_err(unavailable)?,"status":"pending","endpoints":Self::roots(iam)}),
        )
    }
    async fn complete(
        &self,
        iam: &IamClient,
        token: &SecretString,
        org: &str,
        id: Uuid,
        code: &str,
    ) -> Result<Value, IamError> {
        if code.is_empty() || code.len() > 4096 || !code.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(IamError::InvalidInput("authorization_code"));
        }
        let scope = self.scope(iam, token, org).await?;
        let mut tx = self.store.pool().begin().await.map_err(unavailable)?;
        self.lock(&mut tx, &scope).await?;
        let pending:Option<(OffsetDateTime,Option<Vec<u8>>)>=sqlx::query_as("SELECT expires_at,completion_digest FROM hook_private.ting_authorizations WHERE environment_id=$1 AND generation=$2 AND app_id=$3 AND org_id=$4 AND actor_kind=$5 AND actor_id=$6 AND authorization_id=$7 FOR UPDATE")
            .bind(scope.environment).bind(scope.generation).bind(&scope.app).bind(&scope.org).bind(&scope.kind).bind(&scope.actor).bind(id).fetch_optional(&mut *tx).await.map_err(unavailable)?;
        let (expires, completed) = pending.ok_or(IamError::NotFound)?;
        let digest = Sha256::digest(code.as_bytes()).to_vec();
        if let Some(previous) = completed {
            if previous != digest {
                return Err(IamError::InvalidInput("authorization_code"));
            }
            tx.commit().await.map_err(unavailable)?;
            return self.status(iam, token, org, false).await;
        }
        if expires <= OffsetDateTime::now_utc() {
            return Err(IamError::TingAuthorizationRequired);
        }
        let detail = iam
            .sdk()?
            .obo()
            .authorization(id)
            .await
            .map_err(sdk_error)?;
        if detail.id != id
            || detail.app_id != scope.app
            || detail.org_id != scope.org
            || detail.actor.public_id != scope.actor
            || actor_kind(&detail.actor) != scope.kind
        {
            return Err(IamError::Forbidden);
        }
        if detail.providers.as_ref().is_none_or(|providers| {
            !providers.iter().any(|p| {
                p.app_id == "ting"
                    && p.org_id == scope.org
                    && p.actor.public_id == scope.actor
                    && actor_kind(&p.actor) == scope.kind
            })
        }) {
            return Err(IamError::Forbidden);
        }
        let response = iam
            .sdk()?
            .obo()
            .exchange_code(id, code, &retry_key(&format!("hook:code:{id}:{code}"))?)
            .await
            .map_err(token_error)?;
        let roots = Self::roots(iam);
        if response.items.len() != roots.len()
            || roots.iter().any(|id| {
                response
                    .items
                    .iter()
                    .filter(|pair| pair.endpoint_id == *id)
                    .count()
                    != 1
            })
        {
            return Err(IamError::InvalidResponse);
        }
        for pair in response.items {
            self.validate(iam, &scope, &pair).await?;
            self.save(&mut tx, &scope, &pair).await?;
        }
        sqlx::query("UPDATE hook_private.ting_authorizations SET completion_digest=$8 WHERE environment_id=$1 AND generation=$2 AND app_id=$3 AND org_id=$4 AND actor_kind=$5 AND actor_id=$6 AND authorization_id=$7")
            .bind(scope.environment).bind(scope.generation).bind(&scope.app).bind(&scope.org).bind(&scope.kind).bind(&scope.actor).bind(id).bind(digest).execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        self.status(iam, token, org, false).await
    }
    async fn validate(
        &self,
        iam: &IamClient,
        scope: &Scope,
        pair: &models::OboTokenPair,
    ) -> Result<(), IamError> {
        if pair.audience != "ting"
            || pair.org_id != scope.org
            || pair.actor.as_ref().is_none_or(|actor| {
                actor.public_id != scope.actor || actor_kind(actor) != scope.kind
            })
            || !Self::roots(iam).contains(&pair.endpoint_id.as_str())
            || !pair.access_token.starts_with("oba_")
            || !pair.refresh_token.starts_with("obr_")
            || pair.grant_id.is_nil()
            || pair.expires_in <= 0
            || pair.expires_at <= OffsetDateTime::now_utc()
            || !pair
                .scope
                .split_whitespace()
                .any(|s| s == format!("obo:ting:{}", pair.endpoint_id))
        {
            return Err(IamError::InvalidResponse);
        }
        match (
            &pair.testing_context,
            (!scope.environment.is_nil()).then_some(scope.environment),
        ) {
            (None, None) => Ok(()),
            (Some(context), Some(environment)) if context.app_id == "ting" => {
                let client = silicon_iam_client::Client::builder(iam.inner.base_url.as_str())
                    .map_err(sdk_error)?
                    .credential(Credential::application("ting", &context.app_secret))
                    .environment(
                        EnvironmentKey::new(context.iam_test_key.clone()).map_err(sdk_error)?,
                    )
                    .auto_update(false)
                    .build()
                    .map_err(sdk_error)?;
                let actual = client
                    .applications()
                    .testing_context()
                    .await
                    .map_err(sdk_error)?;
                if actual.environment_id != environment || actual.application.app_id != "ting" {
                    return Err(IamError::Forbidden);
                }
                Ok(())
            }
            _ => Err(IamError::Forbidden),
        }
    }
    async fn save(
        &self,
        connection: &mut PgConnection,
        scope: &Scope,
        pair: &models::OboTokenPair,
    ) -> Result<(), IamError> {
        let sealed = self
            .cipher
            .seal_credential(
                &scope.aad(&pair.endpoint_id, pair.grant_id),
                &serde_json::to_value(pair).map_err(unavailable)?,
            )
            .map_err(unavailable)?;
        sqlx::query("INSERT INTO hook_private.ting_obo_credentials(environment_id,generation,app_id,org_id,actor_kind,actor_id,endpoint_id,grant_id,sealed) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(environment_id,generation,app_id,org_id,actor_kind,actor_id,endpoint_id) DO UPDATE SET grant_id=EXCLUDED.grant_id,sealed=EXCLUDED.sealed")
            .bind(scope.environment).bind(scope.generation).bind(&scope.app).bind(&scope.org).bind(&scope.kind).bind(&scope.actor).bind(&pair.endpoint_id).bind(pair.grant_id).bind(sealed).execute(connection).await.map_err(unavailable)?;
        Ok(())
    }
    async fn remove(
        &self,
        connection: &mut PgConnection,
        scope: &Scope,
        endpoint: Option<&str>,
    ) -> Result<(), IamError> {
        sqlx::query("DELETE FROM hook_private.ting_obo_credentials WHERE environment_id=$1 AND generation=$2 AND app_id=$3 AND org_id=$4 AND actor_kind=$5 AND actor_id=$6 AND ($7::text IS NULL OR endpoint_id=$7)")
            .bind(scope.environment).bind(scope.generation).bind(&scope.app).bind(&scope.org).bind(&scope.kind).bind(&scope.actor).bind(endpoint).execute(connection).await.map_err(unavailable)?;
        Ok(())
    }
    async fn status(
        &self,
        iam: &IamClient,
        token: &SecretString,
        org: &str,
        disconnect: bool,
    ) -> Result<Value, IamError> {
        let scope = self.scope(iam, token, org).await?;
        let mut tx = self.store.pool().begin().await.map_err(unavailable)?;
        self.lock(&mut tx, &scope).await?;
        if disconnect {
            self.remove(&mut tx, &scope, None).await?;
        }
        let endpoints:Vec<String>=sqlx::query_scalar("SELECT endpoint_id FROM hook_private.ting_obo_credentials WHERE environment_id=$1 AND generation=$2 AND app_id=$3 AND org_id=$4 AND actor_kind=$5 AND actor_id=$6 ORDER BY endpoint_id")
            .bind(scope.environment).bind(scope.generation).bind(&scope.app).bind(&scope.org).bind(&scope.kind).bind(&scope.actor).fetch_all(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(
            json!({"status":if endpoints.len()==Self::roots(iam).len(){"authorized"}else{"authorization_required"},"endpoints":endpoints,"actor_id":scope.actor,"org_id":scope.org}),
        )
    }
    pub(super) async fn authority(
        &self,
        iam: &IamClient,
        token: &SecretString,
        org: &str,
        endpoint: &str,
    ) -> Result<TingProof, IamError> {
        let scope = self.scope(iam, token, org).await?;
        let mut tx = self.store.pool().begin().await.map_err(unavailable)?;
        self.lock(&mut tx, &scope).await?;
        let row:Option<(Uuid,Value)>=sqlx::query_as("SELECT grant_id,sealed FROM hook_private.ting_obo_credentials WHERE environment_id=$1 AND generation=$2 AND app_id=$3 AND org_id=$4 AND actor_kind=$5 AND actor_id=$6 AND endpoint_id=$7 FOR UPDATE")
            .bind(scope.environment).bind(scope.generation).bind(&scope.app).bind(&scope.org).bind(&scope.kind).bind(&scope.actor).bind(endpoint).fetch_optional(&mut *tx).await.map_err(unavailable)?;
        let (grant, sealed) = row.ok_or(IamError::TingAuthorizationRequired)?;
        let mut pair: models::OboTokenPair = serde_json::from_value(
            self.cipher
                .open_credential(&scope.aad(endpoint, grant), &sealed)
                .map_err(unavailable)?,
        )
        .map_err(unavailable)?;
        if pair.expires_at <= OffsetDateTime::now_utc() + time::Duration::seconds(30) {
            let response = iam
                .sdk()?
                .obo()
                .refresh(
                    &pair.refresh_token,
                    &retry_key(&format!("hook:refresh:{}:{}", grant, pair.refresh_token))?,
                )
                .await
                .map_err(token_error);
            let response = match response {
                Err(IamError::TingAuthorizationRequired) => {
                    self.remove(&mut tx, &scope, Some(endpoint)).await?;
                    tx.commit().await.map_err(unavailable)?;
                    return Err(IamError::TingAuthorizationRequired);
                }
                other => other?,
            };
            if response.items.len() != 1 {
                return Err(IamError::InvalidResponse);
            }
            let next = response
                .items
                .into_iter()
                .next()
                .ok_or(IamError::InvalidResponse)?;
            if next.endpoint_id != endpoint || next.grant_id != grant {
                return Err(IamError::Forbidden);
            }
            self.validate(iam, &scope, &next).await?;
            self.save(&mut tx, &scope, &next).await?;
            pair = next;
        } else {
            self.validate(iam, &scope, &pair).await?;
        }
        let testing = pair
            .testing_context
            .map(|context| {
                super::ting::testing_credentials(context.app_secret, context.iam_test_key)
            })
            .transpose()?;
        tx.commit().await.map_err(unavailable)?;
        Ok(TingProof {
            token: SecretString::from(pair.access_token),
            testing,
        })
    }
}
fn actor_kind(actor: &models::ActorRef) -> &'static str {
    match actor.type_field {
        models::ActorRefType::Carbon => "carbon",
        models::ActorRefType::Silicon => "silicon",
        _ => "invalid",
    }
}

#[cfg(test)]
pub(crate) mod tests;
