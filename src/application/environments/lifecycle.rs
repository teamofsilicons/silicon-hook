//! Honeycomb's protected, retryable participant contract.
use super::{Credentials, EnvironmentRecord, EnvironmentService, hash_key, internal, random_key};
use crate::error::AppError;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

/// Exact participant request sent by Honeycomb. Secrets are never Debug-printed.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleOperation {
    /// Stable retry identity.
    pub operation_id: Uuid,
    /// Shared environment identity.
    pub environment_id: Uuid,
    /// Production organization binding.
    pub org_id: String,
    /// Target application.
    pub app_id: String,
    /// Monotonically increasing shared revision.
    pub environment_revision: i64,
    /// Shared cleaning generation.
    pub generation: i64,
    /// Shared root credential version.
    pub key_version: i64,
    /// Participant action.
    pub action: String,
    /// Shared environment credential, encrypted at rest.
    pub testing_key: String,
    /// Accepted application snapshot; Hook owns no imported catalog data.
    #[serde(default)]
    pub snapshot: Value,
    /// Coordinator audit classification.
    #[serde(default)]
    pub reason: Option<String>,
    /// Applications selected for retirement.
    #[serde(default)]
    pub retired_apps: Vec<String>,
}

impl Drop for LifecycleOperation {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.testing_key.zeroize();
    }
}

#[derive(Clone)]
pub(super) struct Control {
    token: SecretString,
    app_id: String,
    pub(super) base_url: url::Url,
    pub(super) http: reqwest::Client,
}

impl EnvironmentService {
    /// Configures a dedicated service credential and trusted coordinator URL.
    ///
    /// # Errors
    /// Refuses weak credentials or non-HTTPS non-loopback coordinator URLs.
    pub fn with_honeycomb_control(
        mut self,
        token: SecretString,
        app_id: String,
        base_url: url::Url,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            token.expose_secret().len() >= 32
                && token.expose_secret().bytes().all(|b| b.is_ascii_graphic()),
            "invalid Honeycomb service credential"
        );
        anyhow::ensure!(!app_id.is_empty(), "missing Hook application ID");
        anyhow::ensure!(
            base_url.username().is_empty()
                && base_url.password().is_none()
                && base_url.query().is_none()
                && base_url.fragment().is_none()
                && (base_url.scheme() == "https"
                    || (base_url.scheme() == "http"
                        && matches!(
                            base_url.host_str(),
                            Some("127.0.0.1" | "localhost" | "[::1]")
                        ))),
            "Honeycomb URL must use HTTPS or loopback HTTP"
        );
        self.control = Some(Control {
            token,
            app_id,
            base_url,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        });
        Ok(self)
    }

    /// Authenticates service authority independently of test sessions.
    ///
    /// # Errors
    /// Rejects absent, incorrect or unconfigured credentials.
    pub fn authorize_honeycomb(&self, token: &str) -> Result<(), AppError> {
        let control = self.control.as_ref().ok_or(AppError::ProviderUnavailable)?;
        if bool::from(
            Sha256::digest(token.as_bytes())
                .ct_eq(&Sha256::digest(control.token.expose_secret().as_bytes())),
        ) {
            Ok(())
        } else {
            Err(AppError::Unauthenticated)
        }
    }

    /// Applies a protected operation and retains its secret-free receipt.
    ///
    /// # Errors
    /// Rejects changed retries, stale revisions, foreign bindings and invalid transitions.
    pub async fn lifecycle(&self, operation: &LifecycleOperation) -> Result<Value, AppError> {
        let control = self.control.as_ref().ok_or(AppError::ProviderUnavailable)?;
        operation.validate(&control.app_id)?;
        let digest = Sha256::digest(zeroize::Zeroizing::new(
            serde_json::to_vec(operation).map_err(internal)?,
        ))
        .to_vec();
        let mut tx = self.pool.begin().await.map_err(internal)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(operation.environment_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        let previous: Option<(Vec<u8>, Value)> = sqlx::query_as("SELECT input_hash, receipt FROM hook_control.lifecycle_operations WHERE environment_id=$1 AND operation_id=$2 FOR UPDATE")
            .bind(operation.environment_id).bind(operation.operation_id).fetch_optional(&mut *tx).await.map_err(internal)?;
        if let Some((hash, receipt)) = &previous {
            if *hash != digest {
                return Err(AppError::conflict("idempotency_conflict"));
            }
            if receipt["state"] == "completed" {
                return Ok(receipt.clone());
            }
        }
        let row: Option<EnvironmentRecord> =
            sqlx::query_as("SELECT * FROM hook_control.environments WHERE id=$1 FOR UPDATE")
                .bind(operation.environment_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(internal)?;
        self.validate_transition(row.as_ref(), operation, previous.is_some())?;
        if previous.is_none() {
            let credentials = if let Some(row) = &row {
                self.decrypt(row)?
            } else {
                Credentials {
                    hook_key: random_key()?,
                    iam_key: operation.testing_key.clone(),
                    iam: None,
                    app_selector: None,
                }
            };
            let encrypted = self.encrypt(operation.environment_id, &credentials)?;
            sqlx::query("INSERT INTO hook_control.environments(id,org_id,creator_kind,creator_id,name,key_hash,iam_key_hash,encrypted_credentials,creation_request_hash,creation_input_hash,iam_environment_id) VALUES($1,$2,'silicon','honeycomb',$3,$4,$5,$6,$7,$7,$1) ON CONFLICT(id) DO NOTHING")
                .bind(operation.environment_id).bind(&operation.org_id).bind(operation.environment_id.to_string()).bind(hash_key(&credentials.hook_key)).bind(hash_key(&operation.testing_key)).bind(encrypted).bind(&digest).execute(&mut *tx).await.map_err(internal)?;
            // Fence all old pools immediately, before slow cleanup starts.
            sqlx::query("UPDATE hook_control.environments SET honeycomb_revision=$2,honeycomb_generation=$3,honeycomb_key_version=$4,honeycomb_operation=$5,honeycomb_state='pending',generation=generation+1 WHERE id=$1")
                .bind(operation.environment_id).bind(operation.environment_revision).bind(operation.generation).bind(operation.key_version).bind(operation.operation_id).execute(&mut *tx).await.map_err(internal)?;
            sqlx::query("INSERT INTO hook_control.lifecycle_operations(environment_id,operation_id,input_hash,receipt) VALUES($1,$2,$3,$4)")
                .bind(operation.environment_id).bind(operation.operation_id).bind(digest).bind(operation.receipt("pending")).execute(&mut *tx).await.map_err(internal)?;
        }
        tx.commit().await.map_err(internal)?;
        if let Ok(receipt) = self.finish_lifecycle(operation).await {
            return Ok(receipt);
        }
        let receipt = operation.receipt("failed");
        sqlx::query("UPDATE hook_control.lifecycle_operations SET receipt=$3 WHERE environment_id=$1 AND operation_id=$2 AND receipt->>'state' <> 'completed'")
            .bind(operation.environment_id).bind(operation.operation_id).bind(&receipt).execute(&self.pool).await.map_err(internal)?;
        Ok(receipt)
    }

    fn validate_transition(
        &self,
        row: Option<&EnvironmentRecord>,
        operation: &LifecycleOperation,
        replayed: bool,
    ) -> Result<(), AppError> {
        if let Some(row) = row {
            if row.metadata.org_id != operation.org_id {
                return Err(AppError::Forbidden);
            }
            if row.honeycomb_state.as_deref() == Some("purged") {
                return Err(AppError::conflict("environment_permanently_removed"));
            }
            if row.honeycomb_state.as_deref() == Some("pending")
                && row.honeycomb_operation != Some(operation.operation_id)
            {
                return Err(AppError::conflict("lifecycle_operation_pending"));
            }
            if let Some(revision) = row.honeycomb_revision {
                if !replayed
                    && operation.action == "rotate-key"
                    && row.honeycomb_key_version == Some(operation.key_version)
                {
                    return Err(AppError::conflict("key_version_must_advance"));
                }

                if !replayed
                    && row.honeycomb_key_version == Some(operation.key_version)
                    && self.decrypt(row)?.iam_key != operation.testing_key
                {
                    return Err(AppError::conflict("environment_key_version_conflict"));
                }

                if operation.environment_revision < revision
                    || (operation.environment_revision == revision
                        && row.honeycomb_operation != Some(operation.operation_id))
                    || operation.generation < row.honeycomb_generation.unwrap_or(1)
                    || operation.key_version < row.honeycomb_key_version.unwrap_or(1)
                {
                    return Err(AppError::conflict("stale_environment_operation"));
                }
                if operation.generation > row.honeycomb_generation.unwrap_or(1)
                    && operation.action != "clean"
                {
                    return Err(AppError::conflict("environment_clean_required"));
                }
                if operation.action == "clean"
                    && operation.generation == row.honeycomb_generation.unwrap_or(1)
                    && !replayed
                {
                    return Err(AppError::conflict("clean_generation_must_advance"));
                }
            }
        } else if !matches!(operation.action.as_str(), "create" | "prepare" | "import") {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    async fn finish_lifecycle(&self, operation: &LifecycleOperation) -> Result<Value, AppError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        // Use the same lock order as admission, including concurrent identical retries.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(operation.environment_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        let row: EnvironmentRecord =
            sqlx::query_as("SELECT * FROM hook_control.environments WHERE id=$1 FOR UPDATE")
                .bind(operation.environment_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(internal)?;
        if row.honeycomb_operation != Some(operation.operation_id) {
            return Err(AppError::conflict("stale_environment_operation"));
        }
        let completed: Value = sqlx::query_scalar("SELECT receipt FROM hook_control.lifecycle_operations WHERE environment_id=$1 AND operation_id=$2")
            .bind(operation.environment_id).bind(operation.operation_id).fetch_one(&mut *tx).await.map_err(internal)?;
        if completed["state"] == "completed" {
            return Ok(completed);
        }
        let retire = operation.action == "retire-applications"
            && operation.retired_apps.contains(&operation.app_id);
        if matches!(operation.action.as_str(), "clean" | "purge") || retire {
            sqlx::query("SELECT hook_control.clean_environment($1)")
                .bind(operation.environment_id)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            sqlx::query("DELETE FROM hook_control.mutation_results WHERE environment_id=$1")
                .bind(operation.environment_id)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
        }
        sqlx::query("DELETE FROM hook_control.activity_reports WHERE environment_id=$1")
            .bind(operation.environment_id)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        let mut credentials = self.decrypt(&row)?;
        credentials.iam_key.clone_from(&operation.testing_key);
        let state = match operation.action.as_str() {
            "disable" => "disabled",
            "purge" => "purged",
            _ if retire => "disabled",
            _ => "ready",
        };
        let encrypted = if state == "purged" {
            json!({})
        } else {
            self.encrypt(operation.environment_id, &credentials)?
        };
        sqlx::query("UPDATE hook_control.environments SET honeycomb_state=$2,deleted_at=CASE WHEN $2 IN ('disabled','purged') THEN clock_timestamp() ELSE NULL END,encrypted_credentials=$3,iam_key_hash=$4 WHERE id=$1")
            .bind(operation.environment_id).bind(state).bind(encrypted).bind(hash_key(&operation.testing_key)).execute(&mut *tx).await.map_err(internal)?;
        if state == "purged" {
            sqlx::query("UPDATE hook_control.environments SET name=id::text,description=NULL,creator_id='honeycomb',creator_kind='silicon',iam_version=NULL,iam_cleaned_at=NULL WHERE id=$1")
                .bind(operation.environment_id).execute(&mut *tx).await.map_err(internal)?;
        }
        let receipt = operation.receipt("completed");
        sqlx::query("UPDATE hook_control.lifecycle_operations SET receipt=$3 WHERE environment_id=$1 AND operation_id=$2")
            .bind(operation.environment_id).bind(operation.operation_id).bind(&receipt).execute(&mut *tx).await.map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        self.pools
            .lock()
            .await
            .retain(|(id, _), _| *id != operation.environment_id);
        Ok(receipt)
    }
}

impl LifecycleOperation {
    fn validate(&self, app_id: &str) -> Result<(), AppError> {
        if self.environment_id.is_nil()
            || self.operation_id.is_nil()
            || self.app_id != app_id
            || self.org_id.is_empty()
            || self.org_id.len() > 128
            || self.environment_revision < 1
            || self.generation < 1
            || self.key_version < 1
            || self.testing_key.len() != 32
            || !self.testing_key.bytes().all(|b| b.is_ascii_alphanumeric())
            || !matches!(
                self.action.as_str(),
                "create"
                    | "prepare"
                    | "import"
                    | "rotate-key"
                    | "clean"
                    | "disable"
                    | "restore"
                    | "purge"
                    | "retire-applications"
            )
        {
            return Err(AppError::validation("invalid_lifecycle_operation"));
        }
        Ok(())
    }
    fn receipt(&self, state: &str) -> Value {
        json!({"state":state,"operation_id":self.operation_id,"environment_id":self.environment_id,"app_id":self.app_id,"environment_revision":self.environment_revision,"generation":self.generation,"key_version":self.key_version,"retired_apps":self.retired_apps})
    }
}

impl EnvironmentService {
    /// Retrieves a retained operation receipt without requiring an active sandbox.
    ///
    /// # Errors
    /// Returns not found for mismatched organizations or unknown operations.
    pub async fn lifecycle_status(
        &self,
        org: &str,
        environment: Uuid,
        operation: Uuid,
    ) -> Result<Value, AppError> {
        sqlx::query_scalar("SELECT o.receipt FROM hook_control.lifecycle_operations o JOIN hook_control.environments e ON e.id=o.environment_id WHERE e.org_id=$1 AND o.environment_id=$2 AND o.operation_id=$3")
            .bind(org).bind(environment).bind(operation).fetch_optional(&self.pool).await.map_err(internal)?.ok_or(AppError::NotFound)
    }

    /// Retries persisted activity reports; no report can revive a superseded generation.
    ///
    /// # Errors
    /// Returns local storage errors. Remote failures remain queued for the next pass.
    pub async fn report_activity(&self) -> Result<(), AppError> {
        let Some(control) = &self.control else {
            return Ok(());
        };
        let reports: Vec<(Uuid, Uuid, i64, i64)> = sqlx::query_as("SELECT environment_id,report_id,generation,key_version FROM hook_control.activity_reports ORDER BY environment_id LIMIT 32")
            .fetch_all(&self.pool).await.map_err(internal)?;
        for (id, report, generation, key_version) in reports {
            let row = self.record(id).await?;
            if row.honeycomb_state.as_deref() != Some("ready")
                || row.honeycomb_generation != Some(generation)
                || row.honeycomb_key_version != Some(key_version)
            {
                continue;
            }
            let credentials = self.decrypt(&row)?;
            let mut url = control.base_url.clone();
            url.path_segments_mut()
                .map_err(|()| AppError::ProviderUnavailable)?
                .pop_if_empty()
                .extend([
                    "api",
                    "v1",
                    "environments",
                    &id.to_string(),
                    "apps",
                    &control.app_id,
                    "activity",
                ]);
            let result = control
                .http
                .post(url)
                .header("x-testing-environment-key", &credentials.iam_key)
                .header("idempotency-key", report.to_string())
                .json(&json!({"generation":generation,"key_version":key_version}))
                .send()
                .await;
            if result.is_ok_and(|response| response.status().is_success()) {
                sqlx::query("DELETE FROM hook_control.activity_reports WHERE environment_id=$1 AND report_id=$2").bind(id).bind(report).execute(&self.pool).await.map_err(internal)?;
            }
        }
        Ok(())
    }
}
