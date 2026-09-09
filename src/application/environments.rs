//! Organization-owned test environments and their strictly scoped database pools.

use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::{FromRow, PgPool, postgres::PgPoolOptions};
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    config::{DatabaseSettings, IamWebhookSettings},
    domain::{ActorKind, AuthorizationContext, EncryptedSecret, EncryptionKeyId, SigningSecret},
    error::AppError,
    infrastructure::{
        crypto::SecretCipher,
        iam::IamClient,
        postgres::{self, PostgresStore},
    },
};

/// Secret inputs needed to connect Hook to a test-only IAM application.
#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct TestIamConfiguration {
    /// Canonical application ID in the IAM test environment.
    pub app_id: String,
    /// Test-only application credential returned by creation/import in IAM.
    pub app_secret: String,
    /// Signing secret for that application's IAM webhook.
    pub webhook_secret: String,
    /// Signing key version configured in IAM.
    #[serde(default = "first_version")]
    pub webhook_secret_version: u64,
}

const fn first_version() -> u64 {
    1
}

impl fmt::Debug for TestIamConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestIamConfiguration")
            .field("app_id", &self.app_id)
            .finish_non_exhaustive()
    }
}

/// Creation begins with an empty Hook environment linked to an existing IAM test world.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateEnvironment {
    /// Human-readable name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Existing IAM testing environment root key.
    pub iam_test_key: SecretString,
    /// May be supplied now or after creating/importing Hook in the IAM test world.
    pub iam: Option<TestIamConfiguration>,
}

impl fmt::Debug for CreateEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateEnvironment")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Public metadata. Credentials are never part of a normal environment response.
#[derive(Clone, Debug, Deserialize, Serialize, FromRow)]
pub struct TestEnvironment {
    /// Public environment selector used by `hook --test <id>`.
    pub id: Uuid,
    /// Owning production organization.
    pub org_id: String,
    /// Creator category.
    pub creator_kind: String,
    /// Immutable creator identity.
    pub creator_id: String,
    /// Name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Increments on reset, key rotation, deletion and IAM reconfiguration.
    pub generation: i64,
    /// Creation timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    /// Latest activity in this environment.
    #[serde(with = "time::serde::rfc3339")]
    pub last_activity_at: time::OffsetDateTime,
    /// Soft deletion timestamp; recovery lasts thirty days.
    #[serde(with = "time::serde::rfc3339::option")]
    pub deleted_at: Option<time::OffsetDateTime>,
}

#[derive(FromRow)]
struct EnvironmentRecord {
    #[sqlx(flatten)]
    metadata: TestEnvironment,
    encrypted_credentials: serde_json::Value,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Credentials {
    hook_key: String,
    iam_key: String,
    iam: Option<TestIamConfiguration>,
}

#[derive(Serialize, Deserialize)]
struct SealedCredentials {
    key_id: String,
    nonce: [u8; 12],
    ciphertext: String,
}

/// A scoped application store and its matching IAM test client.
#[derive(Clone, Debug)]
pub struct EnvironmentContext {
    /// Environment metadata captured when this request was authorized.
    pub environment: TestEnvironment,
    /// Pool pinned to this environment and generation for its lifetime.
    pub store: PostgresStore,
    /// IAM client that always carries the corresponding test root key.
    pub iam: IamClient,
}

type ScopedPools = Arc<Mutex<BTreeMap<(Uuid, i64), (PgPool, IamClient)>>>;

/// Test control plane; clones share a bounded cache of immutable scoped pools.
#[derive(Clone)]
pub struct EnvironmentService {
    database: DatabaseSettings,
    pool: PgPool,
    cipher: Arc<SecretCipher>,
    production_iam: IamClient,
    pools: ScopedPools,
}

impl fmt::Debug for EnvironmentService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvironmentService").finish_non_exhaustive()
    }
}

impl EnvironmentService {
    /// Connects the shared test database and verifies its migration contract.
    ///
    /// # Errors
    /// Returns database connection and schema-readiness errors.
    pub async fn connect(
        database: DatabaseSettings,
        cipher: Arc<SecretCipher>,
        iam: IamClient,
    ) -> anyhow::Result<Self> {
        let pool = postgres::connect(&database, "hook-test-control").await?;
        PostgresStore::new(pool.clone())
            .ready_for(postgres::RuntimeDatabaseRole::Api)
            .await?;
        Ok(Self {
            database,
            pool,
            cipher,
            production_iam: iam,
            pools: Arc::default(),
        })
    }

    /// Creates an organization-owned empty environment and returns its root key.
    ///
    /// # Errors
    /// Rejects invalid metadata, invalid IAM test keys, duplicate IAM bindings,
    /// or a reused creation request whose content changed.
    pub async fn create(
        &self,
        actor: &AuthorizationContext,
        input: CreateEnvironment,
        request_key: &str,
    ) -> Result<(TestEnvironment, Zeroizing<String>), AppError> {
        use secrecy::ExposeSecret as _;
        if input.name.trim().is_empty()
            || input.name.chars().count() > 200
            || input
                .description
                .as_ref()
                .is_some_and(|s| s.chars().count() > 2000)
        {
            return Err(AppError::validation("invalid_environment_metadata"));
        }
        let iam_key = input.iam_test_key.expose_secret();
        self.production_iam.validate_environment(iam_key).await?;
        if let Some(config) = &input.iam {
            self.iam_client(iam_key, config).await?;
        }
        let binding_hash = hash_key(iam_key);
        // Stable per-creator replay identity, without retaining a caller's key.
        let request_hash = Sha256::digest(
            serde_json::to_vec(&serde_json::json!([
                actor.organization_id().as_str(),
                actor.actor(),
                request_key
            ]))
            .map_err(internal)?,
        )
        .to_vec();
        let input_hash = Sha256::digest(
            serde_json::to_vec(&serde_json::json!([
                input.name,
                input.description,
                binding_hash,
                input.iam
            ]))
            .map_err(internal)?,
        )
        .to_vec();
        let id = Uuid::now_v7();
        let credentials = Credentials {
            hook_key: random_key()?,
            iam_key: iam_key.to_owned(),
            iam: input.iam,
        };
        let encrypted = self.encrypt(id, &credentials)?;
        let result = sqlx::query(
            "INSERT INTO hook_control.environments (id, org_id, creator_kind, creator_id, name, description, key_hash, iam_key_hash, encrypted_credentials, creation_request_hash, creation_input_hash)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (creation_request_hash) DO NOTHING"
        ).bind(id).bind(actor.organization_id().as_str()).bind(actor_kind(actor.actor().kind()))
            .bind(actor.actor().id().as_str()).bind(input.name).bind(input.description)
            .bind(hash_key(&credentials.hook_key)).bind(binding_hash).bind(encrypted)
            .bind(&request_hash).bind(&input_hash).execute(&self.pool).await;
        if let Err(sqlx::Error::Database(error)) = &result
            && error.is_unique_violation()
        {
            return Err(AppError::conflict("iam_environment_already_linked"));
        }
        result.map_err(internal)?;
        let (stored_id, stored_hash): (Uuid, Vec<u8>) = sqlx::query_as(
            "SELECT id, creation_input_hash FROM hook_control.environments WHERE creation_request_hash = $1"
        ).bind(request_hash).fetch_one(&self.pool).await.map_err(internal)?;
        if input_hash != stored_hash {
            return Err(AppError::conflict("idempotency_conflict"));
        }
        self.key(actor, stored_id).await
    }

    /// Lists this production organization's active or recoverable environments.
    ///
    /// # Errors
    /// Rejects unknown status filters or unavailable storage.
    pub async fn list(
        &self,
        actor: &AuthorizationContext,
        status: &str,
        limit: u32,
        after: Option<Uuid>,
    ) -> Result<Vec<TestEnvironment>, AppError> {
        if !(1..=1000).contains(&limit) {
            return Err(AppError::validation("invalid_limit"));
        }
        if !matches!(status, "active" | "deleted" | "all") {
            return Err(AppError::validation("invalid_status"));
        }
        sqlx::query_as("SELECT * FROM hook_control.environments WHERE org_id = $1 AND (deleted_at IS NULL OR deleted_at > clock_timestamp() - INTERVAL '30 days') AND ($2 = 'all' OR ($2 = 'active' AND deleted_at IS NULL) OR ($2 = 'deleted' AND deleted_at IS NOT NULL)) AND ($3::uuid IS NULL OR id < $3) ORDER BY id DESC LIMIT $4")
            .bind(actor.organization_id().as_str()).bind(status).bind(after).bind(i64::from(limit)).fetch_all(&self.pool).await.map_err(internal)
    }

    /// Reads metadata in the authenticated production organization.
    ///
    /// # Errors
    /// Hides absent and foreign-organization environments.
    pub async fn get(
        &self,
        actor: &AuthorizationContext,
        id: Uuid,
    ) -> Result<TestEnvironment, AppError> {
        let row = self.record(id).await?;
        if row.metadata.org_id != actor.organization_id().as_str() {
            return Err(AppError::NotFound);
        }
        Ok(row.metadata)
    }

    /// Returns a root key only to its creator or organization administrators.
    ///
    /// # Errors
    /// Returns permission and storage failures.
    pub async fn key(
        &self,
        actor: &AuthorizationContext,
        id: Uuid,
    ) -> Result<(TestEnvironment, Zeroizing<String>), AppError> {
        let row = self.record(id).await?;
        authorize_owner(actor, &row.metadata)?;
        let secrets = self.decrypt(&row)?;
        Ok((row.metadata, Zeroizing::new(secrets.hook_key.clone())))
    }

    /// Rotates a root key, invalidating existing scoped sessions.
    ///
    /// # Errors
    /// Requires creator/admin authority and an active environment.
    pub async fn rotate_key(
        &self,
        actor: &AuthorizationContext,
        id: Uuid,
        request_key: &str,
    ) -> Result<(TestEnvironment, Zeroizing<String>), AppError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let row = locked_record(&mut tx, id).await?;
        authorize_owner(actor, &row.metadata)?;
        if row.metadata.deleted_at.is_some() {
            return Err(AppError::NotFound);
        }
        let request = mutation_hash(actor, request_key)?;
        let input = hash_key("rotate-key");
        if let Some((metadata, encrypted)) = replay(&mut tx, id, &request, &input).await? {
            let credentials = self.decrypt(&EnvironmentRecord {
                metadata: metadata.clone(),
                encrypted_credentials: encrypted
                    .ok_or_else(|| internal(anyhow::anyhow!("missing rotation result")))?,
            })?;
            return Ok((metadata, Zeroizing::new(credentials.hook_key.clone())));
        }
        let mut credentials = self.decrypt(&row)?;
        credentials.hook_key = random_key()?;
        let encrypted = self.encrypt(id, &credentials)?;
        let metadata: TestEnvironment = sqlx::query_as("UPDATE hook_control.environments SET key_hash = $2, encrypted_credentials = $3, generation = generation + 1, last_activity_at = clock_timestamp() WHERE id = $1 RETURNING *")
            .bind(id).bind(hash_key(&credentials.hook_key)).bind(&encrypted)
            .fetch_one(&mut *tx).await.map_err(internal)?;
        remember(&mut tx, &metadata, &request, &input, Some(&encrypted)).await?;
        tx.commit().await.map_err(internal)?;
        Ok((metadata, Zeroizing::new(credentials.hook_key.clone())))
    }

    /// Soft-deletes or restores an environment within its thirty-day recovery window.
    ///
    /// # Errors
    /// Requires creator/admin authority; expired environments cannot be restored.
    pub async fn set_deleted(
        &self,
        actor: &AuthorizationContext,
        id: Uuid,
        deleted: bool,
        request_key: &str,
    ) -> Result<TestEnvironment, AppError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let row = locked_record(&mut tx, id).await?;
        authorize_owner(actor, &row.metadata)?;
        let request = mutation_hash(actor, request_key)?;
        let input = hash_key(if deleted { "delete" } else { "restore" });
        if let Some((metadata, _)) = replay(&mut tx, id, &request, &input).await? {
            return Ok(metadata);
        }
        let metadata = if row.metadata.deleted_at.is_some() == deleted {
            row.metadata
        } else {
            sqlx::query_as("UPDATE hook_control.environments SET deleted_at = CASE WHEN $2 THEN clock_timestamp() ELSE NULL END, generation = generation + 1, last_activity_at = clock_timestamp() WHERE id = $1 RETURNING *")
                .bind(id).bind(deleted).fetch_one(&mut *tx).await.map_err(internal)?
        };
        remember(&mut tx, &metadata, &request, &input, None).await?;
        tx.commit().await.map_err(internal)?;
        Ok(metadata)
    }

    /// Resets Hook data while retaining the environment and IAM binding.
    ///
    /// # Errors
    /// Requires the current root key; production has no corresponding operation.
    pub async fn clean(&self, key: &str, request_key: &str) -> Result<TestEnvironment, AppError> {
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let id: Uuid = sqlx::query_scalar("SELECT id FROM hook_control.environments WHERE key_hash = $1 AND deleted_at IS NULL FOR UPDATE")
            .bind(hash_key(key)).fetch_optional(&mut *tx).await.map_err(internal)?.ok_or(AppError::Unauthenticated)?;
        let request = root_mutation_hash(key, request_key)?;
        let input = hash_key("clean");
        if let Some((metadata, _)) = replay(&mut tx, id, &request, &input).await? {
            return Ok(metadata);
        }
        sqlx::query("SELECT hook_control.clean_environment($1)")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        let metadata = locked_record(&mut tx, id).await?.metadata;
        remember(&mut tx, &metadata, &request, &input, None).await?;
        tx.commit().await.map_err(internal)?;
        Ok(metadata)
    }

    /// Installs test-only IAM application credentials after bootstrap/import.
    ///
    /// # Errors
    /// Requires a current root key and valid test application credentials.
    pub async fn configure_iam(
        &self,
        key: &str,
        config: TestIamConfiguration,
        request_key: &str,
    ) -> Result<TestEnvironment, AppError> {
        let initial = self.by_key(key).await?;
        let credentials = self.decrypt(&initial)?;
        self.iam_client(&credentials.iam_key, &config).await?;
        let mut tx = self.pool.begin().await.map_err(internal)?;
        let row: EnvironmentRecord = sqlx::query_as("SELECT * FROM hook_control.environments WHERE key_hash = $1 AND deleted_at IS NULL FOR UPDATE")
            .bind(hash_key(key)).fetch_optional(&mut *tx).await.map_err(internal)?.ok_or(AppError::Unauthenticated)?;
        let id = row.metadata.id;
        let request = root_mutation_hash(key, request_key)?;
        let input = Sha256::digest(Zeroizing::new(
            serde_json::to_vec(&serde_json::json!(["configure-iam", config])).map_err(internal)?,
        ))
        .to_vec();
        if let Some((metadata, _)) = replay(&mut tx, id, &request, &input).await? {
            return Ok(metadata);
        }
        let mut credentials = self.decrypt(&row)?;
        credentials.iam = Some(config);
        let metadata: TestEnvironment = sqlx::query_as("UPDATE hook_control.environments SET encrypted_credentials = $2, generation = generation + 1, last_activity_at = clock_timestamp() WHERE id = $1 RETURNING *")
            .bind(id).bind(self.encrypt(id, &credentials)?).fetch_one(&mut *tx).await.map_err(internal)?;
        remember(&mut tx, &metadata, &request, &input, None).await?;
        tx.commit().await.map_err(internal)?;
        Ok(metadata)
    }

    /// Reads current test metadata with the environment root key alone.
    ///
    /// # Errors
    /// Rejects invalid keys and deleted environments.
    pub async fn current(&self, key: &str) -> Result<TestEnvironment, AppError> {
        let row = self.by_key(key).await?;
        self.touch(row.metadata.id, row.metadata.generation).await?;
        Ok(row.metadata)
    }

    /// Records an accepted request without allowing stale sessions to revive an environment.
    ///
    /// # Errors
    /// Returns storage failures; missing or changed generations remain untouched.
    pub async fn touch(&self, id: Uuid, generation: i64) -> Result<(), AppError> {
        sqlx::query("UPDATE hook_control.environments SET last_activity_at = clock_timestamp() WHERE id = $1 AND generation = $2 AND deleted_at IS NULL")
            .bind(id).bind(generation).execute(&self.pool).await.map_err(internal)?;
        Ok(())
    }

    /// Resolves a root key into an isolated application context.
    ///
    /// # Errors
    /// Refuses unknown keys, deleted environments and missing IAM configuration.
    pub async fn resolve_key(&self, key: &str) -> Result<EnvironmentContext, AppError> {
        self.context(self.by_key(key).await?).await
    }

    /// Selects the environment owning a public test provider URL.
    ///
    /// # Errors
    /// Hides unknown, deleted and expired environments.
    pub async fn resolve_endpoint(
        &self,
        silicon: &str,
        key: &str,
    ) -> Result<EnvironmentContext, AppError> {
        let id: Option<Uuid> = sqlx::query_scalar("SELECT environment_id FROM hook_control.endpoint_routes WHERE silicon_id = $1 AND endpoint_key = $2 AND environment_id IS NOT NULL")
            .bind(silicon).bind(key).fetch_optional(&self.pool).await.map_err(internal)?;
        self.context(self.record(id.ok_or(AppError::NotFound)?).await?)
            .await
    }

    /// Selects a test IAM envelope's environment before exact-byte verification.
    ///
    /// The supplied key is only a routing hint. The caller must still use the
    /// returned IAM client's verifier on the original request bytes.
    ///
    /// # Errors
    /// Rejects unknown and inactive bindings.
    pub async fn resolve_iam_key(&self, key: &str) -> Result<EnvironmentContext, AppError> {
        let id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM hook_control.environments WHERE iam_key_hash = $1 AND deleted_at IS NULL")
            .bind(hash_key(key)).fetch_optional(&self.pool).await.map_err(internal)?;
        self.context(self.record(id.ok_or(AppError::NotFound)?).await?)
            .await
    }

    async fn context(&self, row: EnvironmentRecord) -> Result<EnvironmentContext, AppError> {
        if row.metadata.deleted_at.is_some() {
            return Err(AppError::NotFound);
        }
        let credentials = self.decrypt(&row)?;
        let config = credentials
            .iam
            .as_ref()
            .ok_or_else(|| AppError::conflict("test_iam_application_not_configured"))?;
        let mut pools = self.pools.lock().await;
        let identity = (row.metadata.id, row.metadata.generation);
        let (pool, iam) = if let Some(context) = pools.get(&identity) {
            context.clone()
        } else {
            let iam = self.iam_client(&credentials.iam_key, config).await?;
            let options = postgres::connect_options(&self.database, "hook-test-scoped")
                .map_err(internal)?
                .options([
                    ("hook.environment_id", row.metadata.id.to_string()),
                    (
                        "hook.environment_generation",
                        row.metadata.generation.to_string(),
                    ),
                ]);
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .min_connections(0)
                .idle_timeout(Duration::from_secs(60))
                .acquire_timeout(self.database.acquire_timeout)
                .connect_with(options)
                .await
                .map_err(internal)?;
            if pools.len() >= 32 {
                pools.pop_first();
            }
            pools.insert(identity, (pool.clone(), iam.clone()));
            (pool, iam)
        };
        drop(pools);
        Ok(EnvironmentContext {
            environment: row.metadata,
            store: PostgresStore::new(pool),
            iam,
        })
    }

    async fn iam_client(
        &self,
        key: &str,
        config: &TestIamConfiguration,
    ) -> Result<IamClient, AppError> {
        self.production_iam
            .for_environment(
                key,
                &config.app_id,
                &config.app_secret,
                &IamWebhookSettings {
                    secret: SecretString::from(config.webhook_secret.clone()),
                    version: config.webhook_secret_version,
                    previous: None,
                },
            )
            .await
            .map_err(AppError::from)
    }

    async fn record(&self, id: Uuid) -> Result<EnvironmentRecord, AppError> {
        sqlx::query_as("SELECT * FROM hook_control.environments WHERE id = $1 AND (deleted_at IS NULL OR deleted_at > clock_timestamp() - INTERVAL '30 days')")
            .bind(id).fetch_optional(&self.pool).await.map_err(internal)?.ok_or(AppError::NotFound)
    }

    async fn by_key(&self, key: &str) -> Result<EnvironmentRecord, AppError> {
        if key.len() != 32 || !key.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(AppError::Unauthenticated);
        }
        sqlx::query_as(
            "SELECT * FROM hook_control.environments WHERE key_hash = $1 AND deleted_at IS NULL",
        )
        .bind(hash_key(key))
        .fetch_optional(&self.pool)
        .await
        .map_err(internal)?
        .ok_or(AppError::Unauthenticated)
    }

    fn encrypt(&self, id: Uuid, credentials: &Credentials) -> Result<serde_json::Value, AppError> {
        let plain = SigningSecret::from_zeroizing(Zeroizing::new(
            serde_json::to_string(credentials).map_err(internal)?,
        ))
        .map_err(internal)?;
        let encrypted = self.cipher.encrypt(id.into(), &plain).map_err(internal)?;
        serde_json::to_value(SealedCredentials {
            key_id: encrypted.key_id().as_str().to_owned(),
            nonce: *encrypted.nonce(),
            ciphertext: URL_SAFE_NO_PAD.encode(encrypted.ciphertext()),
        })
        .map_err(internal)
    }

    fn decrypt(&self, row: &EnvironmentRecord) -> Result<Credentials, AppError> {
        let wire: SealedCredentials =
            serde_json::from_value(row.encrypted_credentials.clone()).map_err(internal)?;
        let encrypted = EncryptedSecret::new(
            EncryptionKeyId::new(wire.key_id).map_err(internal)?,
            wire.nonce,
            URL_SAFE_NO_PAD.decode(wire.ciphertext).map_err(internal)?,
        )
        .map_err(internal)?;
        let plain = self
            .cipher
            .decrypt(row.metadata.id.into(), &encrypted)
            .map_err(internal)?;
        serde_json::from_str(plain.as_str()).map_err(internal)
    }
}

fn authorize_owner(actor: &AuthorizationContext, env: &TestEnvironment) -> Result<(), AppError> {
    if actor.organization_id().as_str() != env.org_id {
        return Err(AppError::NotFound);
    }
    if (actor_kind(actor.actor().kind()) == env.creator_kind
        && actor.actor().id().as_str() == env.creator_id)
        || matches!(
            actor.organization_role(),
            crate::domain::OrganizationRole::Admin | crate::domain::OrganizationRole::Owner
        )
    {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn actor_kind(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Carbon => "carbon",
        ActorKind::Silicon => "silicon",
    }
}

fn hash_key(key: &str) -> Vec<u8> {
    Sha256::digest(key.as_bytes()).to_vec()
}

fn random_key() -> Result<String, AppError> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut result = String::with_capacity(32);
    while result.len() < 32 {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|_| AppError::internal(anyhow::anyhow!("secure randomness unavailable")))?;
        for byte in bytes {
            if byte < 248 && result.len() < 32 {
                result.push(char::from(ALPHABET[usize::from(byte % 62)]));
            }
        }
    }
    Ok(result)
}

fn internal(error: impl Into<anyhow::Error>) -> AppError {
    AppError::internal(error.into())
}

async fn locked_record(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
) -> Result<EnvironmentRecord, AppError> {
    sqlx::query_as("SELECT * FROM hook_control.environments WHERE id = $1 AND (deleted_at IS NULL OR deleted_at > clock_timestamp() - INTERVAL '30 days') FOR UPDATE")
        .bind(id).fetch_optional(tx).await.map_err(internal)?.ok_or(AppError::NotFound)
}
fn mutation_hash(actor: &AuthorizationContext, key: &str) -> Result<Vec<u8>, AppError> {
    Ok(Sha256::digest(
        serde_json::to_vec(&serde_json::json!([
            "actor",
            actor.organization_id().as_str(),
            actor.actor(),
            key
        ]))
        .map_err(internal)?,
    )
    .to_vec())
}
fn root_mutation_hash(key: &str, request: &str) -> Result<Vec<u8>, AppError> {
    Ok(Sha256::digest(Zeroizing::new(
        serde_json::to_vec(&serde_json::json!(["root", key, request])).map_err(internal)?,
    ))
    .to_vec())
}
async fn replay(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
    request: &[u8],
    input: &[u8],
) -> Result<Option<(TestEnvironment, Option<serde_json::Value>)>, AppError> {
    let result: Option<(Vec<u8>,serde_json::Value,Option<serde_json::Value>)> = sqlx::query_as("SELECT input_hash, metadata, encrypted_credentials FROM hook_control.mutation_results WHERE environment_id = $1 AND request_hash = $2 AND created_at > clock_timestamp() - INTERVAL '24 hours'")
        .bind(id).bind(request).fetch_optional(tx).await.map_err(internal)?;
    match result {
        None => Ok(None),
        Some((hash, metadata, encrypted)) => {
            if hash != input {
                return Err(AppError::conflict("idempotency_conflict"));
            }
            Ok(Some((
                serde_json::from_value(metadata).map_err(internal)?,
                encrypted,
            )))
        }
    }
}
async fn remember(
    tx: &mut sqlx::PgConnection,
    metadata: &TestEnvironment,
    request: &[u8],
    input: &[u8],
    encrypted: Option<&serde_json::Value>,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO hook_control.mutation_results (environment_id,request_hash,input_hash,metadata,encrypted_credentials) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (environment_id,request_hash) DO UPDATE SET input_hash=EXCLUDED.input_hash,metadata=EXCLUDED.metadata,encrypted_credentials=EXCLUDED.encrypted_credentials,created_at=clock_timestamp()")
        .bind(metadata.id).bind(request).bind(input).bind(serde_json::to_value(metadata).map_err(internal)?).bind(encrypted).execute(tx).await.map_err(internal)?;
    Ok(())
}
