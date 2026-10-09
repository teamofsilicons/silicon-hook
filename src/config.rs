//! Typed, startup-validated configuration for every Hook process.

use std::{
    collections::BTreeMap,
    env, fmt,
    net::SocketAddr,
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    str::FromStr,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret as _, SecretString};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

/// Production Silicon Accounts.
pub const DEFAULT_ACCOUNTS_URL: &str = "https://accounts.teamofsilicons.com";
const MAX_INGRESS_BODY_BYTES: usize = 1024 * 1024;
const MAX_MANAGEMENT_BODY_BYTES: usize = 64 * 1024;
const MAX_KEYRING_ENTRIES: usize = 16;
const MAX_MAINTENANCE_BATCH_SIZE: usize = 10_000;
const MAX_MAINTENANCE_BATCHES_PER_CYCLE: u16 = 1_000;
const MAX_TRUSTED_PROXY_HOPS: u8 = 8;

/// Fully validated settings required by the HTTP API process.
#[derive(Clone, Debug)]
pub struct ApiSettings {
    /// Process environment and observability policy.
    pub process: ProcessSettings,
    /// HTTP listener and middleware settings.
    pub server: ServerSettings,
    /// Graceful process shutdown policy.
    pub shutdown: ShutdownSettings,
    /// Runtime PostgreSQL pool settings.
    pub database: DatabaseSettings,
    /// Encryption and cursor-integrity keys.
    pub crypto: CryptoSettings,
    /// Silicon Accounts integration settings.
    pub accounts: AccountsSettings,
    /// Internal Ting publication endpoint and scheduling bounds.
    pub ting: TingSettings,
    /// Retention, replay, and idempotency policy.
    pub policy: PolicySettings,
    /// Variables that are set but no longer read, with what replaced them.
    pub obsolete_variables: Vec<String>,
}

/// Fully validated settings required by the maintenance worker process.
#[derive(Clone, Debug)]
pub struct WorkerProcessSettings {
    /// Process environment and observability policy.
    pub process: ProcessSettings,
    /// Graceful process shutdown policy.
    pub shutdown: ShutdownSettings,
    /// Runtime PostgreSQL pool settings.
    pub database: DatabaseSettings,
    /// Retention maintenance policy.
    pub maintenance: MaintenanceSettings,
}

/// Non-secret configuration for internal Ting delivery.
#[derive(Clone, Debug)]
pub struct TingSettings {
    /// Trusted Ting API origin; proofs are only ever sent to this origin.
    /// `None` (`HOOK_TING_URL` unset) disables delivery: Hook keeps receiving
    /// and storing events, and queues nothing for Ting.
    pub base_url: Option<Url>,
    /// Deadline for one Ting or IAM publication operation.
    pub request_timeout: Duration,
    /// Idle interval between bounded publication cycles.
    pub poll_interval: Duration,
}

impl TingSettings {
    fn load(
        source: &impl ConfigurationSource,
        environment: RuntimeEnvironment,
    ) -> Result<Self, SettingsError> {
        let base_url = source
            .optional("HOOK_TING_URL")
            .map(|raw| {
                let url = parse_url("HOOK_TING_URL", &raw)?;
                validate_service_origin(environment, &url, "HOOK_TING_URL")?;
                Ok::<_, SettingsError>(url)
            })
            .transpose()?;
        let request_seconds: u64 = source.parse_or("HOOK_TING_TIMEOUT_SECONDS", "10")?;
        let poll_millis: u64 = source.parse_or("HOOK_TING_POLL_MILLISECONDS", "1000")?;
        if !(1..=15).contains(&request_seconds) {
            return Err(invalid(
                "HOOK_TING_TIMEOUT_SECONDS",
                "must be between 1 and 15",
            ));
        }
        if !(100..=30_000).contains(&poll_millis) {
            return Err(invalid(
                "HOOK_TING_POLL_MILLISECONDS",
                "must be between 100 and 30000",
            ));
        }
        Ok(Self {
            base_url,
            request_timeout: Duration::from_secs(request_seconds),
            poll_interval: Duration::from_millis(poll_millis),
        })
    }
}

/// Minimal settings accepted by the privileged migration command.
#[derive(Clone, Debug)]
pub struct MigrationSettings {
    /// Process environment and observability policy.
    pub process: ProcessSettings,
    /// Privileged migration pool settings.
    pub database: DatabaseSettings,
}

/// Settings shared by all executable process boundaries.
#[derive(Clone, Debug)]
pub struct ProcessSettings {
    /// Runtime safety policy.
    pub environment: RuntimeEnvironment,
    /// Structured tracing filter.
    pub log_filter: String,
}

/// Graceful shutdown deadline shared by long-running processes.
#[derive(Clone, Copy, Debug)]
pub struct ShutdownSettings {
    /// Maximum time allowed for in-flight work to stop.
    pub timeout: Duration,
}

/// Deployment environment used to enforce unsafe-development feature gates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeEnvironment {
    /// Developer workstation.
    Development,
    /// Automated test process.
    Test,
    /// Deployed production process.
    Production,
}

impl RuntimeEnvironment {
    /// Returns whether production transport and credential policy applies.
    #[must_use]
    pub const fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

/// Listener and inbound-request policy.
#[derive(Clone, Debug)]
pub struct ServerSettings {
    /// Address on which the API listens.
    pub bind_addr: SocketAddr,
    /// Canonical externally visible Hook origin.
    pub public_base_url: Url,
    /// Maximum request processing duration.
    pub request_timeout: Duration,
    /// Maximum webhook ingress body size.
    pub max_ingress_body_bytes: usize,
    /// Maximum management API body size.
    pub max_management_body_bytes: usize,
    /// Maximum concurrent in-flight requests per replica.
    pub concurrency_limit: usize,
    /// Number of trusted reverse proxies that append `X-Forwarded-For`.
    ///
    /// Zero means the TCP peer address is the client. With `n` trusted hops,
    /// the client is the `n`-th address from the right of the header.
    pub trusted_proxy_hops: u8,
}

/// PostgreSQL connection-pool policy.
#[derive(Clone, Debug)]
pub struct DatabaseSettings {
    /// PostgreSQL URL, redacted by its wrapper's `Debug` implementation.
    pub url: SecretString,
    /// Maximum open connections per process.
    pub max_connections: NonZeroU32,
    /// Minimum idle connections per process.
    pub min_connections: u32,
    /// Pool acquisition deadline.
    pub acquire_timeout: Duration,
    /// Database statement deadline.
    pub statement_timeout: Duration,
}

/// Versioned data-encryption and cursor signing keys.
#[derive(Clone, Debug)]
pub struct CryptoSettings {
    /// Key version used for new encryptions.
    pub current_encryption_version: NonZeroU16,
    /// Encryption keys indexed by version; all values are canonical base64url.
    pub encryption_keys: BTreeMap<NonZeroU16, SecretString>,
    /// Dedicated canonical base64url key used to authenticate cursors.
    pub cursor_signing_key: SecretString,
}

/// Silicon Accounts settings.
///
/// Access tokens are verified locally against the JWKS (`iss` = the public URL,
/// `aud` = the app id); lookups, introspection and proofs use the app's
/// credentials against the API URL.
#[derive(Clone)]
pub struct AccountsSettings {
    /// Public origin: the issuer of access tokens and the host of sign-in pages.
    pub public_url: Url,
    /// Origin Hook calls server to server; the public origin unless set.
    pub api_url: Url,
    /// Hook's app id at Silicon Accounts (the `aud` of its access tokens).
    pub app_id: String,
    /// Hook's app secret, used only server side.
    pub app_secret: SecretString,
    /// Webhook signing secrets: the current one first, then the previous one
    /// while a rotation overlaps. Empty when the webhook is not configured.
    pub webhook_secrets: Vec<SecretString>,
    /// Deadline for one call to Silicon Accounts.
    pub request_timeout: Duration,
}

impl AccountsSettings {
    /// The exact `iss` value of Hook's access tokens: the public origin
    /// without a trailing slash.
    #[must_use]
    pub fn issuer(&self) -> String {
        origin_string(&self.public_url)
    }

    /// The server-to-server origin without a trailing slash.
    #[must_use]
    pub fn api_origin(&self) -> String {
        origin_string(&self.api_url)
    }
}

impl fmt::Debug for AccountsSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountsSettings")
            .field("public_url", &self.public_url.as_str())
            .field("api_url", &self.api_url.as_str())
            .field("app_id", &self.app_id)
            .field("app_secret", &"[REDACTED]")
            .field("webhook_secrets", &self.webhook_secrets.len())
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

fn origin_string(url: &Url) -> String {
    url.as_str().trim_end_matches('/').to_owned()
}

/// Security and lifecycle durations enforced by the API process.
///
/// Every value is a fixed product contract; configuration may restate it but
/// cannot change it.
#[derive(Clone, Debug)]
pub struct PolicySettings {
    /// Management idempotency record retention.
    pub idempotency_ttl: Duration,
    /// Maximum replay window for a one-time secret response.
    pub secret_replay_ttl: Duration,
    /// Soft-deleted hook recovery period.
    pub deletion_retention: Duration,
    /// Retention of verified and blocked request logs.
    pub log_retention: Duration,
}

/// Retention maintenance policy.
#[derive(Clone, Debug)]
pub struct MaintenanceSettings {
    /// Maximum rows considered by one independently committed cleanup task.
    pub batch_size: NonZeroUsize,
    /// Maximum drain rounds performed before yielding to the interval timer.
    pub batches_per_cycle: NonZeroU16,
    /// Delay between retention-maintenance runs.
    pub interval: Duration,
}

/// Redacted configuration loading failure.
#[derive(Debug, Error)]
pub enum SettingsError {
    /// A required environment variable is absent or blank.
    #[error("required environment variable {0} is missing")]
    Missing(&'static str),
    /// A value is malformed or violates runtime policy.
    #[error("invalid environment variable {name}: {reason}")]
    Invalid {
        /// Variable name without its value.
        name: &'static str,
        /// Non-sensitive validation reason.
        reason: String,
    },
}

impl ApiSettings {
    /// Loads and validates API settings from `HOOK_*` environment variables.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for missing, malformed, internally
    /// inconsistent, or production-unsafe API settings. Worker-only variables
    /// are neither read nor validated.
    pub fn from_env() -> Result<Self, SettingsError> {
        Self::load(&ProcessEnvironment)
    }

    fn load(source: &impl ConfigurationSource) -> Result<Self, SettingsError> {
        let process = ProcessSettings::load(source, "silicon_hook=info,tower_http=info")?;
        let environment = process.environment;
        let server = ServerSettings::load(source, environment)?;
        let shutdown = ShutdownSettings::load(source)?;
        let database = DatabaseSettings::runtime(source, environment)?;
        let crypto = CryptoSettings::load(source)?;
        let accounts = AccountsSettings::load(source, environment)?;
        let ting = TingSettings::load(source, environment)?;
        let policy = PolicySettings::load(source)?;
        let obsolete_variables = obsolete_variables(source);

        Ok(Self {
            process,
            server,
            shutdown,
            database,
            crypto,
            accounts,
            ting,
            policy,
            obsolete_variables,
        })
    }
}

impl WorkerProcessSettings {
    /// Loads and validates worker settings from `HOOK_*` environment variables.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for missing, malformed, internally
    /// inconsistent, or production-unsafe worker settings. API-only variables
    /// are neither read nor validated.
    pub fn from_env() -> Result<Self, SettingsError> {
        Self::load(&ProcessEnvironment)
    }

    fn load(source: &impl ConfigurationSource) -> Result<Self, SettingsError> {
        let process = ProcessSettings::load(source, "silicon_hook=info")?;
        let environment = process.environment;
        let shutdown = ShutdownSettings::load(source)?;
        let database = DatabaseSettings::runtime(source, environment)?;
        let maintenance = MaintenanceSettings::load(source)?;

        Ok(Self {
            process,
            shutdown,
            database,
            maintenance,
        })
    }
}

impl MigrationSettings {
    /// Loads only settings required by the migration process.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for missing, malformed, or production-unsafe
    /// migration configuration.
    pub fn from_env() -> Result<Self, SettingsError> {
        Self::load(&ProcessEnvironment)
    }

    fn load(source: &impl ConfigurationSource) -> Result<Self, SettingsError> {
        let process = ProcessSettings::load(source, "silicon_hook=info")?;
        let environment = process.environment;
        let raw_url = source.required("HOOK_MIGRATOR_DATABASE_URL")?;
        validate_database_url(environment, &raw_url, "HOOK_MIGRATOR_DATABASE_URL")?;
        let database = DatabaseSettings {
            url: SecretString::from(raw_url),
            max_connections: source.parse_or("HOOK_MIGRATOR_DATABASE_MAX_CONNECTIONS", "2")?,
            min_connections: 0,
            acquire_timeout: source
                .positive_duration_seconds("HOOK_DATABASE_ACQUIRE_TIMEOUT_SECONDS", 3)?,
            statement_timeout: source
                .positive_duration_seconds("HOOK_MIGRATION_STATEMENT_TIMEOUT_SECONDS", 300)?,
        };
        Ok(Self { process, database })
    }
}

impl ProcessSettings {
    fn load(
        source: &impl ConfigurationSource,
        default_log_filter: &str,
    ) -> Result<Self, SettingsError> {
        let environment = source.parse_or("HOOK_ENVIRONMENT", "development")?;
        let log_filter = source.value_or("HOOK_LOG_FILTER", default_log_filter);
        validate_log_filter(&log_filter)?;
        Ok(Self {
            environment,
            log_filter,
        })
    }
}

impl ShutdownSettings {
    fn load(source: &impl ConfigurationSource) -> Result<Self, SettingsError> {
        Ok(Self {
            timeout: source.bounded_duration_seconds(
                "HOOK_SHUTDOWN_TIMEOUT_SECONDS",
                30,
                1,
                300,
            )?,
        })
    }
}

impl ServerSettings {
    fn load(
        source: &impl ConfigurationSource,
        environment: RuntimeEnvironment,
    ) -> Result<Self, SettingsError> {
        let public_base_url = if environment.is_production() {
            source.required_url("HOOK_PUBLIC_BASE_URL")?
        } else {
            source.url_or("HOOK_PUBLIC_BASE_URL", "http://127.0.0.1:8080")?
        };
        validate_http_url(environment, &public_base_url, "HOOK_PUBLIC_BASE_URL")?;
        validate_public_base_url(&public_base_url)?;

        let max_ingress_body_bytes = source.bounded_usize(
            "HOOK_MAX_INGRESS_BODY_BYTES",
            MAX_INGRESS_BODY_BYTES,
            MAX_INGRESS_BODY_BYTES,
            MAX_INGRESS_BODY_BYTES,
        )?;
        let max_management_body_bytes = source.bounded_usize(
            "HOOK_MAX_MANAGEMENT_BODY_BYTES",
            MAX_MANAGEMENT_BODY_BYTES,
            MAX_MANAGEMENT_BODY_BYTES,
            MAX_MANAGEMENT_BODY_BYTES,
        )?;
        let concurrency_limit = source.parse_or("HOOK_CONCURRENCY_LIMIT", "1024")?;
        validate_positive_at_most("HOOK_CONCURRENCY_LIMIT", concurrency_limit, 65_536)?;
        let trusted_proxy_hops: u8 = source.parse_or("HOOK_TRUSTED_PROXY_HOPS", "0")?;
        if trusted_proxy_hops > MAX_TRUSTED_PROXY_HOPS {
            return Err(invalid(
                "HOOK_TRUSTED_PROXY_HOPS",
                format!("must be between 0 and {MAX_TRUSTED_PROXY_HOPS}"),
            ));
        }

        Ok(Self {
            bind_addr: source.parse_or("HOOK_BIND_ADDR", "127.0.0.1:8080")?,
            public_base_url,
            request_timeout: source.bounded_duration_seconds(
                "HOOK_REQUEST_TIMEOUT_SECONDS",
                15,
                1,
                120,
            )?,
            max_ingress_body_bytes,
            max_management_body_bytes,
            concurrency_limit,
            trusted_proxy_hops,
        })
    }
}

impl DatabaseSettings {
    fn runtime(
        source: &impl ConfigurationSource,
        environment: RuntimeEnvironment,
    ) -> Result<Self, SettingsError> {
        let raw_url = source.required("HOOK_DATABASE_URL")?;
        validate_database_url(environment, &raw_url, "HOOK_DATABASE_URL")?;
        let settings = Self {
            url: SecretString::from(raw_url),
            max_connections: source.parse_or("HOOK_DATABASE_MAX_CONNECTIONS", "16")?,
            min_connections: source.parse_or("HOOK_DATABASE_MIN_CONNECTIONS", "1")?,
            acquire_timeout: source
                .positive_duration_seconds("HOOK_DATABASE_ACQUIRE_TIMEOUT_SECONDS", 3)?,
            statement_timeout: source
                .positive_duration_seconds("HOOK_DATABASE_STATEMENT_TIMEOUT_SECONDS", 10)?,
        };
        if settings.min_connections >= settings.max_connections.get() {
            return Err(invalid(
                "HOOK_DATABASE_MIN_CONNECTIONS",
                "must be lower than HOOK_DATABASE_MAX_CONNECTIONS",
            ));
        }
        Ok(settings)
    }
}

impl CryptoSettings {
    fn load(source: &impl ConfigurationSource) -> Result<Self, SettingsError> {
        let current_encryption_version =
            source.parse::<NonZeroU16>("HOOK_ENCRYPTION_CURRENT_VERSION")?;
        let encryption_keys = parse_keyring(
            &source.required_secret("HOOK_ENCRYPTION_KEYS")?,
            "HOOK_ENCRYPTION_KEYS",
        )?;
        if !encryption_keys.contains_key(&current_encryption_version) {
            return Err(invalid(
                "HOOK_ENCRYPTION_CURRENT_VERSION",
                "must identify a configured encryption key",
            ));
        }
        let cursor_signing_key = source.required_secret("HOOK_CURSOR_SIGNING_KEY")?;
        let cursor_bytes = validate_base64url_key(
            "HOOK_CURSOR_SIGNING_KEY",
            cursor_signing_key.expose_secret(),
        )?;
        for key in encryption_keys.values() {
            let encryption_bytes =
                validate_base64url_key("HOOK_ENCRYPTION_KEYS", key.expose_secret())?;
            if encryption_bytes == cursor_bytes {
                return Err(invalid(
                    "HOOK_CURSOR_SIGNING_KEY",
                    "must be distinct from every encryption key",
                ));
            }
        }

        Ok(Self {
            current_encryption_version,
            encryption_keys,
            cursor_signing_key,
        })
    }
}

impl AccountsSettings {
    fn load(
        source: &impl ConfigurationSource,
        environment: RuntimeEnvironment,
    ) -> Result<Self, SettingsError> {
        let public_url = source.url_or("ACCOUNTS_URL", DEFAULT_ACCOUNTS_URL)?;
        validate_service_origin(environment, &public_url, "ACCOUNTS_URL")?;
        let api_url = match source.optional("ACCOUNTS_API_URL") {
            Some(raw) => {
                let url = parse_url("ACCOUNTS_API_URL", &raw)?;
                validate_service_origin(environment, &url, "ACCOUNTS_API_URL")?;
                url
            }
            None => public_url.clone(),
        };
        let app_id = source.value_or("HOOK_APP_ID", "hook");
        validate_app_id(&app_id)?;
        let app_secret = source.required_secret("HOOK_APP_SECRET")?;
        validate_secret_text("HOOK_APP_SECRET", &app_secret, 16)?;
        let mut webhook_secrets = Vec::new();
        if let Some(current) = source.optional_secret("HOOK_ACCOUNTS_WEBHOOK_SECRET") {
            validate_secret_text("HOOK_ACCOUNTS_WEBHOOK_SECRET", &current, 16)?;
            webhook_secrets.push(current);
            if let Some(previous) = source.optional_secret("HOOK_ACCOUNTS_WEBHOOK_PREVIOUS_SECRET")
            {
                validate_secret_text("HOOK_ACCOUNTS_WEBHOOK_PREVIOUS_SECRET", &previous, 16)?;
                webhook_secrets.push(previous);
            }
        } else if source
            .optional_secret("HOOK_ACCOUNTS_WEBHOOK_PREVIOUS_SECRET")
            .is_some()
        {
            return Err(invalid(
                "HOOK_ACCOUNTS_WEBHOOK_PREVIOUS_SECRET",
                "is only used together with HOOK_ACCOUNTS_WEBHOOK_SECRET (the current secret)",
            ));
        } else if environment.is_production() {
            return Err(SettingsError::Missing("HOOK_ACCOUNTS_WEBHOOK_SECRET"));
        }
        Ok(Self {
            public_url,
            api_url,
            app_id,
            app_secret,
            webhook_secrets,
            request_timeout: source.bounded_duration_seconds(
                "HOOK_ACCOUNTS_TIMEOUT_SECONDS",
                5,
                1,
                30,
            )?,
        })
    }
}

/// Variables from the Silicon IAM, Honeycomb and test-environment era that are
/// no longer read, with what replaced them.
const OBSOLETE_VARIABLES: &[(&str, &str)] = &[
    ("HOOK_IAM_BASE_URL", "ACCOUNTS_URL"),
    (
        "HOOK_IAM_ALLOW_INSECURE_LOCAL_HTTP",
        "plain HTTP is allowed for loopback hosts only",
    ),
    ("HOOK_IAM_APP_ID", "HOOK_APP_ID"),
    ("HOOK_IAM_APP_SECRET", "HOOK_APP_SECRET"),
    ("HOOK_IAM_WEBHOOK_SECRET", "HOOK_ACCOUNTS_WEBHOOK_SECRET"),
    (
        "HOOK_IAM_WEBHOOK_SECRET_VERSION",
        "nothing (Accounts secrets are not versioned)",
    ),
    (
        "HOOK_IAM_WEBHOOK_PREVIOUS_SECRET",
        "HOOK_ACCOUNTS_WEBHOOK_PREVIOUS_SECRET",
    ),
    (
        "HOOK_IAM_WEBHOOK_PREVIOUS_SECRET_VERSION",
        "nothing (Accounts secrets are not versioned)",
    ),
    (
        "HOOK_IAM_REQUEST_TIMEOUT_SECONDS",
        "HOOK_ACCOUNTS_TIMEOUT_SECONDS",
    ),
    ("HOOK_IAM_MAX_RESPONSE_BYTES", "nothing"),
    ("HOOK_PROVIDER_CONNECT_TIMEOUT_MS", "nothing"),
    (
        "HOOK_ALLOW_LOCAL_AUTH",
        "access tokens from Silicon Accounts (local stack: ACCOUNTS_URL=http://localhost:9590)",
    ),
    (
        "HOOK_TING_BASE_URL",
        "HOOK_TING_URL (delivery through Ting is off unless it is set)",
    ),
    (
        "HOOK_TEST_DATABASE_URL",
        "nothing (test environments were removed)",
    ),
    (
        "HOOK_TEST_MIGRATOR_DATABASE_URL",
        "nothing (test environments were removed)",
    ),
    (
        "HOOK_TEST_TELEMETRY_KEYS",
        "nothing (test environments were removed)",
    ),
    (
        "HOOK_HONEYCOMB_SERVICE_TOKEN",
        "nothing (Silicon Apps has no lifecycle callbacks)",
    ),
    (
        "HOOK_HONEYCOMB_URL",
        "nothing (Silicon Apps has no lifecycle callbacks)",
    ),
    (
        "HOOK_REALTIME_HEARTBEAT_INTERVAL_SECONDS",
        "nothing (the v1 WebSocket was removed)",
    ),
    (
        "HOOK_REALTIME_HEARTBEAT_TIMEOUT_SECONDS",
        "nothing (the v1 WebSocket was removed)",
    ),
    (
        "HOOK_REALTIME_REPLAY_BATCH_SIZE",
        "nothing (the v1 WebSocket was removed)",
    ),
    (
        "HOOK_REALTIME_POLL_INTERVAL_MS",
        "nothing (the v1 WebSocket was removed)",
    ),
    (
        "HOOK_REALTIME_MAX_SILICONS_PER_CONNECTION",
        "nothing (the v1 WebSocket was removed)",
    ),
];

fn obsolete_variables(source: &impl ConfigurationSource) -> Vec<String> {
    OBSOLETE_VARIABLES
        .iter()
        .filter(|(name, _)| source.raw(name).is_some())
        .map(|(name, replacement)| format!("{name} is no longer read; use {replacement}"))
        .collect()
}

impl PolicySettings {
    fn load(source: &impl ConfigurationSource) -> Result<Self, SettingsError> {
        let idempotency_ttl = source.bounded_duration_seconds(
            "HOOK_IDEMPOTENCY_TTL_SECONDS",
            86_400,
            86_400,
            86_400,
        )?;
        let secret_replay_ttl =
            source.bounded_duration_seconds("HOOK_SECRET_REPLAY_TTL_SECONDS", 600, 600, 600)?;
        let deletion_retention = source.bounded_duration_seconds(
            "HOOK_DELETION_RETENTION_SECONDS",
            45 * 86_400,
            45 * 86_400,
            45 * 86_400,
        )?;
        let log_retention = source.bounded_duration_seconds(
            "HOOK_LOG_RETENTION_SECONDS",
            14 * 86_400,
            14 * 86_400,
            14 * 86_400,
        )?;

        Ok(Self {
            idempotency_ttl,
            secret_replay_ttl,
            deletion_retention,
            log_retention,
        })
    }
}

impl MaintenanceSettings {
    fn load(source: &impl ConfigurationSource) -> Result<Self, SettingsError> {
        let batch_size: NonZeroUsize = source.parse_or("HOOK_MAINTENANCE_BATCH_SIZE", "1000")?;
        if batch_size.get() > MAX_MAINTENANCE_BATCH_SIZE {
            return Err(invalid(
                "HOOK_MAINTENANCE_BATCH_SIZE",
                format!("must be between 1 and {MAX_MAINTENANCE_BATCH_SIZE}"),
            ));
        }
        let batches_per_cycle: NonZeroU16 =
            source.parse_or("HOOK_MAINTENANCE_BATCHES_PER_CYCLE", "32")?;
        if batches_per_cycle.get() > MAX_MAINTENANCE_BATCHES_PER_CYCLE {
            return Err(invalid(
                "HOOK_MAINTENANCE_BATCHES_PER_CYCLE",
                format!("must be between 1 and {MAX_MAINTENANCE_BATCHES_PER_CYCLE}"),
            ));
        }
        Ok(Self {
            batch_size,
            batches_per_cycle,
            interval: source.bounded_duration_seconds(
                "HOOK_MAINTENANCE_INTERVAL_SECONDS",
                5,
                1,
                86_400,
            )?,
        })
    }
}

trait ConfigurationSource {
    fn raw(&self, name: &'static str) -> Option<String>;

    fn optional(&self, name: &'static str) -> Option<String> {
        self.raw(name)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }

    fn optional_secret(&self, name: &'static str) -> Option<SecretString> {
        self.raw(name)
            .filter(|value| !value.trim().is_empty())
            .map(SecretString::from)
    }

    fn required(&self, name: &'static str) -> Result<String, SettingsError> {
        self.optional(name).ok_or(SettingsError::Missing(name))
    }

    fn required_secret(&self, name: &'static str) -> Result<SecretString, SettingsError> {
        self.optional_secret(name)
            .ok_or(SettingsError::Missing(name))
    }

    fn value_or(&self, name: &'static str, default: &str) -> String {
        self.optional(name).unwrap_or_else(|| default.to_owned())
    }

    fn parse<T>(&self, name: &'static str) -> Result<T, SettingsError>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        self.required(name)?
            .parse()
            .map_err(|error: T::Err| invalid(name, error.to_string()))
    }

    fn parse_or<T>(&self, name: &'static str, default: &str) -> Result<T, SettingsError>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        self.value_or(name, default)
            .parse()
            .map_err(|error: T::Err| invalid(name, error.to_string()))
    }

    fn url_or(&self, name: &'static str, default: &str) -> Result<Url, SettingsError> {
        parse_url(name, &self.value_or(name, default))
    }

    fn required_url(&self, name: &'static str) -> Result<Url, SettingsError> {
        parse_url(name, &self.required(name)?)
    }

    fn positive_duration_seconds(
        &self,
        name: &'static str,
        default: u64,
    ) -> Result<Duration, SettingsError> {
        self.bounded_duration_seconds(name, default, 1, u64::MAX)
    }

    fn bounded_duration_seconds(
        &self,
        name: &'static str,
        default: u64,
        minimum: u64,
        maximum: u64,
    ) -> Result<Duration, SettingsError> {
        let seconds = self.parse_or(name, &default.to_string())?;
        if !(minimum..=maximum).contains(&seconds) {
            return Err(invalid(
                name,
                format!("must be between {minimum} and {maximum} seconds"),
            ));
        }
        Ok(Duration::from_secs(seconds))
    }

    fn bounded_usize(
        &self,
        name: &'static str,
        default: usize,
        minimum: usize,
        maximum: usize,
    ) -> Result<usize, SettingsError> {
        let value = self.parse_or(name, &default.to_string())?;
        if !(minimum..=maximum).contains(&value) {
            return Err(invalid(
                name,
                format!("must be between {minimum} and {maximum}"),
            ));
        }
        Ok(value)
    }
}

struct ProcessEnvironment;

impl ConfigurationSource for ProcessEnvironment {
    fn raw(&self, name: &'static str) -> Option<String> {
        env::var(name).ok()
    }
}

fn parse_url(name: &'static str, value: &str) -> Result<Url, SettingsError> {
    let mut url = Url::parse(value).map_err(|error| invalid(name, error.to_string()))?;
    if !url.path().ends_with('/') {
        let normalized_path = format!("{}/", url.path());
        url.set_path(&normalized_path);
    }
    Ok(url)
}

fn validate_http_url(
    environment: RuntimeEnvironment,
    url: &Url,
    name: &'static str,
) -> Result<(), SettingsError> {
    if url.cannot_be_a_base()
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid(
            name,
            "must be an absolute URL without embedded credentials",
        ));
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid(name, "must use HTTP or HTTPS"));
    }
    if environment.is_production() && url.scheme() != "https" {
        return Err(invalid(name, "production URLs must use HTTPS"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid(name, "must not contain a query or fragment"));
    }
    Ok(())
}

fn validate_public_base_url(url: &Url) -> Result<(), SettingsError> {
    if url.path() != "/" {
        return Err(invalid(
            "HOOK_PUBLIC_BASE_URL",
            "must be an origin without a path",
        ));
    }
    Ok(())
}

fn validate_database_url(
    environment: RuntimeEnvironment,
    value: &str,
    name: &'static str,
) -> Result<(), SettingsError> {
    let url = Url::parse(value).map_err(|error| invalid(name, error.to_string()))?;
    if !matches!(url.scheme(), "postgres" | "postgresql") || url.host_str().is_none() {
        return Err(invalid(
            name,
            "must be an absolute postgres:// or postgresql:// URL",
        ));
    }
    if environment.is_production() {
        let ssl_modes = url
            .query_pairs()
            .filter(|(key, _value)| matches!(key.as_ref(), "sslmode" | "ssl-mode"))
            .map(|(_key, value)| value.into_owned())
            .collect::<Vec<_>>();
        match ssl_modes.as_slice() {
            [mode] if matches!(mode.as_str(), "require" | "verify-ca" | "verify-full") => {}
            [_mode] => return Err(invalid(name, "production connections must require TLS")),
            _ => {
                return Err(invalid(
                    name,
                    "production connections must specify exactly one sslmode or ssl-mode",
                ));
            }
        }
    }
    Ok(())
}

fn parse_keyring(
    raw: &SecretString,
    name: &'static str,
) -> Result<BTreeMap<NonZeroU16, SecretString>, SettingsError> {
    let mut keys = BTreeMap::new();
    for entry in raw.expose_secret().split(',') {
        let Some((version, encoded_key)) = entry.split_once(':') else {
            return Err(invalid(name, "entries must use version:base64url-key"));
        };
        let version = version
            .parse::<NonZeroU16>()
            .map_err(|_| invalid(name, "key versions must be non-zero unsigned integers"))?;
        validate_base64url_key(name, encoded_key)?;
        if keys
            .insert(version, SecretString::from(encoded_key.to_owned()))
            .is_some()
        {
            return Err(invalid(name, "key versions must be unique"));
        }
        if keys.len() > MAX_KEYRING_ENTRIES {
            return Err(invalid(name, "too many encryption key versions"));
        }
    }
    if keys.is_empty() {
        return Err(invalid(name, "must contain at least one key"));
    }
    Ok(keys)
}

fn validate_base64url_key(
    name: &'static str,
    encoded: &str,
) -> Result<Zeroizing<[u8; 32]>, SettingsError> {
    let mut key = Zeroizing::new([0_u8; 32]);
    let decoded_length = URL_SAFE_NO_PAD
        .decode_slice(encoded, key.as_mut())
        .map_err(|_| invalid(name, "must contain canonical unpadded base64url keys"))?;
    if decoded_length != key.len() {
        return Err(invalid(
            name,
            "each decoded key must contain exactly 32 bytes",
        ));
    }
    if URL_SAFE_NO_PAD.encode(key.as_ref()) != encoded {
        return Err(invalid(
            name,
            "must contain canonical unpadded base64url keys",
        ));
    }
    Ok(key)
}

/// Bare Silicon Accounts app id, such as `hook`.
fn validate_app_id(app_id: &str) -> Result<(), SettingsError> {
    let valid = (1..=80).contains(&app_id.len())
        && app_id
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && app_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        });
    if valid {
        Ok(())
    } else {
        Err(invalid(
            "HOOK_APP_ID",
            "must be a bare Silicon Accounts app id of lowercase letters, digits, _ or -, such as hook",
        ))
    }
}

fn validate_secret_text(
    name: &'static str,
    secret: &SecretString,
    minimum: usize,
) -> Result<(), SettingsError> {
    let value = secret.expose_secret();
    if (minimum..=512).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic()) {
        Ok(())
    } else {
        Err(invalid(
            name,
            format!("must be {minimum} to 512 visible ASCII characters with no spaces"),
        ))
    }
}

/// An HTTP(S) origin Hook sends credentials to: HTTPS, or plain HTTP to a
/// loopback host outside production (the local Silicon Accounts stack).
fn validate_service_origin(
    environment: RuntimeEnvironment,
    url: &Url,
    name: &'static str,
) -> Result<(), SettingsError> {
    if url.cannot_be_a_base()
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid(
            name,
            "must be an absolute URL without embedded credentials",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
        return Err(invalid(
            name,
            "must be an origin such as https://accounts.teamofsilicons.com, without a path, query or fragment",
        ));
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if environment.is_production() => {
            Err(invalid(name, "production URLs must use HTTPS"))
        }
        "http" if is_loopback(url) => Ok(()),
        "http" => Err(invalid(
            name,
            "plain HTTP is only allowed for a loopback host (localhost, 127.0.0.1 or ::1); use https://",
        )),
        _ => Err(invalid(name, "must use HTTPS")),
    }
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn validate_positive_at_most(
    name: &'static str,
    value: usize,
    maximum: usize,
) -> Result<(), SettingsError> {
    if value == 0 || value > maximum {
        return Err(invalid(name, format!("must be between 1 and {maximum}")));
    }
    Ok(())
}

fn validate_log_filter(value: &str) -> Result<(), SettingsError> {
    if value.is_empty() || value.len() > 2048 || value.contains(['\r', '\n']) {
        return Err(invalid(
            "HOOK_LOG_FILTER",
            "must be 1 to 2048 bytes on one line",
        ));
    }
    Ok(())
}

fn invalid(name: &'static str, reason: impl Into<String>) -> SettingsError {
    SettingsError::Invalid {
        name,
        reason: reason.into(),
    }
}

impl FromStr for RuntimeEnvironment {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "development" | "dev" => Ok(Self::Development),
            "test" => Ok(Self::Test),
            "production" | "prod" => Ok(Self::Production),
            _ => Err("expected development, test, or production"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use pretty_assertions::assert_eq;
    use secrecy::ExposeSecret as _;

    use super::{
        ApiSettings, ConfigurationSource, MAX_MAINTENANCE_BATCH_SIZE,
        MAX_MAINTENANCE_BATCHES_PER_CYCLE, MigrationSettings, RuntimeEnvironment, SettingsError,
        WorkerProcessSettings,
    };

    struct TestEnvironment(BTreeMap<&'static str, String>);

    impl ConfigurationSource for TestEnvironment {
        fn raw(&self, name: &'static str) -> Option<String> {
            self.0.get(name).cloned()
        }
    }

    fn base_environment(environment: &str) -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("HOOK_ENVIRONMENT", environment.to_owned()),
            (
                "HOOK_DATABASE_URL",
                "postgres://hook:secret@db.internal/hook?sslmode=verify-full".to_owned(),
            ),
        ])
    }

    fn valid_api_environment(environment: &str) -> TestEnvironment {
        let encryption_key = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let cursor_key = URL_SAFE_NO_PAD.encode([8_u8; 32]);
        let mut values = base_environment(environment);
        values.extend([
            (
                "HOOK_PUBLIC_BASE_URL",
                "https://backend.hook.teamofsilicons.com".to_owned(),
            ),
            ("HOOK_ENCRYPTION_KEYS", format!("1:{encryption_key}")),
            ("HOOK_ENCRYPTION_CURRENT_VERSION", "1".to_owned()),
            ("HOOK_CURSOR_SIGNING_KEY", cursor_key),
            (
                "HOOK_APP_SECRET",
                "sa_app_hook_production-secret-value".to_owned(),
            ),
            (
                "HOOK_ACCOUNTS_WEBHOOK_SECRET",
                "whsec_production-webhook-secret".to_owned(),
            ),
        ]);
        TestEnvironment(values)
    }

    fn valid_worker_environment(environment: &str) -> TestEnvironment {
        TestEnvironment(base_environment(environment))
    }

    fn valid_migration_environment(environment: &str) -> TestEnvironment {
        TestEnvironment(BTreeMap::from([
            ("HOOK_ENVIRONMENT", environment.to_owned()),
            (
                "HOOK_MIGRATOR_DATABASE_URL",
                "postgres://migrator:secret@db.internal/hook?sslmode=verify-full".to_owned(),
            ),
        ]))
    }

    fn rejected(environment: &TestEnvironment) -> Option<(&'static str, String)> {
        match ApiSettings::load(environment) {
            Err(SettingsError::Invalid { name, reason }) => Some((name, reason)),
            Err(SettingsError::Missing(name)) => Some((name, "missing".to_owned())),
            Ok(_) => None,
        }
    }

    #[test]
    fn production_api_configuration_is_typed_and_redacted() -> Result<(), SettingsError> {
        let settings = ApiSettings::load(&valid_api_environment("production"))?;

        assert_eq!(settings.process.environment, RuntimeEnvironment::Production);
        assert_eq!(settings.crypto.encryption_keys.len(), 1);
        assert_eq!(settings.accounts.app_id, "hook");
        assert_eq!(
            settings.accounts.issuer(),
            "https://accounts.teamofsilicons.com"
        );
        assert_eq!(settings.accounts.api_origin(), settings.accounts.issuer());
        assert_eq!(settings.accounts.webhook_secrets.len(), 1);
        assert!(
            settings.ting.base_url.is_none(),
            "Ting is off unless HOOK_TING_URL is set"
        );
        assert!(settings.obsolete_variables.is_empty());
        assert_eq!(settings.server.trusted_proxy_hops, 0);
        assert_eq!(settings.policy.log_retention.as_secs(), 14 * 86_400);
        let debug = format!("{settings:?}");
        assert!(!debug.contains("production-secret-value"));
        assert!(!debug.contains("production-webhook-secret"));
        assert!(!debug.contains("hook:secret"));
        Ok(())
    }

    #[test]
    fn local_stack_uses_loopback_http_with_a_separate_api_origin() -> Result<(), SettingsError> {
        let mut environment = valid_api_environment("development");
        environment
            .0
            .insert("ACCOUNTS_URL", "http://localhost:9590".to_owned());
        environment
            .0
            .insert("ACCOUNTS_API_URL", "http://127.0.0.1:9589".to_owned());
        environment.0.remove("HOOK_ACCOUNTS_WEBHOOK_SECRET");
        environment
            .0
            .insert("HOOK_TING_URL", "http://127.0.0.1:4202".to_owned());
        let settings = ApiSettings::load(&environment)?;
        assert_eq!(settings.accounts.issuer(), "http://localhost:9590");
        assert_eq!(settings.accounts.api_origin(), "http://127.0.0.1:9589");
        assert!(settings.accounts.webhook_secrets.is_empty());
        assert_eq!(
            settings.ting.base_url.as_ref().map(url::Url::as_str),
            Some("http://127.0.0.1:4202/")
        );
        Ok(())
    }

    #[test]
    fn accounts_origins_must_be_https_unless_loopback_outside_production() {
        for (environment, name, value, reason) in [
            (
                "development",
                "ACCOUNTS_URL",
                "http://accounts.example.com",
                "loopback",
            ),
            (
                "production",
                "ACCOUNTS_URL",
                "http://localhost:9590",
                "HTTPS",
            ),
            (
                "development",
                "ACCOUNTS_URL",
                "https://accounts.example.com/v1",
                "origin",
            ),
            (
                "development",
                "ACCOUNTS_API_URL",
                "https://user:pass@accounts.example.com",
                "credentials",
            ),
            (
                "development",
                "HOOK_TING_URL",
                "http://ting.example.com",
                "loopback",
            ),
        ] {
            let mut settings = valid_api_environment(environment);
            settings.0.insert(name, value.to_owned());
            let refusal = rejected(&settings);
            assert!(
                refusal
                    .as_ref()
                    .is_some_and(|(rejected, why)| *rejected == name && why.contains(reason)),
                "{name}={value} in {environment}: {refusal:?}"
            );
        }
    }

    #[test]
    fn app_credentials_and_webhook_secrets_are_validated() {
        let mut missing = valid_api_environment("development");
        missing.0.remove("HOOK_APP_SECRET");
        assert_eq!(
            rejected(&missing).map(|(name, _)| name),
            Some("HOOK_APP_SECRET")
        );

        let mut production_without_webhook = valid_api_environment("production");
        production_without_webhook
            .0
            .remove("HOOK_ACCOUNTS_WEBHOOK_SECRET");
        assert_eq!(
            rejected(&production_without_webhook).map(|(name, _)| name),
            Some("HOOK_ACCOUNTS_WEBHOOK_SECRET")
        );

        let mut orphan_previous = valid_api_environment("development");
        orphan_previous.0.remove("HOOK_ACCOUNTS_WEBHOOK_SECRET");
        orphan_previous.0.insert(
            "HOOK_ACCOUNTS_WEBHOOK_PREVIOUS_SECRET",
            "whsec_previous-webhook-secret".to_owned(),
        );
        assert_eq!(
            rejected(&orphan_previous).map(|(name, _)| name),
            Some("HOOK_ACCOUNTS_WEBHOOK_PREVIOUS_SECRET")
        );

        for (name, value) in [
            ("HOOK_APP_ID", "Hook"),
            ("HOOK_APP_ID", "tos>hook"),
            ("HOOK_APP_SECRET", "short"),
            ("HOOK_APP_SECRET", "has a space in the middle!"),
        ] {
            let mut environment = valid_api_environment("development");
            environment.0.insert(name, value.to_owned());
            assert_eq!(
                rejected(&environment).map(|(rejected, _)| rejected),
                Some(name)
            );
        }
    }

    #[test]
    fn rotation_keeps_the_current_secret_first() -> Result<(), SettingsError> {
        let mut environment = valid_api_environment("production");
        environment.0.insert(
            "HOOK_ACCOUNTS_WEBHOOK_PREVIOUS_SECRET",
            "whsec_previous-webhook-secret".to_owned(),
        );
        let settings = ApiSettings::load(&environment)?;
        let secrets = settings
            .accounts
            .webhook_secrets
            .iter()
            .map(|secret| secret.expose_secret().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            secrets,
            vec![
                "whsec_production-webhook-secret".to_owned(),
                "whsec_previous-webhook-secret".to_owned()
            ]
        );
        Ok(())
    }

    #[test]
    fn iam_era_variables_are_reported_not_used() -> Result<(), SettingsError> {
        let mut environment = valid_api_environment("production");
        environment.0.insert(
            "HOOK_IAM_BASE_URL",
            "https://backend.iam.teamofsilicons.com".to_owned(),
        );
        environment
            .0
            .insert("HOOK_ALLOW_LOCAL_AUTH", "true".to_owned());
        environment.0.insert(
            "HOOK_TING_BASE_URL",
            "https://backend.ting.teamofsilicons.com/".to_owned(),
        );
        let settings = ApiSettings::load(&environment)?;
        assert_eq!(settings.obsolete_variables.len(), 3);
        assert!(
            settings
                .obsolete_variables
                .iter()
                .any(|line| line
                    .starts_with("HOOK_IAM_BASE_URL is no longer read; use ACCOUNTS_URL"))
        );
        assert!(settings.ting.base_url.is_none());
        Ok(())
    }

    #[test]
    fn worker_does_not_load_api_credentials_or_crypto() -> Result<(), SettingsError> {
        let mut environment = valid_worker_environment("production");
        environment
            .0
            .insert("HOOK_PUBLIC_BASE_URL", "not a URL".to_owned());
        environment
            .0
            .insert("HOOK_ENCRYPTION_KEYS", "not-a-keyring".to_owned());
        environment
            .0
            .insert("HOOK_CURSOR_SIGNING_KEY", "not-a-key".to_owned());
        environment.0.insert("HOOK_APP_SECRET", String::new());

        let settings = WorkerProcessSettings::load(&environment)?;
        assert_eq!(settings.process.environment, RuntimeEnvironment::Production);
        Ok(())
    }

    #[test]
    fn migration_does_not_load_runtime_credentials() -> Result<(), SettingsError> {
        let mut environment = valid_migration_environment("production");
        environment
            .0
            .insert("HOOK_DATABASE_URL", "not a URL".to_owned());
        environment
            .0
            .insert("HOOK_ENCRYPTION_KEYS", "not-a-keyring".to_owned());

        let settings = MigrationSettings::load(&environment)?;
        assert_eq!(settings.process.environment, RuntimeEnvironment::Production);
        Ok(())
    }

    #[test]
    fn each_process_rejects_a_missing_owned_secret() {
        for name in [
            "HOOK_ENCRYPTION_KEYS",
            "HOOK_CURSOR_SIGNING_KEY",
            "HOOK_APP_SECRET",
        ] {
            let mut api = valid_api_environment("production");
            api.0.remove(name);
            assert!(matches!(
                ApiSettings::load(&api),
                Err(SettingsError::Missing(rejected)) if rejected == name
            ));
        }

        let mut migration = valid_migration_environment("production");
        migration.0.remove("HOOK_MIGRATOR_DATABASE_URL");
        assert!(matches!(
            MigrationSettings::load(&migration),
            Err(SettingsError::Missing("HOOK_MIGRATOR_DATABASE_URL"))
        ));
    }

    #[test]
    fn production_database_tls_mode_is_unambiguous_across_driver_aliases()
    -> Result<(), SettingsError> {
        let mut environment = valid_api_environment("production");
        environment.0.insert(
            "HOOK_DATABASE_URL",
            "postgres://hook:secret@db.internal/hook?ssl-mode=verify-full".to_owned(),
        );
        ApiSettings::load(&environment)?;

        for query in [
            "sslmode=require&sslmode=disable",
            "sslmode=require&ssl-mode=disable",
            "ssl-mode=verify-full&sslmode=require",
        ] {
            environment.0.insert(
                "HOOK_DATABASE_URL",
                format!("postgres://hook:secret@db.internal/hook?{query}"),
            );
            assert!(matches!(
                ApiSettings::load(&environment),
                Err(SettingsError::Invalid {
                    name: "HOOK_DATABASE_URL",
                    ..
                })
            ));
        }
        Ok(())
    }

    #[test]
    fn key_roles_must_use_distinct_material() {
        let mut environment = valid_api_environment("production");
        let encryption_key = environment
            .0
            .get("HOOK_ENCRYPTION_KEYS")
            .and_then(|entry| entry.split_once(':'))
            .map(|(_, key)| key.to_owned());
        if let Some(encryption_key) = encryption_key {
            environment
                .0
                .insert("HOOK_CURSOR_SIGNING_KEY", encryption_key);
        }

        assert!(matches!(
            ApiSettings::load(&environment),
            Err(SettingsError::Invalid {
                name: "HOOK_CURSOR_SIGNING_KEY",
                ..
            })
        ));
    }

    #[test]
    fn fixed_public_contract_values_reject_configuration_drift() {
        for (name, value) in [
            ("HOOK_MAX_INGRESS_BODY_BYTES", "1048575"),
            ("HOOK_MAX_MANAGEMENT_BODY_BYTES", "65535"),
            ("HOOK_IDEMPOTENCY_TTL_SECONDS", "86401"),
            ("HOOK_SECRET_REPLAY_TTL_SECONDS", "599"),
            ("HOOK_DELETION_RETENTION_SECONDS", "3888001"),
            ("HOOK_LOG_RETENTION_SECONDS", "1209599"),
            ("HOOK_TRUSTED_PROXY_HOPS", "9"),
            ("HOOK_ACCOUNTS_TIMEOUT_SECONDS", "31"),
        ] {
            let mut environment = valid_api_environment("production");
            environment.0.insert(name, value.to_owned());
            assert!(
                matches!(
                    ApiSettings::load(&environment),
                    Err(SettingsError::Invalid { name: rejected, .. }) if rejected == name
                ),
                "{name} accepted {value}"
            );
        }
    }

    #[test]
    fn maintenance_capacity_is_bounded() {
        for (name, value) in [
            (
                "HOOK_MAINTENANCE_BATCH_SIZE",
                (MAX_MAINTENANCE_BATCH_SIZE + 1).to_string(),
            ),
            (
                "HOOK_MAINTENANCE_BATCHES_PER_CYCLE",
                (MAX_MAINTENANCE_BATCHES_PER_CYCLE + 1).to_string(),
            ),
        ] {
            let mut environment = valid_worker_environment("production");
            environment.0.insert(name, value);
            assert!(matches!(
                WorkerProcessSettings::load(&environment),
                Err(SettingsError::Invalid { name: rejected, .. }) if rejected == name
            ));
        }
    }
}
