//! PostgreSQL test harness without Docker.
//!
//! Every test gets its own empty database (`hook_t_*`) on the server named by
//! `HOOK_TEST_POSTGRES_URL` (an administrator URL such as
//! `postgres://postgres@127.0.0.1:5460/postgres`). Runtime roles
//! (`hook_api_*`, `hook_worker_*`) are created on demand and receive the real
//! grant manifest through `psql`, exactly as production does. Databases and
//! roles are dropped when the handle is dropped, even after a panic.
//!
//! When the variable is unset, [`TestDatabase::create`] returns `None` and the
//! caller skips with the printed reason.
#![allow(dead_code, reason = "each test target uses a different subset")]

use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use sqlx::{PgPool, postgres::PgPoolOptions};
use url::Url;

/// Administrator URL of the PostgreSQL server the tests may create databases on.
pub const POSTGRES_URL_ENV: &str = "HOOK_TEST_POSTGRES_URL";
/// Optional path of the `psql` binary used to apply the grant manifest.
pub const PSQL_ENV: &str = "HOOK_TEST_PSQL";

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// One throwaway database and the roles created for it.
pub struct TestDatabase {
    admin: Url,
    name: String,
    owner: Url,
    roles: Vec<String>,
}

/// Connection URLs of the restricted runtime logins.
pub struct RuntimeRoles {
    /// API login with the manifest's API grants.
    pub api: String,
    /// Worker login with the manifest's worker grants.
    pub worker: String,
}

impl TestDatabase {
    /// Creates an empty database, or returns `None` when no server is configured.
    ///
    /// # Errors
    /// Returns an error when the server is configured but unusable.
    pub async fn create() -> Result<Option<Self>> {
        let Ok(raw) = std::env::var(POSTGRES_URL_ENV) else {
            eprintln!(
                "skipping: {POSTGRES_URL_ENV} is not set (for example \
                 postgres://postgres@127.0.0.1:5460/postgres)"
            );
            return Ok(None);
        };
        let admin = Url::parse(raw.trim()).with_context(|| format!("parse {POSTGRES_URL_ENV}"))?;
        let suffix = unique_suffix();
        let name = format!("hook_t_{suffix}");
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(admin.as_str())
            .await
            .with_context(|| format!("connect to {POSTGRES_URL_ENV}"))?;
        // The name is generated from digits and hex only.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&pool)
            .await
            .with_context(|| format!("create test database {name}"))?;
        pool.close().await;
        let mut owner = admin.clone();
        owner.set_path(&format!("/{name}"));
        Ok(Some(Self {
            admin,
            name,
            owner,
            roles: Vec::new(),
        }))
    }

    /// The database name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The owner (administrator) URL of this database.
    #[must_use]
    pub fn url(&self) -> &str {
        self.owner.as_str()
    }

    /// Connects a pool as the owner.
    ///
    /// # Errors
    /// Returns connection failures.
    pub async fn connect(&self, max_connections: u32) -> Result<PgPool> {
        PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(self.owner.as_str())
            .await
            .with_context(|| format!("connect to test database {}", self.name))
    }

    /// Connects a pool with an explicit URL (for example a runtime role).
    ///
    /// # Errors
    /// Returns connection failures.
    pub async fn connect_as(url: &str, max_connections: u32) -> Result<PgPool> {
        PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(url)
            .await
            .context("connect as a runtime role")
    }

    /// Creates the API and worker logins and applies the grant manifest.
    ///
    /// Call this after migrating, as production does.
    ///
    /// # Errors
    /// Returns role creation or manifest failures.
    pub async fn runtime_roles(&mut self) -> Result<RuntimeRoles> {
        let suffix = unique_suffix();
        let api = format!("hook_api_{suffix}");
        let worker = format!("hook_worker_{suffix}");
        let pool = self.connect(1).await?;
        for role in [&api, &worker] {
            // Role names are generated from digits and hex only.
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
                 NOINHERIT NOREPLICATION"
            )))
            .execute(&pool)
            .await
            .with_context(|| format!("create role {role}"))?;
            self.roles.push(role.clone());
        }
        pool.close().await;
        self.psql_file(
            &manifest_path(),
            &[("api_role", api.as_str()), ("worker_role", worker.as_str())],
        )?;
        Ok(RuntimeRoles {
            api: self.role_url(&api),
            worker: self.role_url(&worker),
        })
    }

    /// Runs a psql script against this database with `--set` variables.
    ///
    /// # Errors
    /// Returns a failure with psql's output when the script does not succeed.
    pub fn psql_file(&self, file: &Path, variables: &[(&str, &str)]) -> Result<()> {
        let mut command = Command::new(psql_binary());
        command
            .arg("--no-psqlrc")
            .arg("--quiet")
            .arg(format!("--dbname={}", self.owner))
            .arg(format!("--file={}", file.display()));
        for (name, value) in variables {
            command.arg(format!("--set={name}={value}"));
        }
        let output = command
            .output()
            .with_context(|| format!("run psql for {}", file.display()))?;
        if !output.status.success() {
            bail!(
                "psql {} failed with {}: {}{}",
                file.display(),
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    fn role_url(&self, role: &str) -> String {
        let mut url = self.owner.clone();
        let _ = url.set_username(role);
        let _ = url.set_password(None);
        url.to_string()
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        // Each --command runs on its own: DROP DATABASE refuses to run inside
        // the implicit transaction of a multi-statement command.
        let mut command = Command::new(psql_binary());
        command
            .arg("--no-psqlrc")
            .arg("--quiet")
            .arg(format!("--dbname={}", self.admin))
            .arg("--command")
            .arg(format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            ));
        for role in &self.roles {
            command
                .arg("--command")
                .arg(format!("DROP ROLE IF EXISTS {role}"));
        }
        let result = command.output();
        match result {
            Ok(output) if output.status.success() => {}
            Ok(output) => eprintln!(
                "warning: could not drop test database {}: {}",
                self.name,
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => eprintln!("warning: could not run psql to drop {}: {error}", self.name),
        }
    }
}

/// The checked-in runtime grant manifest.
#[must_use]
pub fn manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/postgres/grant-runtime.sql")
}

fn psql_binary() -> PathBuf {
    if let Ok(path) = std::env::var(PSQL_ENV) {
        return PathBuf::from(path);
    }
    for candidate in [
        "/opt/homebrew/opt/postgresql@16/bin/psql",
        "/usr/lib/postgresql/16/bin/psql",
    ] {
        if Path::new(candidate).exists() {
            return PathBuf::from(candidate);
        }
    }
    PathBuf::from("psql")
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.subsec_nanos())
        .unwrap_or_default();
    format!(
        "{}_{}_{nanos:x}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}
