//! Crates.io discovery and Cargo updates. Compiled Rust dependencies take effect
//! at the next build; running processes cannot replace linked library code.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub const CLIENT_PACKAGE: &str = "silicon-hook-client";
pub const CLI_PACKAGE: &str = "silicon-hook-cli";

#[derive(Clone, Debug, Serialize)]
pub struct Release {
    pub package: String,
    pub current: String,
    pub latest: String,
    pub update_available: bool,
}
#[derive(Deserialize)]
struct CrateResponse {
    #[serde(rename = "crate")]
    package: CrateVersion,
}
#[derive(Deserialize)]
struct CrateVersion {
    max_stable_version: Option<String>,
}

/// Reads the latest stable release from crates.io. A package that has not yet
/// been published, or has no non-yanked stable release, returns None. No local
/// files are changed by discovery.
pub async fn check(package: &str, current: &str) -> Result<Option<Release>> {
    if ![CLIENT_PACKAGE, CLI_PACKAGE].contains(&package) {
        return Err(Error::Invalid("unsupported Hook package".into()));
    }
    let version = semver::Version::parse(current)
        .map_err(|_| Error::Invalid("invalid current version".into()))?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(concat!(
            "silicon-hook-client/",
            env!("CARGO_PKG_VERSION"),
            " updater"
        ))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = http
        .get(format!("https://crates.io/api/v1/crates/{package}"))
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let response = response.error_for_status()?;
    let data: CrateResponse =
        serde_json::from_slice(&crate::client::bounded_body(response).await?)?;
    // crates.io also returns null when a crate exists but has no eligible
    // stable release (for example, only prereleases or yanked versions).
    let Some(latest) = data.package.max_stable_version else {
        return Ok(None);
    };
    let latest = semver::Version::parse(&latest)
        .map_err(|_| Error::Protocol("invalid crates.io version".into()))?;
    Ok(Some(Release {
        package: package.into(),
        current: current.into(),
        latest: latest.to_string(),
        update_available: latest > version,
    }))
}

/// Updates a consuming application's lockfile within its declared compatible
/// version requirement. Source workspaces and projects without this dependency
/// are left alone. Run a new build to use the new code.
pub async fn update_dependency(manifest: &Path, release: &Release) -> Result<bool> {
    if release.package != CLIENT_PACKAGE || !release.update_available {
        return Ok(false);
    }
    let metadata = tokio::process::Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(manifest)
        .output()
        .await
        .map_err(|e| Error::Protocol(format!("could not run cargo: {e}")))?;
    if !metadata.status.success() {
        return Err(Error::Protocol(
            "Cargo could not inspect the consuming project".into(),
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&metadata.stdout)?;
    let packages = value["packages"]
        .as_array()
        .ok_or_else(|| Error::Protocol("invalid Cargo metadata".into()))?;
    if packages.iter().any(|p| p["name"] == CLIENT_PACKAGE) {
        return Ok(false);
    }
    if !packages.iter().any(|p| {
        p["dependencies"].as_array().is_some_and(|deps| {
            deps.iter().any(|d| {
                d["name"] == CLIENT_PACKAGE
                    && d["source"].as_str().is_some_and(|s| {
                        matches!(
                            s,
                            "registry+https://github.com/rust-lang/crates.io-index"
                                | "sparse+https://index.crates.io/"
                        )
                    })
            })
        })
    }) {
        return Ok(false);
    }
    semver::Version::parse(&release.latest)
        .map_err(|_| Error::Invalid("invalid release version".into()))?;
    let status = tokio::process::Command::new("cargo")
        .args(["update", "--manifest-path"])
        .arg(manifest)
        .args(["--package", CLIENT_PACKAGE, "--precise", &release.latest])
        .status()
        .await
        .map_err(|e| Error::Protocol(format!("could not run cargo update: {e}")))?;
    if !status.success() {
        return Err(Error::Protocol(
            "Cargo refused the dependency update; check the declared version requirement".into(),
        ));
    }
    Ok(true)
}

/// Installs an exact stable CLI release into a Cargo installation root.
/// The caller chooses the destination; this never overwrites a development
/// binary in target/debug or target/release.
pub async fn install_cli(root: &Path, release: &Release) -> Result<()> {
    if release.package != CLI_PACKAGE {
        return Err(Error::Invalid("expected a CLI release".into()));
    }
    semver::Version::parse(&release.latest)
        .map_err(|_| Error::Invalid("invalid release version".into()))?;
    let status = tokio::process::Command::new("cargo")
        .args([
            "install",
            CLI_PACKAGE,
            "--locked",
            "--force",
            "--version",
            &release.latest,
            "--root",
        ])
        .arg(root)
        .status()
        .await
        .map_err(|e| Error::Protocol(format!("could not run cargo install: {e}")))?;
    if !status.success() {
        return Err(Error::Protocol(
            "CLI installation failed; the existing executable remains available".into(),
        ));
    }
    Ok(())
}

pub fn find_manifest(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|p| p.join("Cargo.toml"))
        .find(|p| p.is_file())
}
pub fn automatic_enabled(variable: &str) -> bool {
    !std::env::var(variable).is_ok_and(|v| {
        matches!(
            v.to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        )
    })
}
static ACTIVE: AtomicBool = AtomicBool::new(false);
static LAST_CHECK: OnceLock<Arc<Mutex<Option<Instant>>>> = OnceLock::new();

/// Schedules a best-effort check after a completed SDK request. State stays in
/// memory. Persistent CLI scheduling uses its own last-check timestamp instead.
pub(crate) fn schedule(enabled: bool) {
    if !enabled
        || !automatic_enabled("SILICON_HOOK_CLIENT_AUTO_UPDATE")
        || ACTIVE.swap(true, Ordering::AcqRel)
    {
        return;
    }
    let last = LAST_CHECK
        .get_or_init(|| Arc::new(Mutex::new(None)))
        .clone();
    tokio::spawn(async move {
        struct ActiveGuard;
        impl Drop for ActiveGuard {
            fn drop(&mut self) {
                ACTIVE.store(false, Ordering::Release);
            }
        }
        let _guard = ActiveGuard;
        let mut checked = last.lock().await;
        if checked.is_some_and(|time| time.elapsed() < Duration::from_secs(3600)) {
            return;
        }
        *checked = Some(Instant::now());
        drop(checked);
        if let Ok(Some(release)) = check(CLIENT_PACKAGE, env!("CARGO_PKG_VERSION")).await
            && release.update_available
            && let Ok(cwd) = std::env::current_dir()
            && let Some(manifest) = find_manifest(&cwd)
        {
            let _ = update_dependency(&manifest, &release).await;
        }
    });
}
