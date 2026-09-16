//! Explicit, read-only crates.io discovery. Dependency upgrades belong to the
//! consuming project; Honeycomb owns CLI installation and updates.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

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
