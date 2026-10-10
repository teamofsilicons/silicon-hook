//! The CLI's private state: `profiles.json` under the state directory.
//!
//! Directory: `SILICON_HOOK_HOME` as is; else `<base>/.silicon-hook`, where the
//! base is the one set with `hook config home <dir>`, else `SILICON_HOME`, else
//! `HOME`. The directory is 0700 and files 0600 on Unix. Writes are atomic
//! (temporary file, fsync, rename). A file lock (`profiles.lock`) serializes
//! every change, and above all every token refresh: Silicon Accounts rotates
//! refresh tokens and treats a spent one presented again as theft.
//!
//! Hook before 1.0 kept IAM sign-ins in `state.json`. That file is never read
//! for credentials and never changed; its non-secret settings (url, silicon,
//! telemetry) are carried over once, and profiles that were signed in are told
//! to sign in again.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use silicon_hook_client::{Secret, models::AccountKind};

use crate::output::{CliError, CliResult, EXIT_FAILURE};

mod load;
pub use load::{Locked, read};

pub const STATE_FILE: &str = "profiles.json";
pub const LOCK_FILE: &str = "profiles.lock";
pub const LEGACY_FILE: &str = "state.json";
const DIR_NAME: &str = ".silicon-hook";
const LEGACY_DEFAULT_URL: &str = "https://api.hook.teamofsilicons.com";

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default = "schema")]
    pub schema: u32,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

fn schema() -> u32 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub silicon: Option<String>,
    #[serde(default = "yes")]
    pub telemetry: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<Session>,
    /// This profile was signed in with Hook before 1.0 (IAM); that sign-in
    /// was not carried over.
    #[serde(default, skip_serializing_if = "is_false")]
    pub previous_version_session: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            url: None,
            accounts_url: None,
            silicon: None,
            telemetry: true,
            session: None,
            previous_version_session: false,
        }
    }
}

fn yes() -> bool {
    true
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !value
}

/// A Silicon Accounts sign-in to Hook.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub app_id: String,
    /// The Silicon Accounts deployment that issued the tokens.
    pub accounts_url: String,
    /// The Hook API the tokens are sent to.
    pub url: String,
    pub access_token: Secret,
    pub refresh_token: Option<Secret>,
    /// Unix seconds.
    pub expires_at: i64,
    #[serde(default)]
    pub refresh_expires_at: Option<i64>,
    #[serde(default)]
    pub scope: Option<String>,
    pub account: SessionAccount,
    /// `device` or `slt`.
    pub method: String,
    pub signed_in_at: i64,
    /// Set while a refresh is in flight. Found set later, it means a refresh
    /// was interrupted and the refresh token may already be spent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_started_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionAccount {
    pub uuid: String,
    pub kind: AccountKind,
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub display_name: String,
}

impl Session {
    pub fn who(&self) -> String {
        if self.account.id.is_empty() {
            self.account.uuid.clone()
        } else {
            format!("{} ({})", self.account.id, self.account.uuid)
        }
    }

    pub fn ended(&self) -> bool {
        self.refresh_expires_at.is_some_and(|at| at <= now())
    }
}

/// The resolved state directory.
pub fn folder() -> CliResult<PathBuf> {
    if let Some(path) = std::env::var_os("SILICON_HOOK_HOME").filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    let home = default_folder()?;
    if let Ok(value) = fs::read_to_string(home.join("home")) {
        let base = PathBuf::from(value.trim());
        if base.as_os_str().is_empty() || !base.is_dir() {
            return Err(CliError::new(
                EXIT_FAILURE,
                "home_missing",
                format!(
                    "The home set with `hook config home` ({}) is not a directory anymore.",
                    base.display()
                ),
                format!(
                    "Run `hook config home <existing dir>`, or delete {} to go back to the default.",
                    home.join("home").display()
                ),
            ));
        }
        return Ok(base.join(DIR_NAME));
    }
    Ok(home)
}

fn default_folder() -> CliResult<PathBuf> {
    std::env::var_os("SILICON_HOME")
        .filter(|home| !home.is_empty())
        .or_else(|| std::env::var_os("HOME").filter(|home| !home.is_empty()))
        .map(|home| PathBuf::from(home).join(DIR_NAME))
        .ok_or_else(|| {
            CliError::new(
                EXIT_FAILURE,
                "no_home",
                "Neither SILICON_HOME nor HOME is set, so Hook has nowhere to keep its sign-in.",
                "Set SILICON_HOME (or HOME), or SILICON_HOOK_HOME for the exact directory.",
            )
        })
}

/// Points future state at `{base}/.silicon-hook`.
pub fn set_home(base: &str) -> CliResult<PathBuf> {
    let home_dir = || std::env::var_os("HOME").map(PathBuf::from);
    let expanded = if base == "~" {
        home_dir().ok_or_else(|| {
            CliError::invalid(
                "HOME is not set, so `~` cannot be expanded.",
                "Give an absolute directory.",
            )
        })?
    } else if let Some(rest) = base.strip_prefix("~/") {
        home_dir()
            .ok_or_else(|| {
                CliError::invalid(
                    "HOME is not set, so `~` cannot be expanded.",
                    "Give an absolute directory.",
                )
            })?
            .join(rest)
    } else {
        PathBuf::from(base)
    };
    if !expanded.is_dir() {
        return Err(CliError::invalid(
            format!("not a directory: {}", expanded.display()),
            "Create the directory first, or choose an existing one.",
        ));
    }
    let expanded = expanded
        .canonicalize()
        .map_err(|error| CliError::io("resolve", &expanded, &error))?;
    let marker_dir = default_folder()?;
    private_dir(&marker_dir)?;
    let mut text = expanded.to_string_lossy().into_owned();
    text.push('\n');
    write_atomic(&marker_dir, "home", text.as_bytes())?;
    Ok(expanded.join(DIR_NAME))
}

fn private_dir(path: &Path) -> CliResult<()> {
    fs::create_dir_all(path).map_err(|error| CliError::io("create", path, &error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| CliError::io("protect", path, &error))?;
    }
    Ok(())
}

fn private_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = options;
}

/// Writes `name` in `dir` atomically with owner-only permissions.
pub fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> CliResult<()> {
    let temporary = dir.join(format!(".{name}.{}.tmp", uuid::Uuid::now_v7()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    private_options(&mut options);
    let result = (|| -> std::io::Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, dir.join(name))?;
        #[cfg(unix)]
        File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(CliError::io("write", &dir.join(name), &error));
    }
    Ok(())
}
