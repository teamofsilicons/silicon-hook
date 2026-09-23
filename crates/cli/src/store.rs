//! Stateful CLI storage. The SDK has no dependency on this module.

use anyhow::{Context as _, Result};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use silicon_hook_client::{Client, Mutation, Secret, models::Tokens};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub tokens: Tokens,
    pub expires_at: u64,
    /// Persisted before refresh so a lost response can be retried safely.
    #[serde(default)]
    pub pending_refresh_key: Option<String>,
    #[serde(default)]
    pub refresh_started_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default = "enabled")]
    pub telemetry: bool,
    #[serde(default)]
    pub selected_test: Option<Uuid>,
    #[serde(default)]
    pub test_app_secrets: BTreeMap<Uuid, Secret>,
    #[serde(default)]
    pub test_names: BTreeMap<Uuid, String>,
    pub url: String,
    pub org: Option<String>,
    pub silicon: Option<String>,
    pub session: Option<Session>,
    #[serde(default)]
    pub test_sessions: BTreeMap<Uuid, Session>,
    #[serde(default)]
    pub test_keys: BTreeMap<Uuid, Secret>,
    #[serde(default)]
    pub test_orgs: BTreeMap<Uuid, String>,
    #[serde(default)]
    pub test_silicons: BTreeMap<Uuid, String>,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            selected_test: None,
            telemetry: true,
            test_app_secrets: BTreeMap::new(),
            test_names: BTreeMap::new(),
            url: "https://backend.hook.teamofsilicons.com".into(),
            org: None,
            silicon: None,
            session: None,
            test_sessions: BTreeMap::new(),
            test_keys: BTreeMap::new(),
            test_orgs: BTreeMap::new(),
            test_silicons: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}
fn enabled() -> bool {
    true
}

pub struct LockedStore {
    pub data: Store,
    file: File,
    folder: PathBuf,
}

pub fn folder() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("SILICON_HOOK_HOME").filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    let home = default_home()?;
    let marker = home.join("home");
    if let Ok(value) = fs::read_to_string(&marker) {
        let base = PathBuf::from(value.trim());
        anyhow::ensure!(!base.as_os_str().is_empty(), "configured home is empty");
        anyhow::ensure!(
            base.is_dir(),
            "configured home is not a directory: {}",
            base.display()
        );
        return Ok(base.join(".silicon-hook"));
    }
    Ok(home)
}

fn default_home() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("SILICON_HOME")
            .filter(|home| !home.is_empty())
            .or_else(|| std::env::var_os("HOME"))
            .context("HOME is unset; set SILICON_HOME or SILICON_HOOK_HOME")?,
    )
    .join(".silicon-hook"))
}

/// Point future CLI state at `{base}/.silicon-hook`.
pub fn set_home(base: &str) -> Result<PathBuf> {
    let expanded = if base == "~" {
        PathBuf::from(std::env::var_os("HOME").context("HOME is unset")?)
    } else if let Some(rest) = base.strip_prefix("~/") {
        PathBuf::from(std::env::var_os("HOME").context("HOME is unset")?).join(rest)
    } else {
        PathBuf::from(base)
    };
    anyhow::ensure!(
        expanded.is_dir(),
        "home location is not a directory: {}",
        expanded.display()
    );
    let expanded = expanded.canonicalize()?;
    let marker_home = default_home()?;
    fs::create_dir_all(&marker_home)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&marker_home, fs::Permissions::from_mode(0o700))?;
    }
    let marker = marker_home.join("home");
    let temporary = marker_home.join(format!(".home-{}", Uuid::now_v7()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    private_file(&mut options);
    let mut file = options.open(&temporary)?;
    file.write_all(expanded.to_string_lossy().as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temporary, marker)?;
    #[cfg(unix)]
    File::open(&marker_home)?.sync_all()?;
    Ok(expanded.join(".silicon-hook"))
}

pub fn private_file(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
}

impl LockedStore {
    pub fn open() -> Result<Self> {
        let folder = folder()?;
        fs::create_dir_all(&folder)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&folder, fs::Permissions::from_mode(0o700))?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        private_file(&mut options);
        let file = options.open(folder.join("state.lock"))?;
        file.lock_exclusive()?;
        let path = folder.join("state.json");
        let data = if path.exists() {
            serde_json::from_slice(&fs::read(path)?)
                .context("Hook state is invalid; keep the file and repair it before retrying")?
        } else {
            Store::default()
        };
        Ok(Self { data, file, folder })
    }
    pub fn profile(&mut self, name: &str) -> &mut Profile {
        self.data.profiles.entry(name.to_owned()).or_default()
    }
    pub fn save(&self) -> Result<()> {
        let temporary = self.folder.join(format!(".state-{}.json", Uuid::now_v7()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        private_file(&mut options);
        let mut file = options.open(&temporary)?;
        let encoded = zeroize::Zeroizing::new(serde_json::to_vec_pretty(&self.data)?);
        file.write_all(&encoded)?;
        file.sync_all()?;
        fs::rename(&temporary, self.folder.join("state.json"))?;
        #[cfg(unix)]
        File::open(&self.folder)?.sync_all()?;
        Ok(())
    }
}
impl Drop for LockedStore {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn select_client(
    profile: &Profile,
    env: Option<Uuid>,
    url: Option<&str>,
    org: Option<&str>,
) -> Result<Client> {
    if let Some(url) = url
        && Client::new(url)?.base_url() != Client::new(&profile.url)?.base_url()
        && (profile.session.is_some()
            || !profile.test_sessions.is_empty()
            || !profile.test_keys.is_empty()
            || !profile.test_app_secrets.is_empty())
    {
        anyhow::bail!(
            "This profile is bound to a different backend. Use a new --profile for a new service origin."
        );
    }
    let mut client = Client::new(url.unwrap_or(&profile.url))?
        .with_auto_update(false)
        .with_telemetry(profile.telemetry);
    if let Some(environment) = env {
        if let Some(secret) = profile.test_app_secrets.get(&environment) {
            client = client.with_test_app_secret(secret.expose())?;
        } else {
            let key=profile.test_keys.get(&environment).context("No key stored for this environment. Use hook env attach <id> --key-file <file>, or create it with hook env create.")?;
            client = client.with_test_key(key.expose())?;
        }
    }
    let session = env
        .and_then(|id| profile.test_sessions.get(&id))
        .or_else(|| {
            if env.is_none() {
                profile.session.as_ref()
            } else {
                None
            }
        });
    // IAM can issue an unscoped Silicon login with no token org_id. Its public
    // name still identifies the organization to select; IAM verifies the bearer
    // and membership online. Never borrow production context for a test session.
    let configured_org = match env {
        Some(id) => profile.test_orgs.get(&id).map(String::as_str),
        None => profile.org.as_deref(),
    };
    let org = org
        .or(configured_org)
        .or_else(|| session.and_then(|s| s.tokens.org_id.as_deref()))
        .or_else(|| {
            let actor = &session?.tokens.actor;
            if actor.kind != "silicon" {
                return None;
            }
            let (name, org) = actor.id.split_once(':')?;
            (!name.is_empty() && !org.is_empty() && !org.contains(':')).then_some(org)
        });
    if let Some(org) = org {
        client = client.with_organization(org);
    }
    if let Some(session) = session {
        client = client.with_token(session.tokens.access_token.expose());
    }
    Ok(client)
}

pub async fn refresh_if_needed(
    store: &mut LockedStore,
    name: &str,
    env: Option<Uuid>,
    url: Option<&str>,
    org: Option<&str>,
) -> Result<()> {
    for _ in 0..2 {
        let profile = store.profile(name);
        let session = match env {
            Some(id) => profile.test_sessions.get(&id),
            None => profile.session.as_ref(),
        };
        let Some(session) = session else {
            return Ok(());
        };
        if session.expires_at > now() + 60 && session.pending_refresh_key.is_none() {
            return Ok(());
        }
        let client = select_client(profile, env, url, org)?;
        let mut session = session.clone();
        let mutation = match &session.pending_refresh_key {
            Some(key) => Mutation::with_key(key.clone())?,
            None => Mutation::new(),
        };
        let started_at = session.refresh_started_at.unwrap_or_else(|| {
            if session.pending_refresh_key.is_some() {
                0
            } else {
                now()
            }
        });
        session.refresh_started_at = Some(started_at);
        session.pending_refresh_key = Some(mutation.key().to_owned());
        match env {
            Some(id) => {
                profile.test_sessions.insert(id, session.clone());
            }
            None => profile.session = Some(session.clone()),
        }
        // The lock and durable write span the request: another CLI process
        // must never rotate the same refresh token with a different key.
        store.save()?;
        let tokens = client.refresh(session.tokens.refresh_token.expose(), &mutation)
        .await.context("Session refresh failed; retry the command, or sign in again with hook login --slt-file <file>")?;
        session.expires_at = started_at.saturating_add(tokens.expires_in);
        session.tokens = tokens;
        session.pending_refresh_key = None;
        session.refresh_started_at = None;
        let profile = store.profile(name);
        match env {
            Some(id) => {
                profile.test_sessions.insert(id, session);
            }
            None => profile.session = Some(session),
        };
        store.save()?;
    }
    // Recheck after persisting a replay whose original access token had expired.
    let profile = store.profile(name);
    let session = match env {
        Some(id) => profile.test_sessions.get(&id),
        None => profile.session.as_ref(),
    };
    anyhow::ensure!(
        session.is_some_and(|s| s.expires_at > now() + 60),
        "refreshed access token has no usable lifetime; retry the command"
    );
    Ok(())
}

/// Verify access online and recover one early-invalidated generation. The caller
/// owns the session lock, so the successor is persisted before it is exposed.
pub async fn verified_status(
    store: &mut LockedStore,
    name: &str,
    env: Option<Uuid>,
    url: Option<&str>,
    org: Option<&str>,
) -> Result<silicon_hook_client::models::LoginStatus> {
    refresh_if_needed(store, name, env, url, org).await?;
    for attempt in 0..2 {
        let profile = store.profile(name);
        let status = select_client(profile, env, url, org)?
            .login_status()
            .await?;
        if status.authenticated || attempt == 1 {
            return Ok(status);
        }
        let session = match env {
            Some(id) => profile.test_sessions.get_mut(&id),
            None => profile.session.as_mut(),
        };
        let Some(session) = session else {
            return Ok(status);
        };
        session.expires_at = 0;
        store.save()?;
        refresh_if_needed(store, name, env, url, org).await?;
    }
    unreachable!("the second status check returns directly")
}
