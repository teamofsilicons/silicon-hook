//! Reading the state (without a lock) and changing it (under the lock).

use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

use fs2::FileExt as _;
use serde_json::Value;

use super::{
    LEGACY_DEFAULT_URL, LEGACY_FILE, LOCK_FILE, Profile, STATE_FILE, State, folder, now,
    private_dir, private_options, write_atomic,
};
use crate::output::{CliError, CliResult, EXIT_FAILURE};

/// The state as read, with what the reader should know about it.
#[derive(Debug, Default)]
pub struct Loaded {
    pub state: State,
    /// `profiles.json` could not be parsed; the message says why.
    pub unreadable: Option<String>,
}

impl Loaded {
    pub fn profile(&self, name: &str) -> Profile {
        self.state.profiles.get(name).cloned().unwrap_or_default()
    }
}

/// Reads the state without creating anything. A missing directory or file is
/// an empty state; the pre-1.0 `state.json` contributes its settings only.
pub fn read(folder: &Path) -> CliResult<Loaded> {
    let path = folder.join(STATE_FILE);
    match fs::read(&path) {
        Ok(bytes) => match serde_json::from_slice::<State>(&bytes) {
            Ok(state) => Ok(Loaded {
                state,
                unreadable: None,
            }),
            Err(error) => Ok(Loaded {
                state: State::default(),
                unreadable: Some(format!(
                    "{} is not valid Hook state ({error})",
                    path.display()
                )),
            }),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Loaded {
            state: import_legacy(folder),
            unreadable: None,
        }),
        Err(error) => Err(CliError::io("read", &path, &error)),
    }
}

/// Settings of the pre-1.0 state file. Its IAM credentials are never read.
fn import_legacy(folder: &Path) -> State {
    let mut state = State::default();
    let Ok(bytes) = fs::read(folder.join(LEGACY_FILE)) else {
        return state;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return state;
    };
    let Some(profiles) = value.get("profiles").and_then(Value::as_object) else {
        return state;
    };
    for (name, old) in profiles {
        let text = |key: &str| {
            old.get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        };
        let signed_in = old.get("session").is_some_and(|s| !s.is_null())
            || old
                .get("test_sessions")
                .and_then(Value::as_object)
                .is_some_and(|sessions| !sessions.is_empty());
        let profile = Profile {
            url: text("url").filter(|url| url.trim_end_matches('/') != LEGACY_DEFAULT_URL),
            accounts_url: None,
            silicon: text("silicon"),
            telemetry: old
                .get("telemetry")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            session: None,
            previous_version_session: signed_in,
        };
        state.profiles.insert(name.clone(), profile);
    }
    state
}

/// The state under the exclusive lock, for changes. Dropping it unlocks.
pub struct Locked {
    pub folder: PathBuf,
    pub state: State,
    lock: File,
}

impl Locked {
    /// Creates the directory if needed and waits for the lock. A
    /// `profiles.json` that cannot be parsed fails unless `recover` is set;
    /// then it is moved aside (kept for inspection) and an empty state starts.
    pub fn open(recover: bool) -> CliResult<(Self, Option<String>)> {
        Self::open_in(folder()?, recover)
    }

    /// [`Locked::open`] for an explicit state directory.
    pub fn open_in(folder: PathBuf, recover: bool) -> CliResult<(Self, Option<String>)> {
        private_dir(&folder)?;
        let lock_path = folder.join(LOCK_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        private_options(&mut options);
        let lock = options
            .open(&lock_path)
            .map_err(|error| CliError::io("open", &lock_path, &error))?;
        lock.lock_exclusive()
            .map_err(|error| CliError::io("lock", &lock_path, &error))?;
        let loaded = read(&folder)?;
        let mut notice = None;
        if let Some(problem) = loaded.unreadable {
            if !recover {
                return Err(CliError::new(
                    EXIT_FAILURE,
                    "state_unreadable",
                    format!("{problem}, so Hook will not overwrite it."),
                    "Move the file aside (it may hold other profiles' settings), then sign in again with `hook login`.",
                ));
            }
            let aside = folder.join(format!("{STATE_FILE}.unreadable-{}", now()));
            fs::rename(folder.join(STATE_FILE), &aside)
                .map_err(|error| CliError::io("move aside", &aside, &error))?;
            notice = Some(format!(
                "{problem}; it was moved to {} and a new one was started.",
                aside.display()
            ));
        }
        Ok((
            Self {
                folder,
                state: loaded.state,
                lock,
            },
            notice,
        ))
    }

    pub fn profile(&mut self, name: &str) -> &mut Profile {
        self.state.profiles.entry(name.to_owned()).or_default()
    }

    pub fn save(&self) -> CliResult<()> {
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec_pretty(&self.state)?);
        write_atomic(&self.folder, STATE_FILE, &bytes)
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.lock);
    }
}
