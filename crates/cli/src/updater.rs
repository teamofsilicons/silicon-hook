use crate::store::{self, LockedStore};
use anyhow::Result;
use silicon_hook_client::updater;

pub async fn after_command() -> Result<()> {
    if !updater::automatic_enabled("SILICON_HOOK_AUTO_UPDATE") {
        return Ok(());
    }
    let mut stored = LockedStore::open()?;
    if !stored.data.auto_update || store::now().saturating_sub(stored.data.last_update_check) < 3600
    {
        return Ok(());
    }
    // Claim the check under the same process-shared state lock so concurrent
    // invocations cannot each start cargo install.
    stored.data.last_update_check = store::now();
    stored.save()?;
    drop(stored);
    let Some(release) = updater::check(updater::CLI_PACKAGE, env!("CARGO_PKG_VERSION")).await?
    else {
        return Ok(());
    };
    if !release.update_available {
        return Ok(());
    }
    let exe = std::env::current_exe()?;
    let Some(bin) = exe.parent() else {
        return Ok(());
    };
    let Some(root) = bin.parent() else {
        return Ok(());
    };
    if bin.file_name().is_some_and(|s| s == "bin") && root.join(".crates.toml").is_file() {
        eprintln!(
            "Updating Hook CLI to {} after the command...",
            release.latest
        );
        updater::install_cli(root, &release).await?;
        eprintln!(
            "Hook updated. The next command uses {}. Restart the daemon with hook daemon stop, then hook daemon start to update its running code.",
            release.latest
        );
    } else {
        eprintln!(
            "Hook {} is available; this is a source/custom build. Install with cargo install silicon-hook-cli --locked --version {}.",
            release.latest, release.latest
        );
    }
    Ok(())
}
