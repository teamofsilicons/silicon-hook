//! Private, explicit scoped-capability handoff to the enclosing app.

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use silicon_hook_client::delivery::{ReceiverCapability, ReceiverScope};
#[cfg(unix)]
use std::fs;
use std::{
    fs::{File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub fn read_scope(path: &str, selected: uuid::Uuid) -> Result<ReceiverScope> {
    let file = File::open(path).context("could not open receiver scope file")?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "receiver scope must be a regular JSON file"
    );
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 16 * 1024,
        "receiver scope file exceeds 16 KiB"
    );
    let scope: ReceiverScope = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid receiver scope file"))?;
    anyhow::ensure!(
        scope.environment.kind == "testing"
            && scope.environment.id == selected
            && scope.environment.generation > 0,
        "receiver scope differs from the selected test environment"
    );
    Ok(scope)
}

/// Deserialized separately so a future capability field cannot reach stdout.
#[derive(Deserialize)]
struct Receipt {
    #[serde(flatten)]
    scope: ReceiverScope,
    receiver_id: String,
    expires_at: String,
}

#[derive(Serialize)]
pub struct Metadata {
    scope: ReceiverScope,
    receiver_id: String,
    expires_at: String,
    output: PathBuf,
}

pub struct PrivateOutput {
    file: File,
    path: PathBuf,
    committed: bool,
}

impl PrivateOutput {
    pub fn reserve(path: &str) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            // Prevent reads of the initially empty file, writes and path
            // replacement while its DACL is installed and the token is saved.
            options.share_mode(0);
        }
        let file = options.open(path).context("could not reserve a new private receiver output file; existing files and symlinks are refused")?;
        let output = Self {
            file,
            path: PathBuf::from(path),
            committed: false,
        };
        #[cfg(windows)]
        windows_acl(&output.path, true)?;
        #[cfg(not(any(unix, windows)))]
        anyhow::bail!("private receiver output is unsupported on this platform");
        #[cfg(any(unix, windows))]
        Ok(output)
    }

    pub fn write(&mut self, capability: &ReceiverCapability) -> Result<Metadata> {
        anyhow::ensure!(
            self.is_own_empty(),
            "reserved receiver output file changed; no capability written"
        );
        #[cfg(windows)]
        windows_acl(&self.path, false)?;
        let mut bytes = Zeroizing::new(
            serde_json::to_vec_pretty(capability)
                .context("could not encode scoped receiver capability")?,
        );
        let receipt: Receipt =
            serde_json::from_slice(&bytes).context("could not encode receiver metadata")?;
        bytes.push(b'\n');
        self.file.write_all(&bytes).context(
            "could not write receiver capability; retain the original operation key for recovery",
        )?;
        self.file.sync_all().context(
            "could not sync receiver capability; retain the output and original operation key",
        )?;
        #[cfg(unix)]
        {
            let parent = self
                .path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            File::open(parent)?.sync_all().context("could not sync receiver output directory; retain the output and original operation key")?;
        }
        self.committed = true;
        Ok(Metadata {
            scope: receipt.scope,
            receiver_id: receipt.receiver_id,
            expires_at: receipt.expires_at,
            output: self.path.clone(),
        })
    }

    fn is_own_empty(&self) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let Ok(opened) = self.file.metadata() else {
                return false;
            };
            let Ok(current) = fs::symlink_metadata(&self.path) else {
                return false;
            };
            current.file_type().is_file()
                && current.len() == 0
                && opened.len() == 0
                && current.dev() == opened.dev()
                && current.ino() == opened.ino()
                && current.mode() & 0o777 == 0o600
        }
        #[cfg(windows)]
        {
            // The original create_new handle disallows delete/rename and
            // concurrent data access until Drop, so the path is still ours.
            self.file
                .metadata()
                .is_ok_and(|metadata| metadata.is_file() && metadata.len() == 0)
        }
        #[cfg(not(any(unix, windows)))]
        false
    }
}

impl Drop for PrivateOutput {
    fn drop(&mut self) {
        // On Windows the exclusive handle prevents deletion while held. Leave
        // an empty reservation on failure rather than closing it and racing a
        // replacement path. It contains no credential and is never overwritten.
        #[cfg(unix)]
        if !self.committed && self.is_own_empty() {
            let _ = fs::remove_file(&self.path);
        }
        #[cfg(windows)]
        if !self.committed && self.is_own_empty() {
            eprintln!(
                "Empty receiver output reservation retained at {}. Retry with a new output path and the original scope and operation key.",
                self.path.display()
            );
        }
    }
}

#[cfg(windows)]
fn windows_acl(path: &Path, install: bool) -> Result<()> {
    use std::process::{Command, Stdio};
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
try {
  $path = $env:HOOK_RECEIVER_OUTPUT
  $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  if ($env:HOOK_RECEIVER_INSTALL_ACL -eq '1') {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $path -AclObject $acl
  }
  $current = Get-Acl -LiteralPath $path
  $rules = @($current.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  if (-not $current.AreAccessRulesProtected -or
      $current.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or
      $rules.Count -ne 1 -or $rules[0].IdentityReference.Value -ne $sid.Value -or
      $rules[0].IsInherited -or $rules[0].AccessControlType -ne 'Allow' -or
      $rules[0].FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl) { exit 1 }
  exit 0
} catch { exit 1 }
"#;
    let system =
        std::env::var_os("SystemRoot").context("Windows system directory is unavailable")?;
    let executable = PathBuf::from(system).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let status = Command::new(executable)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SCRIPT,
        ])
        .env("HOOK_RECEIVER_OUTPUT", path)
        .env("HOOK_RECEIVER_INSTALL_ACL", if install { "1" } else { "0" })
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("could not verify private Windows receiver file ACL")?;
    anyhow::ensure!(
        status.success(),
        "private Windows receiver file ACL setup or verification failed; no capability written"
    );
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn cleanup_removes_only_its_original_empty_file() -> Result<()> {
        let path =
            std::env::temp_dir().join(format!("hook-receiver-cleanup-{}", uuid::Uuid::new_v4()));
        let reserved = PrivateOutput::reserve(path.to_str().context("temporary path")?)?;
        fs::remove_file(&path)?;
        fs::write(&path, b"replacement")?;
        drop(reserved);
        assert_eq!(fs::read(&path)?, b"replacement");
        fs::remove_file(&path)?;
        let reserved = PrivateOutput::reserve(path.to_str().context("temporary path")?)?;
        drop(reserved);
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn partial_output_is_retained_instead_of_destroying_recovery_evidence() -> Result<()> {
        let path =
            std::env::temp_dir().join(format!("hook-receiver-partial-{}", uuid::Uuid::new_v4()));
        let mut reserved = PrivateOutput::reserve(path.to_str().context("temporary path")?)?;
        reserved.file.write_all(b"partial")?;
        drop(reserved);
        assert_eq!(fs::read(&path)?, b"partial");
        fs::remove_file(path)?;
        Ok(())
    }
}
