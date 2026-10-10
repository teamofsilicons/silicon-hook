"""Scenario 7: the discovery commands from a packaged Silicon Apps archive, in an empty home."""

import json
import os
import platform
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path

from support import SCRIPTS

REPO = SCRIPTS.parent
TARGETS = {("Darwin", "arm64"): "macos-aarch64", ("Darwin", "x86_64"): "macos-x86_64",
           ("Linux", "x86_64"): "linux-x86_64", ("Linux", "aarch64"): "linux-aarch64"}


def cli_version():
    text = (REPO / "crates/cli/Cargo.toml").read_text()
    return re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE).group(1)


def scenario_7(h):
    h.begin(7, "discovery commands from a packaged Silicon Apps archive, in an empty home")
    target = TARGETS.get((platform.system(), platform.machine()))
    if target is None:
        h.check(f"this machine ({platform.system()} {platform.machine()}) has a Silicon Apps target", False)
        return
    version = cli_version()
    build = subprocess.run(["cargo", "build", "--release", "--locked", "-p", "silicon-hook-cli"], cwd=REPO,
                           capture_output=True, text=True)
    h.check("cargo build --release -p silicon-hook-cli", build.returncode == 0, build.stderr[-400:] or None,
            critical=True)
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", REPO / "target"))
    binary = target_dir / "release" / "hook"
    out_dir = h.work / "dist"
    packed = subprocess.run([str(SCRIPTS / "package-apps.sh"), version, target, str(binary), "--output-dir",
                             str(out_dir), "--discovery", "require"], cwd=REPO, capture_output=True, text=True)
    archive = out_dir / f"hook-{version}-{target}.tar.gz"
    h.check(f"scripts/package-apps.sh {version} {target} … --discovery require",
            packed.returncode == 0 and archive.exists(),
            packed.stdout.strip().splitlines()[-2:] if packed.returncode == 0 else packed.stderr[-600:])
    if not archive.exists():
        return
    extracted = h.work / "extracted"
    extracted.mkdir(exist_ok=True)
    with tarfile.open(archive) as bundle:
        names = sorted(member.name for member in bundle.getmembers() if member.isfile())
        h.check("the archive holds exactly apps.yaml and bin/hook", names == ["apps.yaml", "bin/hook"], names)
        for member in bundle.getmembers():
            if member.isfile() and member.name in ("apps.yaml", "bin/hook"):
                bundle.extract(member, extracted)
    manifest = (extracted / "apps.yaml").read_text()
    h.check("apps.yaml names app hook, this version and only this target",
            "app_id: hook" in manifest and f"version: {version}" in manifest and manifest.count("binary:") == 1
            and target in manifest, manifest.strip().splitlines())
    hook = str(extracted / "bin" / "hook")
    os.chmod(hook, 0o755)
    empty = Path(tempfile.mkdtemp(prefix="hook-e2e-empty-", dir=h.work))
    env = {"HOME": str(empty), "SILICON_HOME": str(empty), "PATH": "/usr/bin:/bin"}

    def run(*args):
        return subprocess.run([hook, *args], env=env, capture_output=True, text=True, timeout=30)

    shown = run("--help")
    h.check("hook --help: exit 0, non-empty", shown.returncode == 0 and len(shown.stdout) > 200,
            {"exit": shown.returncode, "bytes": len(shown.stdout)})
    accounts = run("accounts", "--json")
    parsed = json.loads(accounts.stdout) if accounts.returncode == 0 else {}
    h.check("hook accounts --json: exit 0 with \"app_id\": \"hook\"",
            accounts.returncode == 0 and parsed.get("app_id") == "hook" and parsed.get("version") == version,
            {k: parsed.get(k) for k in ("app_id", "name", "version", "accounts_url", "api_version")})
    status = run("login", "status", "--json")
    h.check("hook login status --json: exit 0, {\"authenticated\": false}",
            status.returncode == 0 and json.loads(status.stdout or "null") == {"authenticated": False},
            status.stdout.strip())
    alias = run("iam", "--json")
    h.check("the hidden `hook iam --json` (Silicon runtime alias) prints exactly `hook accounts --json`; help never shows it",
            alias.returncode == 0 and json.loads(alias.stdout or "null") == parsed
            and not re.search(r"\biam\b", shown.stdout, re.IGNORECASE), {"exit": alias.returncode})
    leftovers = sorted(str(path.relative_to(empty)) for path in empty.rglob("*"))
    h.check("the discovery commands wrote nothing into the empty home", leftovers == [], leftovers)
