#!/usr/bin/env python3
"""Upgrade only an owned fixture's Ting server/daemon using consistent copies.

The old containers remain stopped and retain their original data. New reports
and credentials live in a separate private directory. The parent container list
records every new container so its normal cleanup still removes the whole test.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import urllib.request

import fixture
import hook
import native

RELEASES = {
    "0.1.3": {
        "commit": "115954f074a9dfd48e3f14b39a70ecaf8cc7a6c5",
        "server_sha256": "2153cfc50dc8f250215163bb35550950cce6f532112939687457f1e423c85de0",
        "native_sha256": "dc3496103d01607885cf3e69f76e83f90b7235d8f6fa9c7fc8eeba360284bee0",
    },
    "0.1.4": {
        "commit": "3253ea193c9fc244e6ef7e5fd818240ae0ad4782",
        "server_sha256": "f287a8b9327f575fb4921e58888ef11f412e354b4fbca62ed2a5739b78ba204b",
        "native_sha256": "ae26f0e852e799b81f2c833ac0ff5d85e96e7b883d9921f6e8fb69c3888ec59e",
    },
}


def ignore_sockets(directory, names):
    return [name for name in names if stat.S_ISSOCK((Path(directory) / name).lstat().st_mode)]


def upgrade(directory, version="0.1.3", resume=None):
    release = RELEASES[version]
    commit, server_sha256, native_sha256 = release["commit"], release["server_sha256"], release["native_sha256"]
    server_archive = f"ting-server-{commit}.tar.gz"
    native_archive = f"ting-v{version}-aarch64-unknown-linux-gnu.tar.gz"
    suffix = version.replace(".", "")
    parent = fixture.load(directory)
    old_native, backend = native.native_state(directory), hook.load(directory)
    if parent.get("current_upgrade"):
        raise RuntimeError("owned fixture already has an upgrade; inspect its private state")
    if parent.get("ting_version", "0.1.2") == version:
        raise RuntimeError("fixture already runs the selected Ting version")
    historical = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in directory.glob("*-verification.json")}
    folder = resume or Path(tempfile.mkdtemp(prefix=f"ting-{version}-", dir=directory)).resolve()
    if folder.parent != directory or not folder.name.startswith(f"ting-{version}-"):
        raise RuntimeError("upgrade directory is outside the owned fixture")
    os.chmod(folder, 0o700)
    inspections = {}
    for name in (parent["ting"], old_native["container"]):
        if not name.startswith(parent["network"] + "-"):
            raise RuntimeError("unowned fixture container")
        inspections[name] = json.loads(fixture.command(["docker", "inspect", name], timeout=10))[0]
    if any(item["HostConfig"]["NetworkMode"].split(":", 1)[0] != "container" for item in inspections.values()):
        raise RuntimeError("fixture services no longer share the expected IAM network namespace")
    fixture.private(folder / "original-containers.private.json", inspections)
    for archive, tag, checksum in ((server_archive, "server-" + commit, server_sha256),
                                   (native_archive, "v" + version, native_sha256)):
        url = f"https://github.com/teamofsilicons/silicon-ting/releases/download/{tag}/{archive}"
        if not (folder / archive).exists():
            with urllib.request.urlopen(url, timeout=30) as response, (folder / archive).open("wb") as output:
                shutil.copyfileobj(response, output)
        if hashlib.sha256((folder / archive).read_bytes()).hexdigest() != checksum:
            raise RuntimeError("published Ting archive checksum mismatch")
        target = folder / ("server-artifact" if archive == server_archive else "native-artifact")
        target.mkdir(mode=0o700, exist_ok=True)
        with tarfile.open(folder / archive) as bundle:
            for member in bundle.getmembers():
                path = (target / member.name).resolve()
                if not path.is_relative_to(target) or member.issym() or member.islnk():
                    raise RuntimeError("unsafe Ting release archive member")
            bundle.extractall(target, filter="data")
    servers = list((folder / "server-artifact").rglob("ting-server"))
    if len(servers) != 1:
        raise RuntimeError("release did not contain exactly one Ting server")
    binary = servers[0]
    binary.chmod(0o755)
    for name in ("ting", "ting-daemon"):
        (folder / "native-artifact" / name).chmod(0o755)
    state = dict(parent)
    state.update({"directory": str(folder), "ting": parent["network"] + "-ting-" + suffix,
        "ting_version": version, "ting_commit": commit, "ting_archive_sha256": server_sha256,
        "parent_fixture": str(directory), "containers": list(parent["containers"])})
    new_native = {"owned": True, "container": parent["network"] + "-native-" + suffix, "directory": str(folder),
                  "archive_sha256": native_sha256, "version": version}
    fixture.save(state)
    fixture.private(folder / "native.private.json", new_native)
    fixture.private(folder / "hook.private.json", {**backend, "directory": str(folder)})
    shutil.copy2(Path(directory) / "hook.env.private.json", folder / "hook.env.private.json")
    # Refresh needs the owned DB owner's credential after every upgrade. Older
    # upgrade directories did not retain this file; follow only our ownership chain.
    owner_directory = directory
    while not (owner_directory / "hook-postgres.env").is_file():
        owner_state = fixture.load(owner_directory)
        ancestor = owner_state.get("parent_fixture")
        if not ancestor or owner_state["network"] != parent["network"]:
            raise RuntimeError("owned Hook database owner environment is missing")
        next_directory = Path(ancestor).resolve()
        if next_directory == owner_directory or not owner_directory.is_relative_to(next_directory):
            raise RuntimeError("invalid Hook database owner ancestry")
        owner_directory = next_directory
    shutil.copy2(owner_directory / "hook-postgres.env", folder / "hook-postgres.env")
    shutil.copytree(Path(directory) / "profiles", folder / "profiles", dirs_exist_ok=True)
    print("UPGRADE_STAGE pinned release archives verified; stopping only owned Ting services", flush=True)
    fixture.command(["docker", "stop", "--time", "10", old_native["container"], parent["ting"]],
                    log=folder / "stop.log", timeout=35)
    old_server = inspections[parent["ting"]]
    old_store = Path(next(mount["Source"] for mount in old_server["Mounts"] if mount["Destination"] == "/data"))
    shutil.copytree(old_store, folder / "server-data-backup", dirs_exist_ok=True, ignore=ignore_sockets)
    shutil.copytree(folder / "server-data-backup", folder / "server-data", dirs_exist_ok=True)
    native_backup = folder / "native-home-backup"
    native_backup.mkdir(mode=0o700, exist_ok=True)
    for name in (".ting", ".ting-daemon"):
        (native_backup / name).mkdir(mode=0o700, exist_ok=True)
        fixture.command(["docker", "cp", old_native["container"] + ":/root/" + name + "/.", str(native_backup / name)],
                        log=folder / "native-backup.log", timeout=30)
    shutil.copytree(native_backup, folder / "native-home", dirs_exist_ok=True, ignore=ignore_sockets)
    fixture.private(folder / "ting.env", "".join(value + "\n" for value in old_server["Config"]["Env"] if value.startswith(("TING_", "RUST_LOG="))))
    parent["current_upgrade"] = str(folder)
    for name in (state["ting"], new_native["container"]):
        parent["containers"].append(name)
        state["containers"].append(name)
    # Persist ownership before creating containers, including partial failures.
    fixture.save(parent)
    fixture.save(state)
    ancestor_path = parent.get("parent_fixture")
    seen = {directory}
    while ancestor_path:
        ancestor_dir = Path(ancestor_path).resolve()
        if ancestor_dir in seen or not directory.is_relative_to(ancestor_dir):
            raise RuntimeError("invalid ancestor fixture ownership chain")
        seen.add(ancestor_dir)
        ancestor = fixture.load(ancestor_dir)
        if ancestor["network"] != parent["network"]:
            raise RuntimeError("ancestor fixture does not own this network")
        for name in (state["ting"], new_native["container"]):
            if name not in ancestor["containers"]:
                ancestor["containers"].append(name)
        fixture.save(ancestor)
        ancestor_path = ancestor.get("parent_fixture")
    ca = next(mount["Source"] for mount in old_server["Mounts"] if mount["Destination"] == "/etc/ssl/certs/ca-certificates.crt")
    fixture.command(["docker", "run", "-d", "--name", state["ting"], "--network", "container:" + state["iam"],
        "--env-file", str(folder / "ting.env"), "-v", f"{binary}:/app/ting-server:ro",
        "-v", f"{folder / 'server-data'}:/data", "-v", f"{ca}:/etc/ssl/certs/ca-certificates.crt:ro",
        "--entrypoint", "/app/ting-server", old_server["Config"]["Image"]], log=folder / "server-start.log")
    fixture.wait_health(state["ting_url"])
    health = fixture.request(state["ting_url"], "GET", "/healthz")
    if health.get("version") != version:
        raise RuntimeError("upgraded server did not attest the pinned version")
    old_daemon = inspections[old_native["container"]]
    fixture.command(["docker", "run", "-d", "--name", new_native["container"], "--network", "container:" + state["iam"],
        "-v", f"{folder / 'native-artifact'}:/app:ro", "-v", f"{folder / 'native-home'}:/root",
        "--entrypoint", "sh", old_daemon["Config"]["Image"], "-c",
        "mkdir -p /var/tmp/silicon-ting && chmod 700 /var/tmp/silicon-ting && exec /app/ting-daemon"],
        log=folder / "native-start.log")
    native_version = native.cli(new_native, ["--version"])
    if native_version.get("version") != version:
        raise RuntimeError("upgraded native CLI did not attest the pinned version")
    me = fixture.request(state["ting_url"], "GET", "/v1/me", token=state["ting_session"])
    if me.get("environment") != {"kind": "production"}:
        raise RuntimeError("upgraded Ting did not attest the expected production context")
    login_base = ["docker", "exec", "-i", "-e", f"SILICON_HOME=/root/upgrade-login-{suffix}", new_native["container"],
                  "/app/ting", "--api-url", native.API, "--org", state["org_id"], "--json"]
    def login_call(args, raw=None):
        return json.loads(fixture.command(login_base + args, stdin=raw,
            log=folder / "native-fresh-login.private.log", timeout=40))
    login = login_call(["login", "--token-stdin"], (fixture.slt(state, "recipient", "ting") + "\n").encode())
    if not login.get("authenticated") or login.get("id") != state["actor_id"]:
        raise RuntimeError("fresh native login identity mismatch")
    if not login_call(["login", "status"]).get("authenticated"):
        raise RuntimeError("fresh native login did not remain authenticated")
    login_call(["logout"])
    for name, checksum in historical.items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != checksum:
            raise RuntimeError("historical fixture report changed during upgrade")
    report = {"complete": True, "version": version, "source_commit": commit,
        "previous_version": parent.get("ting_version", "0.1.2"), "retained_report_sha256": historical,
        "server_archive_sha256": server_sha256, "native_archive_sha256": native_sha256,
        "server_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "native_cli_binary_sha256": hashlib.sha256((folder / 'native-artifact' / 'ting').read_bytes()).hexdigest(),
        "native_daemon_binary_sha256": hashlib.sha256((folder / 'native-artifact' / 'ting-daemon').read_bytes()).hexdigest(),
        "health_response": health, "session_environment_attestation": me["environment"],
        "checks": ["published release archives verified against their SHA256SUMS",
            "owned server SQLite and native profile/queue copied while both containers were stopped",
            "old containers/data and historical reports retained unchanged",
            "only fixture Ting server and daemon replaced; host services and production untouched",
            "existing recipient Ting session survives migration and reports production environment",
            "upgraded native CLI fresh isolated profile exchanges Ting-bound IAM SLT, checks status, and logs out"]}
    fixture.private(folder / "upgrade-verification.json", report)
    print(json.dumps(report, indent=2), flush=True)
    print("UPGRADE_READY " + str(folder), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", choices=RELEASES, default="0.1.3")
    parser.add_argument("--resume", type=Path, help="resume a prepared upgrade before new containers were recorded/created")
    args = parser.parse_args()
    upgrade(args.directory.resolve(), args.version, args.resume.resolve() if args.resume else None)
