#!/usr/bin/env python3
"""Fence the owned testing generation, then optionally stop its owned services."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
import urllib.parse
import uuid

import fixture
import hook
import testing
import testing_hook


def clean(directory):
    state, backend = fixture.load(directory), hook.load(directory)
    if not state.get("fixture_owned") or not backend.get("owned") or state.get("cleaned"):
        raise RuntimeError("cleanup requires an active owned testing generation")
    generation = state["generation"]
    archive = directory / f"generation-{generation}-evidence"
    archive.mkdir(mode=0o700, exist_ok=True)
    for path in directory.glob("testing-*-verification.json"):
        value = json.loads(path.read_text())
        selected = value.get("shared_generation", value.get("generation"))
        if selected == generation or path.name in ("testing-idle-quota-verification.json", "testing-web-rate-limit-verification.json"):
            if not (archive / path.name).exists():
                shutil.copy2(path, archive / path.name)
    if not (archive / "fixture-before-clean.private.json").exists():
        fixture.private(archive / "fixture-before-clean.private.json", state)
    # Renew the same dedicated normal-plane Honeycomb app family, whose Carbon
    # identity authorizes only this local fixture's participant management.
    basic = base64.b64encode(("honeycomb:" + state["app_secrets"]["honeycomb"]).encode()).decode()
    raw = urllib.parse.urlencode({"app_id": "honeycomb", "refresh_token": state["honeycomb_actor"]["refresh_token"]}).encode()
    state["honeycomb_actor"] = testing.http(state, state["iam_url"], "POST", "/api/v1/app-auth/tokens", raw,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + basic,
                 "Idempotency-Key": str(uuid.uuid4())})[1]
    fixture.save(state)
    for label in ("test-admin", "test-recipient"):
        status, value = testing_hook.call(state, backend, label, "GET", "/auth/status", expected=(200, 401))
        if status == 401 or not value.get("authenticated"):
            state["hook_sessions"][label] = testing.http(state, backend["url"], "POST", "/api/v2/auth/refresh",
                {"refresh_token": state["hook_sessions"][label]["refresh_token"]}, headers={
                    "X-Hook-Test-App-Secret": state["imports"]["hook"]["app_secret"],
                    "Silicon-Hook-API-Version": "v2", "Idempotency-Key": str(uuid.uuid4())})[1]
            fixture.save(state)
    current = testing.http(state, state["iam_url"], "GET", "/api/v1/honeycomb/testing-environments/" + state["environment_id"],
        token=state["honeycomb_credential"])[1]
    if current.get("environment_id") != state["environment_id"] or current.get("generation") != generation or current.get("state") != "active":
        raise RuntimeError("current official lifecycle state no longer matches the owned active generation")
    prior_revision = state["iam_revision"]
    state["iam_revision"] = current["iam_revision"]
    fixture.save(state)
    testing_hook.clean_fixture(directory)
    result = json.loads((directory / "testing-hook-clean-verification.json").read_text())
    if not result.get("complete") or result["old_shared_generation"] != generation:
        raise RuntimeError("final participant clean did not match the active generation")
    result["evidence_archive"] = str(archive)
    result["iam_revision_before_current_read"] = prior_revision
    result["iam_revision_verified_before_clean"] = current["iam_revision"]
    diagnostic = directory / "testing-web-attempt-diagnostic.json"
    unknown_count = json.loads(diagnostic.read_text()).get("unknown_synthetic_observer_sessions", 0) if diagnostic.exists() else 0
    result["unknown_failed_attempt_observer_session"] = {
        "count": unknown_count, "fenced_by": "complete IAM and Ting environment clean",
        "limitation": "Original token was lost in the first failed harness attempt; whole-generation fencing is verified, not that token individually"}
    fixture.private(directory / "testing-final-cleanup-verification.json", result)
    print(f"SCOPED_FINAL_CLEAN_PASS generation{generation} fenced; evidence retained", flush=True)


def stop(directory):
    state, backend = fixture.load(directory), hook.load(directory)
    report_path = directory / "testing-final-cleanup-verification.json"
    if not state.get("fixture_owned") or not backend.get("owned") or not state.get("cleaned") or not report_path.exists():
        raise RuntimeError("stop requires successful final owned fixture cleanup")
    containers = [*state["containers"], backend["container"]]
    if len(containers) != len(set(containers)) or any(not name.startswith(state["network"] + "-") for name in containers):
        raise RuntimeError("container names do not match this fixture's ownership metadata")
    for name in containers:
        result = subprocess.run(["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", name],
                                capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise RuntimeError("owned container metadata unavailable")
        if name == backend["container"]:
            # The native Hook process uses this separately owned PG container's
            # loopback published port; it intentionally uses Docker's bridge.
            env = json.loads((directory / "hook.env.private.json").read_text())
            expected_port = urllib.parse.urlsplit(env["HOOK_DATABASE_URL"]).port
            if fixture.port(name, 5432) != expected_port:
                raise RuntimeError("Hook database container does not match its owned loopback configuration")
        elif name == state["ting"]:
            # Ting intentionally shares the owned IAM container's network namespace.
            mode = subprocess.run(["docker", "inspect", "--format", "{{.HostConfig.NetworkMode}}", name], capture_output=True, text=True, timeout=10)
            iam_id = subprocess.run(["docker", "inspect", "--format", "{{.Id}}", state["iam"]], capture_output=True, text=True, timeout=10)
            if mode.returncode or iam_id.returncode or mode.stdout.strip() != "container:" + iam_id.stdout.strip():
                raise RuntimeError("Ting no longer shares the owned IAM network namespace")
        elif state["network"] not in json.loads(result.stdout):
            raise RuntimeError("container is outside this fixture's private network")
    pid = backend.get("pid")
    if pid:
        command = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True).stdout.strip()
        if command:
            if command != str(hook.ROOT / "target/debug/hook-api"):
                raise RuntimeError("recorded PID is no longer the owned Hook executable")
            cwd = subprocess.run(["/usr/sbin/lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"], capture_output=True, text=True).stdout
            if "n" + str(directory) not in cwd.splitlines():
                raise RuntimeError("recorded Hook process has another working directory")
            os.kill(pid, signal.SIGTERM)
            for _ in range(100):
                status = subprocess.run(["ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True).stdout.strip()
                if not status or status.startswith("Z"):
                    break
                time.sleep(.1)
            else:
                raise RuntimeError("owned Hook process did not stop gracefully")
        backend["pid"] = None
        fixture.private(directory / "hook.private.json", backend)
    stop_order = [state["ting"], state["iam"], backend["container"], state["postgres"]]
    if set(stop_order) != set(containers):
        raise RuntimeError("owned container inventory changed before stop")
    result = subprocess.run(["docker", "stop", "--time", "20", *stop_order], capture_output=True, text=True, timeout=40)
    if result.returncode:
        raise RuntimeError("one of the owned containers did not stop")
    statuses = {}
    for name in containers:
        result = subprocess.run(["docker", "inspect", "--format", "{{.State.Status}}", name], capture_output=True, text=True, timeout=10)
        statuses[name] = result.stdout.strip()
    if any(status != "exited" for status in statuses.values()):
        raise RuntimeError("owned fixture container still running")
    fixture.private(directory / "testing-services-stopped.json", {"complete": True, "containers": statuses,
        "hook_process_stopped": True, "data_and_logs_retained": True, "unrelated_services_touched": False})
    print("SCOPED_SERVICES_STOPPED owned Hook PID and four owned containers; all data retained", flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--stop", action="store_true", help="only after evidence inspection/copy and successful clean")
    args = parser.parse_args()
    (stop if args.stop else clean)(args.directory.resolve())
