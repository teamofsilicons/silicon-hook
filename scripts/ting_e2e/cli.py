#!/usr/bin/env python3
"""Verify the management CLI against real Hook/IAM and the native Ting receiver.

Uses a new private CLI home, profile, and token family inside an owned fixture.
No existing user's login, Hook relay, or Ting daemon is installed or changed.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.parse
import uuid

import fixture
import hook
import native
import sdk


def owned_processes(binary):
    rows = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True, check=True).stdout.splitlines()
    result = set()
    for row in rows:
        parts = row.strip().split(None, 1)
        if len(parts) == 2 and (parts[1] == str(binary) or parts[1].startswith(str(binary) + " ")):
            result.add(int(parts[0]))
    return result


def verify(directory, binary, receiver_binary):
    upstream, backend, daemon = fixture.load(directory), hook.load(directory), native.native_state(directory)
    folder = Path(tempfile.mkdtemp(prefix="cli-", dir=directory)).resolve()
    home, profile = folder / "hook-home", "ting-e2e"
    actor, org = upstream["actor_id"], upstream["org_id"]
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("SILICON_", "IAM_TEST_")) and key != "ISI"}
    env.update({"SILICON_HOOK_HOME": str(home), "SILICON_HOME": str(folder / "silicon-home"),
                "SILICON_HOOK_TELEMETRY": "off"})
    base = [str(binary), "--url", backend["url"], "--org", org, "--silicon", actor,
            "--profile", profile, "--production", "--json"]
    commands = []

    def cli(args, removed=False):
        result = subprocess.run([*base, *args], env=env, cwd=folder, capture_output=True, timeout=45)
        if removed:
            text = (result.stdout + result.stderr).decode(errors="replace").lower()
            if result.returncode == 0 or "unrecognized subcommand" not in text or args[0] not in text:
                fixture.private(folder / "cli-error.log", result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
                raise RuntimeError("removed CLI command did not fail clearly: " + args[0])
            return None
        if result.returncode:
            fixture.private(folder / "cli-error.log", result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
            raise RuntimeError("Hook CLI failed for " + args[0] + "; inspect private cli-error.log")
        commands.append(args[0])
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise RuntimeError("Hook CLI did not return JSON for " + args[0]) from None

    def saved_profile():
        return json.loads((home / "state.json").read_text())["profiles"][profile]

    def ensure_management_only(before):
        if owned_processes(binary) - before:
            raise RuntimeError("CLI left a background Hook process")
        if {path.name for path in home.iterdir()} - {"state.json", "state.lock"}:
            raise RuntimeError("CLI created non-management state in its isolated home")
        session = saved_profile().get("session") or {}
        for key in ("webhook_url", "webhook_secret", "relay_token", "isi"):
            if session.get(key) is not None:
                raise RuntimeError("CLI persisted removed relay configuration")

    before = owned_processes(binary)
    for removed in ("webhook", "unhook", "daemon", "listen", "deliveries"):
        cli([removed], removed=True)
    token_file = folder / "login.slt"
    fixture.private(token_file, fixture.slt(upstream, "recipient") + "\n")
    login = cli(["login", "--slt-file", str(token_file)])
    token_file.unlink()
    if not login.get("authenticated") or login.get("actor", {}).get("id") != actor or "relay" in login or "webhook_url" in login:
        raise RuntimeError("CLI login identity or management-only response is incorrect")
    status = cli(["login", "status"])
    if not status.get("authenticated") or status.get("actor", {}).get("id") != actor:
        raise RuntimeError("CLI did not confirm real IAM login")
    version = cli(["system", "version"])
    if version.get("service") != "silicon-hook":
        raise RuntimeError("CLI service negotiation did not reach Hook")
    registration = cli(["receiving", "register"])
    if registration.get("for") != actor or not registration.get("active"):
        raise RuntimeError("CLI recipient registration failed")
    provider = cli(["create", "real-ting-cli-e2e"])
    if not provider.get("signing_secret") or provider.get("signature", {}).get("required") is not True:
        raise RuntimeError("CLI provider hook did not enable signatures by default")
    ensure_management_only(before)
    tokens = saved_profile()["session"]["tokens"]
    secret, destination, process = secrets.token_urlsafe(32), None, None
    output = folder / "receiver"
    output.mkdir(mode=0o700)
    config = folder / "receiver.private.json"
    log = open(folder / "receiver.log", "ab")
    raw = json.dumps({"message": "real Hook to Ting delivery", "run": str(uuid.uuid4()),
                      "source": "management CLI"}, separators=(",", ":")).encode()
    try:
        with socket.socket() as reservation:
            reservation.bind(("0.0.0.0", 0))
            port = reservation.getsockname()[1]
            destination = native.cli(daemon, ["webhook", f"http://host.docker.internal:{port}/ting", "--secret-stdin"], (secret + "\n").encode())
            fixture.private(config, {"hook_url": backend["url"], "hook_token": tokens["access_token"],
                "app_id": "hook", "org_id": org, "recipient_id": actor, "environment_id": str(uuid.UUID(int=0)),
                "webhook_id": destination["id"], "callback_secret": secret, "listen_addr": f"0.0.0.0:{port}",
                "output": str(output), "ack_gate": None})
        process = subprocess.Popen([str(receiver_binary), str(config)], stdout=log, stderr=log)
        sdk.wait_for(process, lambda: (output / "ready.json").exists(), "CLI fixture SDK listener")
        identifier, timestamp = str(uuid.uuid4()), str(int(time.time()))
        signature = base64.b64encode(hmac.new(provider["signing_secret"].encode(),
            identifier.encode() + b"." + timestamp.encode() + b"." + raw, hashlib.sha256).digest()).decode()
        accepted = fixture.request(backend["url"], "POST", urllib.parse.urlsplit(provider["endpoint_url"]).path, raw,
            headers={"webhook-id": identifier, "webhook-timestamp": timestamp, "webhook-signature": "v1," + signature})
        event_id = accepted["receipt_id"]
        accepted_path = output / "accepted" / (event_id + ".json")
        sdk.wait_for(process, accepted_path.exists, "native Ting -> SDK receipt of CLI-created hook")
        received = json.loads(accepted_path.read_text())
        event = cli(["event", event_id])
        if event["request"]["body"].encode() != raw or event != received["event"]:
            raise RuntimeError("CLI event output differs from the received provider event")
        history = cli(["events", "--hook", provider["id"], "--limit", "10"])
        if not any(item == event for item in history.get("items", [])):
            raise RuntimeError("CLI history did not contain the exact provider event")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            publication = cli(["publication", event_id])
            receipt = publication.get("recipient_receipt") or {}
            destination_receipt = next((item for item in receipt.get("deliveries", [])
                                        if item["webhook_id"] == destination["id"]), {})
            if (publication.get("state") == "accepted_by_ting" and receipt.get("read")
                    and destination_receipt.get("read_acked") and destination_receipt.get("delivery_acked")):
                break
            time.sleep(.2)
        else:
            raise RuntimeError("CLI publication did not confirm native application acceptance")
        ensure_management_only(before)
        # Capture the latest rotating family after all CLI operations, then
        # prove logout invalidates both its access and refresh credentials.
        tokens = saved_profile()["session"]["tokens"]
        logout = cli(["logout"])
        if not logout.get("signed_out") or cli(["login", "status"]).get("authenticated"):
            raise RuntimeError("CLI logout did not remove its session")
        headers = {"X-Org-Id": org, "Silicon-Hook-API-Version": "v2"}
        identity = fixture.request(backend["url"], "GET", "/api/v2/auth/status", token=tokens["access_token"],
            headers=headers, expected=(200, 401))
        if identity.get("authenticated"):
            raise RuntimeError("CLI logout left the access token authenticated")
        fixture.request(backend["url"], "POST", "/api/v2/auth/refresh", {"refresh_token": tokens["refresh_token"]},
            headers={**headers, "Idempotency-Key": str(uuid.uuid4())}, expected=(401,))
        if saved_profile().get("session") is not None:
            raise RuntimeError("CLI logout retained private session data")
        ensure_management_only(before)
        report = {"complete": True, "hook_api": "v2", "cli_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "receiver_binary_sha256": hashlib.sha256(receiver_binary.read_bytes()).hexdigest(),
            "event_id": event_id, "ting_id": received["ting_id"], "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "removed_commands": ["webhook", "unhook", "daemon", "listen", "deliveries"],
            "checks": ["isolated private CLI home and dedicated IAM token family", "real SLT-file login and online status",
                "v2 recipient registration and signed-default provider creation", "signed provider HTTP request",
                "native Ting daemon -> actual Rust SDK -> durable HTTP204 acceptance", "CLI event and events preserve exact payload",
                "CLI publication reports delivery and read ACK for the current destination", "no Hook relay state or background process",
                "removed delivery commands fail as unrecognized", "logout removes local session and revokes access plus refresh family"],
            "limitations": ["normal fixture plane; sandbox CLI behavior tested separately", "Ting type is fixture seeded"]}
        fixture.private(Path(directory) / "cli-verification.json", report)
        print(json.dumps(report, indent=2), flush=True)
    finally:
        try:
            if destination:
                native.cli(daemon, ["unhook", destination["id"]])
        finally:
            if process and process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
            log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--cli-binary", type=Path, default=hook.ROOT / "target/debug/hook")
    parser.add_argument("--receiver-binary", type=Path, default=hook.ROOT / "target/debug/examples/ting_receiver_e2e")
    args = parser.parse_args()
    verify(args.directory.resolve(), args.cli_binary.resolve(), args.receiver_binary.resolve())
