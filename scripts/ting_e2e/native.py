#!/usr/bin/env python3
"""Run the published native Ting receiver inside this fixture's own container.

The real daemon uses a fixed system socket and the OS user's real home. A
container isolates both without installing a host service or using host profiles.
"""
import argparse
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import tarfile
import threading
import time
import urllib.parse
import urllib.request
import uuid

import fixture
import hook

ARCHIVE = "ting-v0.1.2-aarch64-unknown-linux-gnu.tar.gz"
SHA256 = "db11696107ffb76a3d729c975e77bc925969458a104717c9593de6baedc64c4b"
IMAGE = "ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3"
API = "http://127.0.0.1:8082"


def native_state(directory):
    state = json.loads((Path(directory) / "native.private.json").read_text())
    if not state.get("owned") or not state["container"].startswith("hook-ting-e2e-"):
        raise RuntimeError("unowned native receiver fixture")
    return state


def cli(state, args, raw=None):
    output = fixture.command(["docker", "exec", "-i", state["container"], "/app/ting",
        "--api-url", API, "--org", "tos", "--json", *args], stdin=raw,
        log=Path(state["directory"]) / "native-cli-error.log", timeout=45)
    return json.loads(output)


def setup(directory):
    upstream = fixture.load(directory)
    folder = Path(directory)
    if (folder / "native.private.json").exists():
        raise RuntimeError("native fixture already exists; use verify or cleanup")
    archive, target = folder / ARCHIVE, folder / "ting-native"
    if not archive.exists():
        urllib.request.urlretrieve("https://github.com/teamofsilicons/silicon-ting/releases/download/v0.1.2/" + ARCHIVE, archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        raise RuntimeError("native Ting archive checksum mismatch")
    target.mkdir(mode=0o700, exist_ok=True)
    with tarfile.open(archive) as bundle:
        for entry in bundle.getmembers():
            if entry.name not in ("ting", "ting-daemon") or not entry.isfile():
                raise RuntimeError("unexpected native Ting archive entry")
        bundle.extractall(target, filter="data")
    for name in ("ting", "ting-daemon"):
        (target / name).chmod(0o755)
    name = upstream["network"] + "-native"
    state = {"owned": True, "container": name, "directory": str(folder), "archive_sha256": SHA256}
    fixture.private(folder / "native.private.json", state)
    fixture.command(["docker", "run", "-d", "--name", name, "--network", "container:" + upstream["iam"],
        "-v", str(target) + ":/app:ro", "--entrypoint", "sh", IMAGE, "-c",
        "mkdir -p /var/tmp/silicon-ting && chmod 700 /var/tmp/silicon-ting && exec /app/ting-daemon"],
        log=folder / "native-setup-error.log")
    upstream["containers"].append(name)
    fixture.save(upstream)
    if cli(state, ["--version"]).get("version") != "0.1.2":
        raise RuntimeError("unexpected native Ting version")
    cli(state, ["config", "set", "telemetry.enabled", "false"])
    login = cli(state, ["login", "--token-stdin"], (fixture.slt(upstream, "recipient", "ting") + "\n").encode())
    if not login.get("authenticated") or login.get("id") != upstream["actor_id"]:
        raise RuntimeError("native Ting recipient login failed")
    print("NATIVE_READY isolated published Ting CLI and daemon", flush=True)


def verify(directory):
    upstream, backend, native = fixture.load(directory), hook.load(directory), native_state(directory)
    actor, org = upstream["actor_id"], upstream["org_id"]
    headers = {"X-Org-Id": org, "Silicon-Hook-API-Version": "v2"}
    def call(method, path, body=None, mutate=False, expected=(200,)):
        values = {**headers}
        if mutate:
            values["Idempotency-Key"] = str(uuid.uuid4())
        return fixture.request(backend["url"], method, "/api/v2" + path, body,
            upstream["hook_recipient"]["access_token"], values, expected)

    call("POST", "/delivery/recipient")
    provider = call("POST", f"/silicons/{actor}/hooks", {"name": "real-ting-native-e2e"}, True, (201,))
    raw = json.dumps({"message": "real Hook to Ting delivery", "run": str(uuid.uuid4())}, separators=(",", ":")).encode()
    local_secret = secrets.token_urlsafe(32)
    received, release_ack = threading.Event(), threading.Event()
    callback = {"event_id": None, "ting_id": None, "error": None, "batches": 0}

    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            try:
                if self.path != "/ting" or not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + local_secret):
                    self.send_response(401); self.end_headers(); return
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 1024 * 1024 or not self.headers.get("Ting-Webhook-Id", "").startswith("hook_"):
                    raise RuntimeError("invalid native callback framing")
                body = json.loads(self.rfile.read(size))
                if set(body) != {"tings"} or not isinstance(body["tings"], list) or not body["tings"]:
                    raise RuntimeError("invalid native callback batch")
                found = False
                for item in body["tings"]:
                    data = item.get("data", {})
                    # Native Ting deliberately omits the WS-only `for` field.
                    # This local destination belongs to our configured actor;
                    # authoritative Hook hydration enforces that binding.
                    if item.get("type") != "hook.webhook.received" or data.get("type") != "new_event":
                        raise RuntimeError("unexpected native callback notification")
                    metadata = data.get("data", {}).get("metadata", {})
                    if data.get("data", {}).get("sender") == "fixture" and metadata.get("run", "").startswith("fixture-"):
                        continue
                    if metadata.get("org_id") != org or metadata.get("silicon_id") != actor:
                        raise RuntimeError("unexpected native Hook reference")
                    selected = urllib.parse.urlencode({"environment_id": metadata["environment_id"],
                        "environment_generation": metadata["environment_generation"]})
                    event = call("GET", f"/silicons/{actor}/events/{metadata['id']}?{selected}")
                    for field in ("id", "org_id", "silicon_id", "hook_id", "delivery_sequence", "received_at"):
                        if event[field] != metadata[field]:
                            raise RuntimeError("native hydrated reference mismatch")
                    payload = event["request"]["body"].encode()
                    if json.loads(payload).get("message") != "real Hook to Ting delivery":
                        raise RuntimeError("unexpected retained fixture event")
                    if payload == raw:
                        found = True
                        callback.update(event_id=event["id"], ting_id=item["id"])
                callback["batches"] += 1
                if found:
                    received.set()
                    if not release_ack.wait(8):
                        raise RuntimeError("test did not inspect pre-acceptance status in time")
                self.send_response(204); self.end_headers()
            except Exception as error:
                callback["error"] = type(error).__name__
                received.set()
                self.send_response(503); self.end_headers()

    # Only a random-port, secret-protected controlled callback is exposed to the
    # Docker guest. No user application server or profile is reused.
    server = ThreadingHTTPServer(("0.0.0.0", 0), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    destination = None
    try:
        destination = cli(native, ["webhook", f"http://host.docker.internal:{server.server_port}/ting", "--secret-stdin"], (local_secret + "\n").encode())
        identifier, timestamp = str(uuid.uuid4()), str(int(time.time()))
        signed = identifier.encode() + b"." + timestamp.encode() + b"." + raw
        signature = base64.b64encode(hmac.new(provider["signing_secret"].encode(), signed, hashlib.sha256).digest()).decode()
        accepted = fixture.request(backend["url"], "POST", urllib.parse.urlsplit(provider["endpoint_url"]).path, raw,
            headers={"webhook-id": identifier, "webhook-timestamp": timestamp, "webhook-signature": "v1," + signature})
        if not received.wait(40) or callback["error"]:
            raise RuntimeError("native callback did not validate and hydrate the provider event")
        if callback["event_id"] != accepted["receipt_id"]:
            raise RuntimeError("native callback event identity mismatch")
        path = f"/silicons/{actor}/events/{accepted['receipt_id']}/publication"
        def destination_receipt(status):
            return next((item for item in (status.get("recipient_receipt") or {}).get("deliveries", [])
                         if item["webhook_id"] == destination["id"]), {})

        deadline = time.monotonic() + 3
        while True:
            before = call("GET", path)
            receipt = destination_receipt(before)
            if receipt.get("delivery_acked") or time.monotonic() >= deadline:
                break
            time.sleep(.1)
        if (before["state"] != "accepted_by_ting" or not before.get("recipient_receipt")
                or before["recipient_receipt"]["read"] or not receipt.get("delivery_acked") or receipt.get("read_acked")):
            raise RuntimeError("native delivery ACK incorrectly reported application acceptance")
        release_ack.set()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            final = call("GET", path)
            if (final.get("recipient_receipt") or {}).get("read") and destination_receipt(final).get("read_acked"):
                break
            time.sleep(.2)
        else:
            raise RuntimeError("native HTTP204 acceptance did not reach Hook publication status")
        report = {"complete": True, "ting_version": native.get("version", "0.1.2"), "native_archive_sha256": native["archive_sha256"],
            "event_id": callback["event_id"], "ting_id": callback["ting_id"],
            "payload_sha256": hashlib.sha256(raw).hexdigest(), "callback_batches": callback["batches"],
            "checks": ["official CLI Ting SLT login", "native daemon in isolated OS namespace",
                "signed Hook HTTP ingestion", "native persistent queue and delivery ACK",
                "secret-authenticated native HTTP batch callback", "authenticated Hook hydration preserves exact bytes",
                "publication unread before local HTTP204", "native HTTP204 triggers read ACK visible in Hook"],
            "limitations": ["synthetic application callback; Hook SDK consumer not exercised",
                "normal fixture plane; sandbox delivery not exercised", "daemon restart/retry not exercised"]}
        fixture.private(Path(directory) / "native-verification.json", report)
        print(json.dumps(report, indent=2), flush=True)
    finally:
        release_ack.set()
        if destination:
            cli(native, ["unhook", destination["id"]])
        server.shutdown()
        server.server_close()


def cleanup(directory):
    state = native_state(directory)
    fixture.command(["docker", "rm", "-f", state["container"]])
    state["cleaned"] = True
    fixture.private(Path(directory) / "native.private.json", state)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["setup", "verify", "cleanup"])
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    {"setup": setup, "verify": verify, "cleanup": cleanup}[args.action](args.directory.resolve())
