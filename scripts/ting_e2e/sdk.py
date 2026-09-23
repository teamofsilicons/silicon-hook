#!/usr/bin/env python3
"""Exercise the actual Rust SDK host through the owned native Ting daemon.

Use a private configuration file, reject the first acknowledgment after durable
acceptance, restart both receiving processes, and verify the real retry dedupes.
"""
import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import fixture
import hook
import native


def wait_for(process, predicate, description, seconds=40):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("SDK receiver stopped; inspect private receiver.log")
        result = predicate()
        if result:
            return result
        time.sleep(.1)
    raise RuntimeError("timed out waiting for " + description)


def verify(directory, binary):
    upstream, backend, daemon = fixture.load(directory), hook.load(directory), native.native_state(directory)
    folder = Path(tempfile.mkdtemp(prefix="sdk-", dir=directory)).resolve()
    actor, org = upstream["actor_id"], upstream["org_id"]
    def call(method, path, body=None, mutate=False, expected=(200,)):
        headers = {"X-Org-Id": org, "Silicon-Hook-API-Version": "v2"}
        if mutate:
            headers["Idempotency-Key"] = str(uuid.uuid4())
        return fixture.request(backend["url"], method, "/api/v2" + path, body,
            upstream["hook_recipient"]["access_token"], headers, expected)

    call("POST", "/delivery/recipient")
    provider = call("POST", f"/silicons/{actor}/hooks", {"name": "real-ting-sdk-e2e"}, True, (201,))
    # Larger than Ting's send limit: the compact reference must hydrate back to
    # these exact bytes rather than transporting the raw body through Ting.
    raw = json.dumps({"message": "real Hook to Ting delivery", "run": str(uuid.uuid4()),
                      "padding": "x" * 300000}, separators=(",", ":")).encode()
    secret = secrets.token_urlsafe(32)
    gate = folder / "allow-204"
    config_path = folder / "receiver.private.json"
    destination, process = None, None
    output = folder / "receiver"
    output.mkdir(mode=0o700)
    log = open(folder / "receiver.log", "ab")

    def start():
        ready = output / "ready.json"
        ready.unlink(missing_ok=True)
        child = subprocess.Popen([str(binary), str(config_path)], stdout=log, stderr=log)
        wait_for(child, lambda: ready.exists(), "SDK listener")
        return child

    def evidence():
        path = output / "evidence.json"
        return json.loads(path.read_text()) if path.exists() else {}

    try:
        with socket.socket() as reservation:
            reservation.bind(("0.0.0.0", 0))
            port = reservation.getsockname()[1]
            destination = native.cli(daemon, ["webhook", f"http://host.docker.internal:{port}/ting", "--secret-stdin"], (secret + "\n").encode())
            fixture.private(config_path, {"hook_url": backend["url"], "hook_token": upstream["hook_recipient"]["access_token"],
                "app_id": "tos>hook", "org_id": org, "recipient_id": actor, "environment_id": str(uuid.UUID(int=0)),
                "webhook_id": destination["id"], "callback_secret": secret, "listen_addr": f"0.0.0.0:{port}",
                "output": str(output), "ack_gate": str(gate)})
        process = start()
        invalid = urllib.request.Request(f"http://127.0.0.1:{port}/ting", data=b'{"tings":[]}', method="POST",
            headers={"Content-Type": "application/json", "Authorization": "Bearer invalid", "Ting-Webhook-Id": destination["id"]})
        try:
            with urllib.request.urlopen(invalid, timeout=5) as response:
                invalid_status = response.status
        except urllib.error.HTTPError as error:
            invalid_status = error.code
        if invalid_status not in (400, 401) or list((output / "accepted").glob("*.json")):
            raise RuntimeError("SDK accepted an unauthenticated callback")
        identifier, timestamp = str(uuid.uuid4()), str(int(time.time()))
        signed = identifier.encode() + b"." + timestamp.encode() + b"." + raw
        signature = base64.b64encode(hmac.new(provider["signing_secret"].encode(), signed, hashlib.sha256).digest()).decode()
        accepted = fixture.request(backend["url"], "POST", urllib.parse.urlsplit(provider["endpoint_url"]).path, raw,
            headers={"webhook-id": identifier, "webhook-timestamp": timestamp, "webhook-signature": "v1," + signature})
        event_id = accepted["receipt_id"]
        first = wait_for(process, lambda: (value if (value := evidence()).get("last_status") == 503 else None),
                         "SDK durable acceptance and deliberate non-204 response")
        accepted_path = output / "accepted" / (event_id + ".json")
        saved = json.loads(accepted_path.read_text())
        if (saved["event"]["request"]["body"].encode() != raw or first["new_events"] != 1
                or first["duplicates"] != 0 or first["callback_bytes"] >= 262144):
            raise RuntimeError("SDK did not hydrate and durably accept the exact large provider payload")
        path = f"/silicons/{actor}/events/{event_id}/publication"
        def receipt(status):
            return next((item for item in (status.get("recipient_receipt") or {}).get("deliveries", [])
                         if item["webhook_id"] == destination["id"]), {})
        deadline = time.monotonic() + 5
        while True:
            before = call("GET", path)
            stage = receipt(before)
            if stage.get("delivery_acked") or time.monotonic() >= deadline:
                break
            time.sleep(.1)
        if not stage.get("delivery_acked") or stage.get("read_acked") or (before.get("recipient_receipt") or {}).get("read"):
            raise RuntimeError("Ting confused a failed HTTP callback with application acknowledgment")
        print("SDK_STAGE durable acceptance and non-204 left delivery unread; restarting owned receivers", flush=True)
        process.terminate()
        process.wait(timeout=10)
        process = None
        fixture.command(["docker", "restart", "--time", "1", daemon["container"]], log=folder / "native-restart.log")
        fixture.private(gate, "accept\n")
        process = start()
        final = wait_for(process, lambda: (value if (value := evidence()).get("last_status") == 204 else None),
                         "native automatic retry after daemon and SDK restart", seconds=90)
        if (final["new_events"] != 1 or final["duplicates"] < 1 or final["requests"] < 2
                or final["event_ids"] != [event_id] or final["ting_ids"] != [saved["ting_id"]]
                or json.loads(accepted_path.read_text()) != saved):
            raise RuntimeError("restart retry did not deduplicate the original durable event")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status = call("GET", path)
            if (status.get("recipient_receipt") or {}).get("read") and receipt(status).get("read_acked"):
                break
            time.sleep(.2)
        else:
            raise RuntimeError("SDK HTTP204 did not produce native read ACK")
        report = {"complete": True, "ting_version": daemon.get("version", "0.1.2"), "native_archive_sha256": daemon["archive_sha256"],
            "receiver_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "event_id": event_id, "ting_id": saved["ting_id"], "payload_bytes": len(raw),
            "payload_sha256": hashlib.sha256(raw).hexdigest(), "callback_bytes": final["callback_bytes"],
            "requests": final["requests"], "new_events": final["new_events"], "duplicates": final["duplicates"],
            "checks": ["real signed Hook ingress", "compact native Ting callback below 256KiB for provider payload above 256KiB",
                "actual Rust Hook Receiver authenticates and decodes native callback", "actual SDK hydrates exact original payload",
                "host writes and fsyncs event-ID acceptance before response", "invalid local bearer rejected",
                "non-204 leaves Ting unread with delivery ACK present", "native daemon and SDK process restarted",
                "automatic native retry preserves notification identity", "durable event deduplication survives SDK restart",
                "HTTP204 becomes native read ACK visible in Hook"],
            "limitations": ["normal fixture plane; sandbox delivery not exercised", "type is fixture seeded; Honeycomb bootstrap untested",
                "host acceptance uses the test example, not an external user application"]}
        fixture.private(Path(directory) / "sdk-verification.json", report)
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
    parser.add_argument("--receiver-binary", type=Path, default=hook.ROOT / "target/debug/examples/ting_receiver_e2e")
    args = parser.parse_args()
    verify(args.directory.resolve(), args.receiver_binary.resolve())
