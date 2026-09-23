#!/usr/bin/env python3
"""Prove an unavailable Hook payload does not block later native Ting delivery.

Delete exactly one owned fixture event after real Ting publication, modeling
Hook retention/clean after transport acceptance. No upstream Ting state is edited.
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
import urllib.parse
import urllib.request
import uuid

import fixture
import hook
import native
import sdk


def verify(directory, binary):
    upstream, backend, daemon = fixture.load(directory), hook.load(directory), native.native_state(directory)
    folder = Path(tempfile.mkdtemp(prefix="unavailable-", dir=directory)).resolve()
    actor, org = upstream["actor_id"], upstream["org_id"]
    tokens = fixture.exchange(upstream, "recipient", "tos>hook")
    token = tokens["access_token"]
    secret, destination, process = secrets.token_urlsafe(32), None, None
    output = folder / "receiver"
    output.mkdir(mode=0o700)
    config = folder / "receiver.private.json"
    log = open(folder / "receiver.log", "ab")

    def call(method, path, body=None, mutate=False, expected=(200,)):
        headers = {"X-Org-Id": org, "Silicon-Hook-API-Version": "v2"}
        if mutate:
            headers["Idempotency-Key"] = str(uuid.uuid4())
        return fixture.request(backend["url"], method, "/api/v2" + path, body, token, headers, expected)

    def send(provider, label):
        raw = json.dumps({"message": "real Hook to Ting delivery", "run": str(uuid.uuid4()),
                          "source": "unavailable recovery", "case": label}, separators=(",", ":")).encode()
        identifier, timestamp = str(uuid.uuid4()), str(int(time.time()))
        signature = base64.b64encode(hmac.new(provider["signing_secret"].encode(),
            identifier.encode() + b"." + timestamp.encode() + b"." + raw, hashlib.sha256).digest()).decode()
        response = fixture.request(backend["url"], "POST", urllib.parse.urlsplit(provider["endpoint_url"]).path, raw,
            headers={"webhook-id": identifier, "webhook-timestamp": timestamp, "webhook-signature": "v1," + signature})
        return response["receipt_id"], raw

    def publication(event_id):
        return call("GET", f"/silicons/{actor}/events/{event_id}/publication")

    def receipt(status):
        return next((item for item in (status.get("recipient_receipt") or {}).get("deliveries", [])
                     if item["webhook_id"] == destination["id"]), {})

    def poll(predicate, description, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.1)
        raise RuntimeError("timed out waiting for " + description)

    def remove_payload(event_id):
        sql = ("DELETE FROM hook.events WHERE environment_id='00000000-0000-0000-0000-000000000000'::uuid"
               f" AND org_id={fixture.quote(org)} AND silicon_id={fixture.quote(actor)}"
               f" AND id={fixture.quote(event_id)}::uuid RETURNING id;")
        deleted = fixture.command(["docker", "exec", "-i", backend["container"], "psql", "-U", "postgres",
            "-d", "hook", "-X", "-v", "ON_ERROR_STOP=1", "-At"], stdin=sql.encode(),
            log=folder / "fixture-retention.log").decode().splitlines()
        if deleted != [event_id, "DELETE 1"]:
            raise RuntimeError("fixture retention did not remove exactly its selected event")

    try:
        call("POST", "/delivery/recipient")
        provider = call("POST", f"/silicons/{actor}/hooks", {"name": "real-ting-unavailable-e2e"}, True, (201,))
        with socket.socket() as reservation:
            reservation.bind(("0.0.0.0", 0))
            port = reservation.getsockname()[1]
            destination = native.cli(daemon, ["webhook", f"http://host.docker.internal:{port}/ting", "--secret-stdin"], (secret + "\n").encode())
            # Keep the callback unavailable until the first event is durably
            # queued by the real daemon and its raw Hook payload is removed.
            old_event, _ = send(provider, "removed before callback")
            before = poll(lambda: (value if receipt(value := publication(old_event)).get("delivery_acked") else None),
                          "native durable queue acceptance")
            if (before.get("recipient_receipt") or {}).get("read"):
                raise RuntimeError("native daemon marked an unavailable callback read")
            old_ting = before["ting_id"]
            remove_payload(old_event)
            missing = call("GET", f"/silicons/{actor}/events/{old_event}", expected=(404,))
            if missing.get("error", {}).get("code") != "not_found":
                raise RuntimeError("missing Hook payload did not return its structured terminal result")
            new_event, raw = send(provider, "valid event after unavailable payload")
            poll(lambda: publication(new_event).get("state") == "accepted_by_ting", "later Ting publication")
            fixture.private(config, {"hook_url": backend["url"], "hook_token": token,
                "app_id": "tos>hook", "org_id": org, "recipient_id": actor, "environment_id": str(uuid.UUID(int=0)),
                "webhook_id": destination["id"], "callback_secret": secret, "listen_addr": f"0.0.0.0:{port}",
                "output": str(output), "ack_gate": None})
        process = subprocess.Popen([str(binary), str(config)], stdout=log, stderr=log)
        sdk.wait_for(process, lambda: (output / "ready.json").exists(), "unavailable fixture SDK listener")
        unavailable_path = output / "unavailable" / (old_event + ".json")
        accepted_path = output / "accepted" / (new_event + ".json")
        sdk.wait_for(process, lambda: unavailable_path.exists() and accepted_path.exists(),
                     "native retry terminal result followed by valid application delivery", seconds=100)
        unavailable = json.loads(unavailable_path.read_text())
        accepted = json.loads(accepted_path.read_text())
        evidence = json.loads((output / "evidence.json").read_text())
        if (unavailable["ting_id"] != old_ting or unavailable["reference"]["id"] != old_event
                or accepted["event"]["request"]["body"].encode() != raw
                or evidence["new_events"] != 1 or evidence["unavailable"] != 1
                or (output / "accepted" / (old_event + ".json")).exists()):
            raise RuntimeError("SDK conflated unavailable delivery with accepted application work")
        poll(lambda: receipt(publication(new_event)).get("read_acked"), "later event read ACK")
        old_receipt = fixture.request(upstream["ting_url"], "GET", f"/v1/orgs/{org}/inbox/{old_ting}",
            token=upstream["ting_session"])
        if not old_receipt.get("read"):
            raise RuntimeError("terminal unavailable result did not release the native unread queue")
        # Restart the host, then replay authenticated native callbacks to check
        # its durable dedupe without changing Ting's already-acked state.
        process.terminate()
        process.wait(timeout=10)
        (output / "ready.json").unlink()
        process = subprocess.Popen([str(binary), str(config)], stdout=log, stderr=log)
        sdk.wait_for(process, lambda: (output / "ready.json").exists(), "restarted unavailable fixture listener")

        def replay(item):
            replay_record = {key: item[key] for key in ("id", "created_at", "type", "key", "data", "metadata")}
            request = urllib.request.Request(f"http://127.0.0.1:{port}/ting", method="POST",
                data=json.dumps({"tings": [replay_record]}).encode(),
                headers={"Content-Type": "application/json", "Authorization": "Bearer " + secret,
                         "Ting-Webhook-Id": destination["id"]})
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status != 204:
                    raise RuntimeError("terminal unavailable retry was not acknowledged")

        replay(old_receipt)
        evidence = json.loads((output / "evidence.json").read_text())
        if evidence["unavailable"] != 1 or evidence["new_events"] != 1 or evidence["duplicates"] < 1:
            raise RuntimeError("terminal unavailable retry was not durably deduplicated")
        # Expiry after successful durable acceptance must preserve that prior
        # result rather than creating contradictory unavailable application work.
        new_receipt = fixture.request(upstream["ting_url"], "GET", f"/v1/orgs/{org}/inbox/{accepted['ting_id']}",
            token=upstream["ting_session"])
        remove_payload(new_event)
        replay(new_receipt)
        evidence = json.loads((output / "evidence.json").read_text())
        if (evidence["unavailable"] != 1 or evidence["new_events"] != 1 or evidence["duplicates"] < 2
                or (output / "unavailable" / (new_event + ".json")).exists()
                or json.loads(accepted_path.read_text()) != accepted):
            raise RuntimeError("payload expiry changed already accepted durable application work")
        report = {"complete": True, "receiver_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "unavailable_event_id": old_event, "unavailable_ting_id": old_ting,
            "next_event_id": new_event, "next_ting_id": accepted["ting_id"],
            "new_events": evidence["new_events"], "unavailable": evidence["unavailable"],
            "duplicates": evidence["duplicates"], "next_payload_sha256": hashlib.sha256(raw).hexdigest(),
            "checks": ["real signed event published and durably queued by the native Ting daemon",
                "exactly one owned fixture payload removed after Ting acceptance",
                "authenticated structured Hook 404 becomes a durable unavailable delivery result",
                "unavailable result is recorded separately and not counted as application work",
                "HTTP204 releases the native unread queue", "later valid event hydrates exact payload and receives read ACK",
                "authenticated repeated terminal callback is durably deduplicated after host restart",
                "expiry after durable acceptance retains the original accepted work on retry"],
            "limitations": ["retention is modeled by deleting selected isolated fixture rows; no 14-day clock wait",
                "terminal replay is a controlled local callback; initial retry and later delivery use the real native daemon",
                "normal fixture plane; sandbox clean not exercised"]}
        fixture.private(Path(directory) / "unavailable-verification.json", report)
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
