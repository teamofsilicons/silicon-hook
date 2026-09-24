#!/usr/bin/env python3
"""Real bounded 32-record scoped catch-up across IAM's natural rate window."""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.parse
import uuid

import websocket
import fixture
import hook
import testing
import testing_hook
import testing_web


def verify(directory, node):
    state, backend = fixture.load(directory), hook.load(directory)
    actor = "si:hook-testing"
    testing_hook.prepare_delivery(state, backend)
    observer, website, stream, report = None, None, None, None
    prior = None
    pref_path = "/v1/orgs/tos/preferences"
    pref_body = {"app_id": "hook", "service": None, "type": "hook.webhook.received"}
    pref_query = pref_path + "?" + urllib.parse.urlencode({"app_id": "hook", "type": pref_body["type"]})
    began = time.monotonic()
    try:
        observer = testing_web.operator(state, "test-admin")
        def ting(method, path, body=None):
            return testing.http(state, state["ting_url"], method, path, body, token=observer["session_token"])[1]
        prefs = ting("GET", pref_query)
        if prefs.get("next_cursor"):
            raise RuntimeError("ambiguous preference restoration")
        prior = [p for p in prefs["items"] if p.get("type") == pref_body["type"] and not p.get("service")]
        fixture.private(directory / "testing-catchup-cleanup.private.json", {"observer": observer, "prior_preference": prior})
        ting("PUT", pref_path, {**pref_body, "enabled": False})
        testing_hook.call(state, backend, "test-admin", "POST", f"/silicons/{actor}/delivery/subscription")
        setup_path = directory / "testing-catchup-setup.private.json"
        setup = json.loads(setup_path.read_text()) if setup_path.exists() else {}
        if setup and setup.get("generation") != state["generation"]:
            raise RuntimeError("catch-up setup belongs to a prior generation; archive it before a new run")
        provider = setup.get("provider") or testing_hook.call(state, backend, "test-recipient", "POST", f"/silicons/{actor}/hooks",
                                     {"name": "real scoped32 catch-up"}, expected=(201,))[1]
        event_ids = setup.get("event_ids", [])
        ingress_rate_limits = setup.get("ingress_rate_limits", 0)
        for index in range(len(event_ids), 32):
            raw = json.dumps({"source": "actual scoped catchup", "index": index, "run": str(uuid.uuid4())}, separators=(",", ":")).encode()
            identifier = str(uuid.uuid4())
            for attempt in range(5):
                timestamp = str(int(time.time()))
                signature = base64.b64encode(hmac.new(provider["signing_secret"].encode(),
                    identifier.encode() + b"." + timestamp.encode() + b"." + raw, hashlib.sha256).digest()).decode()
                status, value = testing.http(state, backend["url"], "POST", urllib.parse.urlsplit(provider["endpoint_url"]).path,
                    raw, headers={"webhook-id": identifier, "webhook-timestamp": timestamp, "webhook-signature": "v1," + signature}, expected=(200, 429))
                if status == 200:
                    event_ids.append(value["receipt_id"])
                    fixture.private(setup_path, {"generation": state["generation"], "provider": provider,
                        "event_ids": event_ids, "ingress_rate_limits": ingress_rate_limits})
                    break
                ingress_rate_limits += 1
                try:
                    wait_seconds = min(120, max(1, int(value.get("error", {}).get("retry_after", 60))))
                except (TypeError, ValueError):
                    wait_seconds = 60
                until = time.monotonic() + wait_seconds
                while time.monotonic() < until:
                    print(f"SCOPED_CATCHUP_SETUP ingress429 after {len(event_ids)} records; honoring natural Retry-After", flush=True)
                    time.sleep(min(30, until - time.monotonic()))
            else:
                raise RuntimeError("real signed ingress did not recover within bounded natural rate waits")
            if (index + 1) % 8 == 0:
                print(f"SCOPED_CATCHUP_SETUP accepted {index+1}/32 signed small requests", flush=True)
        # Read-only owned DB observation avoids adding auth traffic while the actual
        # outbox/IAM/Ting path publishes every primary and observer notification.
        quoted = ",".join("'" + str(uuid.UUID(value)) + "'" for value in event_ids)
        sql = "SELECT json_build_object('total',count(*),'accepted',count(*) FILTER(WHERE accepted_at IS NOT NULL),'errors',array_agg(DISTINCT last_error_code) FILTER(WHERE last_error_code IS NOT NULL)) FROM hook_private.ting_outbox WHERE event_id IN (" + quoted + ")"
        deadline = time.monotonic() + 900
        publication = None
        while time.monotonic() < deadline:
            result = subprocess.run(["docker", "exec", backend["container"], "psql", "-U", "postgres", "-d", "hook_testing", "-Atc", sql], capture_output=True, text=True, timeout=10)
            if result.returncode:
                raise RuntimeError("owned outbox observation failed")
            publication = json.loads(result.stdout)
            if publication["total"] == 64 and publication["accepted"] == 64:
                break
            print(f"SCOPED_CATCHUP_SETUP real outbox accepted {publication['accepted']}/{publication['total']} entries; natural30s wait", flush=True)
            time.sleep(30)
        else:
            fixture.private(directory / "testing-catchup-setup-incomplete.json", {"event_ids": event_ids, "publication": publication})
            raise RuntimeError("actual backlog publication did not complete within15minutes")
        print("SCOPED_CATCHUP_SETUP all64 actual outbox sends accepted; clearing setup pressure with natural60s wait", flush=True)
        for _ in range(2):
            time.sleep(30); print("SCOPED_CATCHUP_SETUP natural rate-window wait", flush=True)
        website = testing_web.Website(state, backend, node)
        website.request("POST", "/console/attach", {"app_secret": state["imports"]["hook"]["app_secret"]})
        slt = testing.cli(state, "test-admin", ["login", "--app-id", "hook", "--grant-org", "tos", "--approve-scopes"])["slt"]
        website.request("POST", website.path("/console/login"), {"slt": slt})
        url = website.origin.replace("http://", "ws://") + "/console/stream?" + urllib.parse.urlencode({"plane": state["environment_id"], "org": "tos", "silicon_id": actor, "telemetry": "off"})
        stream = websocket.create_connection(url, cookie="; ".join(f"{c.name}={c.value}" for c in website.jar), origin=website.origin, timeout=2)
        seen, warning_codes = [], []
        first = None
        deadline = time.monotonic() + 300
        last_progress = time.monotonic()
        while time.monotonic() < deadline and len(seen) < 32:
            try:
                raw = stream.recv()
            except websocket.WebSocketTimeoutException:
                if time.monotonic() - last_progress >= 25:
                    print(f"SCOPED_CATCHUP waiting with same stream; forwarded {len(seen)}/32", flush=True); last_progress = time.monotonic()
                continue
            if not raw:
                raise RuntimeError("catch-up stream closed during rate-window recovery")
            frame = json.loads(raw)
            if frame.get("type") == "ready" and first is None:
                first = website.receiver()
            elif frame.get("type") == "error":
                data = frame.get("data", {})
                warning_codes.append(data.get("code"))
                if data.get("fatal"):
                    fixture.private(directory / "testing-catchup-stream-error.private.json", frame)
                    raise RuntimeError("catch-up emitted fatal error")
            elif frame.get("type") == "new_event":
                event = frame["data"]["event"]
                identifier = event["id"]
                if identifier in seen:
                    raise RuntimeError("catch-up forwarded a duplicate event across rate recovery")
                if identifier not in event_ids:
                    raise RuntimeError("default latest32 view included an unexpected older event")
                seen.append(identifier)
                if len(seen) % 8 == 0:
                    print(f"SCOPED_CATCHUP forwarded {len(seen)}/32 unique events", flush=True)
        if set(seen) != set(event_ids) or first is None:
            raise RuntimeError("bounded scoped catch-up did not forward all32 real records")
        # Include another ordinary reconciliation after completion so a resumed
        # view cannot quietly forward the retained records again.
        quiet_until = time.monotonic() + 12
        while time.monotonic() < quiet_until:
            try:
                value = stream.recv()
            except websocket.WebSocketTimeoutException:
                continue
            if not value:
                raise RuntimeError("catch-up stream closed after completion")
            frame = json.loads(value)
            if frame.get("type") == "new_event":
                raise RuntimeError("completed catch-up forwarded a retained duplicate during reconciliation")
            if frame.get("type") == "error" and frame.get("data", {}).get("fatal"):
                raise RuntimeError("completed catch-up became fatal")
        current = website.receiver()
        if current["receiver_id"] != first["receiver_id"] or current["receiver_token"] == first["receiver_token"]:
            raise RuntimeError("catch-up did not preserve receiver identity through renewal")
        if "rate_limited" not in warning_codes:
            raise RuntimeError("catch-up did not exercise an actual upstream429")
        inbox = testing.http(state, state["ting_url"], "GET", "/v1/receivers/inbox?limit=32", token=current["receiver_token"])[1]
        observed = {item.get("data", {}).get("data", {}).get("metadata", {}).get("id"): item for item in inbox["items"]}
        if set(observed) != set(event_ids) or any(item.get("read") or not item.get("silent") for item in observed.values()):
            raise RuntimeError("scoped catch-up changed ACK state or latest32 receipt identity")
        website.request("POST", website.path("/console/logout"))
        testing.http(state, state["ting_url"], "GET", "/v1/receivers/me", token=current["receiver_token"], expected=(401,))
        report = {"complete": True, "environment_id": state["environment_id"], "shared_generation": state["generation"],
            "duration_seconds": round(time.monotonic()-began,3), "event_ids": event_ids,
            "actual_publications": publication, "forwarded_unique_records": len(seen), "duplicate_frames": 0, "scoped_unread_silent_records_verified": len(observed),
            "stream_warning_codes": warning_codes, "setup_ingress_rate_limits": ingress_rate_limits,
            "server_sha256": hashlib.sha256(website.server.read_bytes()).hexdigest(),
            "hook_binary_sha256": backend.get("binary_sha256"),
            "checks": ["32 actual signed provider ingress requests;64 primary/observer outbox sends accepted by real Ting",
                "Default latest32 scoped observer view completed on one live stream across natural IAM429",
                "Forwarded event IDs remained unique across pause/resume",
                "Same receiver ID renewed with replacement token after rate backoff",
                "No seeded accepted notifications, limit changes, clock changes or application read ACK",
                "Logout revoked the current receiver"],
            "limitations": ["Synthetic local participant fixture; full coordinator and production approval not covered"]}
    finally:
        if stream:
            stream.close()
        if website:
            try:
                for attempt in range(4):
                    try:
                        website.request("POST", website.path("/console/logout"), expected=(200,401)); break
                    except RuntimeError:
                        if attempt == 3: raise
                        print("SCOPED_CATCHUP_CLEANUP natural30s wait before durable logout retry", flush=True); time.sleep(30)
            finally:
                website.close()
        if observer:
            if prior is not None:
                if prior:
                    testing.http(state,state["ting_url"],"PUT",pref_path,{**pref_body,"enabled":prior[0]["enabled"]},token=observer["session_token"])
                else:
                    testing.http(state,state["ting_url"],"DELETE",pref_query,token=observer["session_token"])
            testing.http(state,state["ting_url"],"DELETE","/v1/session",token=observer["session_token"],expected=(200,401))
            (directory / "testing-catchup-cleanup.private.json").unlink(missing_ok=True)
        testing.http(state,state["ting_url"],"PUT",state["required_policy_path"],{"enabled":state["required_policy_before"]["enabled"]},token=state["recipient_operator"]["session_token"])
    if report:
        report["preferences_and_required_policy_restored"] = True
        fixture.private(directory / "testing-catchup-verification.json",report)
        print("SCOPED_CATCHUP_PASS 32 unique records across real429, renewal and cleanup",flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory",type=Path)
    parser.add_argument("--node",default="node")
    args=parser.parse_args()
    verify(args.directory.resolve(),args.node)
