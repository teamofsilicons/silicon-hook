#!/usr/bin/env python3
"""Exercise the real Hook scoped receiver adapter in the owned testing fixture."""
import argparse
import base64
import contextlib
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import time
import urllib.parse
import uuid

import websocket

import fixture
import hook
import testing


def control(state, backend, action, generation=None):
    operation = str(uuid.uuid4())
    revision = state.get("hook_revision", 0) + 1
    body = {"app_id": "tos>hook", "org_id": "tos", "environment_id": state["environment_id"],
        "operation_id": operation, "environment_revision": revision,
        "generation": generation or state["generation"], "key_version": state["key_version"],
        "testing_key": state["testing_key"], "action": action}
    receipt = testing.http(state, backend["url"], "PUT",
        f"/internal/honeycomb/organizations/tos/testing-environments/{state['environment_id']}/operations/{operation}",
        body, token=backend["honeycomb_control_token"])[1]
    if receipt.get("state") != "completed":
        raise RuntimeError("Hook lifecycle participant did not complete")
    state["hook_revision"] = revision; fixture.save(state)
    return receipt


def call(state, backend, label, method, path, body=None, key=None, expected=(200,)):
    headers = {"X-Org-Id": "tos", "Silicon-Hook-API-Version": "v2",
        "X-Hook-Test-App-Secret": state["imports"]["tos>hook"]["app_secret"]}
    if method != "GET":
        headers["Idempotency-Key"] = key or str(uuid.uuid4())
    return testing.http(state, backend["url"], method, "/api/v2" + path, body,
        state["hook_sessions"][label]["access_token"], headers, expected)


def capability(state, backend, label, receiver_id=None, key=None):
    scope = call(state, backend, label, "GET", "/delivery/receiver")[1]
    if scope["environment"] != {"kind": "testing", "id": state["environment_id"], "generation": state["generation"]}:
        raise RuntimeError("Hook receiver scope did not match the shared generation")
    body = {"environment_id": scope["environment"]["id"], "generation": scope["environment"]["generation"]}
    if receiver_id:
        body["receiver_id"] = receiver_id
    key = key or str(uuid.uuid4())
    result = call(state, backend, label, "POST", "/delivery/receiver", body, key)[1]
    if any(result[field] != scope[field] for field in scope):
        raise RuntimeError("Hook capability changed its authorized receiver scope")
    return result, body, key


def prepare_delivery(state, backend):
    if not state.get("type_seeded"):
        fixture.command(["docker", "stop", state["ting"]], timeout=20)
        try:
            with contextlib.closing(sqlite3.connect(Path(state["directory"]) / "ting-data/ting.sqlite")) as db:
                with db:
                    db.execute("INSERT OR IGNORE INTO types(ctx,org,app,name,description) VALUES(?,?,?,?,?)", (
                        state["environment_id"], state["test_organization"]["id"], "tos>hook",
                        "tos>hook.webhook.received", "Isolated Hook testing fixture"))
        finally:
            fixture.command(["docker", "start", state["ting"]])
        fixture.wait_health(state["ting_url"])
        state["type_seeded"] = True; fixture.save(state)
    if not state.get("publisher_identity"):
        state["publisher_identity"] = testing.iam(state, "POST", "/organizations/tos/silicons", {
            "silicon_id": "hook-test-publisher", "job_description": "Publish isolated Hook events"},
            actor=state["test_admin"]["access_token"])
        fixture.save(state)
    if not state.get("publisher_direct"):
        state["publisher_direct"] = testing.iam(state, "POST", "/silicon-auth/token", {
            "silicon_id": "hook-test-publisher:tos", "silicon_token": state["publisher_identity"]["silicon_token"]})
        fixture.save(state)
    testing.test_profile(state, "test-publisher", "hook-test-publisher:tos", "silicon", state["publisher_direct"])
    if not state.get("publisher_configured"):
        slt = testing.cli(state, "test-publisher", ["login", "--app-id", "tos>hook", "--grant-org", "tos", "--approve-scopes"])["slt"]
        call(state, backend, "test-admin", "POST", "/delivery/publisher", {"slt": slt})
        state["publisher_configured"] = True; fixture.save(state)
    if not state.get("recipient_operator"):
        slt = testing.cli(state, "test-recipient", ["login", "--app-id", "tos>ting", "--grant-org", "tos", "--approve-scopes"])["slt"]
        state["recipient_operator"] = testing.http(state, state["ting_url"], "POST", "/v1/session", {"slt": slt},
            headers={"IAM_TEST_APP_SECRET": state["imports"]["tos>ting"]["app_secret"],
                "X-Testing-Environment-Key": state["testing_key"], "Idempotency-Key": str(uuid.uuid4())}, expected=(200, 201))[1]
        fixture.save(state)
    operator = state["recipient_operator"]["session_token"]
    subscription = call(state, backend, "test-recipient", "POST", "/delivery/recipient")[1]
    policy_path = "/v1/orgs/tos/subscriptions/" + subscription["id"] + "/required-delivery"
    prior = testing.http(state, state["ting_url"], "GET", policy_path, token=operator)[1]
    if "required_policy_before" not in state:
        state["required_policy_before"] = prior; state["required_policy_path"] = policy_path; fixture.save(state)
    testing.http(state, state["ting_url"], "PUT", policy_path, {"enabled": True}, token=operator)


def verify(directory):
    state, backend = fixture.load(directory), hook.load(directory)
    if not state.get("hook_imported"):
        state["hook_import_receipt"] = control(state, backend, "import")
        state["hook_imported"] = True; fixture.save(state)
    checks = []
    for label in ("test-admin", "test-recipient"):
        call(state, backend, label, "POST", "/delivery/recipient")
        receiver, body, key = capability(state, backend, label)
        scope = {field: receiver[field] for field in ("app_id", "for", "kind", "org_id", "hook_org_id", "environment")}
        replay = call(state, backend, label, "POST", "/delivery/receiver", body, key)[1]
        if replay != receiver:
            raise RuntimeError("Hook exact bootstrap replay changed capability")
        bad_status, _ = call(state, backend, label, "POST", "/delivery/receiver",
            {**body, "generation": body["generation"] + 1}, expected=(409,))
        renewed, _, _ = capability(state, backend, label, receiver["receiver_id"])
        if renewed["receiver_id"] != receiver["receiver_id"] or renewed["receiver_token"] == receiver["receiver_token"]:
            raise RuntimeError("Hook receiver renewal did not replace the capability")
        old_status, _ = testing.http(state, state["ting_url"], "GET", "/v1/receivers/me",
            token=receiver["receiver_token"], expected=(401,))
        testing.http(state, state["ting_url"], "GET", "/v1/receivers/me", token=renewed["receiver_token"])
        testing.http(state, state["ting_url"], "DELETE", "/v1/receivers/session", token=renewed["receiver_token"])
        checks.append({"scope": scope, "bootstrap_replay_identical": True,
            "wrong_generation_status": bad_status, "renewed_old_token_status": old_status,
            "renewed_token_valid_then_revoked": True})
    report = {"complete": True, "stage": "Hook adapter capability control", "environment_id": state["environment_id"],
        "shared_generation": state["generation"], "hook_binary_sha256": hashlib.sha256((hook.ROOT / "target/debug/hook-api").read_bytes()).hexdigest(),
        "checks": checks, "limitations": ["Actual event/watch/clean checks follow in a separate stage",
            "Local authenticated participant protocol; full Honeycomb coordinator and production approvals not exercised"]}
    fixture.private(Path(directory) / "testing-hook-control-verification.json", report)
    print("HOOK_TEST_RECEIVER_CONTROL_PASS Carbon and Silicon scope/bootstrap/replay/renewal/revocation", flush=True)


def watch(state, receiver):
    socket = websocket.create_connection(state["ting_url"].replace("http://", "ws://") + "/v1/receivers/ws?protocol=v1",
        timeout=5, suppress_origin=True)
    ready = json.loads(socket.recv())
    if ready.get("op") != "ready":
        raise RuntimeError("scoped socket did not become ready")
    request_id = str(uuid.uuid4())
    socket.send(json.dumps({"op": "watch", "request_id": request_id, "receiver_token": receiver["receiver_token"]}))
    watching = json.loads(socket.recv())
    if watching.get("op") != "watching_inbox" or watching.get("request_id") != request_id:
        fixture.private(Path(state["directory"]) / "watch-error.private.json", watching)
        raise RuntimeError("scoped socket did not authorize the receiver")
    return socket


def events(directory, clean=False):
    state, backend = fixture.load(directory), hook.load(directory)
    prepare_delivery(state, backend)
    actor = "hook-testing:tos"
    call(state, backend, "test-admin", "POST", f"/silicons/{actor}/delivery/subscription")
    provider = call(state, backend, "test-recipient", "POST", f"/silicons/{actor}/hooks",
        {"name": "real scoped receiving"}, expected=(201,))[1]
    receivers, sockets, hints, items = {}, {}, {}, {}
    try:
        for label in ("test-admin", "test-recipient"):
            receivers[label] = capability(state, backend, label)[0]
            sockets[label] = watch(state, receivers[label])
        raw = json.dumps({"message": "real scoped Hook delivery", "run": str(uuid.uuid4()), "payload": "x" * 300000}, separators=(",", ":")).encode()
        identifier, timestamp = str(uuid.uuid4()), str(int(time.time()))
        signature = base64.b64encode(hmac.new(provider["signing_secret"].encode(),
            identifier.encode() + b"." + timestamp.encode() + b"." + raw, hashlib.sha256).digest()).decode()
        accepted = testing.http(state, backend["url"], "POST", urllib.parse.urlsplit(provider["endpoint_url"]).path, raw,
            headers={"webhook-id": identifier, "webhook-timestamp": timestamp, "webhook-signature": "v1," + signature})[1]
        event_id = accepted["receipt_id"]
        print("HOOK_TEST_EVENT_ACCEPTED " + event_id, flush=True)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline and len(items) != 2:
            for label in ("test-recipient", "test-admin"):
                expires = testing.datetime.datetime.fromisoformat(receivers[label]["expires_at"].replace("Z", "+00:00")).timestamp()
                if expires - time.time() < 10:
                    sockets[label].close()
                    receivers[label] = capability(state, backend, label, receivers[label]["receiver_id"])[0]
                    sockets[label] = watch(state, receivers[label])
                try:
                    frame = json.loads(sockets[label].recv())
                except websocket.WebSocketTimeoutException:
                    continue
                if frame.get("op") == "ping":
                    sockets[label].send(json.dumps({"op": "pong"})); continue
                if frame.get("op") == "inbox_changed":
                    hints[label] = True
                elif frame.get("op") == "error":
                    fixture.private(Path(directory) / "watch-error.private.json", frame)
                    raise RuntimeError("scoped receiver stream returned an error")
                inbox = testing.http(state, state["ting_url"], "GET", "/v1/receivers/inbox",
                    token=receivers[label]["receiver_token"])[1]
                for item in inbox["items"]:
                    if item.get("data", {}).get("data", {}).get("metadata", {}).get("id") == event_id:
                        items[label] = item
            if len(items) != 2:
                print("HOOK_TEST_EVENT_WAITING scoped hints/records " + str(len(items)) + "/2", flush=True)
        if len(items) != 2 or len(hints) != 2:
            raise RuntimeError("both Carbon and Silicon did not receive scoped event hints and records")
        for label, item in items.items():
            ref = item["data"]["data"]["metadata"]
            query = urllib.parse.urlencode({"environment_id": ref["environment_id"], "environment_generation": ref["environment_generation"]})
            event = call(state, backend, label, "GET", f"/silicons/{actor}/events/{event_id}?{query}")[1]
            if event["request"]["body"].encode() != raw or item["read"]:
                raise RuntimeError("scoped hydration changed bytes or acknowledged application work")
            testing.http(state, state["ting_url"], "GET", "/v1/receivers/inbox/" + item["id"], token=receivers[label]["receiver_token"])
        primary = items["test-recipient"]
        if primary.get("delivery") != "required" or items["test-admin"].get("delivery") == "required":
            raise RuntimeError("primary and observer delivery policy mismatch")
        publication = call(state, backend, "test-recipient", "GET", f"/silicons/{actor}/events/{event_id}/publication")[1]
        if publication["state"] != "accepted_by_ting" or publication["recipient_receipt"]["read"]:
            raise RuntimeError("scoped observation performed a primary read ACK")
        # Explicit renewal and reconnect retain the already-published unread record.
        sockets["test-recipient"].close()
        old_token = receivers["test-recipient"]["receiver_token"]
        receivers["test-recipient"] = capability(state, backend, "test-recipient", receivers["test-recipient"]["receiver_id"])[0]
        sockets["test-recipient"] = watch(state, receivers["test-recipient"])
        testing.http(state, state["ting_url"], "GET", "/v1/receivers/me", token=old_token, expected=(401,))
        recovered = testing.http(state, state["ting_url"], "GET", "/v1/receivers/inbox/" + primary["id"],
            token=receivers["test-recipient"]["receiver_token"])[1]
        if recovered["id"] != primary["id"] or recovered["read"]:
            raise RuntimeError("renewed receiver did not recover unread record")
        report = {"complete": True, "environment_id": state["environment_id"], "shared_generation": state["generation"],
            "hook_event_generation": primary["data"]["data"]["metadata"]["environment_generation"],
            "event_id": event_id, "ting_ids": {label: item["id"] for label, item in items.items()},
            "payload_bytes": len(raw), "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "hook_binary_sha256": hashlib.sha256((hook.ROOT / "target/debug/hook-api").read_bytes()).hexdigest(),
            "checks": ["Actual signed provider request published through real Hook outbox and IAM/Ting",
                "Separate explicit recipient-own Ting session opted in to required primary delivery",
                "Carbon and Silicon received scoped watch hints and queried their own app inbox",
                "Current Hook authorization hydrated exact 300KB provider bytes for both actors",
                "Primary required policy and ordinary Carbon copy remained distinct",
                "Scoped reads/watch did not ACK application acceptance",
                "Explicit receiver renewal/reconnect invalidated old capability and recovered same unread record"],
            "limitations": ["Ting event type is synthetic fixture data seeded while only the owned Ting server was stopped",
                "Authenticated participant APIs are driven locally; full Honeycomb coordinator and production scopes are not verified",
                "No application read ACK is expected from a scoped receiver"]}
        fixture.private(Path(directory) / "testing-hook-events-verification.json", report)
        print("HOOK_TEST_SCOPED_EVENT_PASS both actors, exact hydration, no ACK, renewal catch-up", flush=True)
        if clean:
            clean_receivers(state, backend, receivers)
    finally:
        for socket in sockets.values():
            socket.close()
        for receiver in receivers.values():
            testing.http(state, state["ting_url"], "DELETE", "/v1/receivers/session", token=receiver["receiver_token"],
                expected=(200, 401) if state.get("cleaned") else (200,))
        if not state.get("cleaned"):
            testing.http(state, state["ting_url"], "PUT", state["required_policy_path"],
                {"enabled": state["required_policy_before"]["enabled"]}, token=state["recipient_operator"]["session_token"])


def clean_receivers(state, backend, receivers):
    generation = state["generation"]
    deadlines = {label: testing.datetime.datetime.fromisoformat(receiver["expires_at"].replace("Z", "+00:00")).timestamp()
        for label, receiver in receivers.items()}
    if min(deadlines.values()) - time.time() < 15:
        raise RuntimeError("clean verification needs fresh capabilities")
    began = time.time()
    new_generation = generation + 1
    # All identities here belong to this owned environment. IAM is fenced first,
    # preventing new proofs while participants erase their own generation.
    # IAM's instruction pins the current generation and advances it itself;
    # participant receipts use the resulting generation returned by IAM.
    iam_receipt = testing.lifecycle(state, "clean")
    if iam_receipt["environment"]["generation"] != new_generation:
        raise RuntimeError("IAM clean did not advance the shared generation exactly once")
    hook_receipt = control(state, backend, "clean", generation=new_generation)
    ting_receipt = testing.ting_lifecycle(state, "clean", generation=new_generation)
    state["generation"] = new_generation
    state["cleaned"] = True; fixture.save(state)
    results = {}
    for label, receiver in receivers.items():
        status, error = testing.http(state, state["ting_url"], "GET", "/v1/receivers/me",
            token=receiver["receiver_token"], expected=(401, 403))
        hook_status, hook_error = call(state, backend, label, "GET", "/delivery/receiver", expected=(401, 403, 404, 409))
        if time.time() >= deadlines[label]:
            raise RuntimeError("capability expired before clean assertion; lifecycle proof is inconclusive")
        results[label] = {"ting_status": status, "ting_code": error.get("error", {}).get("code"),
            "hook_status": hook_status, "hook_code": hook_error.get("error", {}).get("code"),
            "seconds_before_original_expiry": round(deadlines[label] - time.time(), 3)}
    report = {"complete": True, "environment_id": state["environment_id"],
        "old_shared_generation": generation, "new_shared_generation": new_generation,
        "clean_duration_seconds": round(time.time() - began, 3), "receiver_results": results,
        "iam_completion": iam_receipt["iam_completion"], "hook_state": hook_receipt["state"],
        "ting_receipt": ting_receipt,
        "checks": ["Fresh Carbon and Silicon capabilities were live immediately before cleanup",
            "Actual IAM environment clean erased selected identities/apps/sessions/proofs",
            "Authenticated Hook and Ting participant clean used the same next shared generation",
            "Both capabilities failed before their original thirty-second expiry",
            "Old Hook selector and actor credentials failed without normal-plane fallback"],
        "limitations": ["Participant orchestration is the local harness; full Honeycomb coordinator not running",
            "Rotation and restore are not claimed by this clean test"]}
    fixture.private(Path(state["directory"]) / "testing-hook-clean-verification.json", report)
    print("HOOK_TEST_CLEAN_PASS both fresh capabilities fenced before expiry", flush=True)


def clean_fixture(directory):
    state, backend = fixture.load(directory), hook.load(directory)
    if state.get("cleaned"):
        raise RuntimeError("this environment generation is already cleaned")
    if state.get("recipient_operator"):
        token = state["recipient_operator"]["session_token"]
        live, _ = testing.http(state, state["ting_url"], "GET", "/v1/me", token=token, expected=(200, 401))
        if live == 200:
            testing.http(state, state["ting_url"], "PUT", state["required_policy_path"],
                {"enabled": state["required_policy_before"]["enabled"]}, token=token)
        testing.http(state, state["ting_url"], "DELETE", "/v1/session", token=token)
    receivers = {label: capability(state, backend, label)[0] for label in ("test-admin", "test-recipient")}
    for receiver in receivers.values():
        testing.http(state, state["ting_url"], "GET", "/v1/receivers/me", token=receiver["receiver_token"])
    clean_receivers(state, backend, receivers)
    for receiver in receivers.values():
        testing.http(state, state["ting_url"], "DELETE", "/v1/receivers/session", token=receiver["receiver_token"], expected=(200, 401))


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--events", action="store_true")
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args()
    if args.events:
        events(args.directory.resolve(), args.clean)
    elif args.clean:
        clean_fixture(args.directory.resolve())
    else:
        verify(args.directory.resolve())
