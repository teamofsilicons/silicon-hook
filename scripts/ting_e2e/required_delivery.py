#!/usr/bin/env python3
"""Verify required Hook delivery with real recipient consent in the owned fixture.

No production session is used. Restore the synthetic recipient's exact previous
preference and opt-in after checking refusal, unchanged retry and muted native ACK.
"""
import argparse
import base64
import contextlib
import hashlib
import hmac
import io
import json
from pathlib import Path
import time
import urllib.parse
import uuid

import fixture
import hook
import native


def verify(directory):
    folder = Path(directory)
    upstream, backend = fixture.load(folder), hook.load(folder)
    if upstream.get("ting_commit") != "3253ea193c9fc244e6ef7e5fd818240ae0ad4782":
        raise RuntimeError("this regression requires the pinned Ting 0.1.4 fixture")
    actor, org = upstream["actor_id"], upstream["org_id"]
    app, event_type = "tos>hook", "tos>hook.webhook.received"

    # This fixture can survive hours of staged tests. Renew its own management
    # family before the real five-minute retry wait, retaining the refresh key
    # durably so an interrupted exchange can be replayed without another rotation.
    refresh_key = upstream.setdefault("required_delivery_refresh_key", str(uuid.uuid4()))
    fixture.save(upstream)
    refreshed = fixture.request(backend["url"], "POST", "/api/v2/auth/refresh",
        {"refresh_token": upstream["hook_recipient"]["refresh_token"]},
        headers={"X-Org-Id": org, "Silicon-Hook-API-Version": "v2", "Idempotency-Key": refresh_key})
    if (refreshed.get("actor") != {"type": "silicon", "id": actor}
            or not refreshed.get("access_token") or not refreshed.get("refresh_token")):
        raise RuntimeError("refreshed fixture session did not match its original recipient")
    upstream["hook_recipient"] = refreshed
    upstream.pop("required_delivery_refresh_key")
    fixture.save(upstream)

    def call(method, path, body=None, mutate=False, expected=(200,)):
        headers = {"X-Org-Id": org, "Silicon-Hook-API-Version": "v2"}
        if mutate:
            headers["Idempotency-Key"] = str(uuid.uuid4())
        return fixture.request(backend["url"], method, "/api/v2" + path, body,
                               upstream["hook_recipient"]["access_token"], headers, expected)

    def ting(method, path, body=None):
        return fixture.request(upstream["ting_url"], method, path, body,
                               upstream["ting_session"])

    subscription = call("POST", "/delivery/recipient")
    if subscription.get("for") != actor or subscription.get("app_id") != app:
        raise RuntimeError("recipient subscription mismatch")
    prefix = "/v1/orgs/" + urllib.parse.quote(org, safe="")
    policy_path = prefix + "/subscriptions/" + urllib.parse.quote(subscription["id"], safe="") + "/required-delivery"
    original_policy = ting("GET", policy_path)
    query = urllib.parse.urlencode({"app_id": app, "type": event_type})
    preferences = ting("GET", prefix + "/preferences?" + query)
    if preferences.get("next_cursor"):
        raise RuntimeError("unexpected paginated fixture preference result")
    exact = [p for p in preferences.get("items", [])
             if p.get("app_id") == app and p.get("type") == event_type and not p.get("service")]
    if len(exact) > 1 or not isinstance(original_policy.get("enabled"), bool):
        raise RuntimeError("invalid original recipient preference")
    original_preference = exact[0] if exact else None
    native_report = folder / "native-verification.json"
    previous_native_report = native_report.read_bytes() if native_report.exists() else None
    report = None
    try:
        # This is the fixture recipient making a separate explicit decision,
        # never Hook's OBO token or the bootstrap receiver capability.
        ting("PUT", policy_path, {"enabled": False})
        ting("PUT", prefix + "/preferences",
             {"app_id": app, "service": None, "type": event_type, "enabled": False})
        provider = call("POST", f"/silicons/{actor}/hooks",
                        {"name": "required-delivery-consent-e2e"}, True, (201,))
        raw = json.dumps({"message": "real Hook to Ting delivery", "run": str(uuid.uuid4())},
                         separators=(",", ":")).encode()
        identifier, timestamp = str(uuid.uuid4()), str(int(time.time()))
        signed = identifier.encode() + b"." + timestamp.encode() + b"." + raw
        signature = base64.b64encode(hmac.new(provider["signing_secret"].encode(), signed, hashlib.sha256).digest()).decode()
        accepted = fixture.request(backend["url"], "POST", urllib.parse.urlsplit(provider["endpoint_url"]).path, raw,
            headers={"webhook-id": identifier, "webhook-timestamp": timestamp, "webhook-signature": "v1," + signature})
        event_id = str(uuid.UUID(accepted["receipt_id"]))
        status_path = f"/silicons/{actor}/events/{event_id}/publication"

        def snapshot():
            # Only this owned fixture's one non-secret immutable outbox body is
            # read; no credential or database state is changed for the test.
            sql = "SELECT encode(request_body, 'hex') FROM hook_private.ting_outbox WHERE event_id = " + fixture.quote(event_id) + "::uuid AND recipient_id = " + fixture.quote(actor) + ";"
            result = fixture.command(["docker", "exec", "-i", backend["container"], "psql", "-U", "postgres", "-d", "hook", "-X", "-v", "ON_ERROR_STOP=1", "-At"],
                                     stdin=sql.encode(), log=folder / "required-delivery-sql-error.log")
            body = bytes.fromhex(result.decode().strip())
            parsed = json.loads(body)
            if parsed.get("delivery") != "required":
                raise RuntimeError("new primary Hook send did not select required delivery")
            return hashlib.sha256(body).hexdigest(), parsed["key"]

        original_hash, original_key = snapshot()
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            refused = call("GET", status_path)
            if refused.get("last_error_code") == "required_delivery_not_enabled":
                break
            time.sleep(.2)
        else:
            raise RuntimeError("missing opt-in did not remain an actionable pending send")
        if refused["state"] != "pending" or refused.get("ting_id") or refused.get("delivery") != "required":
            raise RuntimeError("missing required consent was accepted or downgraded")
        ting("PUT", policy_path, {"enabled": True})
        enabled_at = time.monotonic()
        print("REQUIRED_STAGE missing opt-in rejected; explicit synthetic recipient opt-in saved; waiting for unchanged worker retry", flush=True)
        deadline, next_progress = time.monotonic() + 340, time.monotonic() + 30
        while time.monotonic() < deadline:
            recovered = call("GET", status_path)
            if recovered.get("accepted_at"):
                break
            if time.monotonic() >= next_progress:
                print("REQUIRED_STAGE waiting for scheduled worker retry", flush=True)
                next_progress = time.monotonic() + 30
            # Status performs real IAM authorization. Poll below Hook's normal
            # request limit while waiting for the five-minute retry schedule.
            time.sleep(10)
        else:
            raise RuntimeError("worker did not retry the consent-blocked event")
        retry_seconds = round(time.monotonic() - enabled_at, 3)
        if (recovered.get("state") != "accepted_by_ting" or recovered.get("delivery") != "required"
                or recovered.get("silent") is not True or snapshot() != (original_hash, original_key)):
            raise RuntimeError("required muted retry changed its body/key or publication semantics")
        # Reuse the real native callback assertion without replacing historical
        # compatibility evidence. It also consumes the earlier owned test event.
        with contextlib.redirect_stdout(io.StringIO()):
            native.verify(folder)
        delivered = json.loads(native_report.read_text())
        final = call("GET", f"/silicons/{actor}/events/{delivered['event_id']}/publication")
        receipt = final.get("recipient_receipt") or {}
        if (final.get("delivery") != "required" or final.get("silent") is not True
                or final.get("state") != "accepted_by_ting" or receipt.get("delivery") != "required"
                or receipt.get("silent") is not True or not receipt.get("read")):
            raise RuntimeError("muted required native delivery was not independently acknowledged")
        report = {"complete": True, "ting_version": "0.1.4", "source_commit": upstream["ting_commit"],
                  "hook_binary_sha256": hashlib.sha256((hook.ROOT / "target/debug/hook-api").read_bytes()).hexdigest(),
                  "refused_then_retried_event_id": event_id, "ting_id": recovered["ting_id"],
                  "immutable_body_sha256": original_hash, "retry_wait_seconds": retry_seconds,
                  "native": delivered,
                  "checks": ["missing explicit required-delivery opt-in leaves new Hook primary send pending",
                             "no ordinary fallback or Ting acceptance without consent",
                             "recipient own Ting session explicitly opts in in disposable fixture",
                             "unmodified scheduled worker retry preserves exact request bytes and key",
                             "muted required acceptance has delivery=required and silent=true with accepted_by_ting",
                             "real native delivery ACK precedes callback HTTP204/read ACK",
                             "original payload is hydrated under current Hook authorization"],
                  "limitations": ["owned normal-plane fixture; not testing-plane or production approval evidence",
                                  "native callback is the controlled fixture host; SDK restart covered separately"]}
    finally:
        try:
            if original_preference is None:
                ting("DELETE", prefix + "/preferences?" + query)
            else:
                ting("PUT", prefix + "/preferences", {"app_id": app, "service": None,
                     "type": event_type, "enabled": original_preference["enabled"]})
        finally:
            try:
                ting("PUT", policy_path, {"enabled": original_policy["enabled"]})
            finally:
                if previous_native_report is None:
                    native_report.unlink(missing_ok=True)
                else:
                    fixture.private(native_report, previous_native_report.decode())
    if report is not None:
        report["recipient_preferences_restored"] = True
        fixture.private(folder / "required-delivery-verification.json", report)
        print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    verify(parser.parse_args().directory.resolve())
