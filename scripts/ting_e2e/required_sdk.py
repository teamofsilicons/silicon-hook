#!/usr/bin/env python3
"""Run the real native/SDK restart gate with explicit fixture required consent."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import urllib.parse
import uuid

import fixture
import hook
import sdk


def verify(directory, binary):
    folder = Path(directory)
    upstream, backend = fixture.load(folder), hook.load(folder)
    if upstream.get("ting_commit") != "3253ea193c9fc244e6ef7e5fd818240ae0ad4782":
        raise RuntimeError("this regression requires the pinned Ting 0.1.4 fixture")
    actor, org = upstream["actor_id"], upstream["org_id"]
    app, event_type = "tos>hook", "tos>hook.webhook.received"
    key = upstream.setdefault("required_sdk_refresh_key", str(uuid.uuid4()))
    fixture.save(upstream)
    refreshed = fixture.request(backend["url"], "POST", "/api/v2/auth/refresh",
        {"refresh_token": upstream["hook_recipient"]["refresh_token"]},
        headers={"X-Org-Id": org, "Silicon-Hook-API-Version": "v2", "Idempotency-Key": key})
    if (refreshed.get("actor") != {"type": "silicon", "id": actor}
            or not refreshed.get("access_token") or not refreshed.get("refresh_token")):
        raise RuntimeError("refreshed fixture session differs from its recipient")
    upstream["hook_recipient"] = refreshed
    upstream.pop("required_sdk_refresh_key")
    fixture.save(upstream)

    def call(method, path):
        return fixture.request(backend["url"], method, "/api/v2" + path,
            token=upstream["hook_recipient"]["access_token"],
            headers={"X-Org-Id": org, "Silicon-Hook-API-Version": "v2"})

    def ting(method, path, body=None):
        return fixture.request(upstream["ting_url"], method, path, body, upstream["ting_session"])

    subscription = call("POST", "/delivery/recipient")
    if subscription.get("for") != actor or subscription.get("app_id") != app:
        raise RuntimeError("fixture recipient subscription differs")
    prefix = "/v1/orgs/" + urllib.parse.quote(org, safe="")
    policy_path = prefix + "/subscriptions/" + urllib.parse.quote(subscription["id"], safe="") + "/required-delivery"
    original_policy = ting("GET", policy_path)
    query = urllib.parse.urlencode({"app_id": app, "type": event_type})
    preferences = ting("GET", prefix + "/preferences?" + query)
    exact = [p for p in preferences.get("items", [])
             if p.get("app_id") == app and p.get("type") == event_type and not p.get("service")]
    if preferences.get("next_cursor") or len(exact) > 1 or not isinstance(original_policy.get("enabled"), bool):
        raise RuntimeError("invalid original fixture preference")
    original_preference = exact[0] if exact else None
    evidence = folder / "sdk-verification.json"
    previous = evidence.read_bytes() if evidence.exists() else None
    report = None
    try:
        ting("PUT", policy_path, {"enabled": True})
        ting("PUT", prefix + "/preferences",
             {"app_id": app, "service": None, "type": event_type, "enabled": False})
        print("REQUIRED_SDK_STAGE explicit fixture consent and mute saved; running native/SDK restart gate", flush=True)
        with contextlib.redirect_stdout(io.StringIO()):
            sdk.verify(folder, binary)
        nested = json.loads(evidence.read_text())
        publication = call("GET", f"/silicons/{actor}/events/{nested['event_id']}/publication")
        receipt = publication.get("recipient_receipt") or {}
        if (publication.get("delivery") != "required" or publication.get("silent") is not True
                or publication.get("state") != "accepted_by_ting" or receipt.get("delivery") != "required"
                or receipt.get("silent") is not True or not receipt.get("read")):
            raise RuntimeError("required SDK acceptance or notification policy differs")
        report = {"complete": True, "ting_version": "0.1.4", "source_commit": upstream["ting_commit"],
                  "delivery": publication["delivery"], "silent": publication["silent"], "sdk": nested,
                  "checks": ["recipient-own session explicitly opts into required delivery",
                             "muted required send reaches real native daemon and updated Rust SDK",
                             "durable acceptance and duplicate replay survive both process restarts",
                             "final publication and read receipt preserve required policy and silent visibility"],
                  "limitations": ["owned normal-plane fixture; not production approval evidence",
                                  "SDK host is the controlled example, not an external business application"]}
    finally:
        try:
            if original_preference:
                ting("PUT", prefix + "/preferences", {"app_id": app, "service": None,
                    "type": event_type, "enabled": original_preference["enabled"]})
            else:
                ting("DELETE", prefix + "/preferences?" + query)
        finally:
            try:
                ting("PUT", policy_path, {"enabled": original_policy["enabled"]})
            finally:
                if previous is None:
                    evidence.unlink(missing_ok=True)
                else:
                    fixture.private(evidence, previous.decode())
    report["recipient_preferences_restored"] = True
    fixture.private(folder / "required-sdk-verification.json", report)
    print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--receiver-binary", type=Path, default=hook.ROOT / "target/debug/examples/ting_receiver_e2e")
    args = parser.parse_args()
    verify(args.directory.resolve(), args.receiver_binary.resolve())
