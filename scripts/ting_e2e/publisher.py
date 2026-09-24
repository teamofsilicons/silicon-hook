#!/usr/bin/env python3
"""Verify publisher CLI bootstrap without replacing the primary fixture publisher.

Uses a separate owned Hook database/process and new synthetic IAM Silicons.
Only IAM/Ting service origins and application definitions are shared with the
parent fixture. Each recipient's compact references belong to one Hook backend.
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.parse
import uuid

import fixture
import hook


def verify(directory, binary):
    upstream = fixture.load(directory)
    folder = Path(tempfile.mkdtemp(prefix="publisher-cli-", dir=directory)).resolve()
    state = {key: upstream[key] for key in ("iam_url", "ting_url", "iam_cli", "org_id", "app_secrets")}
    state.update({"directory": str(folder), "fixture_owned": True,
                  "network": "hook-ting-e2e-publisher-" + uuid.uuid4().hex[:10], "containers": []})
    fixture.save(state)
    profiles, ting_session, report = [], None, None
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("SILICON_", "IAM_TEST_")) and key != "ISI"}
    env.update({"SILICON_HOOK_HOME": str(folder / "hook-home"), "SILICON_HOME": str(folder / "silicon-home"),
                "SILICON_HOOK_TELEMETRY": "off"})

    def call(profile, args, stdin=None, refused=None):
        base = [str(binary), "--url", backend["url"], "--org", state["org_id"],
                "--profile", profile, "--production", "--json"]
        result = subprocess.run([*base, *args], env=env, cwd=folder, input=stdin, capture_output=True, timeout=45)
        if refused:
            combined = (result.stdout + result.stderr).decode(errors="replace")
            if result.returncode == 0 or refused not in combined:
                fixture.private(folder / "cli-error.log", combined)
                raise RuntimeError("publisher CLI did not refuse the expected conflict; inspect private diagnostic")
            return None
        if result.returncode:
            fixture.private(folder / "cli-error.log", (result.stdout + result.stderr).decode(errors="replace"))
            raise RuntimeError("publisher fixture CLI failed; inspect private diagnostic")
        return json.loads(result.stdout)

    def create_identity(label):
        actor = "publisher-e2e-" + label + "-" + uuid.uuid4().hex[:8] + ":" + state["org_id"]
        created = fixture.cli(upstream, "admin", ["silicon", "create", actor,
            "--job-description", "Synthetic disposable Hook publisher CLI verification"])
        # Authenticate over the real IAM HTTP API to keep the one-time Silicon
        # credential out of both command arguments and terminal output.
        tokens = fixture.request(state["iam_url"], "POST", "/api/v1/silicon-auth/token",
            {"silicon_id": actor, "silicon_token": created["silicon_token"]},
            headers={"Idempotency-Key": str(uuid.uuid4())})
        expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=tokens["expires_in"])).isoformat()
        store = folder / "profiles" / label / ".silicon-iam"
        fixture.private(store / "config.json", {"telemetry": False, "auto_update": False,
            "current_profile": "default", "profiles": {"default": {"url": state["iam_url"]}}})
        fixture.private(store / "credentials.json", {"sessions": {"default": {
            "access_token": tokens["access_token"], "refresh_token": tokens["refresh_token"],
            "expires_at": expiry, "actor_type": "silicon", "actor_id": actor}}})
        profiles.append(label)
        return actor

    try:
        hook.setup(folder)
        backend = hook.load(folder)
        recipient, publisher = create_identity("recipient"), create_identity("publisher")
        admin_slt = folder / "admin.slt"
        fixture.private(admin_slt, fixture.slt(upstream, "admin") + "\n")
        call("admin", ["login", "--slt-file", str(admin_slt)])
        admin_slt.unlink()
        publisher_slt = folder / "publisher.slt"
        fixture.private(publisher_slt, fixture.slt(state, "publisher") + "\n")
        key = str(uuid.uuid4())
        provision_args = ["--idempotency-key", key, "publisher", "provision", "--slt-file", str(publisher_slt)]
        provisioned = call("admin", provision_args)
        replay = call("admin", ["--idempotency-key", key, "publisher", "provision", "--slt-file", "-"],
                      stdin=publisher_slt.read_bytes())
        if provisioned != replay or set(provisioned) != {"org_id", "actor_id", "expires_at"}:
            raise RuntimeError("publisher CLI replay or secret-free output is incorrect")
        if provisioned["org_id"] != state["org_id"] or provisioned["actor_id"] != publisher:
            raise RuntimeError("publisher CLI provisioned a different identity")
        publisher_slt.unlink()
        replacement = folder / "replacement.slt"
        fixture.private(replacement, fixture.slt(state, "publisher") + "\n")
        call("admin", ["--idempotency-key", str(uuid.uuid4()), "publisher", "provision", "--slt-file",
                       str(replacement), "--replace-rejected"], refused="publisher_already_configured")
        replacement.unlink()
        print("PUBLISHER_STAGE provision, same-key stdin replay, healthy replacement refusal passed", flush=True)

        recipient_slt = folder / "recipient.slt"
        fixture.private(recipient_slt, fixture.slt(state, "recipient") + "\n")
        call("recipient", ["login", "--slt-file", str(recipient_slt)])
        recipient_slt.unlink()
        target = ["--silicon", recipient]
        registration = call("recipient", [*target, "receiving", "register"])
        if registration.get("for") != recipient or not registration.get("active"):
            raise RuntimeError("secondary recipient was not registered")
        ting_session = fixture.request(state["ting_url"], "POST", "/v1/session",
            {"slt": fixture.slt(state, "recipient", "ting")},
            headers={"Idempotency-Key": str(uuid.uuid4())}, expected=(200, 201))["session_token"]
        provider = call("recipient", [*target, "create", "publisher-cli-real-delivery"])
        body = json.dumps({"source": "publisher CLI", "run": str(uuid.uuid4())}, separators=(",", ":")).encode()
        identifier, timestamp = str(uuid.uuid4()), str(int(time.time()))
        signature = base64.b64encode(hmac.new(provider["signing_secret"].encode(),
            identifier.encode() + b"." + timestamp.encode() + b"." + body, hashlib.sha256).digest()).decode()
        accepted = fixture.request(backend["url"], "POST", urllib.parse.urlsplit(provider["endpoint_url"]).path,
            body, headers={"webhook-id": identifier, "webhook-timestamp": timestamp, "webhook-signature": "v1," + signature})
        event_id = accepted["receipt_id"]
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            publication = call("recipient", [*target, "publication", event_id])
            if publication.get("state") == "accepted_by_ting":
                break
            time.sleep(.25)
        else:
            raise RuntimeError("secondary publisher did not publish the signed event")
        event = call("recipient", [*target, "event", event_id])
        if event["request"]["body"].encode() != body:
            raise RuntimeError("secondary publisher flow changed the provider body")
        ting_id = publication["ting_id"]
        notification = fixture.request(state["ting_url"], "GET", f"/v1/orgs/{state['org_id']}/inbox/{ting_id}", token=ting_session)
        reference = notification["data"]["data"]["metadata"]
        if notification["for"] != recipient or reference["id"] != event_id or reference["silicon_id"] != recipient:
            raise RuntimeError("secondary publisher sent the wrong Hook reference")
        report = {"complete": True, "cli_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "event_id": event_id, "ting_id": ting_id, "payload_sha256": hashlib.sha256(body).hexdigest(),
            "checks": ["separate owned Hook process/database and fresh synthetic publisher/recipient identities",
                "real CLI publisher provision works without a Silicon target", "only non-secret publisher metadata is returned",
                "same mutation key and SLT replay returns identical metadata via stdin",
                "replace-rejected refuses to replace a healthy publisher",
                "CLI recipient registration and signed provider ingress", "original publisher remains usable after refused replacement",
                "real Ting inbox contains the exact recipient/event reference", "CLI event hydration preserves exact provider body"],
            "limitations": ["isolated normal IAM data plane; Ting type definition is inherited from the seeded fixture",
                "does not repeat native receiver durability checks; separate SDK and CLI fixtures cover those",
                "IAM Silicon direct sessions and the backend-owned publisher family remain only in the disposable IAM fixture until its cleanup; IAM does not support Silicon logout-all"]}
    finally:
        cleanup_errors = []
        if ting_session:
            try:
                fixture.request(state["ting_url"], "DELETE", "/v1/session", token=ting_session,
                    headers={"Idempotency-Key": str(uuid.uuid4())})
            except Exception:
                cleanup_errors.append("Ting session")
        if hook.state_file(folder).exists():
            for profile in ("recipient", "admin"):
                try:
                    call(profile, ["logout"])
                except Exception:
                    cleanup_errors.append("Hook " + profile + " session")
            hook.cleanup(folder)
        for label in profiles:
            try:
                fixture.cli(state, label, ["logout", "--local-only"])
            except Exception:
                cleanup_errors.append("IAM " + label + " local profile")
        if cleanup_errors:
            fixture.private(folder / "cleanup-error.log", "\n".join(cleanup_errors))
            raise RuntimeError("secondary fixture cleanup was incomplete; inspect its private diagnostic")
    report["checks"].append("owned secondary backend/database removed; Hook management and Ting sessions revoked; local IAM profiles cleared")
    fixture.private(Path(directory) / "publisher-verification.json", report)
    print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--cli-binary", type=Path, default=hook.ROOT / "target/debug/hook")
    args = parser.parse_args()
    verify(args.directory.resolve(), args.cli_binary.resolve())
