"""Scenario 6: Hook issues Silicon Accounts proofs to Ting (a stand-in that verifies them for real)."""

import json
import os
import secrets
import signal
import subprocess
import time
from pathlib import Path

from scenario_cli import wait_events
from support import SCRIPTS, Stop


def journal(h):
    try:
        return [json.loads(line) for line in h.dev.ting_journal.read_text().splitlines() if line.strip()]
    except OSError:
        return []


def wait_journal(h, predicate, seconds=30):
    deadline = time.time() + seconds
    while time.time() < deadline:
        found = [entry for entry in journal(h) if predicate(entry)]
        if found:
            return found
        time.sleep(0.5)
    return []


def proof_view(entry):
    keys = ("call", "outcome", "valid", "kind", "issuing_app", "receiving_app", "user", "scopes", "for", "delivery",
            "proof_id", "proof_sha256")
    return {k: entry.get(k) for k in keys if entry.get(k) is not None}


def start_host(h):
    """The client crate's receiving host (crates/client/examples/ting_receiver_e2e.rs) for S1, on base+4."""
    build = subprocess.run(["cargo", "build", "--locked", "-p", "silicon-hook-client", "--example",
                            "ting_receiver_e2e"], cwd=SCRIPTS.parent, capture_output=True, text=True)
    if build.returncode != 0:
        raise Stop(f"building the receiving host failed: {build.stderr[-400:]}")
    binary = Path(os.environ.get("CARGO_TARGET_DIR", SCRIPTS.parent / "target")) / "debug/examples/ting_receiver_e2e"
    evidence = h.work / "receiving-host"
    secret, webhook_id, port = secrets.token_urlsafe(24), "wh_hook_e2e", h.dev.base + 4
    config = h.work / "receiving-host.json"
    descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump({"hook_url": h.api, "hook_token": h.s1.token, "app_id": h.app_id, "recipient_uuid": h.s1.uuid,
                   "recipient_id": h.s1.id, "webhook_id": webhook_id, "callback_secret": secret,
                   "listen_addr": f"127.0.0.1:{port}", "output": str(evidence)}, output)
    log = open(h.dev.logs / "receiving-host.log", "a")
    process = subprocess.Popen([str(binary), str(config)], stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True)
    (h.dev.pids / "receiving-host").write_text(f"{process.pid}\n")
    deadline = time.time() + 15
    while time.time() < deadline and not (evidence / "ready.json").exists():
        if process.poll() is not None:
            raise Stop("the receiving host exited; see its log")
        time.sleep(0.2)
    forward = {"TING_STUB_FORWARD_URL": f"http://127.0.0.1:{port}/ting", "TING_STUB_FORWARD_SECRET": secret,
               "TING_STUB_FORWARD_WEBHOOK_ID": webhook_id, "TING_STUB_FORWARD_FOR": h.s1.uuid}
    return process, evidence, forward


def stop_host(h, process):
    if process is not None and process.poll() is None:
        os.kill(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    (h.dev.pids / "receiving-host").unlink(missing_ok=True)


def scenario_6(h):
    receiver = h.dev.ting_receiver
    h.begin(6, f"Hook as a proof issuer: Ting stand-in on base+2 verifies every proof as the receiving app '{receiver}'")
    h.dev.ting_journal.unlink(missing_ok=True)
    host, evidence, forward = start_host(h)
    try:
        delivery(h, receiver, evidence, forward)
        observers(h)
    finally:
        stop_host(h, host)


def delivery(h, receiver, evidence, forward):
    result = h.dev_command("restart", "--ting-stub", "--refuse-first-proof", env=forward)
    h.check("restart with the Ting stand-in (HOOK_TING_URL=base+2, HOOK_TING_APP_ID=the stand-in's app)",
            result.get("ready") and result.get("ting_stub"), {k: result.get(k) for k in ("ready", "ting_stub")},
            critical=True)
    status, body = h.call("GET", "delivery", h.c1)
    h.check("GET /delivery says delivery through Ting is on", status == 200 and body.get("enabled") is True, body)

    code, out, err = h.hook(h.s1.home, "receiving", "register")
    entries = wait_journal(h, lambda e: e["call"] == "subscribe" and e.get("for") == h.s1.uuid, 5)
    entry = entries[-1] if entries else {}
    h.check("hook receiving register: a User verification proof from the Silicon's own token, verified by the receiver",
            code == 0 and (out or {}).get("ting_subscription_id") and entry.get("valid")
            and entry.get("kind") == "user_verification" and entry.get("user") == h.s1.uuid
            and entry.get("issuing_app") == h.app_id and entry.get("receiving_app") == receiver
            and entry.get("scopes") == ["tings.subscribe"], {"cli": out or err, "verified": proof_view(entry)})

    code, out, err = h.hook(h.c1.home, "--silicon", h.s1.id, "receiving", "subscribe")
    entries = wait_journal(h, lambda e: e["call"] == "subscribe" and e.get("for") == h.c1.uuid, 5)
    entry = entries[-1] if entries else {}
    h.check("the custodian subscribes to copies: a User verification proof for the Carbon",
            code == 0 and entry.get("valid") and entry.get("user") == h.c1.uuid, {"cli": out or err, "verified": proof_view(entry)})

    status, _ = h.provider_post(h.local_demo["endpoint_url"], {"deliver": "through ting"})
    items = wait_events(h, h.s1.home, h.local_demo["id"], 1, seconds=10)
    event_id = next((e["id"] for e in items if e["request"]["body"] == '{"deliver": "through ting"}'), None)
    h.check("a provider request is stored and queued for Ting", status == 200 and event_id, {"event": event_id})
    accepted = wait_journal(h, lambda e: e["call"] == "send" and e.get("outcome") == "accepted"
                            and str(e.get("key", "")).startswith(f"hook:{event_id}:") and e.get("for") == h.s1.uuid)
    sends = [e for e in journal(h) if e["call"] == "send"]
    refused = [e for e in sends if e.get("on_purpose")]
    first = refused[0] if refused else {}
    h.check("the first send carried a valid App verification proof (tings.send) issued by hook for the receiver",
            first.get("valid") and first.get("kind") == "app_verification" and first.get("issuing_app") == h.app_id
            and first.get("receiving_app") == receiver and first.get("scopes") == ["tings.send"], proof_view(first))
    after = [e for e in sends if e.get("outcome") == "accepted"]
    renewed = after[0] if after else {}
    h.check("after the stand-in refused it once, Hook refreshed the proof (same proof, new token) and Ting accepted",
            renewed.get("valid") and renewed.get("proof_id") == first.get("proof_id")
            and renewed.get("proof_sha256") != first.get("proof_sha256"),
            {"refused": proof_view(first), "accepted": proof_view(renewed)})
    primary = accepted[0] if accepted else {}
    h.check("the Silicon's send names it by uuid and asks for required delivery",
            primary.get("for") == h.s1.uuid and primary.get("delivery") == "required", proof_view(primary))
    copies = wait_journal(h, lambda e: e["call"] == "send" and e.get("outcome") == "accepted"
                          and str(e.get("key", "")).startswith(f"hook:{event_id}:") and e.get("for") == h.c1.uuid)
    h.check("the custodian's copy goes out as an ordinary send", copies and copies[0].get("delivery") == "ordinary",
            proof_view(copies[0]) if copies else None)

    code, publication, err = h.hook(h.s1.home, "publication", event_id)
    receipts = wait_journal(h, lambda e: e["call"] == "receipt" and e.get("outcome") == "receipt", 5)
    receipt = receipts[-1] if receipts else {}
    h.check("hook publication: accepted by Ting, with the receipt read through an App verification proof (sent.query)",
            code == 0 and publication.get("state") == "accepted_by_ting" and publication.get("recipient_receipt")
            and receipt.get("valid") and receipt.get("scopes") == ["sent.query"],
            {"state": (publication or {}).get("state"), "receipt_proof": proof_view(receipt)})
    tokens_in_journal = any(key in line for line in h.dev.ting_journal.read_text().splitlines()
                            for key in ("sap_", "sapr_", "Bearer"))
    h.check("the stand-in's journal holds digests, never a proof token", not tokens_in_journal)

    # Ting delivers the reference on; the Silicon's receiving host hydrates the event from Hook with its own token.
    forwarded = wait_journal(h, lambda e: e["call"] == "forward" and str(e.get("key", "")).startswith(f"hook:{event_id}:"))
    accepted_file = evidence / "accepted" / f"{event_id}.json"
    deadline = time.time() + 10
    while time.time() < deadline and not accepted_file.exists():
        time.sleep(0.3)
    hydrated = json.loads(accepted_file.read_text()) if accepted_file.exists() else {}
    event = hydrated.get("event", {})
    h.check("the Silicon's receiving host (client crate SDK) gets the reference, hydrates it from Hook with the "
            "Silicon's own token and answers 204",
            forwarded and forwarded[0].get("status") == 204 and event.get("request", {}).get("body") ==
            '{"deliver": "through ting"}' and event.get("silicon", {}).get("uuid") == h.s1.uuid,
            {"callback_status": forwarded[0].get("status") if forwarded else None,
             "hydrated": {"id": event.get("id"), "provider": event.get("provider"), "silicon": event.get("silicon"),
                          "body": event.get("request", {}).get("body")}})


def sends_for(h, event_id, primary_uuid, settle=3):
    """Waits for the Silicon's own send of an event, lets the copies go out, returns {recipient: delivery}."""
    wait_journal(h, lambda e: e["call"] == "send" and e.get("outcome") == "accepted" and e.get("for") == primary_uuid
                 and str(e.get("key", "")).startswith(f"hook:{event_id}:"))
    time.sleep(settle)
    return {e["for"]: e.get("delivery") for e in journal(h) if e["call"] == "send" and e.get("outcome") == "accepted"
            and str(e.get("key", "")).startswith(f"hook:{event_id}:")}


def post_event(h, marker):
    status, _ = h.provider_post(h.local_demo["endpoint_url"], {"marker": marker})
    body = json.dumps({"marker": marker})
    deadline = time.time() + 10
    while time.time() < deadline:
        _, events = h.call("GET", f"silicons/{h.s1.uuid}/hooks/{h.local_demo['id']}/events?limit=20", h.s1)
        found = [e["id"] for e in (events or {}).get("items", []) if e["request"]["body"] == body]
        if found:
            return found[0]
        time.sleep(0.5)
    raise Stop(f"the event {marker} was not stored (ingress {status})")


def observers(h):
    """Copies follow access: a grantee's stop when its grant goes, a former custodian's when the Silicon moves."""
    s1, c1, c2 = h.s1, h.c1, h.c2
    code, _, err = h.hook(c1.home, "--silicon", s1.id, "access", "grant", c2.id, "--level", "view")
    status, body = h.call("POST", f"silicons/{s1.id}/delivery/subscription", c2)
    h.check("a Carbon granted `view` subscribes to copies (User verification proof for it)",
            code == 0 and status in (200, 201), body if status not in (200, 201) else {"status": status})
    sent = sends_for(h, post_event(h, "grantee-subscribed"), s1.uuid)
    h.check("an event goes to the Silicon (required), its custodian and the grantee (ordinary copies)",
            sent == {s1.uuid: "required", c1.uuid: "ordinary", c2.uuid: "ordinary"}, sent)
    code, _, err = h.hook(c1.home, "--silicon", s1.id, "access", "revoke", c2.id)
    status, body = h.call("GET", f"silicons/{s1.id}/delivery/subscription", c2)
    sent = sends_for(h, post_event(h, "grant-revoked"), s1.uuid)
    h.check("revoking the grant ends the grantee's copies at once", code == 0 and status == 403 and c2.uuid not in sent
            and c1.uuid in sent, {"subscription_status": status, "sent_to": sent})
    before = h.delivery_ids()
    status, offer = h.accounts("POST", f"/v1/me/silicons/{s1.uuid}/transfer", c1, body={"to": c2.id})
    request_id = (offer or {}).get("request", {}).get("id")
    accepted, _ = h.accounts("POST", f"/v1/me/custodian-requests/{request_id}/accept", c2)
    h.wait_delivery("silicon.custodian_changed", s1.uuid, before)
    sent = sends_for(h, post_event(h, "custodian-changed"), s1.uuid)
    h.check("after S1 moves to C2, the former custodian gets no more copies (C2 has not subscribed)",
            status == 201 and accepted == 204 and sent == {s1.uuid: "required"}, {"sent_to": sent})
    status, body = h.call("POST", f"silicons/{s1.id}/delivery/subscription", c2)
    sent = sends_for(h, post_event(h, "new-custodian-subscribed"), s1.uuid)
    h.check("the new custodian subscribes and receives copies", status in (200, 201) and sent.get(c2.uuid) == "ordinary"
            and c1.uuid not in sent, {"status": status, "sent_to": sent})
