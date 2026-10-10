"""Scenario 6: Hook issues Silicon Accounts proofs to Ting (a stand-in that verifies them for real)."""

import json
import time

from scenario_cli import wait_events


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


def scenario_6(h):
    receiver = h.dev.ting_receiver
    h.begin(6, f"Hook as a proof issuer: Ting stand-in on base+2 verifies every proof as the receiving app '{receiver}'")
    h.dev.ting_journal.unlink(missing_ok=True)
    result = h.dev_command("restart", "--ting-stub", "--refuse-first-proof")
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
