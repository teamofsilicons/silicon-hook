#!/usr/bin/env python3
"""A stand-in for Ting that checks Hook's Silicon Accounts proofs for real.

Hook calls Ting with `Authorization: Proof sap_...`. This stub answers Hook's
three Ting calls (POST /v1/tings, /v1/subscriptions, /v1/sent/query) in the
shapes of Hook's Ting contract, and verifies every proof with Silicon Accounts
(`POST /v1/proofs/verify`) using the receiving app's own credentials, as Ting
will. Each call is written to a JSON-lines journal (proof digests, never
tokens) that tests read.

    ACCOUNTS_API_URL=http://127.0.0.1:9589 TING_STUB_APP_ID=<receiving app> \\
    TING_STUB_APP_SECRET=<its secret> TING_STUB_ISSUER=hook \\
    python3 scripts/ting_stub.py --port 4202 --journal .mig/ting-stub.jsonl [--refuse-first-proof]

--refuse-first-proof answers the first send with 401 invalid_proof (after
verifying the proof), once, the way Ting refuses a proof it cannot accept, so
Hook has to renew its proof. For development and tests only.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import sys
import threading
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"sends": {}, "keys": {}, "refused_once": False}
LOCK = threading.Lock()


def iso_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def verify(proof):
    """Asks Silicon Accounts about the proof with the receiving app's credentials."""
    credentials = base64.b64encode(f"{CONFIG['app_id']}:{CONFIG['app_secret']}".encode()).decode()
    request = urllib.request.Request(
        f"{CONFIG['accounts']}/v1/proofs/verify", method="POST",
        data=json.dumps({"proof_token": proof}).encode(),
        headers={"Authorization": f"Basic {credentials}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        return {"valid": False, "status": error.code, "error": error.read().decode(errors="replace")[:300]}
    except (urllib.error.URLError, OSError) as error:
        return {"valid": False, "error": f"unreachable: {error}"}


def record(entry):
    entry["at"] = iso_now()
    with LOCK:
        with open(CONFIG["journal"], "a") as journal:
            journal.write(json.dumps(entry, sort_keys=True) + "\n")


class Handler(BaseHTTPRequestHandler):
    server_version = "ting-stub/1"

    def log_message(self, fmt, *args):
        sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

    def answer(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def refuse(self, status, code, entry):
        entry["outcome"] = code
        record(entry)
        self.answer(status, {"error": {"code": code, "message": f"ting-stub: {code}"}})

    def do_GET(self):
        if self.path == "/healthz":
            self.answer(200, {"ok": True, "receiving_app": CONFIG["app_id"]})
        else:
            self.answer(404, {"error": {"code": "not_found"}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self.answer(400, {"error": {"code": "invalid_input"}})
        call = {"/v1/tings": "send", "/v1/subscriptions": "subscribe", "/v1/sent/query": "receipt"}.get(self.path)
        if call is None:
            return self.answer(404, {"error": {"code": "not_found"}})
        header = self.headers.get("Authorization", "")
        entry = {"call": call}
        if not header.startswith("Proof "):
            return self.refuse(401, "authentication_required", entry)
        proof = header[len("Proof "):].strip()
        verdict = verify(proof)
        entry.update({
            "proof_sha256": hashlib.sha256(proof.encode()).hexdigest()[:16],
            "valid": verdict.get("valid") is True,
            "proof_id": verdict.get("proof_id"),
            "kind": verdict.get("kind"),
            "issuing_app": (verdict.get("issuing_app") or {}).get("app_id"),
            "receiving_app": (verdict.get("receiving_app") or {}).get("app_id"),
            "user": (verdict.get("user") or {}).get("uuid"),
            "scopes": verdict.get("scopes"),
            "expires_at": verdict.get("expires_at"),
        })
        expected = {"send": ("app_verification", "tings.send"), "subscribe": ("user_verification", "tings.subscribe"),
                    "receipt": ("app_verification", "sent.query")}[call]
        if not (entry["valid"] and entry["kind"] == expected[0] and entry["issuing_app"] == CONFIG["issuer"]
                and entry["receiving_app"] == CONFIG["app_id"] and expected[1] in (entry["scopes"] or [])):
            return self.refuse(401, "invalid_proof", entry)
        getattr(self, call)(body, entry)

    def send(self, body, entry):
        recipient = body.get("for") or {}
        entry.update({"for": recipient.get("uuid"), "key": body.get("key"), "delivery": body.get("delivery", "ordinary"),
                      "type": body.get("type")})
        if CONFIG["refuse_first"]:
            with LOCK:
                first = not STATE["refused_once"]
                STATE["refused_once"] = True
            if first:
                return self.refuse(401, "invalid_proof", {**entry, "on_purpose": True})
        if body.get("type") != f"{CONFIG['issuer']}.webhook.received" or not recipient.get("uuid") or not body.get("key"):
            return self.refuse(400, "invalid_input", entry)
        with LOCK:
            existing = STATE["keys"].get(body["key"])
            if existing is None:
                existing = {"id": f"ting_{uuid.uuid4().hex}", "created_at": iso_now(), "body": body}
                STATE["keys"][body["key"]] = existing
                STATE["sends"][existing["id"]] = existing
        answer = {"id": existing["id"], "key": body["key"], "status": "accepted", "silent": False,
                  "created_at": existing["created_at"]}
        if body.get("delivery") == "required":
            answer["delivery"] = "required"
        entry.update({"outcome": "accepted", "ting_id": existing["id"]})
        record(entry)
        self.answer(202, answer)

    def subscribe(self, body, entry):
        recipient = body.get("for") or {}
        entry.update({"for": recipient.get("uuid")})
        if recipient.get("uuid") != entry["user"] or body.get("app_id") != CONFIG["issuer"]:
            return self.refuse(403, "permission_denied", entry)
        entry["outcome"] = "subscribed"
        record(entry)
        self.answer(201, {"id": f"sub_{uuid.uuid4().hex}", "app_id": body["app_id"], "for": recipient,
                          "active": True, "required_delivery": False})

    def receipt(self, body, entry):
        with LOCK:
            sent = STATE["sends"].get(body.get("id"))
        entry.update({"ting_id": body.get("id")})
        if sent is None:
            return self.refuse(404, "not_found", entry)
        detail = {"id": sent["id"], "type": sent["body"]["type"], "for": sent["body"]["for"], "read": False,
                  "silent": False, "deliveries": [], "deliveries_next_cursor": None}
        if sent["body"].get("delivery") == "required":
            detail["delivery"] = "required"
        entry["outcome"] = "receipt"
        record(entry)
        self.answer(200, detail)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--journal", required=True)
    parser.add_argument("--refuse-first-proof", action="store_true")
    args = parser.parse_args()
    missing = [name for name in ("ACCOUNTS_API_URL", "TING_STUB_APP_ID", "TING_STUB_APP_SECRET", "TING_STUB_ISSUER")
               if not os.environ.get(name)]
    if missing:
        parser.error(f"set {', '.join(missing)}")
    CONFIG.update({"accounts": os.environ["ACCOUNTS_API_URL"].rstrip("/"), "app_id": os.environ["TING_STUB_APP_ID"],
                   "app_secret": os.environ["TING_STUB_APP_SECRET"], "issuer": os.environ["TING_STUB_ISSUER"],
                   "journal": args.journal, "refuse_first": args.refuse_first_proof})
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    sys.stderr.write(f"ting-stub on 127.0.0.1:{args.port}, verifying proofs as {CONFIG['app_id']}\n")
    server.serve_forever()


CONFIG = {}

if __name__ == "__main__":
    main()
