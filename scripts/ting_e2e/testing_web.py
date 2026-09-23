#!/usr/bin/env python3
"""Real scoped website receiving against the owned IAM testing fixture."""
import argparse
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import websocket
import fixture
import hook
import sdk
import testing
import testing_hook


class Website:
    def __init__(self, state, backend, node):
        self.state, self.backend, self.node = state, backend, node
        self.folder = Path(tempfile.mkdtemp(prefix="testing-web-", dir=state["directory"]))
        self.server = hook.ROOT / "web/dist/server.js"
        sources = [p for base in (hook.ROOT / "web/src", hook.ROOT / "web/server") for p in base.rglob("*")
                   if p.is_file() and not p.name.endswith(".test.ts")]
        if not self.server.is_file() or self.server.stat().st_mtime < max(p.stat().st_mtime for p in sources):
            raise RuntimeError("website build missing or older than source")
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0)); port = reserved.getsockname()[1]
        self.origin = f"http://127.0.0.1:{port}"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("HOOK_", "IAM_TEST_", "SILICON_"))
                    and k not in ("PORT", "HOST", "NODE_ENV")}
        self.env.update({"HOOK_WEB_ORIGIN": self.origin, "HOOK_API_UPSTREAM": backend["url"],
            "HOOK_TING_UPSTREAM": state["ting_url"], "HOOK_IAM_API_UPSTREAM": state["iam_url"],
            "HOOK_IAM_AUTHORIZE_ORIGIN": state["iam_url"], "HOOK_SESSION_DIR": str(self.folder / "sessions"),
            "HOOK_SESSION_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
            "HOST": "127.0.0.1", "PORT": str(port), "NODE_ENV": "development"})
        fixture.private(self.folder / "server.env.private.json", self.env)
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.log = open(self.folder / "server.log", "ab")
        self.process = subprocess.Popen([node, str(self.server)], cwd=hook.ROOT / "web", env=self.env,
                                        stdout=self.log, stderr=self.log)
        def ready():
            try:
                return self.request("GET", "/console/session")
            except urllib.error.URLError:
                return None
        sdk.wait_for(self.process, ready, "scoped website", seconds=15)

    def request(self, method, path, body=None, expected=(200,)):
        req = urllib.request.Request(self.origin + path, method=method,
            data=json.dumps(body or {}).encode() if method != "GET" else None,
            headers={"Origin": self.origin, "X-Hook-Frontend": "1", "X-Org-Id": "tos",
                     "Content-Type": "application/json", "Idempotency-Key": str(uuid.uuid4())})
        try:
            with self.opener.open(req, timeout=40) as response:
                status, raw = response.status, response.read(2 * 1024 * 1024)
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read(2 * 1024 * 1024)
        value = json.loads(raw) if raw else None
        if status not in expected:
            fixture.private(self.folder / ("http-error-" + path.split("?")[0].split("/")[-1] + ".private.json"), {"path": path, "status": status, "response": value})
            raise RuntimeError(f"scoped website {method} {path.split('?')[0]} returned HTTP{status}; private diagnostic saved")
        return value

    def path(self, path):
        return path + ("&" if "?" in path else "?") + urllib.parse.urlencode({"plane": self.state["environment_id"]})

    def proxy(self, method, path, body=None, expected=(200,)):
        return self.request(method, self.path("/console/proxy/api/v2" + path), body, expected)

    def saved_plane(self):
        identifier = next((c.value for c in self.jar if re.fullmatch("[a-f0-9]{64}", c.value)), None)
        if not identifier:
            raise RuntimeError("owned website session cookie missing")
        script = """const fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
const c=JSON.parse(fs.readFileSync(0,'utf8')),v=fs.readFileSync(path.join(c.folder,c.id));
const d=crypto.createDecipheriv('aes-256-gcm',Buffer.from(c.key,'base64'),v.subarray(0,12));
d.setAAD(Buffer.from(c.id));d.setAuthTag(v.subarray(12,28));
process.stdout.write(Buffer.concat([d.update(v.subarray(28)),d.final()]));"""
        result = subprocess.run([self.node, "-e", script], input=json.dumps({"id": identifier,
            "folder": self.env["HOOK_SESSION_DIR"], "key": self.env["HOOK_SESSION_KEY"]}).encode(), capture_output=True, timeout=10)
        if result.returncode:
            raise RuntimeError("could not decrypt the owned website session")
        return json.loads(result.stdout)["planes"][self.state["environment_id"]]

    def receiver(self):
        plane = self.saved_plane()
        if plane.get("ting"):
            raise RuntimeError("testing website unexpectedly stored a general Ting session")
        slots = list(plane.get("receivers", {}).values())
        if len(slots) != 1 or not slots[0].get("capability"):
            raise RuntimeError("testing website did not persist exactly one scoped receiver")
        return slots[0]["capability"]

    def close(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.wait(timeout=5)
        self.log.close()


def operator(state, label):
    slt = testing.cli(state, label, ["login", "--app-id", "tos>ting", "--grant-org", "tos", "--approve-scopes"])["slt"]
    return testing.http(state, state["ting_url"], "POST", "/v1/session", {"slt": slt}, headers={
        "IAM_TEST_APP_SECRET": state["imports"]["tos>ting"]["app_secret"],
        "X-Testing-Environment-Key": state["testing_key"], "Idempotency-Key": str(uuid.uuid4())}, expected=(200, 201))[1]


def ingress(state, backend, provider, source):
    raw = json.dumps({"message": "real scoped website delivery", "source": source,
        "run": str(uuid.uuid4()), "padding": "s" * 300000}, separators=(",", ":")).encode()
    identifier, timestamp = str(uuid.uuid4()), str(int(time.time()))
    signature = base64.b64encode(hmac.new(provider["signing_secret"].encode(),
        identifier.encode() + b"." + timestamp.encode() + b"." + raw, hashlib.sha256).digest()).decode()
    value = testing.http(state, backend["url"], "POST", urllib.parse.urlsplit(provider["endpoint_url"]).path, raw,
        headers={"webhook-id": identifier, "webhook-timestamp": timestamp, "webhook-signature": "v1," + signature})[1]
    return value["receipt_id"], raw


def verify(directory, node, browser_check=False, playwright="playwright"):
    state, backend = fixture.load(directory), hook.load(directory)
    if state.get("cleaned") or state["generation"] < 2:
        raise RuntimeError("scoped website needs the current rebuilt testing generation")
    testing_hook.prepare_delivery(state, backend)
    website, stream, observer, prior_pref, report = None, None, None, None, None
    browser_failed = False
    pref_path = "/v1/orgs/tos/preferences"
    pref_body = {"app_id": "tos>hook", "type": "tos>hook.webhook.received", "service": None}
    pref_query = pref_path + "?" + urllib.parse.urlencode({"app_id": "tos>hook", "type": "tos>hook.webhook.received"})
    try:
        observer = operator(state, "test-admin")
        fixture.private(Path(directory) / "testing-web-cleanup.private.json", {"observer": observer})
        def ting(method, path, body=None, expected=(200,)):
            return testing.http(state, state["ting_url"], method, path, body, token=observer["session_token"], expected=expected)[1]
        prefs = ting("GET", pref_query)
        if prefs.get("next_cursor"):
            raise RuntimeError("preference restoration requires unambiguous single-page fixture state")
        exact = [p for p in prefs["items"] if p.get("type") == pref_body["type"] and not p.get("service")]
        if len(exact) > 1:
            raise RuntimeError("duplicate fixture notification preferences")
        prior_pref = exact
        fixture.private(Path(directory) / "testing-web-cleanup.private.json", {"observer": observer, "prior_preference": prior_pref})
        # Ensure the first event exercises ordinary hints; the second proves silent catch-up.
        ting("PUT", pref_path, {**pref_body, "enabled": True})
        website = Website(state, backend, node)
        attached = website.request("POST", "/console/attach", {"app_secret": state["imports"]["tos>hook"]["app_secret"]})
        if attached["id"] != state["environment_id"]:
            raise RuntimeError("website selected another testing environment")
        slt = testing.cli(state, "test-admin", ["login", "--app-id", "tos>hook", "--grant-org", "tos", "--approve-scopes"])["slt"]
        logged_in = website.request("POST", website.path("/console/login"), {"slt": slt})
        public = json.dumps(logged_in)
        if slt in public or any(name in public for name in ("access_token", "refresh_token", "receiver_token")):
            raise RuntimeError("website exposed internal credentials")
        actor = "hook-testing:tos"
        provider = website.proxy("POST", f"/silicons/{actor}/hooks", {"name": "scoped-web-" + str(uuid.uuid4())[:8]})
        url = website.origin.replace("http://", "ws://") + "/console/stream?" + urllib.parse.urlencode({
            "plane": state["environment_id"], "org": "tos", "silicon_id": actor, "telemetry": "off"})
        stream = websocket.create_connection(url, cookie="; ".join(f"{c.name}={c.value}" for c in website.jar), origin=website.origin, timeout=2)
        def frame_until(predicate, seconds=60):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                try:
                    raw = stream.recv()
                except websocket.WebSocketTimeoutException:
                    continue
                if not raw:
                    raise RuntimeError("scoped website stream closed early")
                frame = json.loads(raw)
                if frame.get("type") == "error":
                    fixture.private(website.folder / "stream-error.private.json", frame)
                    raise RuntimeError("scoped website stream error; private diagnostic saved")
                if predicate(frame):
                    return frame
            raise RuntimeError("scoped website stream timed out")
        frame_until(lambda f: f.get("type") == "ready")
        first = website.receiver()
        if first["environment"] != {"kind": "testing", "id": state["environment_id"], "generation": state["generation"]}:
            raise RuntimeError("website capability has stale or wrong shared context")
        began = time.monotonic()
        print("SCOPED_WEB_STAGE Hook-only login and scoped watch ready; testing automatic renewal beyond 30 seconds", flush=True)
        while time.monotonic() - began < 35:
            time.sleep(min(5, 35 - (time.monotonic() - began)))
        renewed = website.receiver()
        renewal_seconds = round(time.monotonic() - began, 3)
        if renewed["receiver_id"] != first["receiver_id"] or renewed["receiver_token"] == first["receiver_token"]:
            raise RuntimeError("website automatic renewal failed to preserve ID and replace token")
        testing.http(state, state["ting_url"], "GET", "/v1/receivers/me", token=first["receiver_token"], expected=(401,))
        testing.http(state, state["ting_url"], "GET", "/v1/receivers/me", token=renewed["receiver_token"])
        print("SCOPED_WEB_STAGE automatic renewal kept receiver ID and replaced token", flush=True)
        evidence = []
        for silent in (False, True):
            if silent:
                ting("PUT", pref_path, {**pref_body, "enabled": False})
            event_id, raw = ingress(state, backend, provider, "silent catch-up" if silent else "ordinary notification")
            received = frame_until(lambda f: f.get("type") == "new_event" and f.get("data", {}).get("event", {}).get("id") == event_id)
            event = received["data"]["event"]
            if event["request"]["body"].encode() != raw:
                raise RuntimeError("scoped website did not hydrate exact provider bytes")
            item = ting("GET", "/v1/orgs/tos/inbox/" + received["data"]["ting_id"])
            publication = website.proxy("GET", f"/silicons/{actor}/events/{event_id}/publication")
            if item["read"] or bool(item["silent"]) != silent or publication["state"] != "accepted_by_ting" or publication["recipient_receipt"]["read"]:
                raise RuntimeError("scoped website receipt/policy/primary publication mismatch")
            evidence.append({"event_id": event_id, "ting_id": item["id"], "silent": silent,
                "payload_bytes": len(raw), "payload_sha256": hashlib.sha256(raw).hexdigest(), "primary_read": False, "observer_read": False})
            print("SCOPED_WEB_STAGE exact large payload and no ACK; silent=" + str(silent), flush=True)
        current = website.receiver()
        website.request("POST", website.path("/console/logout"))
        testing.http(state, state["ting_url"], "GET", "/v1/receivers/me", token=current["receiver_token"], expected=(401,))
        website.proxy("GET", "/silicons/" + actor + "/hooks", expected=(401,))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                if not stream.recv():
                    break
            except websocket.WebSocketConnectionClosedException:
                break
            except websocket.WebSocketTimeoutException:
                continue
        else:
            raise RuntimeError("logout left the website stream open")
        stream.close(); stream = None
        report = {"complete": True, "environment_id": state["environment_id"], "shared_generation": state["generation"],
            "server_sha256": hashlib.sha256(website.server.read_bytes()).hexdigest(), "receiver_id": first["receiver_id"],
            "automatic_renewal_wait_seconds": renewal_seconds, "events": evidence,
            "checks": ["Browser BFF received only Hook test app selector and actual Hook SLT",
                "Real scoped receiver and encrypted durable capability; no general Ting session",
                "Automatic renewal beyond 30 seconds preserved receiver ID and replaced token",
                "Actual signed large events hydrated exactly, including silent Carbon inbox catch-up",
                "Observer and primary remain unread; website performed no application read ACK",
                "Logout revoked current capability, closed stream and denied subsequent proxy access"],
            "limitations": ["Local authenticated participant APIs; full Honeycomb coordinator and production approval activation unverified",
                "Synthetic type fixture; actual IAM consent/SLT and Ting runtime"]}
        if browser_check:
            print("SCOPED_WEB_STAGE HTTP complete; waiting natural60 seconds before independent browser setup", flush=True)
            for _ in range(2):
                time.sleep(30)
                print("SCOPED_WEB_STAGE natural IAM rate-window separation", flush=True)
            # Keep Carbon muted so the actual UI also proves periodic inbox recovery.
            output = website.folder / "browser"
            cfg = {"origin": website.origin, "hook": backend["url"], "org": "tos", "actor": actor,
                "plane": state["environment_id"], "generation": state["generation"], "directory": str(directory),
                "python": sys.executable, "scripts": str(Path(__file__).parent.resolve()), "output": str(output),
                "playwright": playwright, "session_folder": website.env["HOOK_SESSION_DIR"],
                "session_key": website.env["HOOK_SESSION_KEY"], "ting": state["ting_url"],
                "server_sha256": hashlib.sha256(website.server.read_bytes()).hexdigest(),
                "hook_binary_sha256": backend.get("binary_sha256") or hashlib.sha256((hook.ROOT / "target/debug/hook-api").read_bytes()).hexdigest()}
            config_file = website.folder / "browser.private.json"; fixture.private(config_file, cfg)
            result = subprocess.run([node, str(Path(__file__).with_name("testing_web_browser.mjs")), str(config_file)], timeout=270)
            browser_failed = bool(result.returncode)
    finally:
        cleanup_errors = []
        if stream:
            stream.close()
        if website:
            try:
                for attempt in range(4):
                    try:
                        website.request("POST", website.path("/console/logout"), expected=(200, 401))
                        break
                    except RuntimeError:
                        diagnostic = website.folder / "http-error-logout.private.json"
                        failure = json.loads(diagnostic.read_text()) if diagnostic.exists() else {}
                        if failure.get("status") != 429 or attempt == 3:
                            raise
                        print("SCOPED_WEB_CLEANUP waiting 30 seconds for the real IAM rate window before durable logout retry", flush=True)
                        time.sleep(30)
            except Exception as error:
                cleanup_errors.append("BFF logout: " + type(error).__name__)
            finally:
                website.close()
        if observer:
            try:
                if prior_pref is not None:
                    if prior_pref:
                        testing.http(state, state["ting_url"], "PUT", pref_path, {**pref_body, "enabled": prior_pref[0]["enabled"]}, token=observer["session_token"])
                    else:
                        testing.http(state, state["ting_url"], "DELETE", pref_query, token=observer["session_token"])
                testing.http(state, state["ting_url"], "DELETE", "/v1/session", token=observer["session_token"], expected=(200, 401))
                (Path(directory) / "testing-web-cleanup.private.json").unlink(missing_ok=True)
            except Exception as error:
                cleanup_errors.append("Observer restoration: " + type(error).__name__)
        try:
            testing.http(state, state["ting_url"], "PUT", state["required_policy_path"],
                {"enabled": state["required_policy_before"]["enabled"]}, token=state["recipient_operator"]["session_token"])
        except Exception as error:
            cleanup_errors.append("Primary consent restoration: " + type(error).__name__)
        if cleanup_errors:
            fixture.private(Path(directory) / "testing-web-cleanup-error.json", {"pending": cleanup_errors})
            raise RuntimeError("Scoped website cleanup incomplete; private durable authority retained for recovery")
    if report:
        report["recipient_preferences_and_required_policy_restored"] = True
        fixture.private(Path(directory) / "testing-web-verification.json", report)
        print("SCOPED_WEB_PASS real renewal, ordinary and silent payloads, no ACK, logout and restoration", flush=True)
    if browser_failed:
        raise RuntimeError("scoped browser fixture failed; HTTP report preserved, inspect private browser diagnostic")


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--node", default="node")
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--playwright", default="playwright")
    args = parser.parse_args()
    verify(args.directory.resolve(), args.node, args.browser, args.playwright)
