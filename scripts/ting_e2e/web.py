#!/usr/bin/env python3
"""Exercise the actual website BFF with real IAM batch login and Ting inbox watch.

The fixture models IAM's browser callback using official atomic batch issuance.
It uses a private cookie jar, encrypted session directory and loopback server.
"""
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
import stat
import subprocess
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


def verify(directory, node, server, browser_check=False, playwright="playwright"):
    website = hook.ROOT / "web"
    sources = [path for base in (website / "src", website / "server") for path in base.rglob("*")
               if path.is_file() and not path.name.endswith(".test.ts")]
    sources += [website / "package.json", website / "vite.config.ts", website / "index.html"]
    if not server.is_file() or server.stat().st_mtime < max(path.stat().st_mtime for path in sources):
        raise RuntimeError("website build is missing or older than its source; run npm --prefix web run build first")
    upstream, backend = fixture.load(directory), hook.load(directory)
    folder = Path(tempfile.mkdtemp(prefix="web-", dir=directory)).resolve()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("HOOK_", "IAM_TEST_", "SILICON_")) and key not in ("PORT", "HOST", "NODE_ENV")}
    env.update({"HOOK_WEB_ORIGIN": origin, "HOOK_API_UPSTREAM": backend["url"],
        "HOOK_TING_UPSTREAM": upstream["ting_url"], "HOOK_IAM_API_UPSTREAM": upstream["iam_url"],
        "HOOK_IAM_AUTHORIZE_ORIGIN": upstream["iam_url"], "HOOK_SESSION_DIR": str(folder / "sessions"),
        "HOOK_SESSION_KEY": base64.b64encode(secrets.token_bytes(32)).decode(),
        "HOST": "127.0.0.1", "PORT": str(port), "NODE_ENV": "development"})
    fixture.private(folder / "server.env.private.json", env)
    jar = http.cookiejar.CookieJar()
    browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    org, actor = upstream["org_id"], upstream["actor_id"]
    log = open(folder / "server.log", "ab")
    process, stream, observer = None, None, None

    def request(method, path, body=None, expected=(200,), raw=False):
        headers = {"Origin": origin, "X-Hook-Frontend": "1", "X-Org-Id": org,
                   "Content-Type": "application/json"}
        if method != "GET":
            headers["Idempotency-Key"] = str(uuid.uuid4())
        req = urllib.request.Request(origin + path, method=method, headers=headers,
            data=json.dumps(body or {}).encode() if method != "GET" else None)
        try:
            with browser.open(req, timeout=45) as response:
                status, data, response_headers = response.status, response.read(2 * 1024 * 1024), response.headers
        except urllib.error.HTTPError as error:
            status, data, response_headers = error.code, error.read(2 * 1024 * 1024), error.headers
        if status not in expected:
            fixture.private(folder / "http-error.private.json", {"path": path, "status": status, "body": data.decode(errors="replace")})
            raise RuntimeError("website " + method + " " + path.split("?")[0] + f" returned HTTP{status}; inspect private diagnostic")
        if raw:
            return data, response_headers
        return json.loads(data)

    def proxy(method, path, body=None, expected=(200,)):
        return request(method, "/console/proxy/api/v2" + path, body, expected)

    def next_frame(description, predicate, seconds=45):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                value = stream.recv()
            except websocket.WebSocketTimeoutException:
                continue
            if not value:
                raise RuntimeError("website stream closed while waiting for " + description)
            frame = json.loads(value)
            if frame.get("type") == "error":
                fixture.private(folder / "stream-error.private.json", frame)
                raise RuntimeError("website stream reported an error; inspect private diagnostic")
            if predicate(frame):
                return frame
        raise RuntimeError("timed out waiting for " + description)

    def paired_login():
        started = request("POST", "/console/login/start")
        authorize = urllib.parse.urlsplit(started["authorize_url"])
        query = urllib.parse.parse_qs(authorize.query)
        if set(query.get("app_ids", [""])[0].split(",")) != {"tos>hook", "tos>ting"}:
            raise RuntimeError("website login did not request one combined IAM batch")
        callback = urllib.parse.urlsplit(query["redirect_uri"][0])
        state = urllib.parse.parse_qs(callback.query)["state"][0]
        callback_html, callback_headers = request("GET", callback.path + "?" + callback.query, raw=True)
        if b"script" not in callback_html or callback_headers.get_content_type() != "text/html":
            raise RuntimeError("website callback did not serve its browser bridge")
        batch = fixture.cli(upstream, "admin", ["batch-login", "--app-id", "tos>hook,tos>ting",
            "--grant-org", org, "--approve-scopes"])
        items = batch["items"]
        if {item["app_id"] for item in items} != {"tos>hook", "tos>ting"}:
            raise RuntimeError("real IAM batch issuance did not return both applications")
        completed = request("POST", "/auth/callback/complete", {"state": state, "slts": items})
        redirect = urllib.parse.urlsplit(completed.get("redirect_url", ""))
        if redirect.scheme + "://" + redirect.netloc != origin or redirect.path != "/" or "slt" in redirect.fragment:
            raise RuntimeError("website callback did not finish in its own frontend")
        resumed = request("POST", "/auth/callback/complete", {"state": state})
        if resumed != completed:
            raise RuntimeError("website completed-login retry was not idempotent")
        return items, completed

    def saved_plane():
        # Only decrypt this driver's owned, isolated BFF session in memory so
        # remote revocation can be proved without printing application tokens.
        identifier = next((item.value for item in jar if re.fullmatch("[a-f0-9]{64}", item.value)), None)
        if not identifier:
            raise RuntimeError("website fixture has no private session cookie")
        script = """const fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
const c=JSON.parse(fs.readFileSync(0,'utf8')),sealed=fs.readFileSync(path.join(c.folder,c.id));
const d=crypto.createDecipheriv('aes-256-gcm',Buffer.from(c.key,'base64'),sealed.subarray(0,12));
d.setAAD(Buffer.from(c.id));d.setAuthTag(sealed.subarray(12,28));
process.stdout.write(Buffer.concat([d.update(sealed.subarray(28)),d.final()]));"""
        result = subprocess.run([node, "-e", script], input=json.dumps({"id": identifier,
            "folder": env["HOOK_SESSION_DIR"], "key": env["HOOK_SESSION_KEY"]}).encode(),
            capture_output=True, timeout=10)
        if result.returncode:
            raise RuntimeError("could not inspect the owned encrypted website session")
        return json.loads(result.stdout)["planes"]["production"]

    def assert_revoked(plane):
        headers = {"X-Org-Id": org, "Silicon-Hook-API-Version": "v2"}
        status = fixture.request(backend["url"], "GET", "/api/v2/auth/status",
            token=plane["tokens"]["access_token"], headers=headers, expected=(200, 401))
        if status.get("authenticated"):
            raise RuntimeError("website retired a local pair without revoking its Hook access")
        fixture.request(backend["url"], "POST", "/api/v2/auth/refresh",
            {"refresh_token": plane["tokens"]["refresh_token"]},
            headers={**headers, "Idempotency-Key": str(uuid.uuid4())}, expected=(401,))
        fixture.request(upstream["ting_url"], "GET", "/v1/me", token=plane["ting"]["token"], expected=(401,))

    try:
        process = subprocess.Popen([node, str(server)], cwd=hook.ROOT / "web", env=env, stdout=log, stderr=log)
        def ready():
            try:
                return request("GET", "/console/session")
            except urllib.error.URLError:
                return None
        initial = sdk.wait_for(process, ready, "website server", seconds=15)
        if any(plane.get("authenticated") for plane in initial["planes"]):
            raise RuntimeError("fresh isolated browser was already authenticated")
        items, completed = paired_login()
        session = request("GET", "/console/session")
        production = next(plane for plane in session["planes"] if plane["id"] == "production")
        if not production.get("authenticated") or production.get("actor", {}).get("type") != "carbon":
            raise RuntimeError("website did not authenticate the real Carbon batch identity")
        public = json.dumps([completed, session])
        if any(item["slt"] in public for item in items) or any(name in public for name in ["access_token", "refresh_token", "session_token"]):
            raise RuntimeError("website exposed internal application credentials to the browser")
        session_files = list((folder / "sessions").iterdir())
        if not session_files or any(stat.S_IMODE(path.stat().st_mode) != 0o600 for path in session_files):
            raise RuntimeError("website session files are not private")
        for path in session_files:
            stored = path.read_bytes()
            if b'"access_token"' in stored or any(item["slt"].encode() in stored for item in items):
                raise RuntimeError("website session file contains plaintext application credentials")
        organizations = request("GET", "/console/organizations")
        if not any(item["id"] == org for item in organizations["items"]):
            raise RuntimeError("website could not select the organization shared by both sessions")
        print("WEB_STAGE real atomic IAM batch and state-bound callback completed", flush=True)
        first_pair = saved_plane()
        replacement_items, replaced = paired_login()
        current_pair = saved_plane()
        if (first_pair["tokens"]["access_token"] == current_pair["tokens"]["access_token"]
                or first_pair["ting"]["token"] == current_pair["ting"]["token"]):
            raise RuntimeError("website paired sign-in did not replace both sessions")
        assert_revoked(first_pair)
        refreshed_session = request("GET", "/console/session")
        if any(item["slt"] in json.dumps([replaced, refreshed_session]) for item in replacement_items):
            raise RuntimeError("website replacement exposed its SLTs")
        live = fixture.request(backend["url"], "GET", "/api/v2/auth/status",
            token=current_pair["tokens"]["access_token"],
            headers={"X-Org-Id": org, "Silicon-Hook-API-Version": "v2"})
        delivery_live = fixture.request(upstream["ting_url"], "GET", "/v1/me", token=current_pair["ting"]["token"])
        if not live.get("authenticated") or not delivery_live.get("authenticated"):
            raise RuntimeError("retiring the old pair invalidated the new application's sessions")
        print("WEB_STAGE second paired sign-in retired both old sessions; replacement pair remains usable", flush=True)
        provider = proxy("POST", f"/silicons/{actor}/hooks", {"name": "real-ting-web-e2e"})
        cookie = "; ".join(f"{item.name}={item.value}" for item in jar)
        stream_url = origin.replace("http://", "ws://") + "/console/stream?" + urllib.parse.urlencode({
            "plane": "production", "org": org, "silicon_id": actor, "telemetry": "off"})
        stream = websocket.create_connection(stream_url, cookie=cookie, origin=origin, timeout=2)
        next_frame("real Ting watch readiness", lambda frame: frame.get("type") == "ready")
        print("WEB_STAGE Carbon receiving subscription and Ting watch ready", flush=True)
        raw = json.dumps({"message": "real Hook to Ting delivery", "source": "website BFF",
                          "run": str(uuid.uuid4()), "padding": "w" * 300000}, separators=(",", ":")).encode()
        identifier, timestamp = str(uuid.uuid4()), str(int(time.time()))
        signature = base64.b64encode(hmac.new(provider["signing_secret"].encode(),
            identifier.encode() + b"." + timestamp.encode() + b"." + raw, hashlib.sha256).digest()).decode()
        ingress = fixture.request(backend["url"], "POST", urllib.parse.urlsplit(provider["endpoint_url"]).path, raw,
            headers={"webhook-id": identifier, "webhook-timestamp": timestamp, "webhook-signature": "v1," + signature})
        event_id = ingress["receipt_id"]
        event_frame = next_frame("website event after internal Ting publication", lambda frame:
            frame.get("type") == "new_event" and frame.get("data", {}).get("event", {}).get("id") == event_id)
        event = event_frame["data"]["event"]
        ting_id = event_frame["data"]["ting_id"]
        if event["request"]["body"].encode() != raw:
            raise RuntimeError("website internal delivery did not hydrate the exact large original body")
        fetched = proxy("GET", f"/silicons/{actor}/events/{event_id}")
        if fetched != event:
            raise RuntimeError("website live event differs from authenticated event retrieval")
        history = proxy("GET", f"/silicons/{actor}/events?hook_id={provider['id']}&limit=10")
        if not any(item == event for item in history["items"]):
            raise RuntimeError("website history did not contain its delivered provider event")
        # Independent same-actor session observes receipt state; it never
        # subscribes a delivery destination or acknowledges the browser event.
        observer = fixture.request(upstream["ting_url"], "POST", "/v1/session",
            {"slt": fixture.slt(upstream, "admin", "tos>ting")},
            headers={"Idempotency-Key": str(uuid.uuid4())}, expected=(200, 201))
        receipt = fixture.request(upstream["ting_url"], "GET", f"/v1/orgs/{org}/inbox/{ting_id}",
            token=observer["session_token"])
        if receipt.get("read") or receipt.get("for") != production["actor"]["id"]:
            raise RuntimeError("website observation changed read ACK state or used another recipient")
        current_pair = saved_plane()
        logout = request("POST", "/console/logout")
        if any(plane.get("authenticated") for plane in logout["planes"]):
            raise RuntimeError("website logout retained an authenticated browser plane")
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
            raise RuntimeError("website logout left its live delivery stream open")
        proxy("GET", f"/silicons/{actor}/events/{event_id}", expected=(401,))
        assert_revoked(current_pair)
        report = {"complete": True, "web_server_sha256": hashlib.sha256(server.read_bytes()).hexdigest(),
            "event_id": event_id, "ting_id": ting_id, "payload_bytes": len(raw),
            "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "checks": ["isolated real website server and private encrypted browser session",
                "one official atomic IAM batch issues independent Hook and Ting SLTs",
                "state-bound website callback exchanges both SLTs and supports completed retry",
                "second paired sign-in revokes old Hook access/refresh and Ting session while its replacement stays usable",
                "browser responses expose no Hook or Ting credentials", "organization available to both application sessions",
                "real Carbon recipient subscription and Ting watch_inbox notification",
                "signed provider payload above 256KiB hydrates exactly through the BFF",
                "live event matches authenticated event retrieval and history", "browser observation leaves Ting unread",
                "logout clears the browser identity and closes its receiving stream", "authenticated operations fail after logout",
                "logout revokes both real application sessions and the Hook refresh family"],
            "limitations": ["callback bridge HTTP protocol exercised; browser JavaScript rendering checked separately",
                "normal fixture plane only; scoped testing receiving is verified separately",
                "Ting type is fixture seeded"]}
        fixture.private(Path(directory) / "web-verification.json", report)
        print(json.dumps(report, indent=2), flush=True)
        if browser_check:
            browser_config = folder / "browser.private.json"
            fixture.private(browser_config, {"origin": origin, "hook": backend["url"], "org": org, "actor": actor,
                "directory": str(directory), "python": os.sys.executable,
                "scripts": str(Path(__file__).resolve().parent), "output": str(folder / "browser"),
                "playwright": playwright})
            result = subprocess.run([node, str(Path(__file__).with_name("web_browser.mjs")), str(browser_config)],
                cwd=hook.ROOT / "web", timeout=180, capture_output=True, text=True)
            if result.returncode:
                fixture.private(folder / "browser-driver.log", result.stdout + result.stderr)
                raise RuntimeError("real browser verification failed; inspect private browser diagnostics")
            print(result.stdout, flush=True)
    finally:
        if stream:
            stream.close()
        if observer:
            try:
                fixture.request(upstream["ting_url"], "DELETE", "/v1/session", token=observer["session_token"],
                    expected=(200, 401))
            except Exception:
                fixture.private(folder / "observer-cleanup.log", "Independent fixture observer session cleanup failed.\n")
        if process and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--node", default="node")
    parser.add_argument("--server", type=Path, default=hook.ROOT / "web/dist/server.js")
    parser.add_argument("--browser", action="store_true", help="also run the actual UI and callback JavaScript in isolated Chromium")
    parser.add_argument("--playwright", default="playwright", help="Playwright package name or absolute package path")
    args = parser.parse_args()
    verify(args.directory.resolve(), args.node, args.server.resolve(), args.browser, args.playwright)
