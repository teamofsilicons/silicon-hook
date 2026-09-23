#!/usr/bin/env python3
"""Run the actual Hook backend against the disposable IAM/Ting fixture.

Uses private generated credentials, a separate disposable Postgres, and a
foreground Hook binary. It never modifies an existing application database.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import time
import urllib.parse
import uuid

import fixture

ROOT = Path(__file__).resolve().parents[2]


def state_file(directory):
    return Path(directory) / "hook.private.json"


def load(directory):
    state = json.loads(state_file(directory).read_text())
    if not state["container"].startswith("hook-ting-e2e-") or not state["owned"]:
        raise RuntimeError("unowned Hook fixture")
    return state


def setup(directory):
    upstream = fixture.load(directory)
    if state_file(directory).exists():
        raise RuntimeError("Hook fixture already exists; use verify or cleanup")
    folder = Path(directory)
    name = upstream["network"] + "-hook-db"
    password = secrets.token_urlsafe(24)
    fixture.private(folder / "hook-postgres.env", f"POSTGRES_PASSWORD={password}\nPOSTGRES_DB=hook\n")
    fixture.command(["docker", "run", "-d", "--name", name, "--env-file", str(folder / "hook-postgres.env"),
                     "-p", "127.0.0.1::5432", "postgres:16-alpine"], log=folder / "hook-setup.log")
    state = {"owned": True, "container": name, "directory": str(folder), "pid": None}
    fixture.private(state_file(folder), state)
    for _ in range(60):
        # TCP excludes PostgreSQL's temporary initdb socket-only postmaster.
        if subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"], capture_output=True).returncode == 0:
            break
        time.sleep(.25)
    db_port = fixture.port(name, 5432)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("HOOK_", "IAM_TEST_"))}
    env.update({"HOOK_ENVIRONMENT":"development", "HOOK_LOG_FILTER":"warn", "HOOK_TELEMETRY":"off",
        "HOOK_BIND_ADDR":f"127.0.0.1:{port}", "HOOK_PUBLIC_BASE_URL":origin,
        "HOOK_MIGRATOR_DATABASE_URL":f"postgres://postgres:{password}@127.0.0.1:{db_port}/hook",
        "HOOK_IAM_BASE_URL":upstream["iam_url"], "HOOK_IAM_APP_ID":"tos>hook",
        "HOOK_IAM_APP_SECRET":upstream["app_secrets"]["tos>hook"], "HOOK_IAM_ALLOW_INSECURE_LOCAL_HTTP":"true",
        "HOOK_ALLOW_LOCAL_AUTH":"false", "HOOK_TING_BASE_URL":upstream["ting_url"],
        "HOOK_TING_POLL_MILLISECONDS":"100", "HOOK_ENCRYPTION_KEYS":"1:"+b64(secrets.token_bytes(32)),
        "HOOK_ENCRYPTION_CURRENT_VERSION":"1", "HOOK_CURSOR_SIGNING_KEY":b64(secrets.token_bytes(32)),
        "HOOK_REQUEST_TIMEOUT_SECONDS":"60"})
    real_testing = upstream.get("coverage", {}).get("real_iam_testing_plane", False)
    if real_testing:
        fixture.command(["docker", "exec", "-i", name, "psql", "-U", "postgres", "-d", "hook", "-v", "ON_ERROR_STOP=1"],
            stdin=b"CREATE DATABASE hook_testing;", log=folder / "hook-grants.log")
        state["honeycomb_control_token"] = secrets.token_urlsafe(36)
        env.update({"HOOK_TEST_MIGRATOR_DATABASE_URL": f"postgres://postgres:{password}@127.0.0.1:{db_port}/hook_testing",
            "HOOK_HONEYCOMB_SERVICE_TOKEN": state["honeycomb_control_token"], "HOOK_HONEYCOMB_URL": "http://127.0.0.1:1",
            "HOOK_TING_POLL_MILLISECONDS": "2000"})
    migrated = subprocess.run([str(ROOT / "target/debug/hook-migrate")], env=env, cwd=folder, capture_output=True, timeout=60)
    if migrated.returncode:
        fixture.private(folder / "hook-migrate.log", (migrated.stdout+migrated.stderr).decode(errors="replace"))
        raise RuntimeError("Hook fixture migration failed; inspect private hook-migrate.log")
    runtime = secrets.token_urlsafe(24)
    sql = f"CREATE ROLE hook_api LOGIN PASSWORD {fixture.quote(runtime)}; CREATE ROLE hook_worker NOLOGIN;"
    fixture.command(["docker", "exec", "-i", name, "psql", "-U", "postgres", "-d", "hook", "-v", "ON_ERROR_STOP=1"],
                    stdin=sql.encode(), log=folder / "hook-grants.log")
    fixture.command(["docker", "exec", "-i", name, "psql", "-U", "postgres", "-d", "hook", "-v", "ON_ERROR_STOP=1",
                    "-v", "api_role=hook_api", "-v", "worker_role=hook_worker"],
                    stdin=(ROOT / "deploy/postgres/grant-runtime.sql").read_bytes(), log=folder / "hook-grants.log")
    if real_testing:
        fixture.command(["docker", "exec", "-i", name, "psql", "-U", "postgres", "-d", "hook_testing", "-v", "ON_ERROR_STOP=1",
            "-v", "api_role=hook_api", "-v", "worker_role=hook_worker"],
            stdin=(ROOT / "deploy/postgres/grant-runtime.sql").read_bytes(), log=folder / "hook-grants.log")
        env["HOOK_TEST_DATABASE_URL"] = f"postgres://hook_api:{runtime}@127.0.0.1:{db_port}/hook_testing"
        env.pop("HOOK_TEST_MIGRATOR_DATABASE_URL")
    env["HOOK_DATABASE_URL"] = f"postgres://hook_api:{runtime}@127.0.0.1:{db_port}/hook"
    env.pop("HOOK_MIGRATOR_DATABASE_URL")
    fixture.private(folder / "hook.env.private.json", env)
    with open(folder / "hook-api.log", "ab") as log:
        process = subprocess.Popen([str(ROOT / "target/debug/hook-api")], env=env, cwd=folder,
                                   stdout=log, stderr=log, start_new_session=True)
    state.update({"pid":process.pid, "url":origin})
    fixture.private(state_file(folder), state)
    fixture.wait_health(origin, "/readyz")
    print(f"HOOK_READY {origin}", flush=True)


def verify(directory):
    import websocket
    upstream, state = fixture.load(directory), load(directory)
    url, org, actor = state["url"], upstream["org_id"], upstream["actor_id"]
    headers = {"X-Org-Id":org, "Silicon-Hook-API-Version":"v2"}
    def call(method, path, body=None, administrator=False, mutate=False, expected=(200,)):
        h = dict(headers)
        if mutate: h["Idempotency-Key"] = str(uuid.uuid4())
        token = upstream["hook_admin" if administrator else "hook_recipient"]["access_token"]
        return fixture.request(url, method, "/api/v2"+path, body, token, h, expected)
    if not state.get("publisher_configured"):
        slt = fixture.slt(upstream, "publisher")
        call("POST", "/delivery/publisher", {"slt":slt}, administrator=True, mutate=True)
        state["publisher_configured"] = True
        fixture.private(state_file(directory), state)
    call("POST", "/delivery/recipient")
    provider = call("POST", f"/silicons/{actor}/hooks", {"name":"real-ting-e2e"}, mutate=True, expected=(201,))
    ws = websocket.create_connection(upstream["ting_url"].replace("http://","ws://")+"/v1/ws?protocol=v1", timeout=40, suppress_origin=True)
    ready, pending = json.loads(ws.recv()), []
    def ws_call(op, **body):
        key = str(uuid.uuid4())
        ws.send(json.dumps({"op":op,"request_id":key,**body}))
        while True:
            value = json.loads(ws.recv())
            if value.get("op") == "ping": ws.send(json.dumps({"op":"pong"})); continue
            if value.get("request_id") == key:
                if value.get("op") == "error": raise RuntimeError("Ting receiver operation failed")
                return value
            pending.append(value)
    ws_call("subscribe",org_id=org,session_token=upstream["ting_session"],webhook_ids=[])
    destination = fixture.request(upstream["ting_url"], "POST", f"/v1/orgs/{org}/webhooks",
        {"receiver_id":ready["receiver_id"]}, token=upstream["ting_session"],
        headers={"Idempotency-Key":str(uuid.uuid4())}, expected=(200,201))
    raw = json.dumps({"message":"real Hook to Ting delivery", "run":str(uuid.uuid4())}, separators=(",",":")).encode()
    identifier, timestamp = str(uuid.uuid4()), str(int(time.time()))
    signed = identifier.encode()+b"."+timestamp.encode()+b"."+raw
    signature = base64.b64encode(hmac.new(provider["signing_secret"].encode(), signed, hashlib.sha256).digest()).decode()
    ingress = urllib.parse.urlsplit(provider["endpoint_url"]).path
    accepted = fixture.request(url, "POST", ingress, raw, headers={"webhook-id":identifier,"webhook-timestamp":timestamp,"webhook-signature":"v1,"+signature})
    event_id = accepted["receipt_id"]
    matched, drained = None, []
    def hydrate(item):
        if item.get("for") != actor or item.get("type") != "tos>hook.webhook.received":
            raise RuntimeError("unexpected fixture notification recipient or type")
        envelope = item.get("data", {})
        reference = envelope.get("data", {}).get("metadata", {})
        if envelope.get("type") != "new_event" or reference.get("silicon_id") != actor or reference.get("org_id") != org:
            raise RuntimeError("unexpected Hook event reference")
        selected = urllib.parse.urlencode({"environment_id":reference["environment_id"],
                                          "environment_generation":reference["environment_generation"]})
        event = call("GET", f"/silicons/{actor}/events/{reference['id']}?{selected}")
        for field in ("id", "org_id", "silicon_id", "hook_id", "delivery_sequence", "received_at"):
            if event[field] != reference[field]:
                raise RuntimeError("hydrated event does not match its Ting reference")
        return event

    deadline = time.monotonic()+60
    while time.monotonic()<deadline:
        frame = pending.pop(0) if pending else json.loads(ws.recv())
        if frame.get("op") == "ping": ws.send(json.dumps({"op":"pong"})); continue
        if frame.get("op") != "tings" or frame.get("webhook_id") != destination["id"]: continue
        earlier = []
        for item in frame.get("tings", []):
            if item.get("data",{}).get("data",{}).get("metadata",{}).get("id") == event_id:
                matched = item
            else:
                # Ting offers one unread batch at a time. Validate and consume
                # earlier controlled-fixture events so they cannot hide this run.
                if item.get("data", {}).get("data", {}).get("sender") == "fixture":
                    run = item.get("data", {}).get("data", {}).get("metadata", {}).get("run", "")
                    if (item.get("for") != actor or item.get("type") != "tos>hook.webhook.received"
                            or item.get("data", {}).get("type") != "new_event" or not run.startswith("fixture-")):
                        raise RuntimeError("unexpected retained fixture notification")
                else:
                    old = hydrate(item)
                    if json.loads(old["request"]["body"]).get("message") != "real Hook to Ting delivery":
                        raise RuntimeError("unexpected retained provider fixture payload")
                earlier.append(item["id"])
        if earlier:
            ws_call("ack",org_id=org,webhook_id=destination["id"],message_ids=earlier,kind="delivery")
            ws_call("ack",org_id=org,webhook_id=destination["id"],message_ids=earlier,kind="read")
            drained.extend(earlier)
        if matched: break
    if not matched: raise RuntimeError("provider event did not reach Ting receiver")
    hydrated = hydrate(matched)
    if hydrated["request"]["body"].encode() != raw: raise RuntimeError("provider payload changed in transit")
    ws_call("ack",org_id=org,webhook_id=destination["id"],message_ids=[matched["id"]],kind="delivery")
    status = call("GET", f"/silicons/{actor}/events/{event_id}/publication")
    if status["state"] != "accepted_by_ting" or status["recipient_receipt"]["read"]:
        raise RuntimeError("delivery ACK reported application acceptance")
    ws_call("ack",org_id=org,webhook_id=destination["id"],message_ids=[matched["id"]],kind="read")
    status = call("GET", f"/silicons/{actor}/events/{event_id}/publication")
    if not status["recipient_receipt"]["read"]: raise RuntimeError("recipient ACK missing from Hook status")
    ws.close()
    report = {"complete":True,"hook_api":"v2","ting_commit":upstream["ting_commit"],
        "event_id":event_id,"ting_id":matched["id"],"payload_sha256":hashlib.sha256(raw).hexdigest(),
        "retained_fixture_events_consumed":len(set(drained)),
        "checks":["real signed provider HTTP ingress","Hook event and outgoing record committed",
        "dedicated IAM publisher SLT","fresh request-bound Ting send","real websocket receipt",
        "current-authority Hook hydration preserves exact raw bytes","delivery ACK distinct from read ACK","Hook live publication status confirms recipient acceptance"],
        "limitations":["Ting type seeded as fixture","native daemon/local webhook not exercised","isolated normal plane; sandbox lifecycle tested separately"]}
    fixture.private(Path(directory)/"hook-verification.json",report)
    print(json.dumps(report,indent=2), flush=True)


def refresh(directory):
    """Apply a rebuilt backend to the same owned fixture without changing origins."""
    folder, state = Path(directory), load(directory)
    env = json.loads((folder / "hook.env.private.json").read_text())
    password = next(line.split("=", 1)[1] for line in (folder / "hook-postgres.env").read_text().splitlines()
                    if line.startswith("POSTGRES_PASSWORD="))
    address = urllib.parse.urlsplit(env["HOOK_DATABASE_URL"])
    pid = state.get("pid")
    if pid:
        process = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True)
        if process.returncode == 0:
            if process.stdout.strip() != str(ROOT / "target/debug/hook-api"):
                raise RuntimeError("refusing to stop a process not owned by the Hook fixture")
            os.kill(pid, signal.SIGTERM)
            for _ in range(100):
                if subprocess.run(["kill", "-0", str(pid)], capture_output=True).returncode:
                    break
                time.sleep(.1)
            else:
                raise RuntimeError("owned Hook process did not stop")
    state["pid"] = None
    fixture.private(state_file(folder), state)
    owner_env = dict(env)
    owner_env["HOOK_MIGRATOR_DATABASE_URL"] = urllib.parse.urlunsplit((address.scheme,
        "postgres:" + urllib.parse.quote(password, safe="") + "@" + address.hostname + ":" + str(address.port),
        address.path, address.query, ""))
    if env.get("HOOK_TEST_DATABASE_URL"):
        test_address = urllib.parse.urlsplit(env["HOOK_TEST_DATABASE_URL"])
        if test_address.hostname != address.hostname or test_address.port != address.port:
            raise RuntimeError("test database is outside the owned Hook fixture container")
        owner_env["HOOK_TEST_MIGRATOR_DATABASE_URL"] = urllib.parse.urlunsplit((test_address.scheme,
            "postgres:" + urllib.parse.quote(password, safe="") + "@" + test_address.hostname + ":" + str(test_address.port),
            test_address.path, test_address.query, ""))
    migrated = subprocess.run([str(ROOT / "target/debug/hook-migrate")], env=owner_env, cwd=folder,
                              capture_output=True, timeout=60)
    if migrated.returncode:
        fixture.private(folder / "hook-migrate.log", (migrated.stdout + migrated.stderr).decode(errors="replace"))
        raise RuntimeError("Hook fixture migration failed; inspect private hook-migrate.log")
    fixture.command(["docker", "exec", "-i", state["container"], "psql", "-U", "postgres", "-d", "hook",
        "-v", "ON_ERROR_STOP=1", "-v", "api_role=hook_api", "-v", "worker_role=hook_worker"],
        stdin=(ROOT / "deploy/postgres/grant-runtime.sql").read_bytes(), log=folder / "hook-grants.log")
    if env.get("HOOK_TEST_DATABASE_URL"):
        fixture.command(["docker", "exec", "-i", state["container"], "psql", "-U", "postgres", "-d", test_address.path.lstrip("/"),
            "-v", "ON_ERROR_STOP=1", "-v", "api_role=hook_api", "-v", "worker_role=hook_worker"],
            stdin=(ROOT / "deploy/postgres/grant-runtime.sql").read_bytes(), log=folder / "hook-grants.log")
    with open(folder / "hook-api.log", "ab") as log:
        process = subprocess.Popen([str(ROOT / "target/debug/hook-api")], env=env, cwd=folder,
                                   stdout=log, stderr=log, start_new_session=True)
    state["pid"] = process.pid
    state["binary_sha256"] = hashlib.sha256((ROOT / "target/debug/hook-api").read_bytes()).hexdigest()
    state["binary_inode"] = (ROOT / "target/debug/hook-api").stat().st_ino
    fixture.private(state_file(folder), state)
    fixture.wait_health(state["url"], "/readyz")
    print(f"HOOK_REFRESHED {state['url']}", flush=True)


def cleanup(directory):
    state = load(directory)
    pid = state.get("pid")
    if pid:
        result = subprocess.run(["ps","-p",str(pid),"-o","command="],capture_output=True,text=True)
        if str(ROOT/"target/debug/hook-api") in result.stdout:
            os.kill(pid, signal.SIGTERM)
    fixture.command(["docker","rm","-f",state["container"]])
    state["cleaned"] = True
    fixture.private(state_file(directory),state)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=["setup","verify","refresh","cleanup"])
    parser.add_argument("directory",type=Path)
    args = parser.parse_args()
    {"setup":setup,"verify":verify,"refresh":refresh,"cleanup":cleanup}[args.action](args.directory.resolve())
