"""Scenario 9: Silicon Accounts stops answering; Hook keeps serving what it can and names the cause."""

import json
import os
import signal
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

from support import Stop

RELAY = Path(__file__).resolve().parent / "relay.py"


def start_relay(h, port, target):
    log = open(h.dev.logs / "accounts-relay.log", "a")
    process = subprocess.Popen([sys.executable, str(RELAY), str(port), str(target)], stdout=log,
                               stderr=subprocess.STDOUT, start_new_session=True)
    (h.dev.pids / "accounts-relay").write_text(f"{process.pid}\n")
    time.sleep(0.4)
    if process.poll() is not None:
        raise Stop(f"the relay could not listen on {port}")
    return process


def stop_relay(h, process):
    if process.poll() is None:
        os.kill(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    (h.dev.pids / "accounts-relay").unlink(missing_ok=True)


def scenario_9(h):
    h.begin(9, "Silicon Accounts stops answering: local checks and ingress keep working, the rest says why")
    relay_port = h.dev.base + 3
    target_port = urllib.parse.urlsplit(h.accounts_api).port or 80
    stack = dict(h.dev.stack, accounts_api_url=f"http://127.0.0.1:{relay_port}")
    stack_file = h.work / "stack-via-relay.json"
    descriptor = os.open(stack_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(stack, output)
    relay = start_relay(h, relay_port, target_port)
    try:
        result = h.dev_command("restart", env={"HOOK_DEV_STACK_FILE": str(stack_file)})
        h.check("Hook restarted with Silicon Accounts reached through a relay on base+3",
                result.get("ready") and result.get("webhook") == "kept", {k: result.get(k) for k in ("ready", "webhook")},
                critical=True)
        status, _ = h.call("GET", f"silicons/{h.s1.uuid}/hooks", h.c1)
        h.check("with Silicon Accounts reachable, the custodian reads the hooks (keys fetched)", status == 200,
                {"status": status})
        stop_relay(h, relay)
        status, _ = h.call("GET", f"silicons/{h.s1.uuid}/hooks", h.c1)
        h.check("cut off: reads verified locally keep working", status == 200, {"status": status})
        code, out, err = h.hook(h.s1.home, "login", "status", "--json")
        h.check("cut off: hook login status still says signed in", code == 0 and out.get("authenticated") is True,
                out or err)
        code, out, err = h.hook(h.s1.home, "--json", "create", "DuringOutage", "--unsigned")
        error = h.hook_json_error(err)
        h.check("cut off: creating a hook (which must confirm the sign-in) is refused as accounts_unavailable",
                code == 1 and error.get("code") == "accounts_unavailable" and error.get("status") == 503, error)
        code, out, err = h.hook(h.s1.home, "login", "status", "--offline", "--json")
        h.check("…and the CLI keeps its sign-in", code == 0 and out.get("authenticated") is True, out or err)
        status, _ = h.provider_post(h.local_demo["endpoint_url"], {"during": "an Accounts outage"})
        h.check("cut off: provider ingress never needs Silicon Accounts", status == 200, {"status": status})
        relay = start_relay(h, relay_port, target_port)
        code, out, err = h.hook(h.s1.home, "create", "AfterOutage", "--unsigned")
        h.check("Silicon Accounts back: the same command succeeds", code == 0, err or None)
    finally:
        stop_relay(h, relay)
