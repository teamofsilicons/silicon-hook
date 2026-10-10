"""Shared plumbing for Hook's end-to-end run against a Silicon Accounts test stack.

Everything here talks to real processes: the Hook API and CLI built from this
repository, the Silicon Accounts test stack, its CLI, and the stack's helper
that mints test identities (`mint.mts`). Tokens, secrets, STKs and short-lived
tokens are kept in memory and never printed.
"""

import base64
import hashlib
import hmac
import json
import os
import random
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS))
import dev_accounts  # noqa: E402  (scripts/dev_accounts.py)

http = dev_accounts.http
SECRET_KEYS = re.compile(r"token|secret|stk|slt|password|code_verifier", re.IGNORECASE)
SECRET_VALUES = re.compile(r"^(sat_|sar_|slt_|stk-|whsec_|sap_|sapr_|sa_app_|v1\.|eyJ)")


class Stop(Exception):
    """A step the rest of the run depends on failed."""


def redact(value):
    if isinstance(value, dict):
        return {k: ("<redacted>" if SECRET_KEYS.search(k) and isinstance(v, str) and v else redact(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str) and SECRET_VALUES.match(value):
        return "<redacted>"
    return value


def short(value, limit=400):
    text = json.dumps(redact(value), separators=(",", ":"), default=str) if not isinstance(value, str) else value
    return text if len(text) <= limit else text[:limit] + "…"


def required_env(name, what):
    value = os.environ.get(name, "").strip()
    if not value:
        raise Stop(f"{name} is not set: {what}")
    return value


class Identity:
    """A test account: what the stack returned for it, plus the tokens the run collects."""

    def __init__(self, label, **fields):
        self.label = label
        self.uuid = fields.get("uuid")
        self.id = fields.get("id")
        self.kind = fields.get("kind")
        self.stk = fields.get("stk")
        self.email = fields.get("email")
        self.custodian = fields.get("custodian")
        self.token = None          # access token issued to Hook
        self.first_party = None    # Silicon Accounts' own access token (account management)
        self.home = None           # SILICON_HOME of its hook CLI

    def __repr__(self):
        return f"{self.label}({self.id}, uuid {self.uuid})"


class Harness:
    def __init__(self, suffix=None, verbose=False):
        self.dev = dev_accounts.Config()
        self.app_id = self.dev.app_id
        self.api = self.dev.api_url
        self.accounts_api = self.dev.accounts_api_url
        self.accounts_url = self.dev.accounts_url
        self.mint_script = required_env("HOOK_E2E_MINT", "the path of the stack's mint.mts identity helper")
        self.tsx = required_env("HOOK_E2E_TSX", "the tsx binary that runs mint.mts")
        self.accounts_cli_bin = required_env("HOOK_E2E_ACCOUNTS_CLI", "the silicon-accounts CLI built for the test stack")
        self.hook_bin = str(self.dev.bin_dir / "hook")
        self.suffix = suffix or f"{random.randint(10000, 99999)}"
        self.verbose = verbose
        self.work = self.dev.state / f"e2e-{self.suffix}"
        self.work.mkdir(parents=True, exist_ok=True)
        self.results = []
        self.scenario = "setup"
        self.web_redirect = f"http://localhost:{self.dev.base}/auth/callback"
        self.app_creds = (self.app_id, self.dev.app_secret(self.app_id))
        self.webhook_secret = None

    # --- recording -------------------------------------------------------------------------------------------
    def begin(self, number, title):
        self.scenario = str(number)
        print(f"\n## Scenario {number}: {title}", flush=True)

    def note(self, text):
        print(f"   {text}", flush=True)

    def check(self, name, ok, shown=None, critical=False):
        ok = bool(ok)
        self.results.append({"scenario": self.scenario, "check": name, "ok": ok})
        line = f"{'PASS' if ok else 'FAIL'} [{self.scenario}] {name}"
        if shown is not None and (not ok or self.verbose):
            line += f"\n      -> {short(shown, 700 if not ok else 300)}"
        elif shown is not None:
            line += f"  ({short(shown, 160)})"
        print(line, flush=True)
        if critical and not ok:
            raise Stop(f"{name} failed; later steps depend on it")
        return ok

    # --- identities --------------------------------------------------------------------------------------------
    def mint(self, *args, timeout=120):
        argv = [self.tsx, self.mint_script, *args]
        for attempt in range(3):
            result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                    env={**os.environ, "ACCOUNTS_URL": self.accounts_api})
            if result.returncode == 0:
                return json.loads(result.stdout)
            limited = "too many" in result.stderr.lower() or "rate" in result.stderr.lower()
            if attempt < 2 and limited:
                self.note(f"mint {args[0]}: the stack is rate limiting codes; waiting 40 s (its janitor resets buckets)")
                time.sleep(40)
                continue
            raise Stop(f"mint {args[0]} failed: {result.stderr.strip()[-600:]}")
        raise Stop("unreachable")

    def home(self, label):
        path = self.work / label
        path.mkdir(parents=True, exist_ok=True)
        return path

    # --- Hook API ---------------------------------------------------------------------------------------------
    def call(self, method, path, who=None, body=None, idempotent=False, headers=None, token=None, raw=None):
        url = path if path.startswith("http") else f"{self.api}{path if path.startswith('/') else '/api/v3/' + path}"
        request_headers = dict(headers or {})
        if idempotent:
            request_headers["Idempotency-Key"] = f"e2e-{uuid.uuid4()}"
        bearer = token or (who.token if who is not None else None)
        if raw is not None:
            return self.raw_post(url, raw, request_headers)
        status, parsed, _ = http(method, url, body=body, bearer=bearer, headers=request_headers)
        return status, parsed

    def raw_post(self, url, body, headers):
        import urllib.request
        import urllib.error
        request = urllib.request.Request(url, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                payload = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            payload, status = error.read(), error.code
        try:
            return status, json.loads(payload) if payload else None
        except ValueError:
            return status, payload.decode(errors="replace")

    def provider_post(self, url, payload, secret=None, extra_headers=None):
        """A provider delivery; with `secret`, signed the Standard Webhooks way (Hook's default policy)."""
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "hook-e2e-provider/1"}
        if secret is not None:
            message_id = f"msg_{uuid.uuid4().hex}"
            timestamp = str(int(time.time()))
            digest = hmac.new(secret.encode(), f"{message_id}.{timestamp}.".encode() + body, hashlib.sha256).digest()
            headers.update({"webhook-id": message_id, "webhook-timestamp": timestamp,
                            "webhook-signature": f"v1,{base64.b64encode(digest).decode()}"})
        headers.update(extra_headers or {})
        return self.raw_post(url, body, headers)

    # --- Silicon Accounts --------------------------------------------------------------------------------------
    def accounts(self, method, path, who=None, body=None, basic=False, idempotent=False, token=None):
        headers = {"Idempotency-Key": f"e2e-{uuid.uuid4()}"} if idempotent else None
        status, parsed, _ = http(method, f"{self.accounts_api}{path}", body=body,
                                 basic=self.app_creds if basic else None,
                                 bearer=None if basic else (token or (who.first_party if who else None)),
                                 headers=headers)
        return status, parsed

    def deliveries(self, limit=50):
        status, body = self.accounts("GET", f"/v1/apps/{self.app_id}/webhook/deliveries?limit={limit}", basic=True)
        return body.get("items", []) if status == 200 else []

    def wait_delivery(self, event_type, account_uuid, since_ids=(), timeout=45):
        """Waits for the stack to deliver an event of this type about this account to Hook."""
        deadline = time.time() + timeout
        seen = None
        while time.time() < deadline:
            for item in self.deliveries():
                if item.get("type") == event_type and item.get("account_uuid") == account_uuid \
                        and item["id"] not in since_ids:
                    seen = item
                    if item.get("status") == "delivered":
                        status, detail = self.accounts("GET", f"/v1/apps/{self.app_id}/webhook/deliveries/{item['id']}", basic=True)
                        return detail if status == 200 else item
            time.sleep(0.5)
        raise Stop(f"the stack did not deliver {event_type} for {account_uuid} within {timeout} s (last: {short(seen)})")

    def delivery_ids(self):
        return {item["id"] for item in self.deliveries(100)}

    # --- the hook CLI ------------------------------------------------------------------------------------------
    def cli_env(self, home):
        return {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(home),
            "SILICON_HOME": str(home),
            "ACCOUNTS_URL": self.accounts_url,
            "SILICON_HOOK_URL": self.api,
            "LANG": "C.UTF-8",
        }

    def hook(self, home, *args, stdin=None, timeout=90):
        """Runs the hook CLI with its own home; returns (exit code, parsed stdout, stderr)."""
        result = subprocess.run([self.hook_bin, *args], input=stdin, capture_output=True, text=True,
                                env=self.cli_env(home), timeout=timeout)
        out = result.stdout.strip()
        try:
            parsed = json.loads(out) if out else None
        except ValueError:
            parsed = out
        return result.returncode, parsed, result.stderr.strip()

    def hook_json_error(self, stderr):
        try:
            return json.loads(stderr.strip().splitlines()[-1]).get("error", {})
        except (ValueError, IndexError, AttributeError):
            return {"raw": stderr[-300:]}

    def device_login(self, home, approve_email):
        """`hook login` as a Carbon: read the code it prints, approve it at the stack, wait for it to finish."""
        process = subprocess.Popen([self.hook_bin, "login", "--json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env=self.cli_env(home))
        first = process.stdout.readline()
        try:
            device = json.loads(first)
        except ValueError:
            process.kill()
            raise Stop(f"hook login printed no device code: {first!r} {process.stderr.read()[-300:]}")
        approval = self.mint("approve", "--email", approve_email, "--code", device["user_code"])
        try:
            rest, err = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            raise Stop("hook login did not finish within 60 s of the approval")
        lines = [line for line in rest.splitlines() if line.strip()]
        final = json.loads(lines[-1]) if lines else None
        return device, approval, process.returncode, final, err

    # --- the Silicon Accounts CLI (test stack only) ------------------------------------------------------------
    def accounts_cli(self, home, *args, stdin=None, timeout=60):
        argv = [self.accounts_cli_bin, "--url", self.accounts_url, "--home", str(home), "--json", *args]
        result = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout,
                                env={"PATH": "/usr/bin:/bin", "HOME": str(home), "ACCOUNTS_HOME": str(home)})
        out = result.stdout.strip()
        try:
            parsed = json.loads(out) if out else None
        except ValueError:
            parsed = out
        return result.returncode, parsed, result.stderr.strip()

    # --- Hook's own Silicon Accounts webhook -------------------------------------------------------------------
    def load_webhook_secret(self):
        secrets = dev_accounts.load_secrets(self.dev)
        self.webhook_secret = secrets.get("WEBHOOK_SECRET")
        if not self.webhook_secret:
            raise Stop("no webhook secret in the dev state; run scripts/dev-accounts.sh start")

    def signed_delivery(self, payload, secret=None, timestamp=None, signature=None):
        """Posts an Accounts-style delivery to Hook's /webhook, signed like Silicon Accounts signs."""
        body = json.dumps(payload, separators=(",", ":")).encode()
        ts = str(int(timestamp if timestamp is not None else time.time()))
        key = (secret if secret is not None else self.webhook_secret).encode()
        digest = hmac.new(key, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "X-Accounts-Event-Id": payload.get("event_id", ""),
            "X-Accounts-Event-Type": payload.get("type", ""),
            "X-Accounts-Timestamp": ts,
        }
        if signature is not False:
            headers["X-Accounts-Signature"] = signature or f"v1={digest}"
        return self.raw_post(f"{self.api}/webhook", body, headers)

    def hook_log_lines(self, needle):
        log = self.dev.logs / "hook-api.log"
        try:
            text = re.sub(r"\x1b\[[0-9;]*m", "", log.read_text(errors="replace"))
        except OSError:
            return []
        return [line for line in text.splitlines() if needle in line]

    def sql(self, query):
        return dev_accounts.psql(self.dev, self.dev.database_url(database=self.dev.database), query)

    def dev_command(self, *args, env=None):
        result = subprocess.run([sys.executable, str(SCRIPTS / "dev_accounts.py"), *args],
                                capture_output=True, text=True,
                                env={**os.environ, "HOOK_DEV_SKIP_BUILD": "1", **(env or {})}, timeout=300)
        if result.returncode != 0:
            raise Stop(f"dev-accounts {' '.join(args)} failed: {result.stderr.strip()[-500:]}")
        return json.loads(result.stdout)
