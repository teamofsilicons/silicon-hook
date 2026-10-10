#!/usr/bin/env python3
"""Run Hook on this machine against a Silicon Accounts test stack.

    scripts/dev-accounts.sh start [--ting-stub [--refuse-first-proof]]
    scripts/dev-accounts.sh restart [--ting-stub [--refuse-first-proof]]
    scripts/dev-accounts.sh status
    scripts/dev-accounts.sh stop
    scripts/dev-accounts.sh down

`start` builds the binaries, creates and migrates the database (with separate
API and worker roles and the real grant manifest), points Hook's Silicon
Accounts webhook at the local API, starts hook-api and hook-worker, and proves
the webhook works with a signed test ping. Running it again changes nothing
that is already right. `stop` ends the processes and keeps the data, the
encryption keys and the webhook secret, so `start` (or `restart`) brings back
the same Hook. `down` also drops the database and its roles, removes Hook's
webhook from the stack and forgets the keys.

With `--ting-stub`, a stand-in for Ting (scripts/ting_stub.py) runs on base+2
and Hook delivers to it: it checks every Silicon Accounts proof Hook presents
with the receiving app's own credentials. `--refuse-first-proof` makes it
refuse the first send proof once, so Hook has to renew it.

Settings (environment):
  HOOK_DEV_STACK_FILE    JSON describing the stack (required): accounts_public_url,
                         accounts_api_url, apps.<app>.app_secret
  HOOK_DEV_PORT_BASE     port block base (default 4200): API base+1, Ting stub base+2
  HOOK_DEV_DATABASE      database name (default hook_e2e); roles <db>_api, <db>_worker
  HOOK_DEV_POSTGRES_URL  administrator URL (default postgres://postgres@127.0.0.1:5460/postgres)
  HOOK_DEV_PSQL          psql binary (default: psql on PATH, else Homebrew's postgresql@16)
  HOOK_DEV_STATE_DIR     pids, logs, keys and the webhook secret (default <repo>/.mig)
  HOOK_DEV_BIN_DIR       built binaries (default ${CARGO_TARGET_DIR:-<repo>/target}/debug)
  HOOK_DEV_SKIP_BUILD=1  use the binaries as they are
  HOOK_DEV_APP_ID        Hook's app id at the stack (default hook)
  HOOK_DEV_TING_RECEIVER app the Ting stub verifies proofs as (default interface: the
                         stack has no Ting app, so Hook's proofs name this app instead)

Secrets never appear in arguments or output: the app secrets stay in the stack
file, and the keys and webhook secret Hook needs are kept in
<state>/dev-accounts.env (mode 0600, git-ignored).
"""

import base64
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROCESSES = ("ting-stub", "hook-api", "hook-worker")


class Failure(Exception):
    """A step failed; the message says what and why."""


def env(name, default=None):
    value = os.environ.get(name, "").strip()
    return value or default


class Config:
    def __init__(self):
        self.app_id = env("HOOK_DEV_APP_ID", "hook")
        self.base = int(env("HOOK_DEV_PORT_BASE", "4200"))
        self.api_port = self.base + 1
        self.ting_port = self.base + 2
        self.database = env("HOOK_DEV_DATABASE", "hook_e2e")
        if not self.database.replace("_", "").isalnum() or not self.database.startswith("hook"):
            raise Failure("HOOK_DEV_DATABASE must start with 'hook' and hold only letters, digits and _")
        self.api_role = f"{self.database}_api"
        self.worker_role = f"{self.database}_worker"
        self.admin_url = env("HOOK_DEV_POSTGRES_URL", "postgres://postgres@127.0.0.1:5460/postgres")
        self.psql = env("HOOK_DEV_PSQL") or shutil.which("psql") or "/opt/homebrew/opt/postgresql@16/bin/psql"
        self.state = Path(env("HOOK_DEV_STATE_DIR", str(REPO / ".mig")))
        self.pids = self.state / "pids"
        self.logs = self.state / "logs"
        self.run_dir = self.state / "run"
        self.secrets_file = self.state / "dev-accounts.env"
        self.ting_journal = self.state / "ting-stub.jsonl"
        target = Path(env("CARGO_TARGET_DIR", str(REPO / "target")))
        self.bin_dir = Path(env("HOOK_DEV_BIN_DIR", str(target / "debug")))
        self.skip_build = env("HOOK_DEV_SKIP_BUILD") == "1"
        self.ting_receiver = env("HOOK_DEV_TING_RECEIVER", "interface")
        self.api_url = f"http://127.0.0.1:{self.api_port}"
        self.webhook_url = f"{self.api_url}/webhook"
        self.stack_file = env("HOOK_DEV_STACK_FILE")
        self._stack = None

    @property
    def stack(self):
        if self._stack is None:
            if not self.stack_file:
                raise Failure("HOOK_DEV_STACK_FILE is not set: name the JSON file that describes the Silicon Accounts test stack")
            try:
                self._stack = json.loads(Path(self.stack_file).read_text())
            except (OSError, ValueError) as error:
                raise Failure(f"cannot read HOOK_DEV_STACK_FILE {self.stack_file}: {error}") from None
            for key in ("accounts_public_url", "accounts_api_url"):
                if not self._stack.get(key):
                    raise Failure(f"{self.stack_file} has no {key}")
        return self._stack

    @property
    def accounts_url(self):
        return self.stack["accounts_public_url"].rstrip("/")

    @property
    def accounts_api_url(self):
        return self.stack["accounts_api_url"].rstrip("/")

    def app_secret(self, app_id):
        secret = (self.stack.get("apps", {}).get(app_id) or {}).get("app_secret")
        if not secret:
            raise Failure(f"{self.stack_file} has no app secret for '{app_id}'")
        return secret

    def database_url(self, role=None, database=None):
        """The administrator URL with another role (no password: local trust auth) or database."""
        parts = urllib.parse.urlsplit(self.admin_url)
        netloc = parts.netloc
        if role is not None:
            host = netloc.rsplit("@", 1)[-1]
            netloc = f"{role}@{host}"
        path = f"/{database}" if database else parts.path
        return urllib.parse.urlunsplit((parts.scheme, netloc, path, parts.query, ""))


def http(method, url, body=None, basic=None, bearer=None, headers=None, timeout=15):
    """One JSON request; returns (status, parsed body or text, response headers)."""
    request_headers = {"Accept": "application/json"}
    request_headers.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        request_headers["Content-Type"] = "application/json"
    if basic is not None:
        token = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        request_headers["Authorization"] = f"Basic {token}"
    if bearer is not None:
        request_headers["Authorization"] = f"Bearer {bearer}"
    request = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            status, response_headers = response.status, dict(response.headers)
    except urllib.error.HTTPError as error:
        raw, status, response_headers = error.read(), error.code, dict(error.headers)
    except (urllib.error.URLError, OSError) as error:
        return 0, str(getattr(error, "reason", error)), {}
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = raw.decode(errors="replace")[:500]
    return status, parsed, response_headers


def psql(config, url, *commands, variables=None, file=None, quiet=True):
    """Runs psql; each command separately (DROP DATABASE refuses a transaction block)."""
    argv = [config.psql, url, "-X", "-v", "ON_ERROR_STOP=1", "-At"]
    if quiet:
        argv.append("-q")
    for name, value in (variables or {}).items():
        argv.append(f"--set={name}={value}")
    for command in commands:
        argv.append(f"--command={command}")
    if file:
        argv.append(f"--file={file}")
    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode != 0:
        raise Failure(f"psql failed ({result.returncode}): {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


def ensure_database(config):
    exists = psql(config, config.admin_url, f"SELECT 1 FROM pg_database WHERE datname = '{config.database}'")
    if not exists:
        psql(config, config.admin_url, f'CREATE DATABASE "{config.database}"')
    for role in (config.api_role, config.worker_role):
        if not psql(config, config.admin_url, f"SELECT 1 FROM pg_roles WHERE rolname = '{role}'"):
            psql(config, config.admin_url, f'CREATE ROLE "{role}" LOGIN')
    owner_url = config.database_url(database=config.database)
    migrate_env = clean_env(config)
    migrate_env["HOOK_MIGRATOR_DATABASE_URL"] = owner_url
    log = config.logs / "hook-migrate.log"
    with open(log, "w") as output:
        result = subprocess.run([str(config.bin_dir / "hook-migrate")], env=migrate_env, cwd=config.run_dir,
                                stdout=output, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise Failure(f"hook-migrate failed ({result.returncode}); see {log}")
    psql(config, owner_url, variables={"api_role": config.api_role, "worker_role": config.worker_role},
         file=str(REPO / "deploy/postgres/grant-runtime.sql"))
    return exists != "1"


def drop_database(config):
    psql(config, config.admin_url, f'DROP DATABASE IF EXISTS "{config.database}" WITH (FORCE)')
    for role in (config.api_role, config.worker_role):
        psql(config, config.admin_url, f'DROP ROLE IF EXISTS "{role}"')


def clean_env(config):
    """A minimal environment: no inherited HOOK_*/ACCOUNTS_* settings leak into the processes."""
    keep = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "USER")
    result = {name: os.environ[name] for name in keep if name in os.environ}
    result["HOOK_ENVIRONMENT"] = "development"
    result["NO_COLOR"] = "1"  # plain log files
    return result


def random_key():
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


def load_secrets(config):
    values = {}
    if config.secrets_file.exists():
        for line in config.secrets_file.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                name, value = line.split("=", 1)
                values[name] = value
    return values


def save_secrets(config, values):
    config.state.mkdir(parents=True, exist_ok=True)
    temporary = config.secrets_file.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as output:
        output.write("# Local Hook development keys and webhook secret (scripts/dev_accounts.py). Never commit.\n")
        for name in sorted(values):
            output.write(f"{name}={values[name]}\n")
    os.replace(temporary, config.secrets_file)


def ensure_keys(config, secrets):
    """Encryption and cursor keys survive restarts, so stored hook secrets stay readable."""
    changed = False
    for name in ("ENCRYPTION_KEY", "CURSOR_SIGNING_KEY"):
        if not secrets.get(name):
            secrets[name] = random_key()
            changed = True
    if changed:
        save_secrets(config, secrets)


def ensure_webhook(config, secrets):
    """Points Hook's app webhook at the local API with a secret this script knows."""
    creds = (config.app_id, config.app_secret(config.app_id))
    base = f"{config.accounts_api_url}/v1/apps/{config.app_id}/webhook"
    status, current, _ = http("GET", base, basic=creds)
    if status != 200:
        raise Failure(f"GET {base} answered {status}: {current}")
    known = secrets.get("WEBHOOK_SECRET") and secrets.get("WEBHOOK_URL") == config.webhook_url
    if known and current.get("url") == config.webhook_url and current.get("secret_set"):
        if current.get("events") is None:
            return "kept"
        # Hook acts on several updates; picks made elsewhere would hide some (PUT keeps the secret).
        status, saved, _ = http("PUT", base, body={"url": config.webhook_url, "events": None}, basic=creds,
                                headers={"Idempotency-Key": f"hook-dev-{uuid.uuid4()}"})
        if status != 200:
            raise Failure(f"PUT {base} answered {status}: {redact(saved)}")
        return "kept (every update restored)"
    # A new secret first (kept by the PUT that follows), saved before Hook needs it.
    status, generated, _ = http("POST", f"{base}/generate-secret", basic=creds,
                                headers={"Idempotency-Key": f"hook-dev-{uuid.uuid4()}"})
    if status != 200 or not (generated or {}).get("secret"):
        raise Failure(f"generate-secret answered {status}: {redact(generated)}")
    secrets["WEBHOOK_SECRET"] = generated["secret"]
    secrets["WEBHOOK_URL"] = config.webhook_url
    save_secrets(config, secrets)
    status, saved, _ = http("PUT", base, body={"url": config.webhook_url, "events": None}, basic=creds,
                            headers={"Idempotency-Key": f"hook-dev-{uuid.uuid4()}"})
    if status != 200:
        raise Failure(f"PUT {base} answered {status}: {redact(saved)}")
    if saved.get("secret"):
        secrets["WEBHOOK_SECRET"] = saved["secret"]
        save_secrets(config, secrets)
    return "registered"


def remove_webhook(config):
    creds = (config.app_id, config.app_secret(config.app_id))
    base = f"{config.accounts_api_url}/v1/apps/{config.app_id}/webhook"
    status, current, _ = http("GET", base, basic=creds)
    if status == 200 and current.get("url") == config.webhook_url:
        status, body, _ = http("DELETE", base, basic=creds)
        if status not in (200, 204):
            raise Failure(f"DELETE {base} answered {status}: {body}")
        return "removed"
    return "left alone (it does not point at this Hook)" if status == 200 and current.get("url") else "not set"


def prove_webhook(config):
    """Queues a ping at the stack and waits until Hook acknowledged it."""
    creds = (config.app_id, config.app_secret(config.app_id))
    base = f"{config.accounts_api_url}/v1/apps/{config.app_id}/webhook"
    status, queued, _ = http("POST", f"{base}/test", basic=creds,
                             headers={"Idempotency-Key": f"hook-dev-{uuid.uuid4()}"})
    if status not in (200, 201, 202):
        raise Failure(f"webhook test answered {status}: {queued}")
    delivery = queued["delivery_id"]
    deadline = time.time() + 30
    detail = None
    while time.time() < deadline:
        status, detail, _ = http("GET", f"{base}/deliveries/{delivery}", basic=creds)
        if status == 200 and detail.get("status") == "delivered":
            return delivery
        time.sleep(0.5)
    raise Failure(f"the stack's ping did not reach Hook within 30 s: {redact(detail)}")


def redact(value):
    if isinstance(value, dict):
        return {k: ("<redacted>" if "secret" in k or "token" in k else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def pid_of(config, name):
    try:
        pid = int((config.pids / name).read_text().strip())
    except (OSError, ValueError):
        return None
    result = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True)
    command = result.stdout.strip()
    expected = "ting_stub.py" if name == "ting-stub" else name
    return pid if result.returncode == 0 and expected in command else None


def listening(port):
    import socket
    with socket.socket() as probe:
        probe.settimeout(0.3)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def launch(config, name, argv, process_env):
    log = open(config.logs / f"{name}.log", "a")
    log.write(f"\n=== {time.strftime('%Y-%m-%dT%H:%M:%S')} start {name}\n")
    log.flush()
    process = subprocess.Popen(argv, env=process_env, cwd=config.run_dir, stdin=subprocess.DEVNULL,
                               stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    (config.pids / name).write_text(f"{process.pid}\n")
    return process


def wait_for(url, seconds, process=None, expect=200):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            return False
        status, _, _ = http("GET", url, timeout=2)
        if status == expect:
            return True
        time.sleep(0.2)
    return False


def service_env(config, secrets, ting):
    process_env = clean_env(config)
    process_env.update({
        "HOOK_LOG_FILTER": "silicon_hook=info,tower_http=warn",
        "HOOK_DATABASE_URL": config.database_url(config.api_role, config.database),
        "HOOK_BIND_ADDR": f"127.0.0.1:{config.api_port}",
        "HOOK_PUBLIC_BASE_URL": config.api_url,
        "HOOK_SHUTDOWN_TIMEOUT_SECONDS": "5",
        "HOOK_ENCRYPTION_KEYS": f"1:{secrets['ENCRYPTION_KEY']}",
        "HOOK_ENCRYPTION_CURRENT_VERSION": "1",
        "HOOK_CURSOR_SIGNING_KEY": secrets["CURSOR_SIGNING_KEY"],
        "ACCOUNTS_URL": config.accounts_url,
        "ACCOUNTS_API_URL": config.accounts_api_url,
        "HOOK_APP_ID": config.app_id,
        "HOOK_APP_SECRET": config.app_secret(config.app_id),
        "HOOK_ACCOUNTS_WEBHOOK_SECRET": secrets["WEBHOOK_SECRET"],
        # Set (even empty) so a stray .env, which the binaries load, cannot add them.
        "HOOK_ACCOUNTS_WEBHOOK_PREVIOUS_SECRET": "",
        "HOOK_TING_URL": f"http://127.0.0.1:{config.ting_port}/" if ting else "",
        "HOOK_TING_APP_ID": config.ting_receiver if ting else "",
        "HOOK_TELEMETRY": "off",
        "HOOK_TELEMETRY_TABLE_KEY": "",
    })
    return process_env


def worker_env(config):
    process_env = clean_env(config)
    process_env.update({
        "HOOK_LOG_FILTER": "silicon_hook=info",
        "HOOK_DATABASE_URL": config.database_url(config.worker_role, config.database),
        "HOOK_SHUTDOWN_TIMEOUT_SECONDS": "5",
        "HOOK_TELEMETRY": "off",
        "HOOK_TELEMETRY_TABLE_KEY": "",
    })
    return process_env


def prepare_state(config):
    for directory in (config.state, config.pids, config.logs, config.run_dir):
        directory.mkdir(parents=True, exist_ok=True)
    ignore = config.state / ".gitignore"
    if not ignore.exists():
        ignore.write_text("*\n")


def build(config):
    if config.skip_build:
        return
    result = subprocess.run(["cargo", "build", "--locked", "--workspace", "--bins"], cwd=REPO)
    if result.returncode != 0:
        raise Failure("cargo build failed")


def start(config, ting=False, refuse_first_proof=False):
    prepare_state(config)
    status, _, _ = http("GET", f"{config.accounts_api_url}/.well-known/jwks.json", timeout=5)
    if status != 200:
        raise Failure(f"the Silicon Accounts stack at {config.accounts_api_url} is not reachable (status {status})")
    running = [name for name in PROCESSES if pid_of(config, name)]
    if running:
        if ting != bool(pid_of(config, "ting-stub")):
            raise Failure("Hook is running with another Ting setting; use restart")
        if pid_of(config, "hook-api") and wait_for(f"{config.api_url}/readyz", 5):
            return {"already_running": running, **describe(config)}
        stop(config)  # ours, but not answering: start them again
    for port in (config.api_port, config.ting_port) if ting else (config.api_port,):
        if listening(port):
            raise Failure(f"port {port} is in use by something this script did not start")
    build(config)
    created = ensure_database(config)
    secrets = load_secrets(config)
    ensure_keys(config, secrets)
    webhook = ensure_webhook(config, secrets)
    if ting:
        stub_env = clean_env(config)
        stub_env.update({
            "ACCOUNTS_API_URL": config.accounts_api_url,
            "TING_STUB_APP_ID": config.ting_receiver,
            "TING_STUB_APP_SECRET": config.app_secret(config.ting_receiver),
            "TING_STUB_ISSUER": config.app_id,
        })
        # Optional delivery on to a receiving host (see scripts/ting_stub.py).
        stub_env.update({name: value for name, value in os.environ.items() if name.startswith("TING_STUB_FORWARD_")})
        argv = [sys.executable, str(REPO / "scripts/ting_stub.py"), "--port", str(config.ting_port),
                "--journal", str(config.ting_journal)]
        if refuse_first_proof:
            argv.append("--refuse-first-proof")
        stub = launch(config, "ting-stub", argv, stub_env)
        if not wait_for(f"http://127.0.0.1:{config.ting_port}/healthz", 10, stub):
            raise Failure(f"the Ting stub did not start; see {config.logs / 'ting-stub.log'}")
    api = launch(config, "hook-api", [str(config.bin_dir / "hook-api")], service_env(config, secrets, ting))
    if not wait_for(f"{config.api_url}/readyz", 30, api):
        raise Failure(f"hook-api did not become ready; see {config.logs / 'hook-api.log'}")
    worker = launch(config, "hook-worker", [str(config.bin_dir / "hook-worker")], worker_env(config))
    time.sleep(1)
    if worker.poll() is not None:
        raise Failure(f"hook-worker exited ({worker.returncode}); see {config.logs / 'hook-worker.log'}")
    delivery = prove_webhook(config)
    return {"database_state": "created" if created else "kept", "webhook": webhook,
            "webhook_ping": f"delivered ({delivery})", **describe(config)}


def stop(config):
    stopped = []
    for name in reversed(PROCESSES):
        pid = pid_of(config, name)
        if pid is None:
            if config.pids.exists():
                (config.pids / name).unlink(missing_ok=True)
            continue
        os.kill(pid, signal.SIGTERM)
        for _ in range(100):
            if pid_of(config, name) is None:
                break
            time.sleep(0.1)
        else:
            os.kill(pid, signal.SIGKILL)
        (config.pids / name).unlink(missing_ok=True)
        stopped.append(name)
    return {"stopped": stopped}


def down(config):
    result = stop(config)
    result["webhook"] = remove_webhook(config)
    drop_database(config)
    result["database"] = f"dropped {config.database} and roles {config.api_role}, {config.worker_role}"
    for path in (config.secrets_file, config.ting_journal):
        path.unlink(missing_ok=True)
    return result


def describe(config):
    processes = {name: pid_of(config, name) for name in PROCESSES}
    return {
        "api": config.api_url,
        "ready": wait_for(f"{config.api_url}/readyz", 1) if processes["hook-api"] else False,
        "ting_stub": f"http://127.0.0.1:{config.ting_port}" if processes["ting-stub"] else None,
        "accounts": config.accounts_url,
        "webhook_url": config.webhook_url,
        "database": config.database_url(database=config.database),
        "pids": {name: pid for name, pid in processes.items() if pid},
        "logs": str(config.logs),
    }


def status(config):
    result = describe(config)
    try:
        creds = (config.app_id, config.app_secret(config.app_id))
        code, webhook, _ = http("GET", f"{config.accounts_api_url}/v1/apps/{config.app_id}/webhook", basic=creds)
        result["stack_webhook"] = {"url": webhook.get("url"), "secret_set": webhook.get("secret_set")} if code == 200 else code
    except Failure as error:
        result["stack_webhook"] = str(error)
    return result


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0 if argv else 2
    command, flags = argv[0], set(argv[1:])
    unknown = flags - {"--ting-stub", "--refuse-first-proof"}
    if unknown or (flags and command not in ("start", "restart")):
        print(f"dev-accounts: unexpected arguments {' '.join(sorted(flags))} for {command}", file=sys.stderr)
        return 2
    try:
        config = Config()
        ting = "--ting-stub" in flags
        refuse = "--refuse-first-proof" in flags
        if command == "start":
            result = start(config, ting, refuse)
        elif command == "restart":
            stop(config)
            result = start(config, ting, refuse)
        elif command == "stop":
            result = stop(config)
        elif command == "down":
            result = down(config)
        elif command == "status":
            result = status(config)
        else:
            print(f"dev-accounts: unknown command {command} (start, restart, status, stop, down)", file=sys.stderr)
            return 2
    except Failure as error:
        print(f"dev-accounts: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
