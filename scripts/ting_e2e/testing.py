#!/usr/bin/env python3
"""Owned real IAM/Ting testing-plane fixture, driven through participant APIs.

This does not run the Honeycomb coordinator or grant production permissions.
Only the disposable normal-plane control identities are SQL fixtures. Test
identities, private app configuration, consent and OBO use the actual IAM API.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import fixture

ENDPOINTS = {**fixture.ENDPOINTS, "receivers.bootstrap": "/v1/receivers/bootstrap"}


def http(state, origin, method, path, body=None, token=None, headers=None, expected=(200,)):
    values = {"Content-Type": "application/json", **(headers or {})}
    if token:
        values["Authorization"] = "Bearer " + token
    raw = body if isinstance(body, bytes) else json.dumps(body, separators=(",", ":")).encode() if body is not None else None
    req = urllib.request.Request(origin + path, data=raw, method=method, headers=values)
    try:
        with urllib.request.urlopen(req, timeout=35) as response:
            status, data = response.status, response.read(1024 * 1024)
    except urllib.error.HTTPError as error:
        status, data = error.code, error.read(1024 * 1024)
    value = json.loads(data) if data else None
    if status not in expected:
        fixture.private(Path(state["directory"]) / "http-error.private.json", {"path": path, "status": status, "response": value})
        code = (value or {}).get("error", {}).get("code", "unknown")
        raise RuntimeError(f"{method} {path} returned HTTP {status}, code={code}; inspect private diagnostic")
    return status, value


def iam(state, method, path, body=None, actor=None):
    return http(state, state["iam_url"], method, "/api/v1" + path, body,
                token=actor, headers={"X-Testing-Environment-Key": state["testing_key"],
                    "Idempotency-Key": str(uuid.uuid4())}, expected=(200, 201, 202, 204))[1]


def management(state, method, path, body):
    return http(state, state["iam_url"], method, "/api/v1/honeycomb" + path, body,
        token=state["honeycomb_credential"], headers={
            "X-Honeycomb-Actor-Token": state["honeycomb_actor"]["access_token"],
            "Idempotency-Key": body["operation_id"]}, expected=(200, 201, 202))[1]


def lifecycle(state, operation, **extra):
    body = {"operation_id": str(uuid.uuid4()), "environment_id": state["environment_id"],
        "expected_iam_revision": state.get("iam_revision", 0), "generation": state["generation"],
        "operation": operation, **extra}
    result = management(state, "POST", f"/testing-environments/{state['environment_id']}/operations", body)
    state["iam_revision"] = result["iam_revision"]
    fixture.save(state)
    return result


def test_profile(state, label, actor, kind, tokens):
    directory = Path(state["directory"]) / "profiles" / label / ".silicon-iam"
    fixture.private(directory / "config.json", {"telemetry": False, "auto_update": False,
        "current_profile": "default", "profiles": {"default": {"url": state["iam_url"]}}})
    fixture.private(directory / "credentials.json", {"test_sessions": {"default": {
        state["environment_id"]: {"access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token", ""), "expires_at": tokens.get("expires_at") or
                (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=tokens["expires_in"])).isoformat(),
            "actor_type": kind, "actor_id": actor}}}, "testing_environment_keys": {
                "default": {state["environment_id"]: state["testing_key"]}}})


def cli(state, label, args, raw=None):
    return fixture.cli(state, label, ["--test", state["environment_id"], *args], raw)


def setup(parent_directory):
    parent = fixture.load(parent_directory)
    if parent.get("ting_version") != "0.1.4" or parent.get("ting_commit") != "3253ea193c9fc244e6ef7e5fd818240ae0ad4782":
        raise RuntimeError("testing fixture requires the pinned owned Ting 0.1.4 parent")
    directory = Path(tempfile.mkdtemp(prefix="hook-ting-e2e-testing-", dir=parent_directory)).resolve()
    directory.chmod(0o700)
    name = directory.name
    state = {"fixture_owned": True, "directory": str(directory), "network": name,
        "postgres": name + "-postgres", "iam": name + "-iam", "ting": name + "-ting",
        "containers": [], "iam_cli": parent["iam_cli"], "iam_image": parent["iam_image"],
        "direct": {}, "org_id": "tos", "org_uuid": fixture.ORG_UUID,
        "app_secrets": {app: fixture.token("ask_") for app in ("tos>hook", "tos>ting", "tos>honeycomb")},
        "honeycomb_credential": fixture.token("hck_"), "ting_control_token": secrets.token_urlsafe(36),
        "environment_id": str(uuid.uuid4()), "generation": 1, "key_version": 1,
        "testing_key": "".join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890") for _ in range(32)),
        "ting_version": "0.1.4", "ting_commit": parent["ting_commit"],
        "coverage": {"real_iam_testing_plane": True, "real_honeycomb_coordinator": False,
            "production_approval_verified": False, "test_identity_sql_seed": False}}
    fixture.save(state)
    print("TESTING_FIXTURE " + str(directory), flush=True)
    fixture.command(["docker", "network", "create", name], log=directory / "setup-error.log")
    db_password, runtime_password = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    fixture.private(directory / "postgres.env", f"POSTGRES_PASSWORD={db_password}\nPOSTGRES_DB=iam\n")
    fixture.command(["docker", "run", "-d", "--name", state["postgres"], "--network", name,
        "--network-alias", "database", "--env-file", str(directory / "postgres.env"), "postgres:16.15-bookworm"], log=directory / "setup-error.log")
    state["containers"].append(state["postgres"]); fixture.save(state)
    for _ in range(60):
        if subprocess.run(["docker", "exec", state["postgres"], "pg_isready", "-U", "postgres"], capture_output=True, timeout=5).returncode == 0:
            break
        time.sleep(.5)
    fixture.psql(state, f"CREATE ROLE silicon_iam_api NOLOGIN; CREATE ROLE silicon_iam_worker NOLOGIN; CREATE ROLE silicon_iam_key_operator NOLOGIN; CREATE ROLE fixture_api LOGIN PASSWORD {fixture.quote(runtime_password)} IN ROLE silicon_iam_api;")
    fixture.psql(state, "CREATE DATABASE iam_testing;")
    pepper = secrets.token_bytes(32)
    b64 = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
    env = {"IAM_ENVIRONMENT": "development", "IAM_BIND_ADDR": "0.0.0.0:8080",
        "IAM_ALLOW_LOCAL_PROVIDERS": "true", "IAM_EXPOSE_LOCAL_OTPS": "true", "IAM_LOG_FILTER": "error",
        "IAM_TELEMETRY": "off", "IAM_DATABASE_URL": f"postgres://fixture_api:{runtime_password}@database:5432/iam",
        "IAM_MIGRATOR_DATABASE_URL": f"postgres://postgres:{db_password}@database:5432/iam",
        "IAM_TESTING_DATABASE_URL": f"postgres://fixture_api:{runtime_password}@database:5432/iam_testing",
        "IAM_TESTING_MIGRATOR_DATABASE_URL": f"postgres://postgres:{db_password}@database:5432/iam_testing",
        "IAM_TOKEN_PEPPER_CURRENT_VERSION": "1", "IAM_TOKEN_PEPPER_KEYRING": json.dumps({"1": b64(pepper)}),
        "IAM_BLIND_INDEX_CURRENT_VERSION": "1", "IAM_BLIND_INDEX_KEYRING": json.dumps({"1": b64(secrets.token_bytes(32))}),
        "IAM_ENCRYPTION_CURRENT_VERSION": "1", "IAM_ENCRYPTION_KEYRING": json.dumps({"1": b64(secrets.token_bytes(32))}),
        "IAM_COOKIE_KEY": b64(secrets.token_bytes(32)), "IAM_PUBLIC_BASE_URL": "http://127.0.0.1:8080",
        "IAM_AUTH_BASE_URL": "http://127.0.0.1:8080", "IAM_CORS_ALLOWED_ORIGINS": "http://127.0.0.1:8080",
        "IAM_HONEYCOMB_APP_ID": "tos>honeycomb", "IAM_HONEYCOMB_CREDENTIAL_SHA256": hashlib.sha256(state["honeycomb_credential"].encode()).hexdigest()}
    fixture.private(directory / "iam.env", "".join(f"{key}={value}\n" for key, value in env.items()))
    fixture.command(["docker", "run", "--rm", "--network", name, "--env-file", str(directory / "iam.env"), state["iam_image"], "iam-migrate"], log=directory / "migration-error.log")
    grants = fixture.command(["docker", "run", "--rm", "--entrypoint", "cat", state["iam_image"], "/opt/silicon-iam/postgres/runtime-grants.sql"]).decode()
    for database in ("iam", "iam_testing"):
        fixture.psql(state, grants, database)
    # Control identities only. No normal-plane critical OBO approvals are seeded.
    endpoints = fixture.ENDPOINTS
    try:
        fixture.ENDPOINTS = {}
        state["iam_url"] = "http://127.0.0.1:8080"
        fixture.seed(state, pepper)
    finally:
        fixture.ENDPOINTS = endpoints
    fixture.command(["docker", "run", "-d", "--name", state["iam"], "--network", name, "--network-alias", "iam",
        "-p", "127.0.0.1::8080", "-p", "127.0.0.1::8082", "--env-file", str(directory / "iam.env"), state["iam_image"], "iam-api"], log=directory / "setup-error.log")
    state["containers"].append(state["iam"])
    state["iam_url"] = f"http://127.0.0.1:{fixture.port(state['iam'], 8080)}"
    state["ting_url"] = f"http://127.0.0.1:{fixture.port(state['iam'], 8082)}"
    fixture.save(state)
    fixture.wait_health(state["iam_url"])
    old = json.loads(fixture.command(["docker", "inspect", parent["ting"]], timeout=10))[0]
    binary = Path(next(mount["Source"] for mount in old["Mounts"] if mount["Destination"] == "/app/ting-server"))
    ca = next(mount["Source"] for mount in old["Mounts"] if mount["Destination"] == "/etc/ssl/certs/ca-certificates.crt")
    state["server_binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    tenv = {"TING_BIND": "0.0.0.0:8082", "TING_PUBLIC_ORIGIN": "http://127.0.0.1:8082",
        "TING_DATABASE_PATH": "/data/ting.sqlite", "TING_ENCRYPTION_KEY": secrets.token_hex(32),
        "TING_IAM_URL": "http://127.0.0.1:8080", "TING_IAM_APP_SECRET": state["app_secrets"]["tos>ting"],
        "TING_HONEYCOMB_URL": "http://127.0.0.1:1", "TING_HONEYCOMB_CONTROL_TOKEN": state["ting_control_token"],
        "TING_SPACESTATION_URL": "http://127.0.0.1:1", "TING_SPACESTATION_KEY": "table-fixture-" + secrets.token_hex(16),
        "TING_SPACESTATION_TABLE": "fixture", "TING_DOCS_URL": "http://127.0.0.1:8080/docs", "RUST_LOG": "error"}
    fixture.private(directory / "ting.env", "".join(f"{key}={value}\n" for key, value in tenv.items()))
    (directory / "ting-data").mkdir(mode=0o700)
    fixture.command(["docker", "run", "-d", "--name", state["ting"], "--network", "container:" + state["iam"],
        "--env-file", str(directory / "ting.env"), "-v", f"{binary}:/app/ting-server:ro",
        "-v", f"{directory / 'ting-data'}:/data", "-v", f"{ca}:/etc/ssl/certs/ca-certificates.crt:ro",
        "--entrypoint", "/app/ting-server", old["Config"]["Image"]], log=directory / "setup-error.log")
    state["containers"].append(state["ting"]); fixture.save(state)
    fixture.wait_health(state["ting_url"])
    print("TESTING_SERVICES_READY separate IAM normal/testing databases and Ting 0.1.4", flush=True)
    prepare(state)


def prepare(state):
    if "honeycomb_actor" not in state:
        state["honeycomb_actor"] = fixture.exchange(state, "admin", "tos>honeycomb")
        fixture.save(state)
    if not state.get("iam_revision"):
        lifecycle(state, "prepare", org_id="tos", name="Owned Hook scoped receiver E2E",
            testing_key=state["testing_key"], key_version=1)
        lifecycle(state, "activate")
    if "test_admin" not in state:
        session = iam(state, "POST", "/signup/sessions", {})["session_id"]
        signup = "/signup/sessions/" + session
        iam(state, "POST", signup + "/email", {"email": "hook-fixture@example.invalid"})
        iam(state, "POST", signup + "/email/verify", {"code": "000000"})
        iam(state, "POST", signup + "/phone", {"phone_number": "+12025550143"})
        iam(state, "POST", signup + "/phone/verify", {"code": "000000"})
        state["test_carbon"] = iam(state, "POST", signup + "/complete", {"carbon_id": "hook_test_admin", "display_name": "Hook isolated tester"})
        challenge = iam(state, "POST", "/login/challenges", {"carbon_id": "hook_test_admin"})
        state["test_admin"] = iam(state, "POST", "/login/challenges/" + challenge["session_id"] + "/verify", {"code": "000000"})
        fixture.save(state)
    tokens = state["test_admin"]
    test_profile(state, "test-admin", "hook_test_admin", "carbon", tokens)
    if "test_organization" not in state:
        state["test_organization"] = iam(state, "POST", "/organizations", {"org_id": "tos", "name": "Isolated Hook test organization"}, actor=tokens["access_token"])
        fixture.save(state)
    if "test_silicon" not in state:
        state["test_silicon"] = iam(state, "POST", "/organizations/tos/silicons", {
            "silicon_id": "hook-testing", "display_name": "Hook test receiver", "job_description": "Receive isolated Hook test events"}, actor=tokens["access_token"])
        fixture.save(state)
    if "test_recipient" not in state:
        state["test_recipient"] = iam(state, "POST", "/silicon-auth/token", {
            "silicon_id": "hook-testing:tos", "silicon_token": state["test_silicon"]["silicon_token"]})
        fixture.save(state)
    test_profile(state, "test-recipient", "hook-testing:tos", "silicon", state["test_recipient"])
    print("TESTING_IDENTITIES_READY real signup/login and isolated organization", flush=True)
    configure(state)


def configure(state):
    state.setdefault("test_apps", {})
    state.setdefault("source_apps", {})
    state.setdefault("imports", {})
    for app in ("tos>ting", "tos>hook"):
        if app in state["test_apps"]:
            continue
        config = {"org_id": "tos", "name": app, "base_url": "http://127.0.0.1:8082" if app == "tos>ting" else "http://127.0.0.1:8083",
            "visibility": "private", "availability": "active", "webhook": {
                "url": "https://fixture.invalid/iam", "secret": secrets.token_hex(24), "scope": ["membership"]},
            "app_scope": {"iam": fixture.TING_SCOPES if app == "tos>ting" else fixture.HOOK_SCOPES,
                "external": [{"app_id": "tos>ting", "endpoint_id": endpoint} for endpoint in ENDPOINTS] if app == "tos>hook" else []},
            "obo_endpoints": [{"endpoint_id": endpoint, "path": path, "metadata": {}, "critical": True, "ttl_seconds": 60}
                for endpoint, path in ENDPOINTS.items()] if app == "tos>ting" else []}
        encoded = urllib.parse.quote(app, safe="")
        if app not in state["source_apps"]:
            source = http(state, state["iam_url"], "GET", "/api/v1/honeycomb/applications/" + encoded,
                token=state["honeycomb_credential"])[1]
            # The source app only supplies an importable identity/webhook. Its
            # external scopes and OBO endpoint catalog stay empty.
            normal = {**config, "app_id": app, "obo_endpoints": [],
                "app_scope": {"iam": config["app_scope"]["iam"], "external": []},
                "operation_id": str(uuid.uuid4()), "expected_iam_revision": source["iam_revision"],
                "configuration_revision": source["configuration_revision"] + 1}
            state["source_apps"][app] = management(state, "PUT", "/applications/" + encoded + "/configuration", normal)
            fixture.save(state)
        if app not in state["imports"]:
            state["imports"][app] = lifecycle(state, "import", app_id=app,
                source_revisions={app: state["source_apps"][app]["iam_revision"]})
            fixture.save(state)
        imported = http(state, state["iam_url"], "GET",
            f"/api/v1/honeycomb/testing-environments/{state['environment_id']}/applications/{encoded}?generation={state['generation']}&key_version={state['key_version']}&expected_environment_revision={state['iam_revision']}",
            token=state["honeycomb_credential"])[1]
        body = {"operation_id": str(uuid.uuid4()), "environment_id": state["environment_id"],
            "generation": state["generation"], "key_version": state["key_version"],
            "expected_environment_revision": state["iam_revision"], "expected_iam_revision": imported["iam_revision"],
            "configuration_revision": imported["configuration_revision"] + 1, "configuration": config}
        state["test_apps"][app] = management(state, "PUT", f"/testing-environments/{state['environment_id']}/applications/{encoded}/configuration", body)
        fixture.save(state)
    if not state.get("apps_activated"):
        lifecycle(state, "activate-apps", app_ids=["tos>ting", "tos>hook"])
        state["apps_activated"] = True; fixture.save(state)
    print("TESTING_CONFIG_READY isolated private Hook and Ting application scopes", flush=True)
    verify_protocol(state)


def ting_lifecycle(state, action, generation=None):
    operation = str(uuid.uuid4())
    revision = state.get("ting_revision", 0) + 1
    body = {"app_id": "tos>ting", "org_id": "tos", "environment_id": state["environment_id"],
        "operation_id": operation, "environment_revision": revision,
        "generation": generation or state["generation"], "key_version": state["key_version"],
        "testing_key": state["testing_key"], "action": action}
    result = http(state, state["ting_url"], "PUT",
        f"/internal/honeycomb/organizations/tos/testing-environments/{state['environment_id']}/operations/{operation}",
        body, token=state["ting_control_token"])[1]
    state["ting_revision"] = revision
    fixture.save(state)
    return result


def proof(state, label, endpoint, raw, subject):
    return cli(state, label, ["app", "obo", "exchange", "tos>ting", endpoint,
        "--as-app-id", "tos>hook", "--app-secret", state["imports"]["tos>hook"]["app_secret"],
        "--subject-token", subject, "--org-context", "tos", "--method", "POST", "--body-file", "-"], raw)


def downstream(state, label, endpoint, path, body, expected=(200, 201)):
    raw = json.dumps(body, separators=(",", ":")).encode()
    result = proof(state, label, endpoint, raw, state["hook_sessions"][label]["access_token"])
    context = result["testing_context"]
    if context["app_id"] != "tos>ting" or context["iam_test_key"] != state["testing_key"]:
        raise RuntimeError("IAM audience testing context mismatch")
    if context["app_secret"] == state["imports"]["tos>hook"]["app_secret"]:
        raise RuntimeError("IAM did not provide a separate Ting audience credential")
    return http(state, state["ting_url"], "POST", path, raw, token=result["access_proof"],
        headers={"IAM_TEST_APP_SECRET": context["app_secret"], "X-Testing-Environment-Key": context["iam_test_key"]}, expected=expected)


def verify_protocol(state):
    if not state.get("ting_imported"):
        state["ting_import_receipt"] = ting_lifecycle(state, "import")
        state["ting_imported"] = True; fixture.save(state)
    state.setdefault("hook_sessions", {})
    for label in ("test-admin", "test-recipient"):
        if label not in state["hook_sessions"]:
            slt = cli(state, label, ["login", "--app-id", "tos>hook", "--grant-org", "tos", "--approve-scopes"])["slt"]
            state["hook_sessions"][label] = cli(state, label, ["app", "token", "exchange", "tos>hook",
                "--slt", slt, "--app-secret", state["imports"]["tos>hook"]["app_secret"]])
            fixture.save(state)
    state.setdefault("test_grants", {})
    evidence = []
    for label, actor in (("test-admin", "hook_test_admin"), ("test-recipient", "hook-testing:tos")):
        grant_body = {"org_id": "tos", "app_id": "tos>hook", "for": actor}
        state["test_grants"][label] = downstream(state, label, "subscriptions.register", "/v1/subscriptions", grant_body)[1]
        fixture.save(state)
        body = {**grant_body, "environment_id": state["environment_id"], "generation": state["generation"], "key": str(uuid.uuid4())}
        status, receiver = downstream(state, label, "receivers.bootstrap", "/v1/receivers/bootstrap", body)
        capability = receiver["receiver_token"]
        if receiver["environment"] != {"kind": "testing", "id": state["environment_id"], "generation": state["generation"]} or receiver["for"] != actor or receiver["app_id"] != "tos>hook":
            raise RuntimeError("receiver scope mismatch")
        me = http(state, state["ting_url"], "GET", "/v1/receivers/me", token=capability)[1]
        http(state, state["ting_url"], "GET", "/v1/receivers/inbox", token=capability)
        ordinary_status, _ = http(state, state["ting_url"], "GET", "/v1/me", token=capability, expected=(401,))
        replay_status, replay = downstream(state, label, "receivers.bootstrap", "/v1/receivers/bootstrap", body)
        if replay_status != 200 or replay != receiver:
            raise RuntimeError("fresh-proof exact receiver replay was not identical")
        wrong_status, _ = downstream(state, label, "receivers.bootstrap", "/v1/receivers/bootstrap",
            {**body, "key": str(uuid.uuid4()), "generation": state["generation"] + 1}, expected=(403,))
        http(state, state["ting_url"], "DELETE", "/v1/receivers/session", token=capability)
        revoked_status, _ = http(state, state["ting_url"], "GET", "/v1/receivers/me", token=capability, expected=(401,))
        _, historical = downstream(state, label, "receivers.bootstrap", "/v1/receivers/bootstrap", body)
        if historical != receiver:
            raise RuntimeError("historical receiver replay changed its identity or expiry")
        http(state, state["ting_url"], "GET", "/v1/receivers/me", token=historical["receiver_token"], expected=(401,))
        evidence.append({"kind": receiver["kind"], "for": actor, "org_id": receiver["org_id"],
            "environment": receiver["environment"], "created_status": status, "exact_replay_status": replay_status,
            "ordinary_session_rejected": ordinary_status, "wrong_generation_rejected": wrong_status,
            "revoked_status": revoked_status, "historical_replay_did_not_resurrect": True,
            "inbox_read_succeeded": True, "scope_me_matched": me["receiver_id"] == receiver["receiver_id"]})
    report = {"complete": True, "scope": "Direct upstream protocol prerequisite; Hook adapter not yet exercised",
        "version": state["ting_version"], "source_commit": state["ting_commit"],
        "server_binary_sha256": state["server_binary_sha256"], "iam_image": state["iam_image"],
        "environment_id": state["environment_id"], "generation": state["generation"],
        "coverage": state["coverage"], "receivers": evidence,
        "checks": ["Separate owned Docker network and separate IAM normal/testing databases",
            "Actual IAM participant prepare/activate/import/private configuration/activate-apps",
            "Actual test Carbon OTP signup/login and Silicon creation/authentication; no seeded test identities",
            "Only Hook-bound consent/SLT app sessions used for receiving bootstrap",
            "Every downstream call uses a fresh actual IAM proof and its separate Ting audience testing context",
            "Actual Ting authenticated lifecycle import with matching environment and generation",
            "Carbon and Silicon scoped create/read/replay/wrong-generation/revoke assertions passed"],
        "limitations": ["Full Honeycomb coordinator is not running; authenticated participant APIs are driven locally",
            "Normal control identities are synthetic fixture rows; production OBO endpoints/scopes remain empty",
            "Clean fencing will be exercised in the subsequent Hook adapter integration run",
            "No production or shared test environment was modified"]}
    fixture.private(Path(state["directory"]) / "testing-prerequisite-verification.json", report)
    print("TESTING_RECEIVERS_VERIFIED Carbon and Silicon; exact replay, scope rejection and revocation", flush=True)


def rebuild(directory):
    state = fixture.load(directory)
    if not state.get("cleaned") or state["generation"] < 2:
        raise RuntimeError("rebuild requires this owned environment's completed clean")
    prior = state["generation"] - 1
    archive = Path(directory) / f"generation-{prior}-evidence"
    archive.mkdir(mode=0o700, exist_ok=False)
    for path in Path(directory).glob("testing-*-verification.json"):
        shutil.copy2(path, archive / path.name)
    fixture.private(archive / "fixture-after-clean.private.json", state)
    lifecycle(state, "activate")
    for key in ("test_admin", "test_carbon", "test_organization", "test_silicon", "test_recipient",
        "test_apps", "imports", "apps_activated", "ting_imported", "hook_imported", "hook_sessions",
        "test_grants", "publisher_identity", "publisher_direct", "publisher_configured", "recipient_operator",
        "type_seeded", "required_policy_before", "required_policy_path", "cleaned"):
        state.pop(key, None)
    state["previous_generation_evidence"] = str(archive)
    fixture.save(state)
    prepare(state)
    print("TESTING_GENERATION_REBUILT " + str(state["generation"]), flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--prepare", action="store_true", help="continue an owned service fixture before environment creation")
    parser.add_argument("--rebuild", action="store_true", help="recreate identities/apps after completed clean, preserving old evidence")
    args = parser.parse_args()
    if args.rebuild:
        rebuild(args.directory.resolve())
    elif args.prepare:
        prepare(fixture.load(args.directory.resolve()))
    else:
        setup(args.directory.resolve())
