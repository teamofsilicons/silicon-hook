#!/usr/bin/env python3
"""Real scoped CLI/SDK handoff, with capability files confined to an owned home."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import uuid

import cli as normal_cli
import fixture
import hook
import testing


def verify(directory, binary):
    state, backend = fixture.load(directory), hook.load(directory)
    if state.get("cleaned") or state["generation"] < 2:
        raise RuntimeError("scoped CLI gate requires the rebuilt owned testing generation")
    folder = Path(tempfile.mkdtemp(prefix="scoped-cli-", dir=directory)).resolve()
    home, profile = folder / "hook-home", "scoped-e2e"
    env = {key: value for key, value in os.environ.items()
        if not key.startswith(("SILICON_", "IAM_TEST_", "HOOK_")) and key != "ISI"}
    env.update({"SILICON_HOOK_HOME": str(home), "SILICON_HOME": str(folder / "silicon-home"), "SILICON_HOOK_TELEMETRY": "off"})
    base = [str(binary), "--url", backend["url"], "--org", "tos", "--profile", profile,
        "--test", state["environment_id"], "--json"]
    tokens, capabilities, calls = [], [], []
    before = normal_cli.owned_processes(binary)
    binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()

    def run(args, success=True):
        result = subprocess.run([*base, *args], env=env, cwd=folder, capture_output=True, timeout=45)
        combined = result.stdout + result.stderr
        if any(token.encode() in combined for token in tokens) or b'"receiver_token"' in combined or b"ting_recv_" in combined:
            raise RuntimeError("CLI exposed a receiver capability in output")
        if state["environment_id"].encode() not in result.stderr or b"TEST ENVIRONMENT:" not in result.stderr:
            raise RuntimeError("CLI omitted its explicit testing footer")
        if (result.returncode == 0) != success:
            fixture.private(folder / "cli-error.private.log", combined.decode(errors="replace"))
            raise RuntimeError("scoped CLI result mismatch; inspect private diagnostic")
        calls.append({"command": args[0], "success": success})
        return json.loads(result.stdout) if success else result

    def read_capability(path):
        if not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise RuntimeError("CLI capability output was not a private0600 regular file")
        value = json.loads(path.read_text())
        token = value["receiver_token"]
        if not token.startswith("ting_recv_"):
            raise RuntimeError("CLI output did not contain an actual scoped capability")
        tokens.append(token); capabilities.append(value)
        if token.encode() in (home / "state.json").read_bytes():
            raise RuntimeError("CLI persisted a receiver capability in its profile")
        return value

    selector = folder / "hook-selector.private"
    fixture.private(selector, state["imports"]["hook"]["app_secret"] + "\n")
    selected = run(["env", "use", "--app-secret-file", str(selector)])
    selector.unlink()
    if selected["id"] != state["environment_id"]:
        raise RuntimeError("CLI selected another testing environment")
    slt_file = folder / "login.private.slt"
    fixture.private(slt_file, testing.cli(state, "test-recipient", ["login", "--app-id", "hook",
        "--grant-org", "tos", "--approve-scopes"])["slt"] + "\n")
    signed_in, report = False, None
    try:
        login = run(["login", "--slt-file", str(slt_file)])
        signed_in = True; slt_file.unlink()
        if not login["authenticated"] or login["actor"]["id"] != "si:hook-testing":
            raise RuntimeError("CLI test SLT login did not match the synthetic Silicon")
        scope = run(["receiving", "scope"])
        if scope["environment"] != {"kind": "testing", "id": state["environment_id"], "generation": state["generation"]}:
            raise RuntimeError("SDK receiver scope did not match current shared generation")
        if scope["org_id"] != state["test_organization"]["id"] or scope["hook_org_id"] != "tos":
            raise RuntimeError("CLI scope mixed the canonical handle and IAM UUID")
        scope_file = folder / "scope.json"
        fixture.private(scope_file, scope)
        key = str(uuid.uuid4())
        first_file = folder / "first.private.json"
        command = ["--idempotency-key", key, "receiving", "bootstrap", "--scope-file", str(scope_file)]
        metadata = run([*command, "--output", str(first_file)])
        first = read_capability(first_file)
        if metadata["receiver_id"] != first["receiver_id"] or metadata["scope"] != scope:
            raise RuntimeError("CLI printed metadata different from its private capability")
        replay_file = folder / "replay.private.json"
        run([*command, "--output", str(replay_file)])
        replay = read_capability(replay_file)
        if replay != first:
            raise RuntimeError("CLI same-scope/same-key retry changed the recovered capability")
        unchanged = hashlib.sha256(first_file.read_bytes()).hexdigest()
        run([*command, "--output", str(first_file)], success=False)
        if hashlib.sha256(first_file.read_bytes()).hexdigest() != unchanged:
            raise RuntimeError("CLI overwrote an existing private capability file")
        renewal_file = folder / "renewal.private.json"
        run(["--idempotency-key", str(uuid.uuid4()), "receiving", "bootstrap", "--scope-file", str(scope_file),
            "--receiver-id", first["receiver_id"], "--output", str(renewal_file)])
        renewal = read_capability(renewal_file)
        if renewal["receiver_id"] != first["receiver_id"] or renewal["receiver_token"] == first["receiver_token"]:
            raise RuntimeError("CLI explicit renewal did not preserve ID and replace token")
        testing.http(state, state["ting_url"], "GET", "/v1/receivers/me", token=first["receiver_token"], expected=(401,))
        testing.http(state, state["ting_url"], "GET", "/v1/receivers/me", token=renewal["receiver_token"])
        stale_file = folder / "scope-stale.json"
        fixture.private(stale_file, {**scope, "environment": {**scope["environment"], "generation": state["generation"] - 1}})
        stale_output = folder / "stale.private.json"
        failure = run(["--idempotency-key", str(uuid.uuid4()), "receiving", "bootstrap", "--scope-file", str(stale_file),
            "--output", str(stale_output)], success=False)
        if b"receiver_environment_changed" not in failure.stdout + failure.stderr:
            raise RuntimeError("stale generation failed for an unrelated reason")
        if stale_output.exists() and stale_output.stat().st_size:
            raise RuntimeError("stale scope produced a nonempty capability file")
        testing.http(state, state["ting_url"], "DELETE", "/v1/receivers/session", token=renewal["receiver_token"])
        testing.http(state, state["ting_url"], "GET", "/v1/receivers/me", token=renewal["receiver_token"], expected=(401,))
        historical_file = folder / "historical.private.json"
        run([*command, "--output", str(historical_file)])
        historical = read_capability(historical_file)
        if historical != first:
            raise RuntimeError("CLI historical replay replaced the original receipt")
        testing.http(state, state["ting_url"], "GET", "/v1/receivers/me", token=historical["receiver_token"], expected=(401,))
        profile_bytes = (home / "state.json").read_bytes()
        if any(token.encode() in profile_bytes for token in tokens) or b"ting_recv_" in profile_bytes:
            raise RuntimeError("scoped CLI left capability authority in its profile")
        if normal_cli.owned_processes(binary) - before or {p.name for p in home.iterdir()} - {"state.json", "state.lock"}:
            raise RuntimeError("scoped CLI started a background process or persisted receiving state")
        report = {"complete": True, "environment_id": state["environment_id"], "shared_generation": state["generation"],
            "cli_binary_sha256": binary_sha, "scope": scope, "receiver_id": first["receiver_id"],
            "capability_file_mode": "0600", "checks": ["Fresh private CLI profile selected only Hook's test app secret",
                "Actual Hook-bound IAM consent/SLT login for the isolated Silicon",
                "CLI invoked real SDK scope/bootstrap/renew methods against Hook and Ting0.1.4",
                "Exact scope/key replay recovered identical token/expiry into a separate new file",
                "Existing output file refused unchanged; no secret in stdout/stderr/profile",
                "Explicit new-key same-ID renewal invalidated old token",
                "Stale generation rejected with receiver_environment_changed and no capability file",
                "Revocation remained effective after historical receipt replay",
                "Every command printed selected testing footer; no receiving daemon or profile transport state"],
            "limitations": ["CLI is the SDK integration caller; no additional SDK example was introduced",
                "This handoff gate does not start a receiver transport; real scoped transport is covered separately",
                "macOS private file behavior tested; Windows source inspected; Windows compile/runtime unverified because SDK headers are unavailable"]}
    finally:
        if slt_file.exists():
            slt_file.unlink()
        for capability in capabilities:
            testing.http(state, state["ting_url"], "DELETE", "/v1/receivers/session", token=capability["receiver_token"], expected=(200, 401))
        if signed_in:
            logout = run(["logout"])
            if not logout.get("signed_out"):
                raise RuntimeError("CLI fixture logout did not complete")
            profile_state = json.loads((home / "state.json").read_text())["profiles"][profile]
            if state["environment_id"] in profile_state.get("test_sessions", {}):
                raise RuntimeError("CLI fixture logout retained its test token family")
        for path in folder.glob("*.private.json"):
            path.unlink()
    if report:
        report["cleanup"] = {"capabilities_revoked": True, "capability_files_removed": True, "cli_family_logged_out": True}
        fixture.private(Path(directory) / "testing-cli-verification.json", report)
        print("SCOPED_CLI_PASS exact replay, private output, explicit renewal, stale scope and revocation", flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--binary", type=Path, default=hook.ROOT / "target/debug/hook")
    args = parser.parse_args()
    verify(args.directory.resolve(), args.binary.resolve())
