#!/usr/bin/env python3
"""Verify Ting login replay using real HTTP and elapsed wall time.

The successful first response is deliberately retained privately as an oracle
and cleanup credential. This does not simulate an actual lost network packet.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import tempfile
import time
import urllib.error
import urllib.request
import uuid

import fixture


def verify(directory, expectation=None):
    upstream = fixture.load(directory)
    health = fixture.request(upstream["ting_url"], "GET", "/healthz")
    expected_by_version = {"0.1.3": "expired", "0.1.4": "recovered"}
    if health.get("version") not in expected_by_version or health["version"] != upstream.get("ting_version"):
        raise RuntimeError("this verification requires a supported pinned Ting fixture")
    expectation = expectation or expected_by_version[health["version"]]
    folder = Path(tempfile.mkdtemp(prefix="login-recovery-", dir=directory)).resolve()
    os.chmod(folder, 0o700)
    state = {**upstream, "directory": str(folder)}
    actor = "login-recovery-" + uuid.uuid4().hex[:10] + ":" + state["org_id"]
    token, logged_in, report = None, False, None
    operation_file = folder / "operation.private.json"

    def call(method, path, body=None, key=None, credential=None):
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Idempotency-Key"] = key
        if credential:
            headers["Authorization"] = "Bearer " + credential
        request = urllib.request.Request(state["ting_url"] + path, data=body,
                                         method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                status, raw = response.status, response.read(128 * 1024)
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read(128 * 1024)
        try:
            return status, json.loads(raw)
        except ValueError:
            raise RuntimeError("Ting login recovery response was not JSON") from None

    try:
        created = fixture.cli(upstream, "admin", ["silicon", "create", actor,
            "--job-description", "Synthetic isolated Ting login operation recovery verification"])
        direct = fixture.request(state["iam_url"], "POST", "/api/v1/silicon-auth/token",
            {"silicon_id": actor, "silicon_token": created["silicon_token"]},
            headers={"Idempotency-Key": str(uuid.uuid4())})
        expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=direct["expires_in"])).isoformat()
        store = folder / "profiles" / "actor" / ".silicon-iam"
        fixture.private(store / "config.json", {"telemetry": False, "auto_update": False,
            "current_profile": "default", "profiles": {"default": {"url": state["iam_url"]}}})
        fixture.private(store / "credentials.json", {"sessions": {"default": {
            "access_token": direct["access_token"], "refresh_token": direct["refresh_token"],
            "expires_at": expiry, "actor_type": "silicon", "actor_id": actor}}})
        logged_in = True
        body = json.dumps({"slt": fixture.slt(state, "actor", "tos>ting")}, separators=(",", ":")).encode()
        key = str(uuid.uuid4())
        initial_status, initial = call("POST", "/v1/session", body, key)
        if initial_status not in (200, 201) or not initial.get("session_token"):
            raise RuntimeError("initial isolated Ting login failed")
        token = initial["session_token"]
        fixture.private(operation_file, {"key": key, "request": json.loads(body), "response": initial})
        completed = time.monotonic()
        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        immediate_status, immediate = call("POST", "/v1/session", body, key)
        if immediate_status != 200 or immediate != initial:
            raise RuntimeError("immediate replay did not recover the identical session response")
        first_me_status, first_me = call("GET", "/v1/me", credential=token)
        if first_me_status != 200 or first_me.get("id") != actor or first_me.get("environment") != {"kind": "production"}:
            raise RuntimeError("new isolated session did not attest its expected identity/environment")
        print("LOGIN_RECOVERY_STAGE first login and identical immediate replay passed; waiting 125 real seconds", flush=True)
        while time.monotonic() - completed < 125:
            time.sleep(min(30, 125 - (time.monotonic() - completed)))
            print(f"LOGIN_RECOVERY_STAGE elapsed {time.monotonic() - completed:.1f}/125 seconds", flush=True)
        elapsed = time.monotonic() - completed
        late_status, late = call("POST", "/v1/session", body, key)
        code = late.get("error", {}).get("code", "")
        correct = (late_status == 401 and code == "session_expired") if expectation == "expired" else (late_status == 200 and late == initial)
        if not correct:
            fixture.private(folder / "unexpected-late-response.private.json", {"status": late_status, "response": late})
            raise RuntimeError("late replay did not match the expected " + expectation + " operation behavior")
        live_status, live = call("GET", "/v1/me", credential=token)
        if live_status != 200 or live.get("id") != actor or not live.get("authenticated"):
            raise RuntimeError("original session was not still active after late operation replay")
        error = late.get("error", {})
        safe_error = {"code": code} if error else None
        for field in ("message", "hint"):
            value = error.get(field)
            if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9 .,'-]{1,200}", value):
                safe_error[field] = value
        if isinstance(error.get("retryable"), bool):
            safe_error["retryable"] = error["retryable"]
        report = {"complete": True, "ting_version": health["version"],
            "expected_late_replay": expectation,
            "source_commit": upstream["ting_commit"], "server_archive_sha256": upstream["ting_archive_sha256"],
            "initial_response_at_utc": created_at, "initial_http_status": initial_status,
            "immediate_replay_http_status": immediate_status, "immediate_response_identical": True,
            "minimum_wait_seconds": 125, "actual_wait_seconds": round(elapsed, 3),
            "late_replay_http_status": late_status, "late_replay_error": safe_error,
            "late_replay_response_identical": late == initial,
            "original_session_after_late_replay_http_status": live_status,
            "original_session_still_authenticated": True, "session_environment": live["environment"],
            "checks": ["new synthetic Silicon authenticated through real IAM and issued a Ting-bound SLT",
                "initial Ting login and immediate exact-key/body replay return identical session responses",
                "wait exceeded the former 120-second operation window without clock/database modification",
                ("exact-key/body replay then returns 401 session_expired" if expectation == "expired"
                 else "exact-key/body replay after 125 seconds recovers the identical original response with HTTP200"),
                "original returned session remains authenticated after late replay"],
            "limitations": ["successful first response was captured privately as an oracle and cleanup credential; no actual lost packet or production outage was simulated",
                "no actual lost-response transport failure was injected; this verifies the real exact-operation recovery boundary",
                "synthetic direct IAM Silicon authority remains confined to the disposable IAM fixture until its cleanup"]}
    finally:
        if token:
            deleted_status, _ = call("DELETE", "/v1/session", credential=token)
            revoked_status, revoked = call("GET", "/v1/me", credential=token)
            if deleted_status != 200 or revoked_status != 401:
                raise RuntimeError("the new isolated Ting session could not be confirmed revoked; retain private cleanup credential")
            after_logout_status, after_logout = call("POST", "/v1/session", body, key)
            after_logout_code = after_logout.get("error", {}).get("code")
            if after_logout_status != 401 or after_logout_code != "session_expired":
                fixture.private(folder / "unexpected-post-logout.private.json", {"status": after_logout_status, "response": after_logout})
                if after_logout.get("session_token"):
                    call("DELETE", "/v1/session", credential=after_logout["session_token"])
                raise RuntimeError("login operation replay was not rejected after logout")
            final_status, _ = call("GET", "/v1/me", credential=token)
            if final_status != 401:
                raise RuntimeError("login replay resurrected the revoked session")
            operation_file.unlink(missing_ok=True)
            if report:
                report["cleanup_delete_http_status"] = deleted_status
                report["cleanup_session_http_status"] = revoked_status
                report["cleanup_error_code"] = revoked.get("error", {}).get("code")
                report["post_logout_replay_http_status"] = after_logout_status
                report["post_logout_replay_error_code"] = after_logout_code
                report["session_after_post_logout_replay_http_status"] = final_status
                report["checks"].append("only the new Ting session was deleted and its credential subsequently returns 401")
                report["checks"].append("exact login replay after logout returns 401 and cannot resurrect the revoked session")
        if logged_in:
            fixture.cli(state, "actor", ["logout", "--local-only"])
    fixture.private(Path(directory) / "login-recovery-verification.json", report)
    print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--expect", choices=("expired", "recovered"), help="override the version-specific late replay assertion")
    args = parser.parse_args()
    verify(args.directory.resolve(), args.expect)
