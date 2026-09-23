#!/usr/bin/env python3
"""Repeat only the actual scoped browser phase after HTTP evidence is complete."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse

import fixture
import hook
import testing
import testing_hook
import testing_web


def verify(directory, node, playwright):
    state, backend = fixture.load(directory), hook.load(directory)
    http_report = json.loads((directory / "testing-web-verification.json").read_text())
    if not http_report.get("complete") or http_report["shared_generation"] != state["generation"]:
        raise RuntimeError("browser-only phase requires successful current-generation HTTP evidence")
    testing_hook.prepare_delivery(state, backend)
    observer = testing_web.operator(state, "test-admin")
    pref_path = "/v1/orgs/tos/preferences"
    preference = {"app_id": "tos>hook", "type": "tos>hook.webhook.received", "service": None}
    query = pref_path + "?" + urllib.parse.urlencode({"app_id": "tos>hook", "type": preference["type"]})
    prior = None
    website = None
    try:
        prefs = testing.http(state, state["ting_url"], "GET", query, token=observer["session_token"])[1]
        if prefs.get("next_cursor"):
            raise RuntimeError("ambiguous notification preferences")
        prior = [item for item in prefs["items"] if item.get("type") == preference["type"] and not item.get("service")]
        fixture.private(directory / "testing-browser-cleanup.private.json", {"observer": observer, "prior_preference": prior})
        testing.http(state, state["ting_url"], "PUT", pref_path, {**preference, "enabled": False}, token=observer["session_token"])
        website = testing_web.Website(state, backend, node)
        server_hash = hashlib.sha256(website.server.read_bytes()).hexdigest()
        # A frontend-only build may change separately; record both actual phase
        # hashes instead of silently claiming that HTTP was repeated.
        cfg = {"origin": website.origin, "hook": backend["url"], "org": "tos", "actor": "hook-testing:tos",
            "plane": state["environment_id"], "generation": state["generation"], "directory": str(directory),
            "python": sys.executable, "scripts": str(Path(__file__).parent.resolve()), "output": str(website.folder / "browser"),
            "playwright": playwright, "session_folder": website.env["HOOK_SESSION_DIR"],
            "session_key": website.env["HOOK_SESSION_KEY"], "ting": state["ting_url"], "server_sha256": server_hash,
            "hook_binary_sha256": backend.get("binary_sha256") or hashlib.sha256((hook.ROOT / "target/debug/hook-api").read_bytes()).hexdigest()}
        config = website.folder / "browser.private.json"; fixture.private(config, cfg)
        result = subprocess.run([node, str(Path(__file__).with_name("testing_web_browser.mjs")), str(config)], timeout=300)
        if result.returncode:
            raise RuntimeError("browser-only phase failed; private diagnostic preserved")
    finally:
        if website:
            website.close()
        if prior is not None:
            if prior:
                testing.http(state, state["ting_url"], "PUT", pref_path, {**preference, "enabled": prior[0]["enabled"]}, token=observer["session_token"])
            else:
                testing.http(state, state["ting_url"], "DELETE", query, token=observer["session_token"])
        testing.http(state, state["ting_url"], "DELETE", "/v1/session", token=observer["session_token"], expected=(200, 401))
        (directory / "testing-browser-cleanup.private.json").unlink(missing_ok=True)
        testing.http(state, state["ting_url"], "PUT", state["required_policy_path"],
            {"enabled": state["required_policy_before"]["enabled"]}, token=state["recipient_operator"]["session_token"])
    path = directory / "testing-web-browser-verification.json"
    report = json.loads(path.read_text())
    report["phase"] = "independent actual browser repeat; successful HTTP evidence preserved"
    report["http_evidence_server_sha256"] = http_report["server_sha256"]
    report["preferences_and_required_policy_restored"] = True
    fixture.private(path, report)
    print("SCOPED_BROWSER_ONLY_PASS actual UI, renewal, silent event, mobile layout and cleanup", flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--node", default="node")
    parser.add_argument("--playwright", default="playwright")
    args = parser.parse_args()
    verify(args.directory.resolve(), args.node, args.playwright)
