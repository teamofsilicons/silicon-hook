#!/usr/bin/env python3
"""Measure real idle testing-plane IAM quota use without changing clocks or limits."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

import fixture
import hook


def verify(directory, seconds=30):
    state, backend = fixture.load(directory), hook.load(directory)
    if not state.get("fixture_owned") or not backend.get("owned"):
        raise RuntimeError("idle quota probe only supports this owned fixture")
    env = json.loads((directory / "hook.env.private.json").read_text())
    def query(container, database, sql):
        result = subprocess.run(["docker", "exec", container, "psql", "-U", "postgres", "-d", database, "-Atc", sql],
                                capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise RuntimeError("owned fixture quota query failed")
        return json.loads(result.stdout)
    def buckets():
        value = query(state["postgres"], "iam_testing", "SELECT COALESCE(json_agg(x),'[]'::json) FROM (SELECT encode(scope_digest,'hex') AS digest,limit_name,window_started_at::text AS window,request_count FROM iam.rate_limit_buckets WHERE limit_name LIKE 'applications_%') x")
        return {(row["digest"], row["limit_name"], row["window"]): row["request_count"] for row in value}
    def due():
        return query(backend["container"], "hook_testing", "SELECT count(*) FROM hook_private.ting_outbox WHERE accepted_at IS NULL AND expires_at>clock_timestamp() AND next_attempt_at<=clock_timestamp() AND (lease_until IS NULL OR lease_until<=clock_timestamp())")
    if due():
        raise RuntimeError("idle probe requires no currently due outbox work")
    previous, increments = buckets(), {}
    began = time.monotonic()
    print(f"SCOPED_IDLE_PROBE measuring {seconds}s with worker poll={env['HOOK_TING_POLL_MILLISECONDS']}ms and unchanged IAM limits", flush=True)
    while time.monotonic() - began < seconds:
        time.sleep(min(5, seconds - (time.monotonic() - began)))
        if due():
            raise RuntimeError("work became due during idle quota probe; measurement is inconclusive")
        current = buckets()
        for key, count in current.items():
            delta = max(0, count - previous.get(key, 0))
            if delta:
                increments[key[1]] = increments.get(key[1], 0) + delta
        previous = current
    elapsed = round(time.monotonic() - began, 3)
    report = {"complete": not increments, "duration_seconds": elapsed,
        "worker_poll_milliseconds": int(env["HOOK_TING_POLL_MILLISECONDS"]), "no_due_work_throughout": True,
        "observed_application_quota_units": increments, "iam_limit_changed": False,
        "hook_binary_sha256": hashlib.sha256((hook.ROOT / "target/debug/hook-api").read_bytes()).hexdigest(),
        "baseline_before_fix": {"worker_poll_milliseconds": 2000, "idle_units_per_minute": 60,
                                "blocked_limit_name": "applications_client_request", "limit_per_minute": 120},
        "checks": ["Read-only real IAM rate buckets sampled across natural wall-clock time",
                   "No application requests or due outbox work during the measurement", "No bucket resets, database clocks or limits changed"]}
    fixture.private(directory / "testing-idle-quota-verification.json", report)
    if increments:
        raise RuntimeError("idle worker still consumes IAM application quota; sanitized report saved")
    print(f"SCOPED_IDLE_PASS zero application IAM quota units over {elapsed}s", flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--seconds", type=int, default=30)
    args = parser.parse_args()
    if not 10 <= args.seconds <= 60:
        parser.error("seconds must be between10 and60")
    verify(args.directory.resolve(), args.seconds)
