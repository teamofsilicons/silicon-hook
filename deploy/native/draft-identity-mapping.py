#!/usr/bin/env python3
"""Draft the mapping file for `hook-migrate link-identities`.

    HOOK_APP_SECRET=... python3 draft-identity-mapping.py \\
        --database-url "$HOOK_MIGRATOR_DATABASE_URL" --out mapping.csv

It ships in the native backend bundle next to install.py (deploy/native/ in the
repository).

Reads every id Hook stored before 1.0 (hook_private.identity_links rows found in
Hook's data, so the URL must be the migrator's) and looks each one up at Silicon
Accounts by its current id (GET /v1/accounts/by-id/{id}, with Hook's app
credentials). It writes mapping.csv (`iam_public_id,accounts_uuid`) with the
ids it could resolve to an active account of the same kind, and a JSON report
beside it (mapping.csv.report.json) that also lists, for each Silicon, its
custodian at Silicon Accounts, and every id it left out with the reason.

The draft is a proposal, not a decision: the same id at Silicon Accounts is not
proof of the same Carbon or Silicon. Review it (does each Silicon's custodian
match who ran it before?), add rows for accounts whose id changed, remove rows
that are wrong, then run `hook-migrate link-identities --file mapping.csv
--dry-run`. It changes nothing anywhere: one read-only query and lookups.

The app secret is read from HOOK_APP_SECRET or --secret-file, never from the
command line. Lookups stay under Silicon Accounts' 600 per minute per app and
wait out a 429.
"""

import argparse
import base64
import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

QUERY = ("SELECT iam_public_id, kind FROM hook_private.identity_links "
         "WHERE in_hook_data ORDER BY iam_public_id")
DEFAULT_ACCOUNTS_URL = "https://accounts.teamofsilicons.com"
INTERVAL = 0.11  # about 545 lookups a minute


class DraftError(Exception):
    """A refusal with its reason; printed without any secret."""


def stored_ids(database_url, psql):
    """(id, kind) for every id Hook's data references, from the migrator's view."""
    result = subprocess.run([psql, "--no-psqlrc", "-X", "-v", "ON_ERROR_STOP=1", "-At", "-F", "\t", "-c", QUERY,
                             database_url], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise DraftError(f"could not read hook_private.identity_links (is this the migrator's URL, and has migration "
                         f"0019 run?): {result.stderr.strip()[:500]}")
    rows = []
    for line in result.stdout.splitlines():
        if line.strip():
            identifier, kind = line.split("\t")
            rows.append((identifier, kind))
    return rows


def lookup(accounts_url, app_id, secret, identifier, opener=urllib.request.urlopen, sleep=time.sleep):
    """(status, body) of GET /v1/accounts/by-id/{id}; retries a 429 after its Retry-After."""
    url = f"{accounts_url.rstrip('/')}/v1/accounts/by-id/{urllib.parse.quote(identifier.lower(), safe=':')}"
    token = base64.b64encode(f"{app_id}:{secret}".encode()).decode()
    for _ in range(5):
        request = urllib.request.Request(url, headers={"Authorization": f"Basic {token}", "Accept": "application/json",
                                                       "User-Agent": "hook-draft-identity-mapping"})
        try:
            with opener(request, timeout=15) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            body = error.read()
            try:
                parsed = json.loads(body or b"{}")
            except json.JSONDecodeError:
                parsed = {"raw": body[:200].decode("utf-8", "replace")}
            if error.code == 429:
                sleep(min(float(error.headers.get("Retry-After") or 5), 60))
                continue
            if error.code in (401, 403):
                raise DraftError(f"Silicon Accounts refused Hook's app credentials ({error.code}): "
                                 f"{parsed.get('error', parsed)}") from None
            return error.code, parsed
    raise DraftError("Silicon Accounts kept answering 429; try again later")


def error_code(body):
    error = body.get("error")
    if isinstance(error, dict):
        return error.get("code") or "error"
    return error if isinstance(error, str) else "error"


def draft(rows, resolve, sleep=time.sleep):
    """The mapping rows and the report for (id, kind) rows, given resolve(id) -> (status, body)."""
    resolved, unresolved, by_uuid = [], [], {}
    for index, (identifier, kind) in enumerate(rows):
        if index:
            sleep(INTERVAL)
        status, body = resolve(identifier)
        if status != 200:
            unresolved.append({"iam_public_id": identifier, "kind": kind, "reason": error_code(body), "status": status})
            continue
        if body.get("kind") != kind:
            unresolved.append({"iam_public_id": identifier, "kind": kind, "reason": "kind_differs",
                               "accounts": {"uuid": body.get("uuid"), "kind": body.get("kind")}})
            continue
        if body.get("status") not in (None, "active"):
            unresolved.append({"iam_public_id": identifier, "kind": kind, "reason": f"account_{body.get('status')}",
                               "accounts": {"uuid": body.get("uuid")}})
            continue
        entry = {"iam_public_id": identifier, "kind": kind, "accounts_uuid": body["uuid"], "accounts_id": body.get("id")}
        if kind == "silicon":
            entry["custodian"] = body.get("custodian")
        by_uuid.setdefault(body["uuid"], []).append(entry)
        resolved.append(entry)
    # link-identities refuses a file that gives one uuid to two ids: leave such ids out for review.
    shared = {uuid for uuid, entries in by_uuid.items() if len(entries) > 1}
    for entry in [e for e in resolved if e["accounts_uuid"] in shared]:
        resolved.remove(entry)
        unresolved.append({"iam_public_id": entry["iam_public_id"], "kind": entry["kind"],
                           "reason": "uuid_shared_with_another_id", "accounts": {"uuid": entry["accounts_uuid"]}})
    return resolved, unresolved


def write(out, report_path, resolved, unresolved, accounts_url):
    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["iam_public_id", "accounts_uuid"])
        for entry in resolved:
            writer.writerow([entry["iam_public_id"], entry["accounts_uuid"]])
    report = {"accounts_url": accounts_url, "stored_ids": len(resolved) + len(unresolved),
              "resolved": resolved, "left_out": unresolved,
              "next": f"review {out.name}, then: hook-migrate link-identities --file {out.name} --dry-run"}
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--database-url", default=os.environ.get("HOOK_MIGRATOR_DATABASE_URL"),
                        help="the migrator's PostgreSQL URL (default: HOOK_MIGRATOR_DATABASE_URL)")
    parser.add_argument("--accounts-url", default=os.environ.get("ACCOUNTS_API_URL") or os.environ.get("ACCOUNTS_URL")
                        or DEFAULT_ACCOUNTS_URL, help="Silicon Accounts (default: ACCOUNTS_API_URL, ACCOUNTS_URL, "
                        "then production)")
    parser.add_argument("--app-id", default=os.environ.get("HOOK_APP_ID", "hook"))
    parser.add_argument("--secret-file", type=Path, help="a file holding Hook's app secret (else HOOK_APP_SECRET)")
    parser.add_argument("--out", type=Path, required=True, help="the mapping CSV to write")
    parser.add_argument("--report", type=Path, help="the JSON report (default: <out>.report.json)")
    args = parser.parse_args(argv)
    try:
        if not args.database_url:
            raise DraftError("give --database-url or set HOOK_MIGRATOR_DATABASE_URL (the migrator's URL)")
        secret = (args.secret_file.read_text().strip() if args.secret_file else os.environ.get("HOOK_APP_SECRET", ""))
        if not secret:
            raise DraftError("set HOOK_APP_SECRET or pass --secret-file with Hook's app secret")
        psql = os.environ.get("HOOK_PSQL") or shutil.which("psql")
        if not psql:
            raise DraftError("psql is not installed (or set HOOK_PSQL to its path)")
        rows = stored_ids(args.database_url, psql)
        resolved, unresolved = draft(rows, lambda identifier: lookup(args.accounts_url, args.app_id, secret, identifier))
        report = args.report or args.out.with_name(args.out.name + ".report.json")
        write(args.out, report, resolved, unresolved, args.accounts_url)
    except (DraftError, OSError) as error:
        print(f"draft-identity-mapping: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"stored_ids": len(rows), "mapped": len(resolved), "left_out": len(unresolved),
                      "mapping": str(args.out), "report": str(report)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
