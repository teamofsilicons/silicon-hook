"""Hook end to end against a Silicon Accounts test stack.

    scripts/e2e-accounts.sh [--keep] [--suffix N] [--skip-package] [--no-build] [--verbose]

Starts Hook from scratch with scripts/dev-accounts.sh (fresh database, Hook's
webhook registered on the stack), then runs, with real tokens:

  1  a Carbon signed in like the web (code + PKCE, app secret) manages its
     Silicon's hooks over the API: create, list, read, update, delete, restore
  2  a Silicon signs in to the hook CLI with a short-lived token, uses it, connects
     its own Silicon Accounts updates (real signed deliveries), logs out
  3  a Carbon signs in to the hook CLI with the device flow
  4  the custodian circle, sharing by c:/si: id, leaving, and Silicons that accept
     grants only from accounts they allowed
  5  every Silicon Accounts webhook event (id change, profile, sign-outs with and
     without app_revoked, custodian change, deletion, access removal), replays and
     forged deliveries
  8  restart safety
  6  Hook as a proof issuer, to a Ting stand-in that verifies every proof
  7  the discovery commands from a packaged Silicon Apps archive

and stops everything (`down`) unless --keep. Needs HOOK_DEV_STACK_FILE (see
scripts/dev_accounts.py), HOOK_E2E_MINT and HOOK_E2E_TSX (the stack's identity
helper and its runner) and HOOK_E2E_ACCOUNTS_CLI (a silicon-accounts CLI; it is
always given the stack's URL and a scratch home). Exit 0 only when every check
passed. Writes <state>/e2e-<suffix>/report.json.
"""

import argparse
import json
import subprocess
import sys
import time
import traceback

from support import SCRIPTS, Harness, Stop
import scenario_api
import scenario_cli
import scenario_events
import scenario_package
import scenario_ting


def main():
    parser = argparse.ArgumentParser(prog="scripts/e2e-accounts.sh", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--keep", action="store_true", help="leave Hook running and its database in place")
    parser.add_argument("--suffix", help="suffix of this run's test identities (default: random)")
    parser.add_argument("--skip-package", action="store_true", help="skip scenario 7 (a release build)")
    parser.add_argument("--no-build", action="store_true", help="use the binaries as they are")
    parser.add_argument("--verbose", action="store_true", help="show more of each answer")
    args = parser.parse_args()
    started = time.time()
    try:
        h = Harness(args.suffix, args.verbose)
    except (Stop, Exception) as error:  # configuration problems are reported, not traced
        print(f"e2e: {error}", file=sys.stderr)
        return 2
    print(f"Hook e2e run {h.suffix}: API {h.api}, Silicon Accounts {h.accounts_url}")
    stopped = None
    try:
        if not args.no_build:
            if subprocess.run(["cargo", "build", "--locked", "--workspace", "--bins"], cwd=SCRIPTS.parent).returncode:
                raise Stop("cargo build failed")
        h.dev_command("down")
        started_stack = h.dev_command("start")
        h.check("scripts/dev-accounts.sh start: fresh database, webhook registered, signed ping delivered",
                started_stack.get("ready") and started_stack.get("webhook") == "registered",
                {k: started_stack.get(k) for k in ("database_state", "webhook", "webhook_ping", "api")}, critical=True)
        scenario_api.setup(h)
        scenario_api.scenario_1(h)
        scenario_cli.scenario_2(h)
        scenario_cli.scenario_3(h)
        scenario_api.scenario_4(h)
        scenario_events.scenario_5(h)
        scenario_events.scenario_8(h)
        scenario_ting.scenario_6(h)
        if not args.skip_package:
            scenario_package.scenario_7(h)
    except Stop as error:
        stopped = str(error)
        print(f"\nSTOPPED: {stopped}", flush=True)
    except Exception:  # an unexpected answer shape: report where, keep the cleanup
        stopped = traceback.format_exc(limit=4)
        print(f"\nSTOPPED by an unexpected error:\n{stopped}", flush=True)
    finally:
        if not args.keep:
            try:
                down = h.dev_command("down")
                print(f"\ncleanup: {json.dumps(down)}")
            except Stop as error:
                print(f"\ncleanup failed: {error}", file=sys.stderr)
    failed = [r for r in h.results if not r["ok"]]
    report = {"suffix": h.suffix, "seconds": round(time.time() - started), "passed": len(h.results) - len(failed),
              "failed": failed, "stopped": stopped, "results": h.results}
    (h.work / "report.json").write_text(json.dumps(report, indent=1))
    print(f"\n{report['passed']} passed, {len(failed)} failed{', stopped early' if stopped else ''} "
          f"in {report['seconds']} s (report: {h.work / 'report.json'})")
    return 0 if not failed and not stopped else 1


if __name__ == "__main__":
    sys.exit(main())
