#!/bin/sh
# Hook end to end against a Silicon Accounts test stack, with real tokens:
#   scripts/e2e-accounts.sh [--keep] [--suffix N] [--skip-package] [--no-build] [--verbose]
# See scripts/e2e_accounts/__main__.py for the scenarios and the settings it needs.
exec python3 "$(dirname "$0")/e2e_accounts" "$@"
