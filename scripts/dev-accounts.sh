#!/bin/sh
# Run Hook on this machine against a Silicon Accounts test stack:
#   scripts/dev-accounts.sh start [--ting-stub [--refuse-first-proof]] | restart | status | stop | down
# See scripts/dev_accounts.py for what each command does and the HOOK_DEV_* settings.
exec python3 "$(dirname "$0")/dev_accounts.py" "$@"
