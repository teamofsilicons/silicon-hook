#!/usr/bin/env bash
# Package one Hook CLI binary for Silicon Apps.
#
#   scripts/package-apps.sh <version> <target> <binary>
#   scripts/package-apps.sh 1.0.0 linux-x86_64 target/x86_64-unknown-linux-gnu/release/hook
#
# Writes dist/apps/hook-<version>-<target>.tar.gz (apps.yaml listing only
# <target>, plus bin/hook or bin/hook.exe) and its .sha256, after
# `silicon-apps validate` and `silicon-apps pack`. When this machine can run the
# binary, it first runs `hook --help`, `hook accounts --json` and
# `hook login status --json` in an empty home and refuses a binary that answers
# them wrongly; PACKAGE_DISCOVERY=require makes "cannot run it here" an error
# too. --check-only stops after checking the binary. Publishes nothing.
#
# Needs Python 3.9+ and silicon-apps 0.2
# (`cargo install --locked silicon-apps-cli --version 0.2.0`, or set
# SILICON_APPS to its path). scripts/package-apps.sh --help lists every option.
set -euo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for candidate in "${PYTHON:-}" python3 python; do
  [ -n "$candidate" ] || continue
  if command -v "$candidate" >/dev/null 2>&1 &&
    "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
    exec "$candidate" "$here/package_apps.py" "$@"
  fi
done
echo "package-apps: Python 3.9 or newer is required (set PYTHON to its path)" >&2
exit 1
