#!/bin/sh
# Compatibility entry point for old installation links.
set -eu
if ! command -v honeycomb >/dev/null 2>&1; then
  echo "Install Honeycomb first: https://docs.honeycomb.teamofsilicons.com/" >&2
  exit 1
fi
honeycomb install 'tos>hook'
printf '\nNext: hook login <slt>, then hook webhook <webhook-url>\n'
