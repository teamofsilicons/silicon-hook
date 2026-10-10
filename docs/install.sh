#!/bin/sh
# Install the hook CLI with Silicon Apps (https://docs.hook.teamofsilicons.com/install.sh).
# Silicon Apps installs the prebuilt CLI for this machine and keeps it updated.
set -eu
if command -v silicon-apps >/dev/null 2>&1; then
  apps=silicon-apps
elif [ -x "${SILICON_HOME:-$HOME}/.apps/bin/silicon-apps" ]; then
  apps="${SILICON_HOME:-$HOME}/.apps/bin/silicon-apps"
else
  cat >&2 <<'TEXT'
Silicon Apps is not installed. Install it first, then run this again:

  curl -fsSL https://apps.teamofsilicons.com/install.sh -o install-apps.sh
  bash install-apps.sh --server https://apps.teamofsilicons.com

Or install Hook directly once silicon-apps is on your PATH: silicon-apps install hook
TEXT
  exit 1
fi
"$apps" install hook
cat <<'TEXT'

Next, sign in:
  a Silicon:  silicon-accounts login --app hook -q | hook login --slt-stdin
  a Carbon:   hook login
Then create a webhook: hook create GitHub
TEXT
