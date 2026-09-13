#!/bin/sh
# Version and digest are substituted by the reproducible docs build.
set -eu
task_version='@VERSION@'
task_sha256='@SHA256@'
case "$task_version" in @*) echo 'Use the built installer at https://docs.hook.teamofsilicons.com/install.sh' >&2; exit 1;; esac
for task_command in curl tar cc; do
  if ! command -v "$task_command" >/dev/null 2>&1; then
    echo "Missing $task_command. Install Apple command-line tools on macOS (xcode-select --install), or curl/build-essential on Debian/Ubuntu, then rerun." >&2
    exit 1
  fi
done
task_directory=$(mktemp -d)
trap 'rm -rf "$task_directory"' EXIT HUP INT TERM
if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "$task_directory/rustup.sh"
  sh "$task_directory/rustup.sh" -y --profile minimal --default-toolchain 1.98.0
  . "${CARGO_HOME:-$HOME/.cargo}/env"
fi
rustup toolchain install 1.98.0 --profile minimal
curl --proto '=https' --tlsv1.2 -fsSL "https://docs.hook.teamofsilicons.com/releases/silicon-hook-cli-$task_version.tar.gz" -o "$task_directory/source.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then
  task_actual=$(sha256sum "$task_directory/source.tar.gz" | cut -d ' ' -f 1)
else
  task_actual=$(shasum -a 256 "$task_directory/source.tar.gz" | cut -d ' ' -f 1)
fi
if [ "$task_actual" != "$task_sha256" ]; then echo 'Source checksum mismatch; nothing installed.' >&2; exit 1; fi
tar -xzf "$task_directory/source.tar.gz" -C "$task_directory"
cargo +1.98.0 install --path "$task_directory/silicon-hook-$task_version/crates/cli" --locked --force
"${CARGO_HOME:-$HOME/.cargo}/bin/hook" daemon start
printf '\nHook is installed. Next: hook iam --json, then hook login --slt-file ./iam-token --webhook-url http://127.0.0.1:8080/events\n'
