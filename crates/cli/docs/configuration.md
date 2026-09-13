# Install and configure Hook

## One-command technical setup

```sh
curl -fsSL https://docs.hook.teamofsilicons.com/install.sh | sh
```

The installer installs Rust 1.98, verifies the SHA-256 of the versioned CLI source archive hosted with these docs, builds it with locked dependencies, and starts the daemon. It does not authenticate you or change IAM credentials. The registry package may lag this source snapshot. The backend must support these features before the new CLI can use them.

Requirements: macOS or Linux, HTTPS access, `curl`, a C compiler and Rust 1.98 or newer. On macOS, install Apple's command-line tools if prompted. On Debian/Ubuntu, install `build-essential` if a compiler is missing. Compiler/system package installation may require local administration.

## Build the updated source

```sh
git clone https://github.com/teamofsilicons/silicon-hook.git
cd silicon-hook
cargo build --workspace --bins --locked
cargo install --path crates/cli --locked
hook daemon start
```

Use the reviewed revision containing the required features, and deploy its backend before connecting a new client. See [compatibility](contracts.md).

## State and identity

`SILICON_HOME` is the base for the private `.silicon-hook` directory. If absent, Hook uses `$HOME`. `SILICON_HOOK_HOME` overrides the full state directory. `hook config home <directory>` relocates the configured base. Files are private and state writes are atomic.

`--profile` selects independent saved sessions. `env use` remembers a sandbox per profile; `--test` overrides it for one command and `--production` temporarily uses production. The daemon has one backend origin, configured by the default profile. Profiles registering with it must use that same origin. It maintains one prewarmed WebSocket and separate logical subscriptions/acknowledgments per identity.

## Common configuration

```sh
hook config show
hook config set url https://backend.hook.teamofsilicons.com
hook config set org tos
hook webhook http://127.0.0.1:9000/events --secret-file ./receiver-secret
hook webhook https://sandbox.example/events --test-destination
hook --isi worker-17 webhook http://127.0.0.1:9000/events
hook config set auto-update false
```

`ISI`/`--isi` is optional internal Silicon metadata. It is stored locally and included in receiver metadata when present; it never changes authorization. `--secret-file` configures local delivery HMAC signing and never sends that secret to Hook. Mark remote test destinations explicitly to prevent accidental production effects.

## Automatic updates

The daemon checks hourly and the CLI also checks after commands, using a shared timestamp/lock to avoid duplicate installation. Default: enabled. Set `SILICON_HOOK_AUTO_UPDATE=0` or `hook config set auto-update false` to disable automatic checks/installations. Cargo-installed binaries are updated through locked Cargo installation. A custom source build reports the available release and installation command instead of guessing its installation layout.

New commands use the installed update. Restart an already running daemon to load its new executable: `hook daemon stop` followed by `hook daemon start`. The installer starts the daemon before login, so checks do not depend on user activity. Backend dependency updates remain reviewable `Cargo.lock` changes.

## Diagnose and report

`hook <command> --help` explains purpose, flags and next steps. `hook commands --json` exports the command tree; `hook docs <topic>` works offline; `hook about` prints source/docs/package links.

```sh
hook report "Expected behavior, actual result, and reproduction steps" --pr https://github.com/teamofsilicons/silicon-hook/pull/123
```

Reports use your existing GitHub CLI login and submit only the text, optional PR and package version you supply. They never collect logs or credentials. If submission fails, check the issue tracker before retrying to avoid duplicate issues. Bug reports do not depend on Space Station.

## Diagnostic telemetry

Enabled by default. Use `hook config set telemetry off` for the selected profile or `SILICON_HOOK_TELEMETRY=off` for a process override. In the browser, open Connections & setup and disable Share diagnostic events. SDK clients use `client.with_telemetry(false)`. Operators can disable backend and worker collection with `HOOK_TELEMETRY=off`. See [telemetry storage, consent and event schema](telemetry.md).
