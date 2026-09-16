# Install and configure Hook

## One-command technical setup

```sh
honeycomb install 'tos>hook'
```

Honeycomb installs a prebuilt executable for Linux, Windows or macOS on x86_64 or aarch64. No Rust compiler is needed. Then run `hook login <slt>` and `hook webhook <webhook-url>`.

For local source development:

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
```

`ISI`/`--isi` is optional internal Silicon metadata. It is stored locally and included in receiver metadata when present; it never changes authorization. `--secret-file` configures local delivery HMAC signing and never sends that secret to Hook. Mark remote test destinations explicitly to prevent accidental production effects.

## Automatic updates

Honeycomb owns CLI updates. Hook commands and its daemon never install or replace binaries. Rust dependencies change only when the consuming project updates its manifest or lockfile. After upgrading, restart a running daemon with `hook daemon stop` and `hook daemon start`.

## Diagnose and report

`hook <command> --help` explains purpose, flags and next steps. `hook commands --json` exports the command tree; `hook docs <topic>` works offline; `hook about` prints source/docs/package links.

```sh
hook report "Expected behavior, actual result, and reproduction steps" --pr https://github.com/teamofsilicons/silicon-hook/pull/123
```

Reports use your existing GitHub CLI login and submit only the text, optional PR and package version you supply. They never collect logs or credentials. If submission fails, check the issue tracker before retrying to avoid duplicate issues. Bug reports do not depend on Space Station.

## Diagnostic telemetry

Enabled by default. Use `hook config set telemetry off` for the selected profile or `SILICON_HOOK_TELEMETRY=off` for a process override. In the browser, open Connections & setup and disable Share diagnostic events. SDK clients use `client.with_telemetry(false)`. Operators can disable backend and worker collection with `HOOK_TELEMETRY=off`. See [telemetry storage, consent and event schema](telemetry.md).
