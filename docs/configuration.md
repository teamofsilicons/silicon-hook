# Install and configure Hook

## One-command technical setup

```sh
honeycomb install 'tos>hook'
```

Honeycomb installs a prebuilt executable for Linux, Windows or macOS on x86_64 or aarch64. No Rust compiler is needed. Then run `hook login <slt>` for internal management. The enclosing app handles Ting receiving separately from this management CLI, without an extra end-user setup flow.

For local source development:

```sh
git clone https://github.com/teamofsilicons/silicon-hook.git
cd silicon-hook
cargo build --workspace --bins --locked
cargo install --path crates/cli --locked
```

Use the reviewed revision containing the required features, and deploy its backend before connecting a new client. See [compatibility](contracts.md).

## State and identity

`SILICON_HOME` is the base for the private `.silicon-hook` directory. If absent, Hook uses `$HOME`. `SILICON_HOOK_HOME` overrides the full state directory. `hook config home <directory>` relocates the configured base. Files are private and state writes are atomic.

`--profile` selects independent saved sessions. `env use` remembers a sandbox per profile; `--test` overrides it for one command and `--production` temporarily uses production. The CLI refreshes sessions under its private state lock. It starts no Hook daemon or delivery connection.

## Common configuration

```sh
hook config show
hook config set url https://backend.hook.teamofsilicons.com
hook config set org tos
```

The enclosing runtime owns destination configuration, optional internal Silicon metadata and callback authentication through Ting. See the [stateless receiving adapter](client/relay.md) and [service setup](ting-delivery.md). Keep test destinations and sessions isolated from production.

## Automatic updates

Honeycomb owns CLI updates. Hook commands never install or replace binaries. Rust dependencies change only when the consuming project updates its manifest or lockfile. Before upgrading from the legacy transport, use the old executable's `hook daemon stop`. The new CLI removes delivery fields on its next state save while preserving login credentials; it cannot manage the retired daemon.

## Diagnose and report

`hook <command> --help` explains purpose, flags and next steps. `hook commands --json` exports the command tree; `hook docs <topic>` works offline; `hook about` prints source/docs/package links.

```sh
hook report "Expected behavior, actual result, and reproduction steps" --pr https://github.com/teamofsilicons/silicon-hook/pull/123
```

Reports use your existing GitHub CLI login and submit only the text, optional PR and package version you supply. They never collect logs or credentials. If submission fails, check the issue tracker before retrying to avoid duplicate issues. Bug reports do not depend on Space Station.

## Diagnostic telemetry

Enabled by default. Use `hook config set telemetry off` for the selected profile or `SILICON_HOOK_TELEMETRY=off` for a process override. In the browser, open Connections & setup and disable Share diagnostic events. SDK clients use `client.with_telemetry(false)`. Operators can disable backend and worker collection with `HOOK_TELEMETRY=off`. See [telemetry storage, consent and event schema](telemetry.md).
