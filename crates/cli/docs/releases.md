# Release Hook

Silicons and Carbons install the `hook` CLI from Silicon Apps:

```sh
silicon-apps install hook          # the latest production release
silicon-apps install 'hook>dev'    # the latest development release
```

Silicon Apps' updater keeps installed copies current, checking every minute;
`hook` never downloads or replaces itself. After installing, a Silicon signs in
with `silicon-accounts login --app hook -q | hook login --slt-stdin` and a Carbon
with `hook login`. The Rust client is an ordinary crates.io dependency that
changes only when a project updates its manifest.

The rest of this page is for maintainers: how a release is built, checked and
handed to Silicon Apps.

## Versions

The service (`silicon-hook`), the client (`silicon-hook-client`) and the CLI
(`silicon-hook-cli`) share one version, `1.0.0` today. A release tag is
`v<version>` and must equal `crates/cli/Cargo.toml`; the package manifest takes
its version from the same file, so the three never disagree. Breaking API changes
also need a new API major ([contracts](contracts.md)).

## Build and pack

Push the tag (or run the `Silicon Apps release archives` workflow by hand). The
workflow builds the CLI on these runners:

| Silicon Apps target | Rust target | Runner | Executable |
| --- | --- | --- | --- |
| linux-x86_64 | x86_64-unknown-linux-gnu | ubuntu-24.04 | hook |
| linux-aarch64 | aarch64-unknown-linux-gnu | ubuntu-24.04-arm | hook |
| windows-x86_64 | x86_64-pc-windows-msvc | windows-2025 | hook.exe |
| windows-aarch64 | aarch64-pc-windows-msvc | windows-2025 (cross) | hook.exe |
| macos-x86_64 | x86_64-apple-darwin | macos-15 (cross) | hook |
| macos-aarch64 | aarch64-apple-darwin | macos-15 | hook |

Each runner checks the binary it built: the right executable format and
processor, a glibc no newer than Ubuntu 24.04's for Linux, and, wherever the
runner can execute it, the three commands every Silicon Apps package must answer
signed out in an empty home: `hook --help`, `hook accounts --json` (with
`"app_id": "hook"`) and `hook login status --json` (`{"authenticated": false}`).
The Windows build links the Visual C++ runtime statically.

A packing job then runs `scripts/package-apps.sh` for each target. It renders
[`packaging/apps.yaml.in`](../packaging/apps.yaml.in) for that one target, stages
`apps.yaml` and `bin/hook` (`bin/hook.exe` on Windows), runs `silicon-apps
validate` and `silicon-apps pack` (silicon-apps-cli 0.2.0), checks that the
archive holds exactly those two files and validates it again. The artifact
`hook-silicon-apps-release` holds `hook-<version>-<target>.tar.gz` for each
target, a `.sha256` beside each, and `SHA256SUMS`. The workflow publishes
nothing.

To package a build yourself:

```sh
cargo build --locked --release -p silicon-hook-cli
scripts/package-apps.sh 1.0.0 macos-aarch64 target/release/hook
```

It needs Python 3.9 or newer and `silicon-apps` 0.2
(`cargo install --locked silicon-apps-cli --version 0.2.0`, or `SILICON_APPS=<path>`).
Validating and packing are local: the script gives `silicon-apps` an empty home
and no server, so no sign-in is used or needed. `PACKAGE_DISCOVERY=require`
refuses to pack a binary this machine cannot run; `--check-only` checks a binary
without packing.

## Hand the release to Silicon Apps

Silicon Apps validates every uploaded package by running the three commands on a
worker for its target. Today the four Linux workers are live, so `linux-x86_64`
and `linux-aarch64` (what the Silicons' hosts run) can be uploaded. The macOS
and Windows archives are built with every release and kept for when their
workers go live; `silicon-apps capabilities` shows which are live now.

An author of the `hook` app uploads after review, from a signed-in
`silicon-apps`:

```sh
silicon-apps upload hook --target linux-x86_64 hook-1.0.0-linux-x86_64.tar.gz
silicon-apps upload hook --target linux-aarch64 hook-1.0.0-linux-aarch64.tar.gz
silicon-apps release hook --version 1.0.0 --package PACKAGE_ID --package PACKAGE_ID
silicon-apps promote hook DEVELOPMENT_RELEASE_ID --version 1.0.0
```

A new release starts in the development channel (`hook>dev`); promoting it makes
the production release that `silicon-apps install hook` and the updater pick up.
If a release turns out bad, withdraw it with a one-sentence reason
(`silicon-apps withdraw hook RELEASE_ID --reason "…"`); installed copies move off
it within about a minute. Publish the crates in dependency order:
`cargo publish -p silicon-hook-client`, then `cargo publish -p silicon-hook-cli`.

Deploy the matching backend before promoting a release whose API changed
([deployment](deployment.md)): the CLI refuses a server that does not serve its
API major.

## Cross builds on macOS

With the six Rust targets, Xcode's macOS SDK, `cargo-zigbuild` with Zig, and
`cargo-xwin` with LLVM on `PATH`:

```sh
cargo build --locked --release -p silicon-hook-cli --target aarch64-apple-darwin --target x86_64-apple-darwin --target-dir target/apps-macos
cargo zigbuild --locked --release -p silicon-hook-cli --target x86_64-unknown-linux-gnu.2.28 --target aarch64-unknown-linux-gnu.2.28 --target-dir target/apps-linux
cargo xwin build --locked --release -p silicon-hook-cli --target x86_64-pc-windows-msvc --target aarch64-pc-windows-msvc --target-dir target/apps-windows
```

The Linux cross builds target glibc 2.28 or newer. Package each output from its
`<rust-target>/release/` folder with `scripts/package-apps.sh`. `dist/` is
ignored by git.

## Release notes

### 1.0.0 (not yet released)

- Carbons and Silicons sign in with Silicon Accounts: `hook login` (device code)
  or `silicon-accounts login --app hook -q | hook login --slt-stdin`.
- Hooks belong to their Silicon; its custodian manages them, and either can grant
  others `view` or `manage` access.
- API v3; v1 and v2 answer `410 api_version_sunset`. Provider URLs keep working.
- Installed and updated by Silicon Apps (`silicon-apps install hook`).
- Delivery through Ting is optional and off until the server sets `HOOK_TING_URL`.

Upgrading from an earlier release: sign in again (earlier sign-ins are not
carried over), and see [the CLI guide](cli/README.md#upgrading-from-hook-before-10).
Notes for 0.x releases are in the repository's history records.
