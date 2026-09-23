# Build a Hook release for Honeycomb

Install the released CLI with `honeycomb install 'tos>hook'`, then run `hook login --slt-file ./hook-slt`. The enclosing application configures internal Ting receiving; Hook's CLI manages webhooks and inspects retained events. Honeycomb owns installation and updates. The Rust client remains a normal Cargo dependency and never modifies a consuming project at runtime.

## Build all targets

The release workflow builds these native executables:

| Honeycomb target | Rust target | Executable |
| --- | --- | --- |
| linux-x86_64 | x86_64-unknown-linux-gnu | hook |
| linux-aarch64 | aarch64-unknown-linux-gnu | hook |
| windows-x86_64 | x86_64-pc-windows-msvc | hook.exe |
| windows-aarch64 | aarch64-pc-windows-msvc | hook.exe |
| macos-x86_64 | x86_64-apple-darwin | hook |
| macos-aarch64 | aarch64-apple-darwin | hook |

For each Rust target, run `cargo build --locked --release -p silicon-hook-cli --target <rust-target>` on the corresponding build runner. Collect each executable as `artifacts/<honeycomb-target>/<executable>`. Windows ARM64 uses the Windows runner's cross compiler. The checked-in Cargo configuration statically links the Visual C++ runtime for both Windows targets.

## Validate and pack

Keep the app version in `honeycomb.yaml` equal to `crates/cli/Cargo.toml`. A release tag must be `v<version>`. With Honeycomb available:

```sh
python3 scripts/package-cli.py --artifacts artifacts --output dist
```

The packager requires all six nonempty native executables and checks their OS and CPU headers, stages `honeycomb.yaml` at the archive root, runs `honeycomb validate <staging-directory>`, then `honeycomb pack <staging-directory> --output <archive>`. It then validates the finished archive, checks its exact file inventory and writes a SHA-256 sidecar. It fails without a complete set. The output is one `silicon-hook-<version>.tar.gz` containing every platform. The GitHub release workflow uploads that archive and checksum as build artifacts; publication is a separate release action.

A docs build only renders documentation. It does not build binaries, publish a release or substitute a source archive for the prebuilt package. See [Honeycomb's package documentation](https://docs.honeycomb.teamofsilicons.com/) for its manifest contract.

## Local cross builds on macOS

Install the six Rust targets above, Xcode's macOS SDK, `cargo-zigbuild` with Zig, and `cargo-xwin` with LLVM. With their executables on `PATH`:

```sh
cargo build --locked --release -p silicon-hook-cli --target aarch64-apple-darwin --target x86_64-apple-darwin --target-dir target/honeycomb-macos
cargo zigbuild --locked --release -p silicon-hook-cli --target x86_64-unknown-linux-gnu.2.28 --target aarch64-unknown-linux-gnu.2.28 --target-dir target/honeycomb-linux
cargo xwin build --locked --release -p silicon-hook-cli --target x86_64-pc-windows-msvc --target aarch64-pc-windows-msvc --target-dir target/honeycomb-windows
```

The Linux cross builds target glibc 2.28 or newer. Collect the outputs from each build directory's `<rust-target>/release/` into the artifact layout above before packaging. Native CI builds use the system libraries of their listed runners.

Locally staged executables can also live at the paths declared by the root manifest: `targets/<honeycomb-target>/bin/<executable>`. Then `honeycomb validate .` verifies the complete local package. Generated `targets/` and `dist/` are kept on disk and excluded from source commits.

## 0.8.0: internal Ting delivery

API v2 publishes verified events through Ting 0.1.4. Applications fetch the full
original from Hook using current authorization; the CLI and stateless Rust SDK
provide management and receiving helpers. The website handles its paired normal
sessions and scoped testing receiver internally. Login no longer starts a Hook
relay, and the removed `webhook`, `unhook` and daemon commands must be replaced by
the enclosing application's Ting runtime. Existing v1 contracts retain their
recorded deprecation/sunset policy; they are not restored by installing 0.8.0.

Deploy migrations 10–16 to both databases, activate the approved Ting scopes,
register the Hook notification type, and provision a dedicated publisher in each
organization. Required primary delivery needs the recipient's explicit automation
opt-in. Existing queued requests keep their original policy and retry identity.
See [internal delivery setup](ting-delivery.md) and [deployment](deployment.md).

The release includes scoped capability replay/renewal, private CLI output,
rate-limit recovery without duplicate browser events, and silent inbox polling.
The [verification record](verification/ting-e2e-2026-09-23.md) documents real
send/receive, native ACKs, restart recovery, CLI/browser checks and remaining limits.

## 0.7.0: event payload without summary

REST history/deliveries, WebSocket `new_event` metadata and local recipient payloads
no longer contain the generated `summary`. The event ID, provider, receipt time,
request and delivery sequence remain available. No database migration is needed;
existing stored event rows are preserved.

Update Rust consumers to `silicon-hook-client` 0.7.0. Update the CLI with
`honeycomb update 'tos>hook'` and restart existing relay daemons before using the
new backend. Earlier clients require the removed field when decoding events.
The separate DM-style protocol proposal in `understanding/api.yaml` is not part
of this release; existing WebSocket message names and ACK/replay behavior remain.

## 0.7.1: localhost subdomain recipients

`hook webhook` and `Recipient::new` now accept plain HTTP recipients on any
`*.localhost` name, such as `http://chef.bricks.localhost`, in addition to
`localhost` and loopback IP addresses. Earlier CLIs rejected such a URL with
`recipient must be HTTPS (or HTTP on loopback)`, which made `silicon connect`
fail while registering the `tos>hook` webhook. `Client::new` applies the same
rule to service origins. No backend change is included; the API contract and
database are unchanged.

Update Rust consumers to `silicon-hook-client` 0.7.1. Update the CLI with
`honeycomb update 'tos>hook'` and restart existing relay daemons.
