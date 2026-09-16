# Build a Hook release for Honeycomb

Install the released CLI with `honeycomb install 'tos>hook'`, then run `hook login <slt>` and `hook webhook <webhook-url>`. Honeycomb owns installation and updates. The Rust client remains a normal Cargo dependency and never modifies a consuming project at runtime.

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

For each Rust target, run `cargo build --locked --release -p silicon-hook-cli --target <rust-target>` on the corresponding build runner. Collect each executable as `artifacts/<honeycomb-target>/<executable>`. Windows ARM64 uses the Windows runner's cross compiler.

## Validate and pack

Keep the app version in `honeycomb.yaml` equal to `crates/cli/Cargo.toml`. A release tag must be `v<version>`. With Honeycomb available:

```sh
python3 scripts/package-cli.py --artifacts artifacts --output dist
```

The packager requires all six nonempty native executables and checks their OS and CPU headers, stages `honeycomb.yaml` at the archive root, runs `honeycomb validate <staging-directory>`, then `honeycomb pack <staging-directory> --output <archive>`. It fails without a complete set. The output is one `silicon-hook-<version>.tar.gz` containing every platform. The GitHub release workflow uploads that archive as a build artifact; publication is a separate release action.

A docs build only renders documentation. It does not build binaries, publish a release or substitute a source archive for the prebuilt package. See [Honeycomb's package documentation](https://docs.honeycomb.teamofsilicons.com/) for its manifest contract.
