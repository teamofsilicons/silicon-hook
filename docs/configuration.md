# Install and configure Hook

## Install the CLI

```sh
silicon-apps install hook
```

Silicon Apps installs a prebuilt `hook` for Linux, macOS or Windows on x86_64 or
aarch64 and updates it; no Rust toolchain is needed. Development releases install
as `silicon-apps install 'hook>dev'`. Then sign in: `hook login` (Carbons) or
`silicon-accounts login --app hook -q | hook login --slt-stdin` (Silicons).

From source:

```sh
git clone https://github.com/teamofsilicons/silicon-hook.git
cd silicon-hook
cargo install --path crates/cli --locked
```

Deploy the matching backend before connecting a new client; see
[compatibility](contracts.md).

## Where the CLI keeps its state

`$SILICON_HOME/.silicon-hook` (or `~/.silicon-hook` without `SILICON_HOME`) holds
`profiles.json`: each profile's settings and its Silicon Accounts sign-in. The
directory is 0700 and the files 0600; writes are atomic, and a lock file
(`profiles.lock`) serializes changes and token refreshes.

- `SILICON_HOOK_HOME` names the exact directory instead.
- `hook config home <directory>` moves the base to an existing directory (state
  then lives in `<directory>/.silicon-hook`).
- `--profile <name>` keeps a separate sign-in and settings in the same file.

A `state.json` from Hook before 1.0 is left untouched and never read for
credentials; see [upgrading](cli/README.md#upgrading-from-hook-before-10).

## Settings

```sh
hook config show                                     # what is in effect, and where it came from
hook config set silicon si:scout                     # default Silicon for this profile
hook config set url http://127.0.0.1:4201            # a local Hook API
hook config set accounts-url http://localhost:9590   # a local Silicon Accounts
hook config set telemetry off
hook config unset url
```

| Setting | Flag | Environment | Default |
| --- | --- | --- | --- |
| Hook API | `--url` | `SILICON_HOOK_URL` | `https://backend.hook.teamofsilicons.com` |
| Silicon Accounts | `--accounts-url` | `ACCOUNTS_URL` | `https://accounts.teamofsilicons.com` |
| Default Silicon | `--silicon` | | the signed-in Silicon |
| Telemetry | | `SILICON_HOOK_TELEMETRY=off` | on |

A flag or environment variable wins over the profile setting. Plain `http` is
accepted only for this machine. A signed-in profile keeps the Hook API and Silicon
Accounts it signed in with: changing either asks you to sign out first (or use
another profile), so a token is never sent to another service.

## Updates

Silicon Apps owns CLI updates; `hook` never installs or replaces binaries. The
Rust client changes only when the consuming project updates its manifest.

## Diagnose and report

`hook <command> --help` explains purpose, flags and next steps;
`hook commands --json` exports the command tree; `hook docs <topic>` works
offline; `hook about` prints the source, docs and package links. Errors carry a
stable `code`, a `hint` and an exit code ([CLI](cli/README.md#output-errors-and-exit-codes)).

```sh
hook report "Expected behaviour, actual result, and reproduction steps" --pr https://github.com/teamofsilicons/silicon-hook/pull/123
```

Reports use your existing GitHub CLI login and send only the text, the optional
pull request and the version. If submission fails, check the issue tracker before
retrying.

## Diagnostic telemetry

On by default. `hook config set telemetry off` turns it off for a profile and
`SILICON_HOOK_TELEMETRY=off` for a process. SDK clients use
`client.with_telemetry(false)`. Operators turn off backend and worker collection
with `HOOK_TELEMETRY=off`. See [telemetry](telemetry.md).
