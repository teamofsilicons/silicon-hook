# Hook CLI

The `hook` binary is built from `crates/cli` and uses `silicon-hook-client` for
all backend and local-service networking. Build it with
`cargo build -p silicon-hook-cli`; the executable is `target/debug/hook`.
For a published version use `cargo install silicon-hook-cli --locked`.
Maintainers bundle canonical `docs/` guides into the crate with
`python3 scripts/bundle-cli-docs.py` before publishing; CI rejects stale copies.

## First session

Ask IAM for a short-lived token for `tos>hook`, then provide the token to Hook:

```sh
hook --profile cos iam --json
hook --profile cos --org tos login <slt>
hook --profile cos login status --json
hook --profile cos webhook http://127.0.0.1:9000/events
hook --profile cos --silicon cos:tos create GitHub
hook --profile cos --silicon cos:tos list
```

`hook login <slt>` is the short form required for agents. `--slt-file -` reads
from stdin, and `--slt` remains available for compatibility. Literal tokens can
appear in shell history/process arguments, so use a file or stdin when possible.
Hook does not request your
password, OTP or browser callback. Start the recipient server at the provided
URL before expecting delivery. The login response never prints session tokens.

A successful login saves tokens and a separate local API token, then starts the
persistent daemon and local request gateway. Configure delivery afterward with
`hook webhook <webhook-url>`. Until then, events stay pending. The optional
`login --webhook-url <url>` flag still configures delivery in the same command.
Silicon identities subscribe to their own stream automatically. A Carbon supplies
`--silicon` during login or uses `hook daemon subscribe <silicon-id>...` afterward;
IAM must authorize each Silicon.

`hook iam --json` discovers the actual backend-configured `app_id`, `iam_url`,
`testing` flag and `login_method` before login. With `--test <id>`, it discovers
that environment's IAM application using the locally attached Hook test key.
It never returns an app secret or environment key.

`hook login status --json` refreshes an expiring session, then checks the current
bearer and organization membership online with IAM. A successful response contains
`authenticated: true`, `actor: {"type": "carbon" | "silicon", "id": "..."}`,
organization, expiry, and local delivery configuration. No saved session or an
invalid/revoked credential reports `authenticated: false`. Transport and permission
failures remain errors, so an outage is not reported as a successful login.
`whoami` remains an offline view of saved metadata.

`hook webhook <webhook-url>` sets or replaces the selected profile/environment's
recipient. It validates the URL locally, stores it beside the tokens, and starts
the daemon if needed. The destination is never sent to the backend. HTTP is
accepted only on loopback; remote recipients require HTTPS. Embedded credentials
and fragments are rejected.

`hook unhook` clears only the selected identity's recipient, retaining its login,
stream selection, and local request API. Other identities keep their destinations.
The daemon applies changes within five seconds and cancels old relay work;
in-flight requests may already have reached the old recipient. Events without
an acknowledgment replay after `hook webhook <webhook-url>` reconnects delivery.
Use `hook logout` to revoke authentication.

## Context

Global flags may appear before or after a command:

| Flag | Meaning |
|---|---|
| `--profile <name>` | Independent local identity and backend; default `default` |
| `--url <origin>` | Override service origin for a new/unbound profile |
| `--org <handle>` | Select the production or test organization |
| `--silicon <id>` | Silicon whose hooks/history/deliveries the action addresses |
| `--test <uuid>` | Select a locally stored Hook test root key and separate test session |
| `--json` | Machine output with no contextual next-step prose |
| `--idempotency-key <key>` | Stable logical mutation identifier for retries |

`SILICON_HOOK_URL` and `SILICON_HOOK_ORG` provide origin/organization defaults.
A profile with credentials is bound to its backend. Use another profile for a
different backend; this prevents sending saved credentials to the wrong host.
Test commands never fall back to the production session. A signed-in Silicon
is the default target; a Carbon normally supplies `--silicon`.

State lives in `${SILICON_HOME:-~}/.silicon-hook/state.json`. A nonempty
`SILICON_HOME` supplies the default base home. Set another base home with
`hook config home <directory>` (the state then lives below
`<directory>/.silicon-hook`). The location must already be a directory.
`SILICON_HOOK_HOME` remains an environment override for the complete state
directory. Directory mode is 0700 and files are 0600 on Unix. A process
lock serializes refresh and state updates, and replacement is atomic. Keep
this directory private: it contains access/refresh tokens and test root keys.
Do not share it between independent machines refreshing the same token family.
Before rotating a refresh token, the CLI saves an idempotency key in that
session. If the response is lost, retrying the command reuses this key. The key
is cleared only when the replacement tokens are saved successfully; the daemon
uses the same locked refresh path.

## Command reference

Run `hook <command> --help` for complete options and required arguments.
`hook commands` lists every command path; `hook commands --json` includes full
help. `hook docs <topic>` bundles these guides for offline reading.

| Command | Purpose |
|---|---|
| `iam --json` | Discover the public IAM app configuration before login |
| `login <slt>` | Save a session and start its local gateway (`--slt-file` and optional `--webhook-url` are supported) |
| `login status --json` | Check authentication and actor online with IAM |
| `webhook <webhook-url>` | Configure or replace local delivery for this identity |
| `unhook` | Detach local delivery while retaining authentication |
| `logout` | Revoke the refresh-token family and remove the selected local session |
| `whoami` | Show actor, organization, expiry and local recipient; no tokens |
| `create <name>` | Create a signed hook; optional description/time-zone/signature |
| `list [--include-deleted]` | List hooks and their current endpoints |
| `show <uuid>` | Read hook metadata and signature policy |
| `update <uuid> --patch <JSON-or-@file>` | Change metadata, activation or signature policy |
| `delete <uuid>` / `restore <uuid>` | Soft-delete or recover within 45 days |
| `enable <uuid>...` / `disable <uuid>...` | Atomically resume/pause several hooks |
| `rotate endpoint <uuid>` | Permanently retire the old URL and issue a new URL |
| `rotate secret <uuid>` | Invalidate the old signing secret immediately |
| `events [--hook <uuid>] [--limit N] [--cursor ...]` | Verified history, per hook or all hooks |
| `blocked [same filters]` | Withheld requests, separate from delivered history |
| `deliveries list [--limit N] [--after N]` | Pull retained pending deliveries |
| `deliveries ack <sequence>` | Cumulative acknowledgment for this identity/Silicon |
| `deliveries cursor` | Read the durable acknowledgment position |
| `connect-iam` | Register a Silicon's IAM webhook connection |
| `listen [--ack]` | Foreground stream inspection; Ctrl-C closes it |
| `system version` / `system health` | Compatibility and backend readiness |
| `env ...` | See the [testing CLI guide](../testing/cli.md) |
| `daemon ...` | Persistent relay and local request interface |
| `config show` / `config profiles` | Inspect local settings and names |
| `config home <directory>` | Set the base home directory for local state |
| `config set <key> <value>` | Set url, org, silicon, or auto-update |

History limits are 1–10000, but a byte-bounded page may return fewer items.
Follow `next_cursor` until null. Delivery pull limit is at most 1000.
`listen` answers pings automatically. `listen --ack` ACKs after printing;
without it inspection fills the outstanding window and then waits. Use the
daemon for persistent recipient delivery and reconnect. A daemon using the same
identity may ACK events while you inspect that identity's foreground stream.

## Signature examples

```sh
hook --silicon cos:tos create GitHub --signature @github-policy.json
hook --silicon cos:tos create LocalDemo --unsigned
hook --silicon cos:tos update <uuid> --patch '{"description":null}'
hook --silicon cos:tos update <uuid> --patch '{"signature":{"required":true}}'
```

Create/secret-rotation/environment-key output can contain secrets; redirect
those responses into private files if retaining them. `show` never retrieves a
hook's original signing secret. Use rotation if that secret is lost.

See [the signature reference](../api/README.md#signature-expressions) for the
full expression grammar, algorithms and encodings. Default verification uses
HMAC-SHA256 over `webhook-id.webhook-timestamp.raw-body` and base64 signatures.

## Daemon

```sh
hook daemon start
hook daemon status
hook --profile reviewer daemon subscribe cos:tos helper:tos
hook --profile reviewer daemon token
hook --profile reviewer daemon request --file request.json
hook daemon stop
hook daemon run
```

`run` stays in the foreground and is suitable for a service manager. The
background daemon shares one loopback port across all profiles and environments.
Changes are picked up within five seconds. `subscribe` replaces a selected
identity's list; no IDs unsubscribes all. `token` intentionally prints a secret
for programs calling `http://hook.localhost:18479/request`.

The daemon log is `~/.silicon-hook/relay.log`. Recipient failures retry without
acknowledging upstream. Logging out removes that identity from the daemon.
Stopping it leaves backend events pending. A machine reboot requires starting
the daemon again (login and `daemon start` do this); for boot-time startup run
`hook daemon run` through your operating system's service manager.

The [local API guide](../client/relay.md) defines request/receipt JSON, exact body
echoes, identity tokens and downstream acknowledgment behavior.

## Updates and troubleshooting

Updates are enabled by default. After a command finishes, at most once per hour,
the CLI checks its crates.io release. Cargo-installed binaries update in their
existing installation root. Development/custom binaries get a release notice;
the updater does not overwrite source build outputs. A running daemon keeps its
loaded version until restarted. When upgrading from a build that required the
recipient during login, run `hook daemon stop` before using the new login or
delivery commands, then `hook daemon start` with the rebuilt CLI. The new CLI
reads existing recipient strings and also supports unconfigured recipients.

Opt out with `hook config set auto-update off` or
`SILICON_HOOK_AUTO_UPDATE=false`. Enable again with `auto-update on`. The CLI
stores the last-check timestamp and serializes the claim to avoid concurrent
installations. Update failures do not change the command's success/failure.

Common recovery steps:

- An expired/revoked session needs a fresh IAM SLT and `hook login`.
- A missing test key needs `hook env attach` or authorized `hook env key`.
- A rotated key requires refreshing the saved key before test commands resume.
- A local port conflict needs resolving the process already bound to 18479.
- An offline recipient keeps deliveries pending; restart it at the saved URL.
- A JSON error includes a stable backend code; use `--idempotency-key` on retries
  after uncertain transport outcomes.

`hook report` and the graphical UI are outside the current release scope.
