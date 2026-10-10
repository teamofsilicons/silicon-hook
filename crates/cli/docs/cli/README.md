# Hook CLI

`hook` manages a Silicon's signed provider webhooks: the URLs providers call,
their signature policies, the request history, and who else may see or change
them. It is built only on [`silicon-hook-client`](../client/README.md) and speaks
Hook API v3. It starts no daemon or listener; delivery to Silicons goes through
Ting, set up by the app that hosts the Silicon.

## Install

```sh
silicon-apps install hook
```

Silicon Apps installs the prebuilt CLI and keeps it updated; `hook` never
replaces itself. Development releases install as `silicon-apps install 'hook>dev'`.
From source: `cargo install --path crates/cli --locked` (binary `hook`).

## First session

A Silicon:

```sh
hook accounts --json                                        # what signing in needs; works offline
silicon-accounts login --app hook -q | hook login --slt-stdin
hook login status --json
hook create GitHub                                          # give GitHub the endpoint_url
hook list
hook events
```

A Carbon looking after Silicons:

```sh
hook login                                  # approve the printed code in a browser
hook silicons                               # the Silicons you look after or were granted
hook --silicon si:scout list
hook config set silicon si:scout            # save a default Silicon
```

[Sign in to Hook](../accounts/README.md) explains both sign-ins, the saved
session and who can do what.

## Output, errors and exit codes

Results print as JSON on stdout. Hints about the next step go to stderr; `--json`
silences them and prints errors as JSON on stderr:

```json
{"error": {"code": "forbidden", "message": "The actor is not authorized for this action.", "hint": "…", "status": 403, "request_id": "…", "exit_code": 3}}
```

`code` is stable: Hook's own refusal codes (`forbidden`, `not_found`,
`delivery_disabled`, `session_ended`…), the sign-in codes from Silicon Accounts
(`invalid_grant`, `access_denied`, `expired_token`…), and the CLI's own
(`not_signed_in`, `signed_in_elsewhere`, `refresh_interrupted`,
`previous_version_session`, `state_unreadable`, `invalid_input`). Exit codes:
0 success, 1 failure, 2 invalid input, 3 sign-in required or refused,
4 not found, 5 conflict, 6 rate limited, 130 interrupted.

## Choosing the Silicon

Hook commands act on one Silicon's hooks. The CLI uses, in order: `--silicon`
(a `si:` id or the Silicon's uuid), the profile's `hook config set silicon`, and
for a signed-in Silicon its own uuid. A Carbon without either gets an error that
names `hook silicons`.

## Global flags

| Flag | Meaning |
| --- | --- |
| `--silicon <si:id or uuid>` | The Silicon to act on |
| `--profile <name>` | A separate saved sign-in and settings (default `default`) |
| `--url <origin>` | Hook API; env `SILICON_HOOK_URL`; default `https://backend.hook.teamofsilicons.com` |
| `--accounts-url <origin>` | Silicon Accounts; env `ACCOUNTS_URL`; default `https://accounts.teamofsilicons.com` |
| `--json` | JSON only: no hints, errors as JSON |
| `--idempotency-key <key>` | Reuse when retrying the same change after an uncertain result |

Plain `http` is accepted only for this machine (`localhost` or a loopback
address), for a local Hook and Silicon Accounts.

## Commands

`hook <command> --help` explains each command, how it combines with others and
its flags. `hook commands` lists every path; `hook commands --json` adds the full
help of each. `hook docs <topic>` reads these guides offline.

| Command | Purpose |
| --- | --- |
| `login` | Carbons: device code. Silicons: `--slt-stdin`, `--slt <SLT>` or `login <SLT>` |
| `login status [--offline]` | Who you are; Hook confirms it |
| `logout` | End the sign-in at Silicon Accounts and forget it |
| `whoami` | The saved sign-in, offline |
| `accounts --json` | App id, Silicon Accounts URL, API URL, version; offline |
| `silicons` | The Silicons you can open, and why (`self`, `custodian`, `manage`, `view`) |
| `create <name>` | A provider webhook, signed by default; the generated secret prints once |
| `list [--include-deleted]` | The Silicon's hooks |
| `show <id>` | One hook's settings and signing policy (never its secret) |
| `update <id> --patch <JSON or @file>` | Change name, description, time_zone, enabled, signature |
| `set-secret <id> --secret-file <file or ->` | Bring your own secret; URL and policy stay |
| `delete <id>` / `restore <id>` | Delete; restore within 45 days |
| `enable <id>...` / `disable <id>...` | Resume or pause ingress, all or nothing |
| `rotate endpoint <id>` | Retire the URL for good and issue a new one |
| `rotate secret <id>` | New signing secret, printed once |
| `events` / `blocked` `[--hook <id>] [--limit N] [--cursor C]` | Verified or withheld requests, newest first |
| `event <id>` | One retained event with its original request |
| `publication <event-id>` | Where its delivery through Ting stands |
| `access list` / `grant <id> --level view\|manage` / `revoke <id>` / `leave` | Who else can see or manage the Silicon's hooks |
| `allow-list list` / `add <id>` / `remove <id>` | Who outside the custodian's Silicons may give this Silicon access |
| `connect-accounts [--secret-file -]` | Receive the Silicon's own Silicon Accounts events in a hook |
| `receiving register` / `status` / `subscribe` / `unsubscribe` | Delivery through Ting (when the server has it) |
| `config show` / `profiles` / `home <dir>` / `set <key> <value>` / `unset <key>` | Local settings: `url`, `accounts-url`, `silicon`, `telemetry` |
| `system version` / `health` / `delivery` | The Hook API's version, readiness, and whether it delivers through Ting |
| `commands`, `docs <topic>`, `about`, `report <message> [--pr <url>]` | Discovery, guides, links, bug reports |

History limits are 1 to 10,000; a page may hold fewer because of a byte budget.
Continue with `next_cursor`. Reading history never acknowledges anything.

## Signatures and provider secrets

```sh
hook create GitHub --signature @github-policy.json
hook create Stripe --signature @stripe-policy.json --secret-file stripe-secret.txt
hook create LocalDemo --unsigned
hook set-secret <id> --secret-file encoded-secret.txt --secret-encoding hex
hook update <id> --patch '{"description": null}'
```

Secret files keep spaces and lose one trailing line ending; empty, multi-line,
control-character or over-4096-byte secrets are refused. Do not give a secret
both inside `--signature` and with `--secret-file`. Without one, creation
generates a secret and prints it once. `set-secret` keeps the encoding unless you
pass one, and the previous secret stops verifying at once.
[Signature expressions](../api/README.md#signature-expressions) lists the
algorithms and encodings.

## A Silicon's own Silicon Accounts events

Silicon Accounts can tell a Silicon when it is signed out, renamed or given a new
custodian, by calling a webhook. Point it at a Hook hook:

```sh
hook connect-accounts                         # prints the hook URL and the command to run
silicon-accounts webhook set <url>            # as the Silicon; prints a whsec_ secret once
silicon-accounts silicon webhook set si:scout <url>   # or as its custodian
hook connect-accounts --secret-file -         # paste the whsec_ secret
```

Until the secret is stored, Silicon Accounts deliveries are withheld as
unverified (`hook blocked` shows them).

## Delivery through Ting

When the Hook server delivers through Ting, each verified request reaches the
Silicon as a compact reference that its app hydrates with
[the receiving SDK](../client/relay.md). `receiving register` enrols you with
Ting; a Carbon with access can `receiving subscribe` to a Silicon's future
events. When the server has no Ting, Hook still receives and stores every event,
these commands answer `delivery_disabled`, and `publication` says
`delivery_disabled`: read events with `hook events`.

## State, settings and telemetry

State lives in `${SILICON_HOME:-~}/.silicon-hook/profiles.json` (0600, directory
0700). `SILICON_HOOK_HOME` names the exact directory; `hook config home <dir>`
moves the base to an existing directory. Writes are atomic and serialized by a
lock file.

Telemetry is on by default and carries no payloads or credentials: one event per
command (name, outcome, duration), sent to Hook only while signed in. Turn it off
with `hook config set telemetry off` or `SILICON_HOOK_TELEMETRY=off`. See
[telemetry](../telemetry.md).

## Upgrading from Hook before 1.0

- Sign in again: `hook login` (Carbons) or the Silicon command above. The old
  `state.json` is left untouched and never read for credentials; its URL, default
  Silicon and telemetry choice carry over.
- Hooks belong to Silicons: choose one with `--silicon`. Flags and commands of
  earlier versions that no longer apply (test environments, publisher setup,
  separate Ting approval) are gone; the old global flags fail with an
  explanation of what replaced them.
- New: `hook login` without arguments (device flow), `--slt-stdin`,
  `accounts --json`, `silicons`, `access`, `allow-list`, `connect-accounts`.

`hook report "what happened" --pr https://github.com/teamofsilicons/silicon-hook/pull/123`
files a bug through your authenticated GitHub CLI. Only your text, the optional
pull request and the version are sent.
