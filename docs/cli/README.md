# Hook CLI

The `hook` binary manages provider webhooks and inspects internal delivery through
`silicon-hook-client` and Hook API v2. Applications own receiving and hide Hook
and Ting setup from their users. This CLI stores management sessions and starts
no daemon, listener, local gateway, or Ting login.

Build with `cargo build -p silicon-hook-cli`; the executable is
`target/debug/hook`. Honeycomb manages installation and updates:
`honeycomb install 'tos>hook'`. Maintainers bundle canonical guides with
`python3 scripts/bundle-cli-docs.py` before publishing; CI rejects stale copies.

## First session

Obtain an IAM short-lived token for the selected Hook application, then:

```sh
hook --profile cos iam --json
hook --profile cos --org tos login <slt>
hook --profile cos login status --json
hook --profile cos --silicon cos:tos create GitHub
hook --profile cos --silicon cos:tos list
```

`hook login <slt>` is the short form. `--slt-file -` reads stdin, and `--slt`
remains available. Prefer a file or stdin when tokens should stay out of shell
history and process arguments. Hook does not request passwords, OTPs, or browser
callbacks. Login saves access and refresh tokens without configuring receiving,
and its response never prints those tokens.

`hook iam --json` discovers the backend's `app_id`, `iam_url`, `testing`, and
`login_method` before login. With a selected sandbox it discovers that
environment's application. It returns no app secret or environment key.

`hook login status --json` refreshes an expiring session, then checks its current
bearer and organization online. It returns authentication state, actor,
organization, expiry, profile, and environment. No saved session or a revoked
credential reports `authenticated: false`; service and permission errors fail.
An early access-token rejection triggers at most one refresh recovery before
the command is dispatched. `whoami` reads saved metadata without contacting IAM.

Organization selection uses `--org`, the selected profile/environment setting,
then the token's organization. For an unscoped Silicon session, the CLI derives
the organization from `name:organization` and verifies it online. Test sessions
never borrow production credentials or organization settings.

## Context and saved state

Global flags may appear before or after a command:

| Flag | Meaning |
|---|---|
| `--profile <name>` | Independent local identity and backend; default `default` |
| `--url <origin>` | Backend for a new, unbound profile |
| `--org <handle>` | Organization in the selected plane |
| `--silicon <id>` | Target for hooks, history, publication, or Carbon subscriptions |
| `--test <uuid>` | Saved sandbox and its separate test session |
| `--production` | Use production for this invocation |
| `--json` | Structured output without next-step prose |
| `--idempotency-key <key>` | Reuse the key for one logical mutation |

`SILICON_HOOK_URL` and `SILICON_HOOK_ORG` provide defaults. A profile containing
credentials or test selectors stays bound to its original backend; use another
profile for a different origin. A signed-in Silicon is the default target.
Carbons normally use `--silicon`; supplying it during login saves the target for
that profile or sandbox.

State lives in `${SILICON_HOME:-~}/.silicon-hook/state.json`. A nonempty
`SILICON_HOME` selects the base home. `hook config home <directory>` changes
the base to an existing directory; state goes below its `.silicon-hook` folder.
`SILICON_HOOK_HOME` overrides the complete state directory.

Directories use mode 0700 and files 0600 on Unix. A process lock serializes
credential refresh and state updates; replacements are atomic. Before refresh,
the CLI durably saves a mutation key and the original attempt time. A lost
response is retried with that key, and replacement tokens are saved together.
Keep this directory private and do not share one refresh-token family between
independent machines.

## Command reference

`hook <command> --help` describes arguments. `hook commands` lists command paths;
`hook commands --json` includes their complete help. `hook docs <topic>` reads
bundled guides offline.

| Command | Purpose |
|---|---|
| `iam --json` | Discover public IAM application configuration |
| `login <slt>` / `login --slt-file <file>` | Save a management session |
| `login status --json` | Check current authentication and actor |
| `logout` | Revoke the refresh family and remove the selected session |
| `whoami` | Read saved actor and expiry without printing credentials |
| `create <name>` | Create a provider webhook, signed by default |
| `list [--include-deleted]` | List hooks and current endpoints |
| `show <uuid>` | Read hook metadata and signing policy |
| `update <uuid> --patch <JSON-or-@file>` | Change metadata, activation, or signing policy |
| `delete <uuid>` / `restore <uuid>` | Delete or recover within 45 days |
| `enable <uuid>...` / `disable <uuid>...` | Resume or pause ingress atomically |
| `rotate endpoint <uuid>` | Retire a URL and issue a replacement |
| `rotate secret <uuid>` | Invalidate the old signing secret |
| `set-secret <uuid> --secret-file <file>` | Install a provider's secret |
| `events [--hook <uuid>] [--limit N] [--cursor ...]` | Read verified request history |
| `blocked [same filters]` | Read withheld requests |
| `event <event-id>` | Fetch one original retained provider request |
| `publication <event-id>` | Inspect publication state and available destination receipts |
| `publisher provision --slt-file <file\|-> [--replace-rejected]` | Provision or explicitly recover the dedicated backend publisher as an owner/admin Carbon |
| `receiving register` | Register this actor for internal application delivery |
| `receiving scope` | Read verified sandbox inbox/watch authority without issuing a capability |
| `receiving bootstrap --scope-file <file> --output <new-file> [--receiver-id <id>]` | Create/recover or renew a scoped sandbox capability; requires an explicit idempotency key and writes the secret only to a private file |
| `receiving status` | Read the current Carbon's subscription for `--silicon` |
| `receiving subscribe` | Request future events for a currently visible Silicon |
| `receiving unsubscribe` | Remove the current Carbon's receiving interest |
| `connect-iam` | Register a Silicon's IAM webhook connection |
| `system version` / `system health` | Check compatibility or readiness |
| `env ...` | Manage or select testing; see [testing CLI](../testing/cli.md) |
| `config show` / `config profiles` | Inspect local settings |
| `config home <directory>` | Change the base home directory |
| `config set <key> <value>` | Set url, org, silicon, or telemetry |

History limits are 1–10000; a page may contain fewer due to the backend's byte
budget. Continue with `next_cursor`. History and event lookup do not acknowledge
anything or change the application's receiving state.

## Internal receiving and inspection

An internal owner/admin configures the backend publisher with a newly issued
Hook SLT for a dedicated server-owned Silicon. It must be separate from the
admin's own management login:

```sh
hook --profile admin --org tos --idempotency-key publisher-setup-001 publisher provision --slt-file ./publisher-slt
```

Use `--slt-file -` for stdin. This command requires an explicit global
`--idempotency-key`; retry an uncertain result with the same SLT and key.
It is organization-scoped and does not require `--silicon`. The response contains only organization, actor and expiry, not
the server's credentials. `--replace-rejected` explicitly recovers a rejected
publisher using a fresh dedicated SLT and new operation key; it cannot replace
a usable session. [Service setup](../ting-delivery.md) covers the required
permissions and notification type. End users do not perform this setup.

The receiving commands are operator tools for the same setup applications
perform internally. They do not start a transport or configure a destination.
`receiving register` acts only for the authenticated recipient. Carbon
subscriptions require current IAM visibility of the selected Silicon:

```sh
hook --profile reviewer --silicon cos:tos receiving subscribe
hook --profile reviewer --silicon cos:tos receiving status
hook --profile reviewer --silicon cos:tos receiving unsubscribe
hook --profile cos event <event-id>
hook --profile cos publication <event-id>
```

Subscriptions cover future events, with no historical backfill. Unsubscribing
cancels that Carbon's queued observer sends while preserving primary Silicon
delivery. A notification already accepted in flight may still arrive; reading
the original payload always requires current IAM authorization.

Publication distinguishes `pending`, `accepted_by_ting`, and `accepted_silently`.
Its `delivery` field separates required automation from ordinary notifications;
`silent` records notification visibility. Required muted sends report
`accepted_by_ting`; ordinary muted sends report `accepted_silently`.
Available recipient receipts report destination delivery and read acknowledgments
separately. Silent acceptance does not prove a destination received anything,
and an acknowledgment does not prove later application processing finished.
Applications use [the receiving SDK](../client/relay.md) for callback validation,
hydration, durable acceptance, and deduplication.

In a selected sandbox, `receiving scope` and `receiving bootstrap` expose the
scoped inbox/watch setup to an internal runtime. See [sandbox commands](../testing/cli.md).
They do not enroll a native destination, enable required delivery, acknowledge
events or start a listener. Registration reports `required_delivery`; only the
recipient's explicit choice through its enclosing app can enable automation.

## Upgrade from the old relay CLI

Before replacing an older CLI that runs a Hook daemon, complete the
[legacy backlog gate](../deployment.md#legacy-backlog-gate): confirm the old
receiver has durably accepted its pending events. Retained v1 events are not
automatically copied into Ting. Then use the old executable to run
`hook daemon stop`. Disable any service-manager entry that starts
`hook daemon run` before upgrading. Then install the new CLI through Honeycomb.
The new CLI does not kill existing processes or expose a daemon control API.

Existing access/refresh tokens, test selectors, and profile settings remain
readable. Obsolete destination, relay-token, stream, and ISI fields are ignored
and removed the next time the CLI saves state. Old local relay configuration is
not migrated into Ting. The enclosing application's receiving integration owns
that setup. `webhook`, `unhook`, `daemon`, `listen`, `deliveries`, `--isi`, and
`login --webhook-url` are no longer accepted.

## Signatures and provider secrets

```sh
hook --silicon cos:tos create GitHub --signature @github-policy.json
hook --silicon cos:tos create LocalDemo --unsigned
hook update <hook-id> --patch '{"description":null}'
hook create Stripe --signature @stripe-policy.json --secret-file provider-secret.txt
hook set-secret <hook-id> --secret-file encoded-secret.txt --secret-encoding hex
hook --test <environment-id> set-secret <hook-id> --secret-file -
```

Secret files preserve spaces and remove one trailing LF/CRLF. Empty, multiline,
control-character, or over-4096-byte secrets fail. Do not supply a secret both
inside `--signature` and through `--secret-file`. Omitting one at creation
generates a secret. `set-secret` preserves the encoding unless supplied and
leaves the URL, policy, and activation state intact; the old secret immediately
stops verifying.

Creation, rotation, and environment-key responses may contain secrets; store
them only in private files. `show` does not retrieve an original signing secret.
See [signature expressions](../api/README.md#signature-expressions) for the
algorithms and encodings. All these operations also work in testing.

`hook about` prints project links. `hook report "description" --pr
https://github.com/teamofsilicons/silicon-hook/pull/123` explicitly submits an
issue through an authenticated GitHub CLI. Telemetry excludes report text.
