# Sign in to Hook

Hook signs Carbons and Silicons in with [Silicon Accounts](https://accounts.teamofsilicons.com).
Every call to Hook's API carries a Silicon Accounts access token issued to Hook
(`Authorization: Bearer …`, audience `hook`). The `hook` CLI and the
[Rust client](../client/README.md) get that token for you.

## Carbons: approve a code

```sh
hook login
```

The CLI prints a URL and a code:

```text
To sign in to Hook, open https://accounts.teamofsilicons.com/device and enter the code

    WDJB-MJHT

Waiting for approval (the code expires in 10 minutes; Ctrl-C to stop)...
```

Open the URL in a browser where you are signed in to Silicon Accounts, check the
code, and approve. The CLI finishes on its own. Add `--open` to open the page for
you; nothing opens without it. With `--json`, the CLI prints one JSON object per
line: first `{"event": "device_code", "user_code", "verification_uri", …}`, then
the result.

## Silicons: hand over a short-lived token

```sh
silicon-accounts login --app hook -q | hook login --slt-stdin
```

`silicon-accounts login --app hook -q` prints a short-lived token (`slt_…`) for
Hook. It works once, for two minutes, and only for Hook. `hook login --slt-stdin`
exchanges it for Hook tokens without any secret. `hook login <SLT>` and
`hook login --slt <SLT>` do the same; prefer stdin, because arguments are visible
to other processes. The CLI never prints or stores the short-lived token.

If Silicon Accounts refuses it, the CLI says exactly why, and the fix is always
the same: mint a fresh one and sign in right away.

| `details.reason` | What happened |
| --- | --- |
| `already_used` | The token was exchanged before. Each one works once. |
| `expired` | More than two minutes passed since it was minted. |
| `wrong_app` | It was minted for another app (`--app` was not `hook`). |
| `unknown` | It is mistyped, or it comes from another Silicon Accounts. |
| `not_an_slt` | The value is not a short-lived token at all. Nothing was sent. |
| `ended` | The sign-in that minted it has ended since (an STK rotation, or Hook's access removed). |

## Check and end the sign-in

```sh
hook login status --json   # who you are; Hook confirms the token
hook whoami                # the saved sign-in, without contacting anything
hook logout                # ends the sign-in at Silicon Accounts and forgets it
```

`hook login status --json` always exits 0. Signed out it prints
`{"authenticated": false}` (with a `reason` when there is one: `session_ended`,
`signed_in_elsewhere`, `previous_version_session`, `state_unreadable`,
`no_home`). Signed in it prints `authenticated: true`, `uuid`, `id`, `kind`,
`display_name`, `expires_at`, `refresh_expires_at` and `verified`. `verified` is
true when Hook (or Silicon Accounts, right after signing in) confirmed the
sign-in during this command. If Hook cannot be reached, the saved sign-in is
shown with `verified: false` and a `warning`. `--offline` reads only the saved
file. Without `--json`, signed out exits 1.

`hook accounts --json` tells a Silicon what signing in needs, offline and signed
out: Hook's `app_id`, the Silicon Accounts URL, the API URL and the version.

## How the sign-in is kept

The CLI keeps one sign-in per profile in `profiles.json` in its state directory
(`$SILICON_HOME/.silicon-hook`, or `~/.silicon-hook`), readable only by you. The
access token lasts 30 minutes. When less than a minute is left, the next command
refreshes it with the refresh token.

Silicon Accounts rotates the refresh token on every refresh, and treats a spent
refresh token presented again as theft: it ends the whole sign-in. So the CLI
refreshes under a file lock (concurrent `hook` commands share one refresh) and
saves the new pair before it uses it. If a refresh was interrupted and the CLI
cannot know whether the old refresh token was spent, it does not present it
again: it ends that sign-in (`refresh_interrupted`) and asks you to sign in
again.

A sign-in belongs to the Silicon Accounts and the Hook API it was made with. If
`ACCOUNTS_URL` or the Hook URL changes, the CLI reports `signed_in_elsewhere`
instead of sending the token somewhere else. Use another `--profile` to keep a
second sign-in in the same home.

Sign-ins made by Hook before 1.0 are not carried over. The CLI keeps their
settings (URL, default Silicon, telemetry choice), leaves the old `state.json`
untouched, and reports `previous_version_session` until you sign in again.

## Who can do what

A Silicon's hooks belong to it. The Silicon and its custodian (the Carbon who
looks after it) can do everything with them; the custodian acts as itself, never
as the Silicon. They can give another Carbon or Silicon `view` access (hooks,
history, delivery status) or `manage` access (also create and change hooks):

```sh
hook --silicon si:scout access grant c:ada --level view
hook --silicon si:scout access list
hook --silicon si:scout access revoke c:ada
hook --silicon si:scout access leave     # a grantee gives up its own access
```

A Silicon looked after by a different custodian only accepts a grant after it
(or its custodian) allowed the granting Silicon or its custodian:
`hook --silicon si:friend allow-list add c:ada`. Nobody else sees a Silicon's
hooks, including its sibling Silicons.

## Build your own

Hosts embedding Hook use the same public-client sign-in through
[`silicon_hook_client::signin`](../client/README.md#sign-in), or their own
Silicon Accounts app with `silicon-accounts-client`. Whatever the route, the
token Hook accepts is a Silicon Accounts access token whose audience is `hook`.
