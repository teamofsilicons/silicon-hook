# Start using Silicon Hook

Hook gives every Silicon its own signed webhook URLs. Providers (GitHub, Stripe,
Silicon Accounts, ...) post to them; Hook verifies each request against the
hook's signature policy, keeps verified requests for 14 days and withheld ones in
a separate log, and, when the server delivers through Ting, passes a reference
to the Silicon. The app that hosts the Silicon handles delivery; nobody sets up
Hook or Ting by hand.

## Install

```sh
silicon-apps install hook
```

Silicon Apps installs the prebuilt CLI for your platform and keeps it updated.

## Sign in and create a webhook

A Silicon:

```sh
silicon-accounts login --app hook -q | hook login --slt-stdin
hook create GitHub
hook login status --json
```

A Carbon looking after Silicons:

```sh
hook login                         # approve the printed code in a browser
hook silicons                      # the Silicons you look after
hook --silicon si:scout create GitHub
```

Give the provider the `endpoint_url` from the answer, and its signing secret
(printed once) or your own (`--secret-file`). `hook events` shows what arrived;
`hook blocked` shows requests that failed verification. [Sign in to
Hook](accounts/README.md) covers both sign-ins and who can see a Silicon's hooks:
the Silicon, its custodian, and accounts they granted `view` or `manage` access.

Hook never asks for a password, a one-time code or a long-lived credential: the
CLI uses the Silicon Accounts device flow for Carbons and a single-use
short-lived token for Silicons.

## Build on Hook

| Goal | Start here |
| --- | --- |
| Sign in, keep the session, understand access | [Sign in to Hook](accounts/README.md) |
| Every command, offline help | [CLI](cli/README.md), `hook commands`, `hook docs <topic>` |
| Embed the stateless Rust client | [Rust client](client/README.md) |
| Receive events through Ting in your app | [Receiving through Ting](client/relay.md) |
| Integrate over HTTP | [API reference](api/README.md), [OpenAPI](../openapi.yaml) |
| Plan compatible integrations | [Contract lifecycle](contracts.md) |
| Configure or run a deployment | [Configuration](configuration.md), [deployment](deployment.md) |

Source: [teamofsilicons/silicon-hook](https://github.com/teamofsilicons/silicon-hook).
Packages: [client](https://crates.io/crates/silicon-hook-client),
[CLI](https://crates.io/crates/silicon-hook-cli). Report a bug with
`hook report "what happened" --pr https://github.com/teamofsilicons/silicon-hook/pull/123`
through your authenticated GitHub CLI.

Hook 1.0 serves API v3 and signs in with Silicon Accounts; deploy the 1.0 backend
before upgrading clients ([deployment](deployment.md)). Telemetry goes to Hook's
private outbox and its Space Station table; see [telemetry](telemetry.md).
