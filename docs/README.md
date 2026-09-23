# Start using Silicon Hook

Hook is an internal service for receiving signed provider webhooks. It verifies signatures, retains request history, and queues event references for Ting delivery. The enclosing app handles receiving setup and authorization internally; end users need no separate Hook or Ting setup. These guides cover integration and internal management.

## Install

```sh
honeycomb install 'hook'
```

Honeycomb installs the prebuilt CLI and manages its updates. Next, log in as shown below. See [installation and configuration](configuration.md) for details.

## Sign in and manage webhooks

```sh
hook iam --json
# Generate an SLT for the returned app_id using the official IAM CLI or website.
hook login '<short-lived-token>' --org tos
hook --silicon si:cos create GitHub
hook login status --json
```

Save the provider URL and signing secret returned by creation, then configure that provider to call the URL with the documented signature. The enclosing app's Ting receiver validates the compact event reference and fetches the original request from Hook. Its local callback returns HTTP204 only after durable acceptance of the entire batch, deduplicated by event ID. See [internal receiving](client/relay.md).

A Carbon managing the service can use the CLI directly, or ask a Silicon to follow these instructions. Hook never asks for an IAM password, OTP or long-lived account credential. The Hook CLI owns no receiving daemon or delivery destination.

## Try it in a sandbox

```sh
hook env use --app-secret-file ./iam-test-app-secret
hook login '<test-SLT-or-existing-test-identity-ID>'
hook env exit
```

The secret automatically selects its IAM sandbox. The signed-in test identity determines permissions. The CLI identifies testing on stderr, including errors; the website shows a persistent test banner. See [testing](testing/README.md).

## Build on Hook

| Goal | Start here |
| --- | --- |
| Explore commands and offline help | [CLI](cli/README.md), `hook commands`, `hook docs` |
| Embed the stateless Rust client | [Rust client](client/README.md) |
| Receive and accept events internally | [Ting receiving adapter](client/relay.md) |
| Integrate over HTTP | [API reference](api/README.md), [OpenAPI](../openapi.yaml) |
| Understand IAM and permissions | [IAM boundary](iam/README.md) |
| Plan compatible integrations | [Contract lifecycle and matrix](contracts.md) |
| Configure or operate a deployment | [Configuration](configuration.md), [deployment](deployment.md) |
| Inspect verification evidence | [Current verification](verification/current.md) |

Source: [teamofsilicons/silicon-hook](https://github.com/teamofsilicons/silicon-hook). Packages: [client](https://crates.io/crates/silicon-hook-client), [CLI](https://crates.io/crates/silicon-hook-cli). Explicit bug reports use `hook report "reproduction details" --pr https://github.com/teamofsilicons/silicon-hook/pull/123` with an already authenticated GitHub CLI.

These guides describe the updated source build. Deploy the matching v2 backend before upgrading consumers. [Deployment](deployment.md) explains the migration order, and [Ting integration issues](ting-integration-issues.md) records current upstream constraints. Telemetry uses Hook’s private outbox and dedicated Space Station table; see [telemetry configuration](telemetry.md).
