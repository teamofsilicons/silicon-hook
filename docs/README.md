# Start using Silicon Hook

Hook gives a Silicon one reliable place to receive signed webhooks from other applications. It verifies incoming signatures, retains request history, and forwards events to your local endpoint. Delivery is acknowledged only after your endpoint returns a successful HTTP response.

## Install

```sh
honeycomb install 'tos>hook'
```

Honeycomb installs the prebuilt CLI and manages its updates. Next, log in as shown below. See [installation and configuration](configuration.md) for details.

## Sign in and receive events

```sh
hook iam --json
# Generate an SLT for the returned app_id using the official IAM CLI or website.
hook login '<short-lived-token>' --org tos
hook webhook http://127.0.0.1:9000/events
hook --silicon cos:tos create GitHub
hook login status --json
```

Save the provider URL and signing secret returned by creation, then configure that provider to call the URL with the documented signature. Your local receiver handles `{ "type": "new_event", "data": { ... }, "metadata": { ... } }`. Return `2xx` only after durable processing, and deduplicate by event ID. See [delivery and signing](client/relay.md).

A Carbon can use the CLI directly, or ask a Silicon to follow these instructions. Hook never asks for an IAM password, OTP or long-lived account credential. Local webhook destinations stay on your system.

## Try it in a sandbox

```sh
hook env use --app-secret-file ./iam-test-app-secret
hook login '<test-SLT-or-existing-test-identity-ID>'
hook webhook http://127.0.0.1:9000/test-events
hook env exit
```

The secret automatically selects its IAM sandbox. The signed-in test identity determines permissions. The CLI identifies testing on stderr, including errors; the website shows a persistent test banner. See [testing](testing/README.md).

## Build on Hook

| Goal | Start here |
| --- | --- |
| Explore commands and offline help | [CLI](cli/README.md), `hook commands`, `hook docs` |
| Embed the stateless Rust client | [Rust client](client/README.md) |
| Receive and acknowledge events | [Relay and local API](client/relay.md) |
| Integrate over HTTP or WebSocket | [API reference](api/README.md), [OpenAPI](../openapi.yaml) |
| Understand IAM and permissions | [IAM boundary](iam/README.md) |
| Plan compatible integrations | [Contract lifecycle and matrix](contracts.md) |
| Configure or operate a deployment | [Configuration](configuration.md), [deployment](deployment.md) |
| Inspect verification evidence | [Current verification](verification/current.md) |

Source: [teamofsilicons/silicon-hook](https://github.com/teamofsilicons/silicon-hook). Packages: [client](https://crates.io/crates/silicon-hook-client), [CLI](https://crates.io/crates/silicon-hook-cli). Explicit bug reports use `hook report "reproduction details" --pr https://github.com/teamofsilicons/silicon-hook/pull/123` with an already authenticated GitHub CLI.

These guides describe the updated source build. Deploy matching backend and browser code before using new sandbox selection or shared-relay features. [Deployment](deployment.md) explains the upgrade order. Telemetry is included through Hook’s private outbox and dedicated Space Station table; see [telemetry configuration](telemetry.md).
