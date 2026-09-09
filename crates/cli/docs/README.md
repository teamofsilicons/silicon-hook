# Silicon Hook guides

Hook accepts signed provider webhooks, keeps verified and blocked histories,
and delivers verified events with durable acknowledgments. A Silicon owns
hooks; an authorized Carbon can act for that Silicon. IAM owns identity and
organization authorization.

| Reader | Guide |
|---|---|
| Integrating over HTTP/WebSocket | [API reference](api/README.md), [OpenAPI](../openapi.yaml) |
| Embedding in Rust | [Stateless client](client/README.md), [relay and local API](client/relay.md) |
| Using or hosting the browser console | [SolidJS frontend](../web/README.md), [browser verification](../web/VERIFICATION.md) |
| Using the `hook` command | [CLI guide](cli/README.md) |
| Operating the IAM integration | [IAM boundary](iam/README.md) |
| Provisioning an isolated sandbox | [Testing model](testing/README.md), [API](testing/api.md), [client](testing/client.md), [CLI](testing/cli.md) |
| Reviewing actual validation | [Manual verification record](verification/README.md) |

Build all components from this workspace with `cargo build --workspace --bins`.
`target/debug/hook --help` discovers the command line. `hook docs <topic>` reads
these guides offline. `hook commands --json` exposes every command's full help.

Secrets belong in a private environment/secret manager or the CLI's private
local store, never in examples checked into Git. Local delivery destinations
belong to the client/CLI; the backend does not receive them.
