# Silicon Hook

Silicon Hook gives every Silicon its own set of signed webhook endpoints. A
provider such as GitHub, Stripe, or Silicon IAM posts to an endpoint, Hook
verifies the request with the hook's configured signature scheme, records it,
and delivers it to the Silicon over an ordered, acknowledged WebSocket stream.
Unverified requests are withheld, logged separately, and counted against the
sending address.

The product behavior is defined in [UNDERSTANDING.md](./UNDERSTANDING.md).
That file is the single source of truth; the human API guide is
[API_DOCS.md](./API_DOCS.md), the machine contract is
[openapi.yaml](./openapi.yaml), and the Silicon IAM boundary is
[IAM_INTEGRATION.md](./IAM_INTEGRATION.md). Rationale for individual choices
lives as comments next to the code it explains.

## What a hook is

An authenticated Silicon owns the namespace `https://hook.teamofsilicons.com/{silicon_id}/`.
Every hook created for it gets a six-character alphanumeric endpoint key and a
public URL:

```text
https://hook.teamofsilicons.com/silicon/{silicon_id}/{endpoint_key}
```

Each hook carries:

- a name (the provider shown in every delivery summary) and optional description;
- a signature policy: whether verification is required, the algorithm, the
  expression that rebuilds the bytes the provider signed, the expression that
  locates the presented signature, and the encodings involved;
- an encrypted signing secret or a provider public key;
- an IANA time zone used to render the summary line
  `{provider} triggered at HH:MM:SS DD-MM-YYYY IANA_ZONE_ID`.

The default policy is the Standard Webhooks convention: HMAC-SHA-256 over
`webhook-id.webhook-timestamp.body`, presented in base64 in the
`webhook-signature` header. Creating a hook with no configuration produces a
`v1.`-prefixed secret you hand to the provider. Providers with their own
conventions are described with the expression language documented in
[API_DOCS.md](./API_DOCS.md#signature-expressions).

## Lifecycle

- **Create** returns the endpoint URL, the endpoint key, and the signing secret once.
- **Update** changes name, description, time zone, activation, or the signature policy.
- **Disable / enable** pauses and resumes ingress individually or in atomic batches.
- **Rotate secret** issues a new generated secret; the previous one stops working immediately.
- **Rotate endpoint** issues a new endpoint key and permanently retires the old
  one for that Silicon. Requests to a retired key receive `410 endpoint_retired`.
- **Delete** soft-deletes for 45 days, during which **restore** brings the hook back.

## Receiving and delivery

Every request to an active endpoint is answered with `200` and
`{"status":"webhook.ok","receipt_id":...}` as soon as it is captured. Verified
requests join the Silicon's ordered delivery stream; withheld requests go to
the blocked log. Both logs keep 14 days of history and are readable by the
Silicon and by Carbons who can see it.

Delivery is over `GET /api/v1/ws?silicon_id=...`. On connect the server sends
every event the consumer has not acknowledged, then live events as they
arrive, each with a per-Silicon `delivery_sequence`. The client acknowledges
with `{"type":"ack","silicon_id":...,"through_sequence":N}`. The server sends a
JSON `ping` every 30 seconds; a client that fails to answer with the matching
`pong` for two minutes is closed with code `4000` and reason
`heartbeat-timeout`. The same stream is available by polling
`GET /api/v1/silicons/{silicon_id}/deliveries` and acknowledging with
`POST /api/v1/silicons/{silicon_id}/deliveries/ack`.

## Safety

A client address that sends twenty unverified requests to one endpoint is
blocked from that endpoint for one day. After ten such blocks it is blocked
permanently. Blocked addresses receive `403 ip_blocked`; nothing they send is
stored.

## Architecture

The repository is one Rust modular monolith with independently scalable
processes:

- `hook-api` serves management, ingress, history, IAM provisioning, and the
  WebSocket delivery stream. Every replica listens for PostgreSQL
  notifications so an event accepted on one replica reaches sessions on any.
- `hook-worker` purges 14-day logs, expired 45-day deletions, stale address
  blocks, and expired idempotency records in bounded, fair batches.
- `hook-migrate` is the only process that applies PostgreSQL migrations.

PostgreSQL is authoritative: hooks, encrypted secrets, request logs, delivery
sequences, acknowledgment cursors, and address blocks all live there, and IAM
authorization is checked online for every management call.

## Local development

Rust 1.98 and Docker are supported. Copy `.env.example` to `.env`, replace the
development cryptographic material when testing secret rotation, and start the
database:

```bash
docker compose up -d postgres
cargo run --bin hook-migrate
cargo run --bin hook-api
```

Run the worker in another terminal:

```bash
cargo run --bin hook-worker
```

Or build and run all processes with `docker compose up --build`.

Each executable validates only the configuration it owns. In production,
provide API secrets only to `hook-api` and the privileged migrator database
URL only to `hook-migrate`. The Compose services model these separate
environment boundaries; `.env.example` is the union used for convenient local
runs. The executable production privilege manifest and reviewed API/worker
matrix are documented in [deploy/postgres/README.md](./deploy/postgres/README.md).
Apply it after every migration. The schema was rebuilt for signed delivery, so
recreate any development volume created before this version.

Behind a load balancer set `HOOK_TRUSTED_PROXY_HOPS` to the number of proxies
that append `X-Forwarded-For`; otherwise address blocking would count the
balancer instead of the sender.

## Quality gates

```bash
cargo fmt --all -- --check
cargo check --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
npx --yes @redocly/cli@2.49.0 lint openapi.yaml
cargo deny --locked check
```

Database and WebSocket integration tests start isolated PostgreSQL 16
containers and never share the development database. The same gates run in
`.github/workflows/ci.yml`. Production must use separate runtime and migrator
credentials and must not enable the local IAM adapter.
