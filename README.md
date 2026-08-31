# Silicon Hook

Silicon Hook is the durable webhook ingress service for the Silicon platform.
It gives each Silicon independently signed endpoints, retains the latest 10,000
events per endpoint, and forwards accepted events to Silicon DM through a
transactional outbox.

The product behavior is defined in [UNDERSTANDING.md](./UNDERSTANDING.md), the
human API guide is [API_DOCS.md](./API_DOCS.md), the machine contract is
[openapi.yaml](./openapi.yaml), and implementation choices are recorded in
[decisions.md](./decisions.md). The versioned cross-service requirements and
current sibling compatibility status are in
[IAM_INTEGRATION.md](./IAM_INTEGRATION.md).

## Architecture

The repository is one Rust modular monolith with independently scalable
processes:

- `hook-api` serves management, IAM provisioning, event history, and public
  ingress.
- `hook-worker` leases durable outbox rows, delivers them to DM, and performs
  fair, independently bounded retention and expired-deletion maintenance.
- `hook-migrate` is the only process that applies PostgreSQL migrations.

PostgreSQL is authoritative. API replicas do not migrate at startup, delivery
does not depend on in-memory queues, and IAM authorization is checked online.

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
provide API secrets only to `hook-api`, DM credentials and delivery policy only
to `hook-worker`, and the privileged migrator database URL only to
`hook-migrate`. The Compose services model these separate environment
boundaries; `.env.example` is the union used for convenient local runs.
The executable production privilege manifest and reviewed API/worker matrix are
documented in [deploy/postgres/README.md](./deploy/postgres/README.md). Apply it
after every migration. Compose applies that same manifest to separate local
runtime roles; if upgrading an existing development volume, recreate the volume
once so PostgreSQL runs the local role bootstrap.

Maintenance capacity is independent from DM delivery. Tune
`HOOK_MAINTENANCE_BATCH_SIZE`, `HOOK_MAINTENANCE_BATCHES_PER_CYCLE`, and
`HOOK_MAINTENANCE_INTERVAL_SECONDS` together; a `cycle_limit_reached=true`
worker log means eligible cleanup remains after the configured drain budget.

## Signing an event

Hook creation returns a secret once in the form
`whsec_<base64url-without-padding>`. Decode the suffix into the 32-byte HMAC
key, serialize the body once, and compute HMAC-SHA-256 over:

```text
<unix_timestamp>.<exact_raw_body>
```

Send the lowercase hexadecimal digest as
`X-Hook-Signature: v1=<digest>`, with the same timestamp in
`X-Hook-Timestamp` and a stable `Idempotency-Key`. See
[API_DOCS.md](./API_DOCS.md) for the normative test vector.

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

Database integration tests use isolated PostgreSQL 16 containers and never
share the development database. The same gates run in
`.github/workflows/ci.yml`. Production must use separate runtime and migrator
credentials and must not enable the local IAM adapter.
