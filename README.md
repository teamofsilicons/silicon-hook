# Silicon Hook

Silicon Hook gives every Silicon its own signed webhook endpoints. A provider
such as GitHub, Stripe or Silicon Accounts posts to an endpoint, Hook verifies
the request with that hook's signature policy, records it, and (when the server
delivers through Ting) passes a compact reference to the Silicon, which fetches
the original request from Hook. Unverified requests are withheld, logged
separately and counted against the sending address.

The product behaviour is defined in [UNDERSTANDING.md](./understanding/UNDERSTANDING.md),
the single source of truth. The guides start at [docs/README.md](docs/README.md);
the HTTP guide is [docs/api/README.md](docs/api/README.md) and the machine contract
[openapi.yaml](./openapi.yaml). Rationale for individual choices lives as comments
next to the code it explains.

## Install and sign in

```sh
silicon-apps install hook
```

A Silicon signs in with a short-lived token from Silicon Accounts; a Carbon
approves a device code in the browser:

```sh
silicon-accounts login --app hook -q | hook login --slt-stdin   # a Silicon
hook login                                                       # a Carbon
hook create GitHub
```

Silicon Apps keeps the CLI updated. [Sign in to Hook](docs/accounts/README.md)
explains both sign-ins and who can see a Silicon's hooks; the
[CLI guide](docs/cli/README.md) lists every command.

## What a hook is

Every Silicon has the namespace `https://backend.hook.teamofsilicons.com/silicon/{silicon}/`,
where `{silicon}` is its id (`si:scout`) or its Silicon Accounts uuid. Every hook
created for it gets an eight-character uppercase alphanumeric endpoint key and a
public URL:

```text
https://backend.hook.teamofsilicons.com/silicon/{silicon}/{endpoint_key}
```

The key alone decides which hook receives a request, and keys are unique across
Hook, so a URL keeps working after the Silicon changes its id.

Each hook carries:

- a name (the provider shown in received events) and optional description;
- a signature policy: whether verification is required, the algorithm, the
  expression that rebuilds the bytes the provider signed, the expression that
  locates the presented signature, and the encodings involved;
- an encrypted signing secret or a provider public key;
- an IANA time zone kept with the hook.

The default policy is the Standard Webhooks convention: HMAC-SHA-256 over
`webhook-id.webhook-timestamp.body`, presented in base64 in the
`webhook-signature` header. Creating a hook with no configuration produces a
`v1.`-prefixed secret you hand to the provider. Providers with their own
conventions are described with the expression language in the
[API guide](docs/api/README.md).

## Who can see and manage a Silicon's hooks

Hooks belong to the Silicon they were made for. The Silicon and its custodian
(the Carbon who looks after it) can do everything with them; the custodian acts
as itself, never as the Silicon. They can grant another Carbon or Silicon `view`
access (hooks, history, delivery status) or `manage` access (also create and
change hooks), and a grantee can leave. A Silicon looked after by someone else
only accepts a grant after it, or its custodian, has allowed the granting
account. Nobody else sees a Silicon's hooks, including its sibling Silicons.

## Lifecycle

- **Create** returns the endpoint URL, the endpoint key, and the signing secret once.
- **Update** changes name, description, time zone, activation, or the signature policy.
- **Disable / enable** pauses and resumes ingress individually or in atomic batches.
- **Rotate secret** issues a new generated secret; the previous one stops working immediately.
- **Rotate endpoint** issues a new endpoint key and permanently retires the old
  one. Requests to a retired key receive `410 endpoint_retired`.
- **Delete** soft-deletes for 45 days, during which **restore** brings the hook back.
  When a Silicon's account is deleted, its hooks are deleted at once (`410`) and
  removed after the same 45 days.

## Receiving and delivery

Accepted requests receive `200` and `{"status":"webhook.ok","receipt_id":...}`
once the request (and its pending publication, when delivery is on) is committed.
Verified requests receive a per-Silicon sequence; withheld requests go to the
blocked log. Both logs keep 14 days of history, readable by the Silicon, its
custodian and accounts with `view` access.

Delivery through Ting is optional. With `HOOK_TING_URL` set, Hook retries each
publication with the same producer key until Ting confirms storage; receivers
hydrate the compact reference through Hook, accept and deduplicate the event,
then acknowledge. Delivery can replay or arrive out of order, and an
acknowledgement never means the Silicon finished its work. Without
`HOOK_TING_URL`, Hook still receives, verifies and stores every event, queues
nothing and says so. See [delivery through Ting](docs/ting-delivery.md).

## Safety

A client address that sends twenty unverified requests to one endpoint is
blocked from that endpoint for one day. Counting restarts after each block.
Blocked addresses receive `403 ip_blocked`; nothing they send is stored.

## Architecture

One Rust modular monolith with independently scalable processes:

- `hook-api` serves management, provider ingress, history, publication status
  and Hook's Silicon Accounts webhook (`POST /webhook`), and publishes committed
  records through Ting when delivery is on.
- `hook-worker` purges 14-day logs, expired 45-day deletions, stale address
  blocks and expired idempotency records in bounded, fair batches, and exports
  telemetry.
- `hook-migrate` is the only process that applies PostgreSQL migrations; its
  `link-identities` command links identities stored before 1.0 to Silicon
  Accounts uuids.
- `hook-contract` reports and changes API major lifecycle state.

Every API call carries a Silicon Accounts access token issued to Hook (audience
`hook`), verified locally against Silicon Accounts' published keys; routes that
reveal secrets or change access also confirm with Silicon Accounts that the
token is still active. The official `silicon-accounts-client` crate does both.
PostgreSQL is authoritative: hooks, encrypted secrets, request logs, delivery
sequences, pending publications, grants, allow-lists, the account cache and
address blocks all live there.

The `hook` CLI (`crates/cli`) uses the Rust client (`crates/client`,
`silicon-hook-client`) for every network action; the client negotiates the API
major with `GET /api/version` and pins every request to it. The web console
(`https://hook.teamofsilicons.com`) is a Next.js app whose server signs Carbons in
with Silicon Accounts and calls the API for them.

## Local development

Rust 1.98 and PostgreSQL 16 are needed. Copy `.env.example` to `.env`; point
`ACCOUNTS_URL` at a Silicon Accounts (a local stack works over plain `http` on
loopback) and set `HOOK_APP_SECRET` to Hook's app secret there. Then:

```bash
docker compose up -d postgres    # or any PostgreSQL 16 matching the URLs in .env
cargo run --bin hook-migrate
cargo run --bin hook-api
cargo run --bin hook-worker      # in another terminal
```

`docker compose up --build` runs the same processes, with separate runtime roles
and the grant manifest applied. Each executable validates only the configuration it owns: in
production the API secrets reach only `hook-api`, and the migrator's database URL
only `hook-migrate`. [Configuration](docs/configuration.md) and
[deployment](docs/deployment.md) list every variable; the privilege manifest and
the API/worker matrix are in [deploy/postgres/README.md](deploy/postgres/README.md).

Behind a load balancer set `HOOK_TRUSTED_PROXY_HOPS` to the number of proxies
that append `X-Forwarded-For`; otherwise address blocking would count the
balancer instead of the sender.

## Quality gates

```bash
cargo fmt --all -- --check
cargo check --workspace --locked --all-targets --all-features
cargo clippy --workspace --locked --all-targets --all-features -- -D warnings
HOOK_TEST_POSTGRES_URL=postgres://postgres@127.0.0.1:5432/postgres \
  cargo test --workspace --locked --all-targets --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps --all-features
npx --yes @redocly/cli@2.49.0 lint openapi.yaml
cargo deny --locked check
python3 scripts/bundle-cli-docs.py --check
python3 -m unittest discover -s scripts -p 'test_*.py'
(cd docs-site && npm ci && npm run build && npm run check)
```

Database tests create and drop their own database and runtime roles on the
server `HOOK_TEST_POSTGRES_URL` names (an administrator URL) and skip, saying
why, without it. The same gates run in `.github/workflows/ci.yml`. Releases are
built by `.github/workflows/release.yml` ([releases](docs/releases.md)).
