# Deploy the updated services and docs

## Service configuration

`hook-api` reads these variables (see `.env.example` for every setting):

| variable | purpose |
| --- | --- |
| `ACCOUNTS_URL` | Silicon Accounts public URL, also the token issuer. Default `https://accounts.teamofsilicons.com`. |
| `ACCOUNTS_API_URL` | Optional private address of the same Silicon Accounts service. |
| `HOOK_APP_ID` | Hook's app id at Silicon Accounts (the audience of its access tokens). Default `hook`. |
| `HOOK_APP_SECRET` | Hook's app secret (`sa_app_...`). Required. Server only. |
| `HOOK_ACCOUNTS_WEBHOOK_SECRET` | Signing secret of Hook's Silicon Accounts webhook (`POST /webhook`). Required in production. `HOOK_ACCOUNTS_WEBHOOK_PREVIOUS_SECRET` holds the old one during a rotation. |
| `HOOK_ACCOUNTS_TIMEOUT_SECONDS` | Deadline for one call to Silicon Accounts, 1 to 30 seconds. Default 5. |
| `HOOK_TING_URL` | Ting origin. Unset turns delivery off: Hook still receives, verifies and stores every event, queues nothing, and says so in its logs, `/readyz` and the delivery routes. |

Plain `http` is accepted only for loopback hosts and never in production. Hook refuses to
start when a value is malformed, and names the variable and the reason. Variables from
earlier versions are no longer read; `hook-api` logs each one it finds together with what
replaced it.

Hook's sign-in setup at Silicon Accounts needs the webhook pointed at
`https://<hook backend>/webhook` with the six account events (`account.id_changed`,
`account.updated`, `account.deleted`, `membership.signed_out`, `membership.access_removed`,
`silicon.custodian_changed`).

## Upgrade to Hook 1.0

1. Back up the PostgreSQL database and the matching encryption keys.
2. Run the new `hook-migrate`. Migration `0019` adds the Silicon Accounts identity columns
   next to the existing ones, Hook's account cache, grants, allow-lists, observer
   subscriptions and the identity inventory. It changes no existing value.
3. Reapply `deploy/postgres/grant-runtime.sql` for the API and worker roles.
4. Produce the identity mapping (one line per stored `si:`/`c:` id with its Silicon
   Accounts uuid; `hook_private.identity_links` lists every id Hook holds), review it,
   and run `hook-migrate link-identities --file mapping.csv --dry-run`, then without
   `--dry-run`. The report lists ids that are still unmatched and hooks without an owner.
   Running it again with a corrected file is safe.
5. Set the variables above and deploy the API and worker. Validate `/healthz`, `/readyz`,
   `/api/version` and `/api/contracts`, then provider ingress on an existing hook URL.

Provider URLs keep working throughout. Until a stored id is linked, its hooks keep
receiving but cannot be managed. API v1 and v2 answer `410 api_version_sunset`; deploy
the matching CLI, client and web before switching consumers.

## Where Hook runs

- **API, worker and PostgreSQL**: one ARM64 EC2 host behind Caddy at
  `https://backend.hook.teamofsilicons.com` (also the provider ingress host). Releases
  are native systemd bundles installed with `deploy/native/install.py`, which takes
  Hook's Silicon Accounts secrets on the first 1.0 install, backs up before it migrates
  and rolls back a failed switch ([native releases](../deploy/native/README.md),
  [the host](../deploy/aws/README.md)).
- **Web console**: a Next.js app on Vercel at `https://hook.teamofsilicons.com`. Its
  server signs Carbons in with Silicon Accounts, keeps the session in a sealed cookie
  and calls the API with the Carbon's access token; the browser never holds a token.
  Its sign-in setup at Silicon Accounts lists `https://hook.teamofsilicons.com/auth/callback`
  as a redirect URI.
- **Docs**: a static Vercel site at `https://docs.hook.teamofsilicons.com` (below).

Building or publishing this repository does not change those running services.
Rolling back a release does not reverse a migration: keep the backup the installer
takes before migrating.

## Documentation hosting

The documentation lives at [docs.hook.teamofsilicons.com](https://docs.hook.teamofsilicons.com). Its static Vercel build is generated from `docs/`, with full-text local search, per-page anchors, source links and the current OpenAPI download.

```sh
cd docs-site
npm ci
npm run build
npm run check
vercel deploy --prod
```

Configure the Vercel project root as `docs-site`. The `vercel.json` file declares the build and output directory. DNS needs only the `docs.hook` host record; preserve every unrelated domain record. Validate HTTPS, canonical URLs, the `/install.sh` entry point, search and internal links after publication. The site publishes the guides in `docs/` except `docs/history/` and `docs/migration/`.

## Bug-report email

The `bug-report.yml` GitHub workflow sends newly opened issues, including CLI reports and their optional PR links, through Postmark. Configure repository secret `POSTMARK_SERVER_TOKEN` and verify `hook@teamofsilicons.com` as a sender. Repository variable `POSTMARK_FROM_EMAIL` can override that sender. Recipients match the project requirements: `saketdev12@gmail.com`, `shubhastro2@gmails.com`, and `bugs@teamofsilicons.com`. The second address intentionally preserves the spelling in the requirements. The workflow reads report text as data and never interpolates it into shell code. It sends no local logs or Hook credentials. See the [Postmark email API](https://postmarkapp.com/developer/api/email-api) for sender and server-token setup.

## Space Station export

Apply migration 0008 and the updated worker grants, then supply the dedicated `HOOK_TELEMETRY_TABLE_KEY` securely to the worker. Mount `HOOK_TELEMETRY_SPOOL_DIR` as a persistent private directory. Never put this key in browser environment variables, CLI distributions or docs. Restart the worker after changing its configuration. `HOOK_TELEMETRY=off` stops collection and export. See [telemetry](telemetry.md) for retention and delivery semantics.

## CLI release artifacts

The [release workflow](releases.md) builds the CLI for six targets and packs one Silicon Apps archive per target; an author of the `hook` app uploads the Linux ones to Silicon Apps. Documentation deployment does not produce or publish CLI binaries.
