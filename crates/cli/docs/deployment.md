# Deploy the updated services and docs

## Upgrade order

1. Back up the production and shared-test PostgreSQL databases and matching encryption keys.
2. Run the new `hook-migrate` against both databases. Migration 9 adds Honeycomb lifecycle receipts, durable activity reports and database write fences.
3. Reapply `deploy/postgres/grant-runtime.sql` for each database's API and worker roles. The contract function requires explicit execute permission.
4. Configure [the Honeycomb service integration](testing/honeycomb.md), then deploy the matching Hook API and worker. Validate `/healthz`, `/readyz`, `/api/version` and `/api/contracts`.
5. Deploy the matching browser gateway and frontend, then install the updated CLI/client. Restart old daemon processes to load the new shared-relay implementation.
6. Verify an IAM test app_secret, test identity login, provider ingress, local recipient delivery and acknowledgment before production rollout.

Read [the existing AWS runbook](../deploy/aws/README.md) for Hook's standalone API, worker, PostgreSQL and gateway infrastructure. A source implementation or docs publication does not itself upgrade those running services. Preserve the previous application image for rollback; schema changes are not reversed by rolling back an image.

## Documentation hosting

The documentation lives at [docs.hook.teamofsilicons.com](https://docs.hook.teamofsilicons.com). Its static Vercel build is generated from `docs/`, with full-text local search, per-page anchors, source links and the current OpenAPI download.

```sh
cd docs-site
npm ci
npm run build
npm run check
vercel deploy --prod
```

Configure the Vercel project root as `docs-site`. The `vercel.json` file declares the build and output directory. DNS needs only the `docs.hook` host record; preserve every unrelated domain record. Validate HTTPS, canonical URLs, installer, search and internal links after publication.

## Bug-report email

The `bug-report.yml` GitHub workflow sends newly opened issues, including CLI reports and their optional PR links, through Postmark. Configure repository secret `POSTMARK_SERVER_TOKEN` and verify `hook@teamofsilicons.com` as a sender. Repository variable `POSTMARK_FROM_EMAIL` can override that sender. Recipients match the project requirements: `saketdev12@gmail.com`, `shubhastro2@gmails.com`, and `bugs@teamofsilicons.com`. The second address intentionally preserves the spelling in the requirements. The workflow reads report text as data and never interpolates it into shell code. It sends no local logs or Hook credentials. See the [Postmark email API](https://postmarkapp.com/developer/api/email-api) for sender and server-token setup.

## Space Station export

Apply migration 0008 and the updated worker grants, then supply the dedicated `HOOK_TELEMETRY_TABLE_KEY` securely to the worker. Mount `HOOK_TELEMETRY_SPOOL_DIR` as a persistent private directory. Never put this key in browser environment variables, CLI distributions or docs. Restart the worker after changing its configuration. `HOOK_TELEMETRY=off` stops collection and export. See [telemetry](telemetry.md) for retention, sandbox routing and delivery semantics.

## CLI release artifacts

Use [the six-target release workflow](releases.md) to produce one validated Honeycomb archive. Documentation deployment does not produce or publish CLI binaries.
