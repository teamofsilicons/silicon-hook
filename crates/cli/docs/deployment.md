# Deploy the updated services and docs

## Upgrade order

1. Back up the production and shared-test PostgreSQL databases and matching encryption keys.
2. Run the new `hook-migrate` against both databases. Migrations 10–16 add the durable Ting queue, encrypted publisher credentials, v2 contract, original event generation, Carbon observer bindings and their encrypted current access authority, plus the required-delivery diagnostic.
3. Reapply `deploy/postgres/grant-runtime.sql` for each database's API and worker roles. The contract function requires explicit execute permission.
4. Configure [the Honeycomb service integration](testing/honeycomb.md) and [internal Ting service setup](ting-delivery.md), including each org's dedicated publisher and notification type, then deploy the matching Hook API and worker. Validate `/healthz`, `/readyz`, `/api/version` and `/api/contracts`.
5. Drain and reconcile each legacy destination's unacknowledged events before stopping its receiver, as described below. Then stop legacy Hook daemons with the old executable's `hook daemon stop` and deploy the matching browser gateway/frontend and v2 CLI/client. The enclosing app owns Ting receiving and shared transport; no replacement Hook daemon is started.
6. Verify an IAM test app_secret, test identity login, provider ingress, local recipient delivery and acknowledgment before production rollout.

After migration `0015`, existing Carbon receiving interests remain queued until the enclosing runtime repeats its subscription POST with a current Hook access token. The runtime must renew each active interest after token refresh and receiving reconnects. Hook retains the encrypted access token only and checks that Carbon's current IAM access before every observer publication. It never takes ownership of the Carbon refresh family. Monitor `observer_authority_refresh_required` for missing or expired authority and `observer_authorization_unavailable` for temporary IAM failures; primary Silicon sends continue independently.

Migration `0016` permits `required_delivery_not_enabled` in outbox diagnostics; it does not rewrite existing send bodies or keys. New primary sends require the recipient's separate automation opt-in. Deploy Ting 0.1.4-compatible services and finish the official scope approvals before relying on scoped testing bootstrap or required delivery.

### Legacy backlog gate

Migration `0010` queues only new events; it does not copy retained v1 events into Ting. Before switching a destination, keep its old receiver running and inspect its v1 delivery cursor and pending events for every identity, organization and environment it serves. Confirm durable application acceptance before advancing ACKs. Coordinate ingress and the final drain so events cannot arrive unnoticed between verification and shutdown; retain event-ID deduplication across the transition because both transports may carry newer events.

Do not retire an old receiver while it still has unaccepted events. Reconcile those originals while Hook retains them, or keep that destination on v1 until resolved. Record the backlog/cursor check and accepted event IDs as cutover evidence. History retention is 14 days, and v1's idle sunset still applies; neither migrates or extends an unresolved backlog. The new CLI cannot inspect or stop the removed relay, so preserve the old executable until this gate is complete.

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
