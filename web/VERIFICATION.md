# Frontend verification — 2026-09-06

This records actual checks of the SolidJS console, not complete backend E2E
acceptance. No frontend deployment or IAM application configuration was changed.

## Build and regression checks

- `npm run build`: TypeScript checking, Vite client build and Node server bundle passed.
- `npm test`: five session/gateway regression tests passed (encrypted storage,
  tamper detection, private permissions, serialized updates, expiry/path safety,
  route restrictions and production configuration).
- `npm run check`: passed. Frontend source was formatted with Prettier.
- `docker build -t silicon-hook-web:local web`: completed successfully.
- Packaged Node server served the local preview with CSP and frame-denial headers.
- The private development session key was absent from built client/server files;
  the development environment file is Git-ignored and excluded from Docker contexts.

## Manual browser checks against real services

Used the hosted IAM console as the visual reference. Tested the Hook console in
an in-app browser against the local Hook API and dedicated PostgreSQL test data,
using real IAM-issued production and test SLTs. Credentials were loaded through
private files and are not included in this record.

- Production Carbon sign-in and isolated test Silicon sign-in succeeded.
  The Silicon identity and organization populated the context selectors.
- Attached the existing test root key and listed all ten real sandbox hooks.
- Edited hook `01a073fd-2412-7f60-b809-0db80bf8bb04`. Retested the final save flow:
  the table showed `GitHub · browser verified` without manually refreshing.
- Connected the live WebSocket stream, ingested a real request, inspected its
  body and explicitly acknowledged sequence **79**. The Deliveries page then
  showed cursor 79 and zero pending events. Application heartbeats kept the stream
  alive during interaction.
- Event `01a07745-7d7b-7620-93e6-f08e8b811338` contained an HTML-like string;
  the inspector displayed it as literal text rather than executing markup.
- Created empty environment **Frontend browser QA**
  (`01a0774f-f820-7e12-8134-5b2d687d6420`), retrieved its key, deleted it, filtered
  the deleted list and restored it. The restored environment is active, generation
  3. Key results stayed visible until dismissed and were attached server-side.
- Sessions survived switching from Vite to the packaged Node server using the
  same private session directory and encryption key.
- Signed-out desktop and 390 × 844 mobile layouts were visually checked. Mobile
  navigation worked and document width equaled viewport width without overflow.

Browser testing exposed and fixed two lifecycle issues: background session
refresh previously unmounted one-time key dialogs, and hook edits closed before
the list refresh completed. Environment restore also verified the gateway's
handling of a genuinely empty request body.

## Authentication boundary checks

- Requests missing the console header, carrying a hostile Origin, or marked
  cross-site were rejected with HTTP 403. Normal session reads succeeded with
  an HttpOnly cookie.
- The IAM callback exchanged a real production SLT and redirected to a clean
  URL. Invalid state and replay were rejected. Public session JSON omitted access
  and refresh tokens.
- Hosted IAM rejected the localhost browser callback with HTTP 403. An
  unauthenticated request using the planned HTTPS callback returned a redirect;
  this is **not** a verified hosted sign-in. Local preview therefore uses SLT
  sign-in. Full IAM browser handoff must be tested after HTTPS hosting.

## Coverage limits and remaining gates

All public browser-applicable management operations have controls; the feature
matrix is in [README.md](README.md). This manual run did not exercise every
control, every signing configuration, multi-Silicon reconnect scenario or every
failure path. The five automated tests are regression checks, not a full browser
E2E suite. In particular, successful hook creation was not retested through the
browser because the populated sandbox already contains its maximum ten hooks.

Existing backend/IAM gates remain: Carbon target-Silicon visibility through
application tokens and authority for `connect-iam`. Their failures are surfaced
without bypassing authorization. See [IAM integration](../docs/iam/README.md)
and the separate [backend verification record](../docs/verification/README.md).

Before production acceptance, verify hosted HTTPS IAM handoff, production/test
isolation against the deployed backend, WebSocket proxy behavior and the remaining
operation/error-path browser coverage. The included encrypted file session store
supports one server process/instance with persistent private storage.

## Cross-component pass — 2026-09-08

- CLI help, command discovery (`59` command entries), offline docs, CLI build and
  client tests passed. A manual CLI/client pass found and fixed test-environment
  bootstrap: `hook env attach --key-file` now selects the production client before
  validating and storing the supplied test key.
- The fresh disposable PostgreSQL fixture used for this pass had to be recreated
  with the API role and schema/function grants before the backend could start.
  IAM test-token exchange then returned the upstream 409/provider-unavailable
  responses already recorded in the integration gate; the full CLI/client test
  environment lifecycle could not be completed against that fresh fixture.
- The website was manually opened against the packaged Node gateway, exercised
  through its sign-in and error states, and remained responsive. The sign-in
  blocker is surfaced as a request ID and `unauthenticated`/gateway error rather
  than exposing credentials or crashing the page. The successful real-data
  browser run above remains the authoritative website flow coverage.

## Live AWS / Vercel deployment — 2026-09-08

The SolidJS frontend is deployed at `https://hook.teamofsilicons.com`; the API
and browser gateway are deployed at `https://backend.hook.teamofsilicons.com`.
Infrastructure, backup details and the temporary public-IP limitation are in
[the deployment runbook](../deploy/aws/README.md).

- Public HTTPS readiness/version checks passed with certificate verification.
  The frontend returns HTTP 200. All six gateway/session regression tests and
  the TypeScript check passed, including credentialed CORS and rejected foreign
  origins for the separate frontend/gateway origins.
- Real IAM production and test-world SLTs exchanged successfully against the
  deployed Hook service. A new isolated Hook testing environment was linked to
  the IAM test world, and a test hook was created. Test authentication requires
  `x-hook-test-key`; an initial probe using an incorrect header returned 409.
  Correcting the probe completed test authentication successfully. This live
  result supersedes the unresolved test-token-exchange observation in the
  preceding local-fixture pass, without resolving unrelated IAM permissions.
- A webhook POST to that test hook produced a receipt. An authenticated public
  gateway WebSocket received the event, replayed delivery sequence 1 after
  reconnect, and confirmed acknowledgment through sequence 1. The probe used
  the gateway's secure cookie and exact frontend Origin.
- The deployed IAM callback exchanged a real production SLT and redirected to
  the frontend's clean signed-in URL. Replaying the callback was rejected.
  Public session metadata omitted tokens and kept production/test sessions
  separate. This verifies the callback server path, not the complete browser
  handoff through IAM.
- Both authoritative nameservers and public resolvers returned the deployed
  backend address. HTTPS checks using ordinary DNS on the AWS host passed.
  This workstation's local Unbound resolver retained an earlier NXDOMAIN, so
  Chrome and the in-app browser rendered the frontend but showed a connection
  error. Local backend probes pinned the correct IP with curl `--resolve` while
  retaining normal certificate verification. Full browser SSO and authenticated
  browser operation coverage remain pending local DNS cache expiry.
- All six containers were running; PostgreSQL reported TLS for API/worker
  connections. The daily backup timer was active, and the first database/config
  backup completed to the private encrypted S3 bucket. Restore was not tested.

This deployment smoke pass used manual service requests and WebSocket actions.
It is not a claim of full CLI, client, and browser end-to-end coverage of every
operation. Disposable verification credentials remain in private local storage;
the isolated testing environment is named `Hook deployment verification`.

## Unscoped browser login update — 2026-09-08

- Production sign-in now contains only **Continue with IAM**; token entry and
  token-file controls remain confined to attached testing environments.
- The gateway no longer includes `org_id` in IAM's login URL. A manual request
  to the deployed gateway with the legacy `{"org":"tos"}` body confirmed that
  the organization is ignored and the HTTPS callback still includes state.
- Deployed the frontend to Vercel and replaced only the AWS gateway container,
  preserving its configuration and session volume. TypeScript, all six existing
  gateway/session tests, and both production builds passed. SSM reported success.
- Local DNS now resolves the backend. In the hosted browser, opened the new
  dialog, clicked **Continue with IAM**, and reached IAM signed in as the existing
  account. The URL contained only `app_id` and `redirect_uri`. **Choose
  organizations** opened IAM's organization checklist. No organization grant
  was submitted in this check; callback completion after consent was not tested.

## Unscoped organization context repair — 2026-09-08

- Reproduced `missing_required_header` on the signed-in user's hosted Testing
  environments page. Unscoped IAM tokens correctly omit a single `org_id`, but
  Hook's organization context was left empty and the list request still ran.
- Added private gateway organization discovery using IAM's application-token
  organization list, including pagination. Only IDs/names reach the frontend.
  Sandbox discovery uses the attached Hook environment instead of production
  credentials. The sidebar now lists shared organizations, automatically selects
  a sole organization, and requires a choice when there are several. Environment
  listing/creation waits for a selection; other organization-scoped browser API
  calls reject a missing selection locally with a useful message.
- TypeScript and all seven gateway/session tests passed, including authenticated
  paginated organization discovery and sandbox credential isolation. The gateway
  image and Vercel frontend builds passed and both updates were deployed.
- In the user's existing signed-in Chrome tab, IAM returned Team of Silicons
  (`tos`), Hook selected it automatically, and the Testing environments table
  loaded the existing `Hook deployment verification` sandbox without the header
  error. No new login, consent grant, key rotation, or environment creation was
  needed. This verifies the previously missing organization context with a real
  unscoped browser session.
- A fresh reload exposed a select-label mismatch when the saved organization
  preceded its asynchronously loaded option. Binding selection on the options
  fixes the label while retaining the saved workspace.
