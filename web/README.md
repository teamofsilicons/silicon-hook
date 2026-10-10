# Silicon Hook console

Next.js 16, React 19, TypeScript, pnpm, and vendored Silicon UI. Requires Node 24.
The console signs Carbons in through Silicon Accounts and manages their visible
Silicons. Tokens stay in an encrypted HTTP-only session cookie; the browser calls
same-origin `/api/*`, which forwards to Hook with the access token.

## Product pages

- Hooks: create and edit signature rules, bring a secret or public key, enable and
  disable in bulk, rotate secrets and endpoints, delete and restore within 45 days,
  and set up Accounts event ingress. New secrets appear once, with copy/download.
- History and Blocked requests: filter by hook, paginate, inspect raw bodies and
  ordered headers, and export JSON. Provider filtering applies to the current page.
- Deliveries: inspect publication status, receipt and attempts, and manage observer
  delivery enrollment and subscriptions. Live stream observes without acknowledging.
- Access: named view grants, leave/revoke, and allow-lists. Management controls appear
  only for the Silicon or its custodian; authorization is also enforced by the API.
- Settings: theme, telemetry preference, CLI installation, API diagnostics and sign-out.

## Local development

Run Hook's API and a Silicon Accounts stack first. Register the `hook` app with
`http://127.0.0.1:4200/auth/callback` and `http://localhost:4200/auth/callback`.
Copy `.env.example` to `.env.local` and set the real local app secret and a fresh
session secret (`openssl rand -base64 48`).

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm dev
```

Open `http://127.0.0.1:4200`. The defaults use hosted Accounts on 9590, its private
API on 9589, and Hook API on 4201. `PORT` changes the frontend listener.

## Environment

All configuration is read at runtime. Builds require no application secrets.

| Variable | Purpose |
| --- | --- |
| `APP_ID` | Accounts audience; `hook`. |
| `APP_SECRET` | Hook app secret, server only. |
| `ACCOUNTS_URL` | Public Accounts origin and issuer. |
| `ACCOUNTS_API_URL` | Optional server-to-server address of the same Accounts service. |
| `APP_API_URL` | Hook API origin, including any deployment prefix. |
| `SESSION_SECRET` | At least 32 bytes of randomness for sealed cookies. |
| `PUBLIC_URL` | Console origin; register its `/auth/callback` at Accounts. |
| `EXTRA_IMG_ORIGINS` | Optional additional profile-image origins. |
| `EXTRA_ORIGINS` | Optional additional trusted origins for state-changing requests. |

Production origins use HTTPS. Secrets must never have a `NEXT_PUBLIC_` prefix.
Sign-in uses PKCE and state; unsafe requests require same-origin checks. Refreshes
are single-flight per server process. Multi-replica hosting needs the Accounts
refresh replay behavior verified during release testing. The API validates every
bearer and owns lifecycle enforcement; hiding a button does not grant authority.

## Checks and browser evidence

```sh
pnpm typecheck
pnpm lint
pnpm test
NEXT_OUTPUT=standalone pnpm build
TEST_STACK_JSON=/path/to/test-stack.json HOOK_E2E_MINT=/path/to/mint.mts pnpm test:e2e
```

The browser suite uses real local hosted Accounts and Hook, plus a proof-verifying
local delivery receiver. `HOOK_E2E_MINT` is the migration stack's identity helper;
the setup exchanges a Silicon SLT and records the Silicon in Hook. It creates two
Carbons and a custodial Silicon, then exercises sharing, real signed/blocked
provider requests, management, receipts, sessions and refresh, and axe accessibility
checks at phone/desktop widths in both themes. Test artifacts and credentials are
ignored. `e2e/hook.spec.ts` also writes populated page PNGs to `screens/`.

Run the suite after the backend starts with `scripts/dev-accounts.sh start --ting-stub`
(see that script's stack/state configuration). Tests spend email-code quotas on the
shared local Accounts stack; they do not disable account quotas or contact production.

## Deployment

Vercel: set project root to `web`, Node 24, and the runtime environment above.
`vercel.json` selects Next.js and the frozen pnpm install. Register the production
callback before switching domains. Keep the previous deployment for rollback.

Self-hosting: `docker build -t silicon-hook-web web` from the repository root builds
a non-root Node standalone server. Supply runtime settings, terminate HTTPS at the
proxy, and forward to port 4200. The image contains no app secret. Local standalone
builds use `NEXT_OUTPUT=standalone pnpm build`; copy `public/` and `.next/static/`
into the standalone directory before running `node .next/standalone/server.js`.

Deploy the matching Hook API and console together: this console uses API v3 and
Accounts identities. The previous IAM session cookie cannot be migrated; visitors
sign in again. Switching the frontend alone does not migrate the backend identity
inventory or the fleet's consumers. See `../docs/deployment.md` and
`../docs/migration/` for the coordinated cutover and rollback evidence.

Arc sources and licenses remain in `vendor/`; `DESIGN.md` documents the shared
visual system. `ADOPTING.md` is the original kit maintainer reference.
