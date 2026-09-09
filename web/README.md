# Silicon Hook frontend

Minimal SolidJS + TypeScript console, with a same-origin Node gateway. The visual
reference is the **hosted IAM console at iam.teamofsilicons.com**, not IAM's docs:
IBM Plex fonts, the Silicon brand mark, a pale sidebar, fine borders, white panels
and restrained blue controls. Brand assets are reused from the local IAM frontend.

Production serves the static console on Vercel at `https://hook.teamofsilicons.com`.
Its persistent Node gateway runs beside the API on the dedicated AWS host at
`https://backend.hook.teamofsilicons.com`. `VITE_HOOK_GATEWAY_ORIGIN` selects that
public address at build time; `HOOK_FRONTEND_ORIGIN` pins the only allowed browser
origin on the gateway. HTTP uses credentialed CORS and WebSockets check the exact
origin. The Secure HttpOnly session cookie stays on the backend hostname. Both
origins must be on the same site for the SameSite=Lax cookie. See the
[production runbook](../deploy/aws/README.md).

## Run locally

Requires Node 24 or newer and a running Hook backend.

```sh
cd web
npm ci
cp .env.example .env.development.local
npm run dev
```

Open http://127.0.0.1:4317. The default upstream is http://127.0.0.1:18480.
Configure `HOOK_API_UPSTREAM` and `HOOK_WEB_ORIGIN` to change them. An origin is
fixed by the server; the browser cannot redirect stored credentials to another
backend. HTTPS is required except for literal loopback/localhost development.

For sessions to survive dev-server restarts, set a stable `HOOK_SESSION_KEY`
(32 random bytes encoded as base64) and a private `HOOK_SESSION_DIR`. Without a
configured key, development generates a temporary one and restarting signs users
out. `.env*`, local sessions, build output and dependencies are excluded from Git
and Docker contexts. Never put server secrets in `VITE_*` variables.

## Sign in and select a workspace

- Production sign-in offers only **Continue with IAM**. It starts an unscoped
  login for `tos>hook`, without an `org_id`; users choose organizations in IAM.
  The sidebar's workspace selection does not scope sign-in. Hook binds the
  return to a five-minute, one-use server-side state value. `/auth/callback`
  exchanges the SLT through Hook's backend and immediately redirects to a clean
  URL; no token is returned to frontend JS. Browser handoff needs an HTTPS
  callback accepted by IAM.
- Token entry/file sign-in is available only for attached testing environments,
  using an SLT issued for `tos>hook` in the linked IAM test world.
- The organization picker loads the organizations shared with Hook from IAM
  through the private browser gateway. A single organization is selected
  automatically; with several, choose the workspace in the sidebar. Organization
  requests wait for that selection. Sandbox organization comes from its attached
  environment. Silicon sign-in fills its own ID; Carbon users enter the target
  Silicon ID. Credentials stay server-side during organization discovery.
- Attach a Hook test root key to open a sandbox, then sign in with a token from
  its linked **IAM test world**. Production and each test environment keep
  separate credentials. Test requests never fall back to production tokens.
- Production identity is used to create/list/delete/restore sandboxes and
  retrieve/rotate their keys. An attached root key can inspect, clean and configure
  its test world without an actor token. Creation/key retrieval/rotation save the
  resulting root key in the current browser's server-side session.

## Feature coverage

| View | Public functionality |
|---|---|
| Overview | Actual connection counts, latest request and recent events |
| Webhooks | List/search, create, inspect, edit name/description/time zone, single and batch enable/disable, recoverable delete/restore, rotate endpoint and signing secret |
| Signing editor | All twelve algorithms; all four signature and six secret encodings; full payload/locator expressions, custom shared secret and PEM public key; generated secret display/copy/download |
| Events | Per-hook and account-wide history, selectable limits through 10000, opaque-cursor pagination, headers/body/metadata/full-JSON inspector, JSON export |
| Blocked requests | Separate retained history with reason/detail, filtering, pagination, inspection and export |
| Deliveries | Pull pending events, page by sequence, read the consumer cursor, explicitly acknowledge a contiguous sequence |
| Live stream | Multiple Silicon IDs, ready/event/error/ACK frames, heartbeat replies, bounded recent display, reconnect, explicit ACK and resume |
| Testing environments | Create with optional IAM bootstrap, attach keys, list/filter/page, inspect current sandbox, retrieve/rotate key, delete/restore, typed confirmation for clean, configure IAM credentials |
| Connections & setup | Sign in/switch/refresh/revoke/forget the selected identity, connect IAM notifications, liveness/readiness/version/API negotiation, CLI and SDK relay setup |

The browser never silently acknowledges a request. Acknowledgments change the
shared cursor used by all clients of that Silicon. Live display keeps the latest
32 events; full retained data stays available in history. Large history bodies
can reduce a page's item count; continue with Next. Request content is rendered
as text, including HTML-like payloads; binary bodies remain available as base64
and in downloads. Hooks' endpoint and IAM application receivers remain backend
HTTP endpoints used by providers, not browser-authenticated proxy routes.

A hosted page cannot start or supervise a daemon on the user's computer. The
Connections view provides CLI/SDK setup; its browser stream runs only while the
page is open. The CLI owns local recipient forwarding, local request receipts,
its own profiles and executable updates. OBO and the deferred report command
are not frontend operations.

## Sessions and gateway

The browser receives an opaque HttpOnly, SameSite=Lax session cookie. HTTPS adds
Secure and the `__Host-` prefix. Lax allows the top-level IAM callback; every
console request also requires the frontend header, exact configured host, and
same-origin checks. WebSocket upgrades require the exact Origin and a valid
session. No access/refresh tokens or saved test keys are kept in localStorage;
only non-secret organization/Silicon/environment selection is persisted there.

Sessions expire after seven days. Files use AES-256-GCM, with the session ID as
associated data, private directory/file modes, fsynced atomic replacement and
per-session request serialization. Refresh saves its idempotency key before
calling IAM through Hook, and reuses it after a failed response. Expired sessions
are removed when accessed; operators may remove old abandoned session files as
part of maintenance. Changing the encryption key invalidates existing sessions.

The gateway accepts only the explicitly listed public management operations.
It cannot forward browser-supplied Authorization, testing keys or arbitrary
origins. It excludes IAM event receivers, provider ingress and raw auth routes.
Responses are no-store; the production server adds CSP, frame denial, nosniff,
no-referrer and HTTPS transport headers. Limits: 2 MiB console request body,
64 MiB upstream response, 4 MiB upstream WebSocket message, 8 KiB browser frame.

The file store is deliberately a **single-process, single-instance** deployment.
Do not run multiple workers against it: its refresh lock is in-process. Before
horizontal scaling or serverless deployment, replace the store with a shared
transactional store and distributed refresh locking. Ephemeral serverless
filesystem storage is not supported by this build.

## Build and host later

```sh
npm run build
npm test
NODE_ENV=production node dist/server.js
```

The production process requires:

| Variable | Value |
|---|---|
| `HOOK_WEB_ORIGIN` | Exact gateway HTTPS origin; production uses `https://backend.hook.teamofsilicons.com` |
| `HOOK_FRONTEND_ORIGIN` | Exact browser origin; production uses `https://hook.teamofsilicons.com`; defaults to gateway origin locally |
| `HOOK_API_UPSTREAM` | Hook backend origin, e.g. `https://backend.hook.teamofsilicons.com` |
| `HOOK_SESSION_KEY` | Stable, secret base64 encoding of 32 random bytes |
| `HOOK_SESSION_DIR` | Dedicated private persistent directory |
| `HOST` | Bind address; defaults to loopback, use `0.0.0.0` inside a container |
| `PORT` | Listen port, defaults to 4317 |

Serve the **Node gateway and built assets together**, not just `dist/client`.
Terminate TLS in a reverse proxy, preserve the public Host, forward WebSocket
upgrades on `/console/stream`, and allow idle connections longer than the
heartbeat interval. Do not log callback query strings, cookies, authorization,
form bodies or credential responses. Use a persistent private volume for sessions
and inject the encryption key from the hosting platform's secret store.

A container definition is included. Build from the `web` directory:

```sh
docker build -t silicon-hook-web .
```

Mount `/var/lib/hook-web/sessions` with ownership suitable for the image's `node`
user, and provide the required origin/upstream/key variables. No app secret is
needed by this server: the Hook backend already owns IAM application credentials.

After deployment, verify IAM browser handoff using the real HTTPS callback,
backend health, signed-in production/test isolation and WebSocket delivery.
The deployment record in the production runbook describes the active hosting.

## Verification and existing integration gates

See [manual browser verification](./VERIFICATION.md). Build/type-check and the
session/gateway regression checks are included in repository CI. Solid's reactive
resource API and Vite's build conventions follow their official documentation:
[Solid createResource](https://docs.solidjs.com/reference/basic-reactivity/create-resource),
[Vite](https://vite.dev/guide/).

The pre-existing IAM integration gate remains: IAM must provide authoritative
application-token target-Silicon visibility for Carbons and the required authority
for `connect-iam`. The frontend exposes these operations and their real errors;
it does not bypass backend authorization or claim those IAM-dependent flows are
complete. See [IAM integration](../docs/iam/README.md).
