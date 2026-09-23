# Silicon Hook frontend

Internal SolidJS + TypeScript management console, with a Node gateway. Applications
handle Hook and Ting setup for their users. The visual
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

- Production sign-in offers only **Continue with IAM**. The gateway requests
  Hook and Ting SLTs in one unscoped IAM batch login; users choose organizations
  in IAM. The sidebar's workspace selection does not scope sign-in. Hook binds
  the return to a five-minute, one-use server-side state value. The callback
  script clears the SLT fragment and posts the pair to the same-origin gateway.
  Both exchanges must identify the same actor before the session becomes active.
  Receiving requires Ting 0.1.3 or a compatible `/v1/me` response that explicitly
  identifies the production environment. A missing, malformed or testing
  environment is rejected before activating the paired session.
  Access, refresh and opaque Ting session tokens remain encrypted server-side.
  Browser handoff needs a callback accepted by IAM. Batch consent may name both
  internal apps; hiding them behind an enclosing app requires IAM's application
  bundle contract. `HOOK_IAM_BUNDLE_ID` selects an existing bundle containing
  exactly Hook and Ting; the gateway still checks the exact returned app pair.
- Token entry/file sign-in is available only for attached testing environments,
  using an SLT issued for `tos>hook` in the linked IAM test world.
- The organization picker loads the organizations shared with Hook from IAM
  through the private browser gateway. A single organization is selected
  automatically; with several, choose the workspace in the sidebar. Organization
  requests wait for that selection. Sandbox organization comes from its attached
  environment. Silicon sign-in fills its own ID; Carbon users enter the target
  Silicon ID. Credentials stay server-side during organization discovery.
- Attach a Hook test application secret to select its sandbox, then sign in as
  an identity from its linked **IAM test world**. Production and each test
  environment keep separate credentials. Test requests never fall back to
  production tokens. Honeycomb owns environment lifecycle; IAM owns identities.
- Test receiving uses Ting 0.1.4's scoped inbox/watch through Hook, using only
  the attached Hook app secret and signed-in test actor. The gateway validates
  the full scope, keeps the capability encrypted, renews the same receiver ID
  before expiry, and revokes it on close/logout/context replacement. It can
  retain four receiving slots per test plane, including pending cleanup.
  Lost responses are recovered with the exact saved operation; unresolved
  cleanup retains authority and reports `receiver_cleanup_pending`. See the
  [authority-loss recovery limitation](../docs/ting-integration-issues.md#uncertain-scoped-receiver-cleanup-after-authority-loss).

## Feature coverage

| View | Public functionality |
|---|---|
| Overview | Actual connection counts, latest request and recent events |
| Webhooks | List/search, create, inspect, edit name/description/time zone, single and batch enable/disable, recoverable delete/restore, rotate endpoint and signing secret |
| Signing editor | All twelve algorithms; all four signature and six secret encodings; full payload/locator expressions, explicit BYOS selection at creation and editing, custom shared secret and PEM public key; generated secret display/copy/download |
| Events | Per-hook and account-wide history, selectable limits through 10000, opaque-cursor pagination, headers/body/metadata/full-JSON inspector, JSON export |
| Blocked requests | Separate retained history with reason/detail, filtering, pagination, inspection and export |
| Deliveries | Retained events, pagination, publication state, ordinary/required policy, independent notification silence, separate destination receipt and acceptance |
| Live stream | Authorized Silicon selection, internal Ting inbox watch, original event hydration, explicit errors, bounded recent display and reconnect |
| Testing environments | Select with the Hook app secret, inspect current sandbox, sign in as a test identity and return to production |
| Connections & setup | Sign in/switch/refresh/revoke/forget the selected identity, connect IAM notifications, liveness/readiness/version/API negotiation, CLI and stateless SDK management |

The browser's live view observes Ting's inbox and never sends delivery/read ACKs.
Both normal and scoped watches reconcile the inbox every ten seconds so silent
arrivals appear even without a watch hint. On a scoped rate limit, the gateway
pauses the watch and polling for Retry-After while preserving the receiver slot
and already displayed event IDs. It then renews the same receiver, including
after capability expiry, and resumes reconciliation without duplicate rows.
Logout cancels the pending recovery. Each compact reference is fetched from
Hook using current authorization and its original event generation. An
unavailable original is reported rather than displayed as a processed event.
Publication status refers to the primary Silicon, not the viewing Carbon's
observer copy. Receipt and acceptance are distinct from completed work.
Live display keeps the latest
32 events; full retained data stays available in history. Large history bodies
can reduce a page's item count; continue with Next. Request content is rendered
as text, including HTML-like payloads; binary bodies remain available as base64
and in downloads. Hooks' endpoint and IAM application receivers remain backend
HTTP endpoints used by providers, not browser-authenticated proxy routes.

The browser stream runs while the page is open. The enclosing application owns
the shared Ting runtime for continuous delivery. The Hook CLI manages its own
profiles and provides management and inspection commands; it starts no delivery
daemon. Honeycomb manages its installation and updates.

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

Replacing an identity revokes the previous saved sessions before activating the
new pair. Interrupted exchanges retain their recovery state encrypted on the
server. Sign out and Forget also revoke partial sign-ins. If revocation fails,
the identity is disabled locally and its credentials remain only for retrying
cleanup; the console exposes **Retry sign out**.

The gateway accepts only the explicitly listed public management operations.
It cannot forward browser-supplied Authorization, testing keys or arbitrary
origins. It excludes IAM event receivers, provider ingress and raw auth routes.
Responses are no-store; the production server adds CSP, frame denial, nosniff,
no-referrer and HTTPS transport headers. Limits: 2 MiB console request body,
64 MiB Hook response, 2 MiB Ting response, 64 KiB Ting watch frame and 8 KiB
browser frame. The browser stream does not accept application commands or ACKs.

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
| `HOOK_TING_UPSTREAM` | Ting backend origin; defaults to `https://backend.ting.teamofsilicons.com` |
| `HOOK_IAM_API_UPSTREAM` | Trusted IAM API origin; defaults to `https://backend.iam.teamofsilicons.com` |
| `HOOK_IAM_AUTHORIZE_ORIGIN` | IAM browser sign-in origin; defaults to `https://auth.iam.teamofsilicons.com` |
| `HOOK_IAM_BUNDLE_ID` | Optional existing IAM bundle for Hook and Ting; otherwise internal console batch login is used |
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
