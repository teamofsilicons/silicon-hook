# Silicon Hook ↔ Silicon IAM integration

**Contract version:** `silicon-hook-iam/v3`

**Status:** implemented on the official `silicon-iam` crate (0.1.0) against
the IAM API and client documentation at
<https://backend.iam.teamofsilicons.com/docs/client/>.

Hook is a registered Silicon IAM Application. Everything a caller could get
wrong without noticing lives in the crate: the compatibility handshake, PKCE
sign-in, token introspection, and exact-byte webhook verification. What the
crate deliberately leaves to the bearer holder, Hook does with the caller's
own token against IAM's documented directory routes. Hook caches no
authorization fact and exposes no OBO endpoints.

## 1. Startup

`hook-api` connects with `ApplicationCredentials::new(HOOK_IAM_APP_ID,
HOOK_IAM_APP_SECRET)` and `Client::builder(..).connect()`. The crate performs
the unversioned handshake (`GET /api/version`), pins every later call to the
negotiated API major, and fails closed; a process whose IAM cannot be reached
or does not agree on a version does not start.

| Setting | Meaning |
| --- | --- |
| `HOOK_IAM_BASE_URL` | IAM origin. HTTPS is mandatory in production. |
| `HOOK_IAM_APP_ID`, `HOOK_IAM_APP_SECRET` | Hook's Application ID and current `ask_` secret. |
| `HOOK_IAM_REDIRECT_URI`, `HOOK_IAM_SCOPES` | Enable Carbon sign-in; the redirect URI must be the one registered with IAM. |
| `HOOK_IAM_WEBHOOK_SECRET`, `..._VERSION`, `..._PREVIOUS_SECRET`, `..._PREVIOUS_SECRET_VERSION` | Enable receipt of Hook's own Application webhook. |
| `HOOK_IAM_ALLOW_INSECURE_LOCAL_HTTP` | Development only: plain HTTP to a loopback IAM. |
| `HOOK_ALLOW_LOCAL_AUTH` | Development only: deterministic `local:` bearers, see section 6. |

## 2. Authenticating a management call

Every management route needs `Authorization: Bearer <token>` and `X-Org-ID`.
Two token classes are accepted:

- **Hook-issued `oat_` tokens** from the sign-in flow in section 3. Hook
  first introspects them through the crate with an exact organization
  assertion (`IntrospectionOptions::for_organization`), which proves the
  token was issued to Hook, is active, and belongs to the organization.
- **IAM-native `cat_`/`sat_` tokens** a Carbon or Silicon obtained from IAM
  directly, for example through `POST /api/v1/silicon-auth/token`.

For both classes Hook then reads, with the caller's own bearer:

```http
GET /api/v1/organizations/{org_id}/directory/self?fields=id,role,org
Authorization: Bearer <caller token>
Silicon-IAM-API-Version: v1
```

The `id` is the public Carbon ID or the global Silicon ID (`handle:org`); the
role's `org_role` is `owner`, `admin`, or `member`. IAM answers `401` for a
dead token and `403`/`404` for a token without an active membership in the
organization; Hook turns all three into `401 unauthenticated`. A Silicon ID
whose organization suffix differs from `X-Org-ID` is a contract violation and
fails closed.

Visibility is established per request. A Silicon sees only itself. An owner
or administrator sees every Silicon in the organization. A member Carbon sees
a Silicon exactly when IAM returns its profile:

```http
GET /api/v1/organizations/{org_id}/silicons/{silicon_id}
Authorization: Bearer <caller token>
```

`200` confirms visibility; `403` and `404` deny it. Hook's policy then
applies: reading, creating, history, and delivery streams need visibility;
deleting, restoring, enabling, updating, rotating, and connecting the IAM
hook need the Silicon itself, an owner, or an administrator.

## 3. Carbon sign-in

| Route | Body | Result |
| --- | --- | --- |
| `POST /api/v1/auth/login` | `{"org_id": "…"}` optional | `{"authorization_url", "continuation"}` |
| `POST /api/v1/auth/callback` | `{"continuation", "callback_url"}` | Tokens, or `403 login_denied` |
| `POST /api/v1/auth/refresh` | `{"refresh_token"}` | Tokens |
| `POST /api/v1/auth/logout` | bearer `oat_` token | `204` |

`login` builds the PKCE authorization URL with the crate and returns the
sealed, encrypted continuation the crate produced. The client persists the
continuation, sends the browser to the URL, and on return posts the exact
callback URL it received together with the continuation. Hook restores the
attempt, verifies state, exchanges the code, and returns
`{access_token, refresh_token, token_type, expires_in, scopes, actor, org_id}`.
Refresh tokens rotate on every use; the client must replace the stored token
atomically and never refresh the same family concurrently.

## 4. The Silicon's IAM hook

`POST /api/v1/silicons/{silicon_id}/hooks/iam` (bearer, `X-Org-ID`,
`Idempotency-Key`) connects IAM events to the Silicon:

1. Hook finds the Silicon's `Silicon IAM` hook or creates it, restoring a
   soft-deleted one. There is exactly one per Silicon.
2. Hook registers the hook's endpoint URL as the Silicon's IAM webhook with
   the caller's own bearer: `GET …/silicons/{silicon_id}/webhook` for the
   current `ETag`, then `PUT` with `If-Match` when one exists. IAM answers
   with a fresh `swhs_` signing secret.
3. Hook stores that secret as the hook's signing secret.

The hook's policy is IAM's own convention: HMAC-SHA-256 over
`{X-Silicon-IAM-Timestamp}.{exact body}` keyed with the UTF-8 bytes of the
`swhs_` secret, presented as `v1=<lowercase hex>` in
`X-Silicon-IAM-Signature`. Every verified delivery reaches the Silicon as a
raw captured request with the summary `Silicon IAM triggered at …`, which is
how a Silicon learns about logouts, removals, and directory changes.

IAM requires a Carbon manager to present verified-channel step-up for this
registration; a Silicon registers its own webhook without it. IAM's `403`,
`404`, and precondition failures surface as `403`, `404`, and
`409 iam_rejected`. Retrying with the same `Idempotency-Key` reconciles a
partial failure at any step.

## 5. Hook's own Application webhook

IAM posts Hook's Application webhook to `POST /api/v1/iam/events`. Hook
verifies each delivery with the crate's `WebhookVerifier` over the configured
`whs_` keyring (current and, during a rotation, previous version), then logs
the authenticated envelope and answers `204`. Hook keeps no authorization
cache, so no further action is needed for the event to take effect.

## 6. Local adapter

With `HOOK_ALLOW_LOCAL_AUTH=true` (never in production) a bearer of the form
`local:<carbon|silicon>:<member|admin|owner>:<id>` is accepted without IAM. A
local Silicon sees itself; a local Carbon sees every Silicon a request names.
The IAM hook connection returns a deterministic `swhs_` secret so the flow
works end to end. Sign-in is unavailable in local mode.
