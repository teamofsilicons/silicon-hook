# Adopting the web kit

The exact steps for building an app's web frontend from the kit: Briefcase, DM, Extend, Hook, Commit, Waveform, Remind,
MCPort, or any Silicon app with its own service. Do them in order; each ends with something you can check.

The kit assumes the app's service already accepts Silicon Accounts access tokens (an EdDSA JWT with `aud` = the app's
`app_id` and `iss` = the Accounts public URL, verified against `{ACCOUNTS_URL}/.well-known/jwks.json`) and answers
errors as `{"error": {"code", "message", "hint"}}`. Silicon Accounts' docs: `docs/start/add-sign-in.md`,
`docs/start/tokens.md`, `docs/reference/rust-client.md` (`verify_access_token_locally`).

## 1. Copy the kit into `web/`

From the app's repository root (replace the old frontend; keep anything you still need to port next to it until the
new pages exist):

```sh
rsync -a --exclude node_modules --exclude '.next*' --exclude test-results --exclude playwright-report \
  --exclude screens --exclude .mig --exclude .env.local --exclude .git \
  /Users/codanium/Documents/silicon/.migration/web-kit/ web/
cd web && pnpm install
```

Then, in `web/`:

- `package.json`: set `name` (`@silicon-<app>/web`) and `description`; change the port in `dev` and `start`
  (`${PORT:-4260}`) to the first port of the app's block (briefcase 4100, dm 4120, commit 4140, waveform 4160, remind
  4180, hook 4200, extend 4220, mcport 4240). Keep every dependency pin as it is.
- `playwright.config.ts`: the same port as the default of `E2E_PORT`, and the app's service in place of the stub
  (step 6).
- Keep `components/silicon-ui/`, `vendor/silicon-ui/` and the historical `vendor/uiarc/` MIT attribution, `styles/`, `public/fonts/`,
  `assets/og/` and their licence files exactly as they are.

Check: `pnpm typecheck && pnpm lint && pnpm test` pass before you change anything else.

## 2. Make it the app's: `lib/app.config.ts`

Every field, in the app's own words (the copy rules in step 9 apply):

| Field | Set it to |
| --- | --- |
| `appId` | the app's `app_id` (`remind`) |
| `name` | the product name (`Remind`) |
| `brandPrefix` | `"Silicon"` for the family's two-word wordmark ("Silicon" + the muted name, like Silicon Apps); leave it out for the bare name |
| `tagline` | one line: what it is |
| `description` | two or three sentences for search engines, link previews and `llms.txt` |
| `mark.paths` | the glyph: SVG path data with round 2 px strokes on a 24 × 24 grid (paste a lucide icon's paths, or draw one) |
| `accent` | only if the app has a product colour: `{ light, dark }`, each at least 3:1 on its page colour. It tints the mark and the landing wash, never actions |
| `cli.command` | the command in `apps.yaml` (`remind`); leave `cli` out for an app without a command line |
| `home` | where a signed-in Carbon lands (usually the first nav item) |
| `nav` | the workspace's sections: `{ href, label, icon, keywords? }`, three to seven of them; `icon` is a lucide icon |
| `links.docs`, `links.store`, `links.source?` | the app's docs, its page in the Silicon Apps store (`https://apps.teamofsilicons.com/apps/<app_id>`), its source |
| `signIn.scopes` | the details the app asks for at sign-in beyond the profile: `email`, `phone`, `dob`, `timezone` (match the app's `required_fields` and `optional_fields`) |
| `landing` | the landing page's headline, lede, and three to four features each for Carbons and for Silicons |
| `api.forwardHeaders`, `api.exposeHeaders` | extra headers the proxy passes to the service and back (lower case), if the service uses any |

The file is bundled into the browser: never put a secret in it.

Check: `pnpm dev` shows the app's name, mark and landing page at `/`, and `pnpm test` still passes (the agent-file
tests read the config).

## 3. Register the web frontend at Silicon Accounts

The redirect URI is exactly `{PUBLIC_URL}/auth/callback`. Register one per place the frontend runs: production
(`https://<domain>/auth/callback`), and for local work `http://127.0.0.1:<port>/auth/callback` and
`http://localhost:<port>/auth/callback`. Arrays replace, so read the current list and send it back whole, with the
version you read:

```sh
APP=remind; ACCOUNTS=http://127.0.0.1:9589          # production: https://accounts.teamofsilicons.com (with care)
curl -s -u "$APP:$APP_SECRET" "$ACCOUNTS/v1/apps/$APP" | jq '{v: .config_version, uris: .signin_config.redirect_uris}'
curl -s -X PATCH -u "$APP:$APP_SECRET" "$ACCOUNTS/v1/apps/$APP/signin-config" -H 'Content-Type: application/json' \
  -d '{"expected_version": 7, "redirect_uris": ["…every uri you read…", "http://127.0.0.1:4180/auth/callback", "http://localhost:4180/auth/callback"]}'
```

On the shared local test stack, keep `http://127.0.0.1:9593/<app>/callback` in the list. Set the details the app asks
for (`required_fields`, `optional_fields`) in the same way if `signIn.scopes` changed.

Check: `curl -s -o /dev/null -w '%{redirect_url}\n' http://127.0.0.1:<port>/auth/sign-in` goes to
`<ACCOUNTS_URL>/authorize?app_id=<app>&redirect_uri=…`, and that page shows the app's sign-in, not an error page.

## 4. Set the environment

Locally, `cp .env.example .env.local` and fill it in. On Vercel: Project → Settings → Environment Variables, the same
names for Production, and for Preview only with a `PUBLIC_URL` whose callback is registered (a fixed preview domain);
mark `APP_SECRET` and `SESSION_SECRET` sensitive.

| Variable | Local | Production |
| --- | --- | --- |
| `APP_ID` | the app_id (or leave it to the config) | the same |
| `APP_SECRET` | the app's secret on the stack (`test-stack.json` → `apps.<app>.app_secret`) | the production secret, from wherever the service keeps it; never in the repository |
| `ACCOUNTS_URL` | `http://localhost:9590` | `https://accounts.teamofsilicons.com` |
| `ACCOUNTS_API_URL` | `http://127.0.0.1:9589` | leave unset (or a private address of the Accounts API) |
| `APP_API_URL` | the service on the app's port (`http://127.0.0.1:4181`) | the service's origin (https unless it is on a private network beside this server) |
| `SESSION_SECRET` | `openssl rand -base64 48` | a new `openssl rand -base64 48`, never the local one |
| `PUBLIC_URL` | `http://127.0.0.1:<port>` | `https://<domain>` |
| `EXTRA_IMG_ORIGINS` | `http://127.0.0.1:9594` (the stack's mock Iris) | leave unset unless photos come from elsewhere |

Check: `pnpm build && pnpm start` prints `<app>: <PUBLIC_URL> signs Carbons in on <ACCOUNTS_URL> and calls its service
at <APP_API_URL>`. With a setting missing it exits and names it.

## 5. Delete the demo

```sh
rm -r demo app/'(workspace)'/items app/'(workspace)'/settings e2e/demo.spec.ts e2e/screens.spec.ts
```

and remove `pnpm stub` from `package.json` and the stub's `webServer` entry from `playwright.config.ts`. Keep
`e2e/accounts.setup.ts`, `e2e/public.spec.ts`, `e2e/session.spec.ts`, `e2e/refresh.spec.ts`, `e2e/a11y.spec.ts`
(point its detail-page part at one of the app's own pages) and `e2e/support.ts`: they read the config. Write the app's own `screens.spec.ts` from the demo's.

## 6. Build the screens

For every screen of the old frontend, in the order Carbons use them:

1. A route under `app/(workspace)/<section>/page.tsx` (a Server Component). Read with `tryApiFetch("/v1/…")` and show
   `<ErrorAlert>` on failure; `apiFetch(path, { notFound: true })` for one thing by id.
2. The interactive part as a client component that takes the server's answer as `initialData` for a React Query hook
   (`useQuery({ queryKey, queryFn: ({ signal }) => api.get(path, { signal }), initialData })`), with mutations through
   `api.post/patch/put/delete` that update or invalidate the queries.
3. A `loading.tsx` when the page is slow to read (skeletons in the final layout), and the page in `appConfig.nav` if it
   is a section.
4. Silicon UI for every control (step 8); the foundation's `Page`, `PageHeader`, `Section`, `Surface`, `SettingsGroup` and
   `SettingsRow`, `DescriptionList` for layout; `AccountChip` wherever an account appears; `ShareWithAccounts` wherever
   something is shared (D2: sharing names exact accounts by `c:`/`si:` id; the service resolves them and stores uuids).
5. Every list has an empty state (nothing yet: say what will appear and offer the action; nothing matches: offer to
   clear the filters). Every destructive action holds (`HoldToConfirm`) or asks in place (`ConfirmMorph`). Toasts are
   for background results and failures; a foreground action confirms where it happened.

Check each screen in both themes, at 1440 and 390 wide, with the keyboard alone.

## 7. Call the service

The browser calls `/api/<the service's own path>`; the kit forwards it to `APP_API_URL` unchanged and adds
`Authorization: Bearer <access token>`. So the old frontend's `fetch("https://service/v1/x", { headers: { Authorization
} })` becomes `api.get("/v1/x")` in a client component, or `apiFetch("/v1/x")` in a Server Component.

- **Paths** stay the service's own (`/v1/reminders/42`). Encode ids with `seg()` (`/v1/accounts/by-id/${seg("c:ada")}`).
- **Headers**: the proxy forwards an allowlist (README, "The API proxy"). A header the service needs from the browser
  (`x-<app>-cursor`) goes in `appConfig.api.forwardHeaders`; one the browser needs back (`x-total-count`) in
  `exposeHeaders`. Cookies and the browser's `Authorization` never cross.
- **Writes** need this site's `Origin` (browsers send it on every fetch and form post). Send `idempotencyKey: true` on
  creates the service treats as idempotent.
- **Uploads** stream: `api.post(path, undefined, { raw: file, contentType: file.type })`. Nothing is buffered here.
- **Downloads**: a plain link to `/api/<path>`; the answer streams through with its `Content-Disposition`.
- **Long-lived streams** (server-sent events) pass through too, but the proxy ends any request after 5 minutes: reconnect
  (EventSource does by itself).
- **Errors**: the service's `{"error": {...}}` reaches the page as `ApiError` with its code, message and hint; a 422's
  `details.fields` is `error.fields` (show each next to its field). A 401 ends the session: the Carbon is sent to
  `/sign-in?reason=session_ended`, which explains and signs them in again. A 403 or 404 is shown where it happened.
- **Who is calling**: the service reads the account from the token (`sub` = the uuid, plus `id` and `kind`). The page
  knows it from `requireSession()` (server) or the shell (client); never send the account's id from the browser to
  mean "me".
- **Server-only calls** (to Silicon Accounts with the app's credentials, or to another app with a proof) belong in the
  service, not here; the web frontend only ever acts as the signed-in account.

## 8. Add Silicon UI components

Use the official registry at `https://ui.teamofsilicons.com/r/{name}.json`, configured as `@silicon-ui` in `components.json`. Components live in `components/silicon-ui/`; read their documentation on `ui.teamofsilicons.com`, including foundation and motion dependencies. Record the source URL and hash in `silicon-ui-registry.json`.

Preserve app-owned layout compatibility tokens in `styles/tokens.css` and the documented keyboard confirmation correction. Review updates before replacing local files. Keep the historical MIT notice for derived application shell styles, plus current upstream attribution.

## 9. Copy rules (D9)

Everything a Carbon or Silicon reads: pages, buttons, errors, toasts, `llms.txt`, metadata, the docs.

- People are **Carbons**, agents are **Silicons**. An account is a Carbon or a Silicon; a Silicon has a custodian (a
  Carbon). Never write "AI agent", "human", "user account", "organization", "org", or "team" for a group of accounts.
- Never mention Honeycomb or IAM (a migration note under `docs/migration/` may).
- Accounts are shown by their current `c:`/`si:` id and display name, never by uuid (the uuid is a key, not a name).
- Errors say exactly what happened and why, then what to do: the service's `message` and `hint`, shown together.
  "Could not save the reminder: the time is in the past. Pick a time after now." Not "Something went wrong".
- Sentence case everywhere (titles, buttons, menu items). Buttons say what happens: "Create reminder", "Save sharing",
  "Hold to delete". No "please", no exclamation marks, no "simply" or "just".
- Name parts of the system by what they are: "the account site", "Silicon Accounts", "the service", "the command
  line". Write numbers and times the way the kit's `lib/format.ts` does ("3 hours ago", "Oct 10, 2026, 14:05").

## 10. Design rules

[DESIGN.md](DESIGN.md) is the full system. In short:

- **Type**: BDO Grotesk 600 for page titles (`clamp(2.25rem, 4.8vw, 3.25rem)`, −0.025em), section titles at 1.125rem 500
  in the text face, body 1rem/1.4, secondary text 0.875rem, labels 0.75rem. Tabular figures for numbers that line up.
- **Spacing**: the 4 px scale (`--space-1` … `--space-24`); 32 to 48 px between sections, 16 to 24 px inside surfaces,
  `--gutter` at the page edge. One `Page` per page.
- **Squircles**: every rounded surface carries `data-sq` and `--sq-r` (`--radius-control` 18 px for controls,
  `--radius-panel` 26 px for groups, `--radius-surface` 34 px for page surfaces, `--radius-pill` for chips); never set
  `border-radius` on a squircled element.
- **Colour**: tokens only (`--background`, `--surface`, `--foreground`, `--text-secondary`, `--text-muted`, `--border`,
  `--accent`, `--accent-ink`, `--primary`, `--success`, `--warning`, `--danger`). Brand blue fills only where you act;
  cards rest on a border, not a shadow; shadows only on floating layers. Every text colour pair is 4.5:1 or more in both
  themes.
- **Density**: controls 36/44/50 px (`--control-height-sm/md/lg`), table rows about 52 px, settings rows 64 px; one
  primary action per surface.
- **Motion**: Silicon UI's tokens (`--duration-*`, `--ease-*`, `motionTokens.spring.*`); things glide and morph rather than
  pop; everything respects reduced motion (the providers set Motion's `reducedMotion: "user"`; CSS transitions sit in
  `@media (prefers-reduced-motion: no-preference)` or are switched off under `reduce`).

## 11. Tests

- Keep `tests/*.test.ts`: they cover the kit's sign-in, sealing, refresh and proxy, and pass unchanged.
- Keep `e2e/accounts.setup.ts`, `e2e/public.spec.ts`, `e2e/session.spec.ts`, `e2e/refresh.spec.ts` and
  `e2e/a11y.spec.ts`; add the app's own journeys the way `demo.spec.ts` did: start from `accountsSession(browser,
  "carbon")` (or `"friend"`, the second Carbon to share with), `signIn()` through the hosted pages, `putSession()` to
  test what happens when the token is about to expire. The stack is shared and allows 30 email codes per network in 10
  minutes: never sign in with a new email per test.
- `pnpm screens` with the app's own `screens.spec.ts`; look at every PNG, light and dark, desktop and phone.

## 12. Before you ship

- [ ] `pnpm typecheck && pnpm lint && pnpm test && pnpm build` pass; `pnpm test:e2e` passes against the local stack.
- [ ] Every redirect URI is registered (step 3); production's `PUBLIC_URL` is https.
- [ ] The environment is set in every deployment; `SESSION_SECRET` is new and only there; `APP_SECRET` is nowhere in
      the repository, the config or the browser bundle (`grep -r sa_app_ .next/static` finds nothing).
- [ ] Profile photos load (their origin is `ACCOUNTS_URL`, Iris, or in `EXTRA_IMG_ORIGINS`).
- [ ] The landing page, `llms.txt` and the metadata say what the app does in its own words; `llms.txt` is replaced by
      the Carbon's own text once they write it.
- [ ] Every page has been looked at in both themes at 1440 and 390 wide, and used with the keyboard alone.
- [ ] Nothing a Carbon or Silicon reads says "AI agent", "human", "user account", "organization", "org", "team",
      Honeycomb or IAM: `grep -rniE "ai agent|human|user account|organi[sz]ation|(^|[^./])\borgs?\b|honeycomb|\biam\b" app components lib`.
