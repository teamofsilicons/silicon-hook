# Silicon web kit

The template a Silicon app's web frontend is built from: Next.js 16 App Router, React 19, TypeScript strict, pnpm, Silicon UI in `components/silicon-ui/`, TanStack Query in `lib/client/`. `README.md` is the guide (the BFF, the session, the proxy,
the environment); `ADOPTING.md` is the checklist for an app; `DESIGN.md` is the design system. Read the bundled Next
docs in `node_modules/next/dist/docs/` before relying on memory.

- `lib/app.config.ts` is the one file an app edits for its name, mark, navigation, links and landing page. It is bundled
  into the browser: no secrets.
- The browser never holds a token: pages call the service through `/api/*` (`api` in `lib/client/api.ts`), Server
  Components through `apiFetch()` / `tryApiFetch()` (`lib/server/rsc.ts`).
- Words: Carbons and Silicons; never "AI agent", "human", "user account", "organization", "org", "team" for a group of
  accounts, Honeycomb or IAM. Errors say what happened, why, and what to do.
- Every rounded surface is a squircle: `data-sq` plus `--sq-r` / `--sq-fill` / `--sq-stroke`, never `border-radius`.
- Focus shows as fills and edges, never rings; every change respects reduced motion.
- Before finishing: `pnpm typecheck && pnpm lint && pnpm test && pnpm build`, and `pnpm test:e2e` against the local
  Accounts stack.
