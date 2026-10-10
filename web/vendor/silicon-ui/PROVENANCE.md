# Silicon UI provenance

Installed official source files from https://ui.teamofsilicons.com/r/{name}.json on 2026-10-10. The exact source URLs and SHA-256 hashes are recorded in `silicon-ui-registry.json`. Components live in `components/silicon-ui`; package dependencies were already present. The application focus-return helper is maintained separately in `components/foundation/return-focus.ts`.

Historical third-party notices remain retained for previously derived application styling. The former Arc component tree is removed.

Application compatibility: numeric spacing and panel/surface/pill radius aliases live in styles/tokens.css. Registry components retain their semantic spacing.
Local ConfirmMorph accessibility correction: deliberate keyboard confirmation bypasses the pointer double-click guard; held-key repeat remains ignored.
