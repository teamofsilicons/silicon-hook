# Arc UI provenance

Source index: https://uiarc.dev/llms.txt
Registry: https://uiarc.dev/r/registry.json (`@uiarc` in `components.json`)
License: https://uiarc.dev/license. Free components are MIT, copyright 2026 Elia Kuratli; the notice is kept in
`LICENSE` next to this file, and it must travel with every copy of `components/arc/`.

`components/arc/` is the Silicon developer site's vendored set (`silicon-accounts/developer/components/arc`, copied on
2026-10-10), which was installed with the shadcn CLI from the `@uiarc` registry: every Free item, with the Silicon
local edits recorded in `silicon-accounts/web/README.md` (Arc UI, Local edits) and `silicon-accounts/developer/README.md`
(squircles, brand-blue primary actions, keyboard focus as fills and edges, layers that return focus, Escape order).
Checked against the registry on 2026-10-10: all 60 vendored components and blocks are Free (MIT).

Only Free components belong in this kit. Arc's Pro license allows using Pro components in your own product but not
redistributing their source as a library, kit or template, which is what this repository is. An app that buys Pro
components adds them to its own `web/` after copying the kit, never to the kit.
