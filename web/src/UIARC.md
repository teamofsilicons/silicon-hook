# UIArc component provenance

`arc.css` adapts actual free UIArc Button, Input, Card and Badge CSS to the existing Solid/native component markup. The public registry is pinned at commit `792791245398f1009a0054544a02fb4f3455df07`; exact upstream files, official URLs and SHA-256 digests are in `UIARC-SOURCES.json`. Source: https://uiarc.dev/ and https://github.com/kuratlielia/arc-library. The original MIT copyright and license are preserved in `UIARC-LICENSE` and the bundled public `/uiarc-license.txt`.

Base and state rules are copied from the component CSS modules, with selectors mapped to existing component classes and foundation tokens namespaced to `--arc-*`. Blue accent, existing app typography, compact radii and 44px touch controls adapt the foundation to this workspace. Cards retain visible overflow where application menus require it. React/Motion quick-look and text morphing are omitted; existing native dialogs, handlers, disabled states and form submission semantics remain intact. Visible keyboard focus deliberately replaces the upstream foundation's focus suppression. Reduced-motion preferences disable transitions. No Pro source or new runtime dependency is used.

`workspace-polish.css` contains app-specific layout and typography refinements, separate from the component port. IAM context selection and feature-consent flows are unchanged.
