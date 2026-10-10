# Hook 0.8.0 production verification

Released September 23, 2026 from source `ab28cf575af0bfed6fc0724d197838a41b5efd9a`.
The [machine-readable record](ting-live-0.8.0.json) contains artifact checksums,
platform hashes and the controlled event identifiers. This supplements the
[local integration evidence](ting-e2e-2026-09-23.md).

## Published and deployed

- [GitHub release](https://github.com/teamofsilicons/silicon-hook/releases/tag/v0.8.0),
  `silicon-hook-client` and `silicon-hook-cli` 0.8.0 on crates.io, and the production
  Honeycomb `tos>hook` archive with all six platforms.
- Exact-source [CI](https://github.com/teamofsilicons/silicon-hook/actions/runs/35839273192),
  [six-platform build](https://github.com/teamofsilicons/silicon-hook/actions/runs/35839344847)
  and [deployment build](https://github.com/teamofsilicons/silicon-hook/actions/runs/35839677470)
  all succeeded. macOS ARM64 installation from Honeycomb returned `hook 0.8.0`.
- Native API and worker release `ab28cf575af0` is active. Production and shared-test
  databases have migrations 1–16, with runtime grants reapplied. Both services and
  the upgraded gateway had zero restarts during verification.
- Private encrypted off-host database/configuration backups include quiesced dumps
  from `before-native-20260923T090344Z`. Previous native release and gateway are
  retained. Database migrations are not automatically reversed by binary rollback.
- [Website](https://hook.teamofsilicons.com) and [docs](https://docs.hook.teamofsilicons.com)
  are deployed. Browser inspection confirmed the live frontend. Gateway environment
  and encrypted session storage were preserved. Caddy now forwards both
  `/auth/callback` and its script/completion subroutes to the gateway; the production
  proxy configuration was validated before reload.
- Ting revision 3 is effective. Hook's Ting subscription, send, status and scoped
  receiver permissions passed official review and activation. The production Hook
  notification type and dedicated `hook-delivery:tos` publisher are configured.

## Live acceptance

A dedicated controlled Silicon registered its own subscription and explicitly
opted into required delivery. A signed provider request containing 300,068 bytes
was stored by Hook, published by its separate server-owned publisher family, and
received over the real production Ting WebSocket. The released CLI hydrated the
exact original bytes. Every reference identity/sequence/timestamp matched the
stored event, and publication reported `accepted_by_ting` with the same Ting ID.
A delivery ACK left the notification unread; a read ACK marked it read.

The production browser gateway also completed a state-bound paired login using
an official IAM atomic Hook/Ting SLT batch, returned the current organization
intersection, and revoked its own pair on logout. This was an HTTP session-flow
check; the frontend itself was separately inspected in Chrome.

The owned provider was soft-deleted, receiver removed, recipient grant revoked
(clearing its opt-in), and smoke Hook/Ting sessions revoked. The dedicated backend
publisher family remains configured. Its service identity is stored privately
outside the temporary verification directory. No test event was sent to another
person's recipient.

## Boundaries

Each additional organization needs its own dedicated publisher. Recipients must
explicitly opt into required automation delivery; deployment does not enable that
setting for existing users. Legacy v1 clients retain their deprecation/idle sunset
contract, and applications must adopt the v2 receiving integration.

The uncertain scoped-issuance cleanup case remains fail-closed as
`receiver_cleanup_pending`; see [remaining integration constraints](../ting-integration-issues.md).
Windows x64 and ARM64 compiled successfully in CI; Windows runtime ACL behavior
was not executed in this release verification. The public version endpoint reports
build `0.8.0` and commit `unknown`; the deployed bundle manifest and gateway image
label verify the full source revision above.
