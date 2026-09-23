# Public identifier cutover

Hook uses `si:assistant`, `c:alice` and bare application IDs (`hook`, `ting`). New ingress URLs are `/silicon/si:assistant/<existing-endpoint-key>`. Actor classification uses the explicit `si:`/`c:` prefix. Organization authority comes from the selected IAM directory/snapshot and the Silicon resource's `org_id`.

Apply IAM's collision-checked cutover first, with all service writers stopped and backups for the production/shared sandbox database. Drain Hook's unaccepted, unexpired Ting outbox first: migration 0017 refuses to rewrite the exact body associated with a previous proof and idempotency key.

Migration 0017 converts enumerated actor/Silicon references, delivery cursors, management replay scopes, recipient subscriptions, routing tombstones and testing creators. It rejects many-to-one actor mappings within a data plane. Hook/event/environment UUIDs, endpoint keys, stream sequences, ciphertext, exact request bodies, request hashes, receipts and timestamps are retained. The original FK definitions, user triggers and RLS flags are restored in the same transaction. Signing-secret AAD uses the unchanged hook UUID.

Set `HOOK_IAM_APP_ID=hook`, replace OBO scope audiences with bare app IDs, and update each upstream webhook registration and IAM's default Silicon webhook URL to the new URL. The old URL is not a new alias and must not be guessed from a handle. Refresh clients' IAM session metadata and explicitly select `--org` if the session does not specify one: public Silicon IDs cannot select an organization.

Validate ingress signature verification, event history, receipt replay, Carbon observer subscriptions, Silicon self-access, cross-org denial and each sandbox generation. Existing exact replay bodies and already accepted Ting records remain historical bytes. Rollback restores the whole coordinated database/configuration backup with old binaries; do not start old writers on migrated data.

For the local Ting integration fixture, build current IAM as `silicon-iam:id-schema` or set `HOOK_E2E_IAM_IMAGE` to a schema-compatible image. The old pinned release image cannot exercise these identifiers. Rebuild the matching Ting dependency before an end-to-end run.

The matching IAM SDK 4.0.0 source is vendored under `vendor/silicon-iam-client`, with normalized Cargo metadata and local snapshot provenance. Standalone and Docker builds use this source. This change does not publish a new SDK release.

Ting is an external coordinated dependency. The local checkout does not contain its server source: deploy a schema-compatible Ting service and migrate its state before reopening delivery. Hook uses its own HTTP adapter; it does not depend on a Rust Ting SDK.
