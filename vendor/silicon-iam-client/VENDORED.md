# Vendored local SDK snapshot

This is the normalized `cargo package --allow-dirty --no-verify` archive of `silicon-iam-client` from the coordinated public identifier schema cutover. It is a local working snapshot, not a published crates.io release. See `.cargo_vcs_info.json` for base revision and dirty state.

Archive SHA-256: `9060e3ec524f7e249ff28fb12def8b85a480d753230bd3713eaab852b9eb70c4`.

The normalized package manifest resolves all workspace inheritance. Keep its complete source, tests and license together. Refresh from the owning repository's package output; do not edit this snapshot independently. The parent application uses this copy so standalone checkout and Docker builds use the matching schema without sibling repositories.

Coordinated documentation-only update from IAM commit `05f9e36`: the two Membership description lines in `src/models.rs` now use canonical examples in code spans so warning-free rustdoc succeeds. This patch is mirrored from the owning repository; runtime code is unchanged. The base archive checksum above identifies the original package. Updated `src/models.rs` SHA-256: `07e18b70fbc566230e43bf6990d02455fa289332750e0f1b4dc39fc229142225`.
