# Coordinated IAM 5 release

This release separates feature OBO consent from ordinary login, refreshes the
vendored IAM client to the exact 5.0.0 release commit, and retires implicit
login-derived delegated authority. Existing users keep their ordinary sessions
and authorize delegated features when needed.

IAM client source: `f1e9c4768029aacabe337ca41be52e05023d1631`.
See `vendor/silicon-iam-client/VENDORED.md` for package provenance.

Production rollout is coordinated with IAM 5 and the receiving providers. Build
artifacts are candidates until integration checks and database backups pass.

The web console offers separate Carbon and Silicon popups and full-page choices
that stay available while a popup is pending. Both Hook and its existing paired
Ting ordinary session must return the requested actor kind and the same identity
and organization before installation. No provider source or feature consent is
changed by this login flow.

Encrypted callback attempts retain stable exchange keys and the completed local
context ID across restart. The opener validates its exact context against both
live services before selection. Nonce-bound cancellation and workspace changes
invalidate late callbacks. Retryable failures preserve the pending attempt;
full-page callback fragments are redacted only after completion succeeds.
