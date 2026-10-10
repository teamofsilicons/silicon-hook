# Parallel Accounts production release

The user narrowed the production rollout on 2026-10-10 to the apps themselves. Existing IAM Silicons and custody are not imported, linked, re-enrolled or updated through Honeycomb. This plan supersedes the in-place production steps in `cutover.md`; that document remains historical reference for the earlier migration design.

- Accounts API origin: `https://api.hook.teamofsilicons.com`.
- Existing IAM API origin: `https://backend.hook.teamofsilicons.com`; its service, database, credentials, data keys and client traffic remain unchanged.
- New website: `https://hook.teamofsilicons.com`, using the new Accounts BFF and API origin.
- New package version: `1.0.0`; its CLI/SDK defaults target the new API origin. No existing IAM installation is automatically changed by this operation.
- New database: `hook_accounts`. New role names: `hook_accounts_migrator / hook_accounts_api / hook_accounts_worker`. Never point the Accounts binary or installer at the IAM database or reuse a role whose credentials an IAM service uses.

## Deployment boundary

Separate native units silicon-hook-accounts-api/worker on the existing host; API loopback 8081 and /opt/silicon-hook-accounts release/config/state paths.

Apply migrations through 0021 to the new empty store. Existing provider URLs, ingress namespaces, secrets, pending deliveries and IAM units stay live. The new Accounts store contains only Accounts-created data. Old conversations, devices, todos and hooks do not appear in the new account interface without a separately authorized identity/data migration; they remain accessible to existing IAM clients and recoverable from their original stores and backups.

Accounts registrations are already active with the public website callback and device/public-client flows. First-use webhook signing secrets and subscriptions must be configured only for the new API. Existing IAM webhooks and delivery workers remain untouched. The new website uses a distinct session secret.

DNS is centrally managed by the rollout coordinator. Current authoritative DNS is Namecheap, not Route53. Add the new API hostname without replacing the old backend hostname or any mail records. Preserve the previous Vercel deployment for website rollback.

## Verification and rollback

Before exposure, prove the new database name and role, migrate it, verify health and anonymous auth refusal, then sign in with an existing Accounts identity. Create and read a resource in the new app; confirm the corresponding IAM store has not changed. Check both API origins independently. Native Extend acceptance includes new-device pairing, screenshot/file transfer and the real Briefcase integration, while an existing IAM device remains connected to its existing service.

Rollback changes only the new deployment, new DNS alias and website promotion. No restore or destructive changes are needed on the still-running IAM store. Keep the new Accounts store and any data written there for diagnosis; do not drop it during rollback.

## Build and inventory evidence

The deployment runs from isolated migration branches and draft PRs; no production service or data migration has run. Read-only infrastructure, database provenance, Accounts configuration before-states and backup availability are recorded privately under the workspace `.migration/live/`. Optimized release builds run in GitHub Actions, and package publication remains coordinated with the platform rollout. The earlier local archives were development builds and are not the production artifacts.
