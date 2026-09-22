# Session reliability release — 22 September 2026

Final CLI release: **0.7.3**. The production backend and browser deployment revisions below remain unchanged by this CLI follow-up.

Hook client and CLI 0.7.2 are published. Native backend and browser gateway fixes are deployed from `dc9c2e39dddc21e629e26c3f57b8d0f137625b87`, tag `v0.7.2`. The backend package version remains 0.7.0; source revision and immutable release identity identify this deployment.

## Deployment

On `i-04398b332e0a3c1b7`, `/opt/silicon-hook/current` selects `/opt/silicon-hook/releases/dc9c2e39dddc`. The ARM64 native archive SHA-256 is:

`ec1fbb77b713dd2147c41364be66ed075f26fa2b7012bd73ff31267fe2cf1254`

The exact tagged source was compiled using Rust 1.98, cargo-zigbuild 0.23.4 and Zig 0.15.2, targeting glibc 2.28. Every deployed native file was verified against its manifest. API and worker units are active with zero restarts. The installer verified prerequisites, backed up both databases and configuration before and after pausing writers, reapplied existing migrations/grants, and retained the previous release. Backup: `/opt/silicon-hook/backups/before-native-20260921T223512Z`, also copied to the private artifacts bucket.

The gateway runs immutable image ID:

`sha256:e7de674d3390ec9700da17a9b74feb5b6a2fe7deafcc8c9509d5df8df7b30514`

Its CI Docker archive SHA-256 is `88cf80c74dd60d3c0d5e2fc462e342b4b870a222eae4cee3cfe01e8b9d332b74`, retained at `releases/session-dc9c2e39dddc/gateway.tar` in `silicon-hook-standalone-artifacts-lxpfsbc0jpuk`. The existing session mount, private key and environment hashes were retained. Session directory mode is 0700. The previous container remains stopped with automatic restart disabled. `gateway-image.json` records the active immutable image; the existing production tag selects that image for the historical installer. Static Vercel frontend source was unchanged.

Initial gateway switches rolled back because a loopback probe omitted or used the wrong Host header. The valid host is `backend.hook.teamofsilicons.com`; a corrected probe was verified against the old gateway before the successful switch. No application change was needed for this deployment probe issue.

## Verification

- Public backend readiness: 200. Gateway anonymous session request with the required Origin and `X-Hook-Frontend: 1` headers: 200. Requests without that frontend header remain rejected.
- [Full source CI](https://github.com/teamofsilicons/silicon-hook/actions/runs/35662254673) and [six-platform CLI build/package](https://github.com/teamofsilicons/silicon-hook/actions/runs/35662254703) passed. A transient artifact-upload 403 required retry; compilation succeeded.
- The new [manual deployment workflow](https://github.com/teamofsilicons/silicon-hook/actions/runs/35663966511) passed after matching the verified Zig/cargo-zigbuild versions. [Final workflow-source CI](https://github.com/teamofsilicons/silicon-hook/actions/runs/35663964115) passed.
- Maharaj's existing identity remained authenticated and its Hook listing succeeded. Supported daemon stop/start activated 0.7.2 with the same identity count; `silicon ping chef:bricks` returned online. No logout, disconnect or message send was used.

## Publication

[GitHub release 0.7.2](https://github.com/teamofsilicons/silicon-hook/releases/tag/v0.7.2) is public. Honeycomb accepted `tos>hook` 0.7.2 as release `38a05824-2c69-41ac-8289-da62102e1fdd`. Archive SHA-256: `d8604b58e81494a13258147db46f9ed652a933cb633c1b2fcf4b2c14ee7fb3ac`. All six platform binaries and the manifest were validated; GitHub asset sizes and digests match the locally verified archive. A fresh anonymous default-latest installation resolved 0.7.2 and passed native macOS ARM64 version/help checks.

Registry packages `silicon-hook-client`, `silicon-hook-cli` 0.7.2 were downloaded from crates.io and checked for the exact clean tagged source revision.

Maharaj's CLI and daemon now run 0.7.2. The old daemon was PID 19474; the activated daemon was PID 90053. The Silicon interpreter was not restarted.

## Early access rejection follow-up

CLI 0.7.3, source `cd91afca912409dd8345af6ba37a61beb7f6f80b`, recovers access rejected before its saved expiry with one forced refresh and one status retry. Only live inactive/401 responses trigger this recovery; permission denials and provider outages remain errors and retain saved credentials. Successors are saved before use.

Ordinary authenticated commands perform read-only session validation under the store lock before dispatch. Mutation commands execute once after successful validation, preserving their original payload and idempotency key.

Residual daemon behavior: normal expiry refresh is automatic. An unexpected early subscription rejection is repaired by an authenticated CLI command or `hook login status`; the daemon then reloads saved credentials within five seconds. It does not independently force renewal on ambiguous subscription rejection notices. The separate IAM family-isolation fix targets the observed sibling-logout cause.

Targeted regressions and Clippy with warnings denied passed. Final Maharaj activation is pending because reading its retained session file blocks at the filesystem level. A bounded Hook activation attempt stopped at its first read-only daemon-status command, before package update or daemon stop; existing daemons were left running. No session was deleted, rewritten, logged out or replaced.

[Final CLI full CI](https://github.com/teamofsilicons/silicon-hook/actions/runs/35666141183) passed. All six native builds in [release CI](https://github.com/teamofsilicons/silicon-hook/actions/runs/35666141280) passed at the tagged source revision. The downloaded immutable native artifacts were checked for all six operating-system/architecture formats and packaged locally using the clean tagged packaging script and Honeycomb; this avoided rebuilding the packaging CLI inside CI. The archive contains only the manifest and six native executables.

[GitHub 0.7.3](https://github.com/teamofsilicons/silicon-hook/releases/tag/v0.7.3) is public; every release asset size and SHA-256 matches its locally verified file. Honeycomb accepted `tos>hook` 0.7.3 in the production channel, release `c968f2b5-dd7d-4416-bd5b-67f1288dbb09`. Archive SHA-256:

`df13e02d369080b28f11fce16150ff27aae0819d0bce394b5a160901cb2ba420`

A fresh anonymous default-latest install resolved 0.7.3 and passed native macOS ARM64 version/help checks. `HONEYCOMB_NO_SERVICE=1` prevented installing a background service in the disposable verification home.

New registry archives were downloaded independently and verified against the clean tagged source:

- `silicon-hook-cli` 0.7.3: SHA-256 `1e1db3bde6c540661d38891b56ca8fd087e7af62e45726e7179cdf6525186fe8`.

Machine-readable final CLI release evidence: `/tmp/session-deploy-dhr-20260922/hook-final-release-proof.json`. The retained Maharaj package rollout is coordinated separately so its existing session and package homes stay intact.
