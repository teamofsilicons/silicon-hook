# Hook implementation and verification

Hook 0.7.0 is published and deployed. Public events and recipient deliveries no longer include `summary`; the frontend and published OpenAPI match. The DM-style WebSocket contract in `understanding/api.yaml` remains a design document. [Release evidence](docs/verification/summary-removal-0.7.0.json) records tests, hashes, backups, deployments and validation limits. Update existing CLI daemons to 0.7.0 and restart them.

The September 16 Honeycomb lifecycle and CLI distribution changes are implemented and deployed. The human-owned requirements file was not edited.

- IAM 1.8 application-secret sandbox selection, empty isolated storage, online lifecycle validation, and separate browser/CLI identities.
- One prewarmed daemon WebSocket with independently authorized logical subscriptions and ACK cursors.
- Receiver metadata, optional HMAC signing and ISI, and explicit sandbox destination controls.
- Durable contract usage, deprecation/sunset management and compatibility documentation.
- Configurable telemetry with a private PostgreSQL outbox and the dedicated Space Station `tos/siliconhook` table; a live synthetic delivery passed.
- Honeycomb-managed CLI installation and updates, one six-platform prebuilt release workflow, and a stateless Rust dependency.
- Authenticated Honeycomb lifecycle operations, durable receipts, transactional cleanup, stale-write/delivery fences and retention activity reporting.
- Published docs at https://docs.hook.teamofsilicons.com.

The September 16 backend changes were deployed on September 17 as native Linux ARM64 API and worker binaries under systemd, release `2c3a41118ad4`. Both databases now have migrations 1–9. Public health, readiness, version and IAM discovery checks pass; both services are enabled, running as `silicon-hook`, with zero restarts. Previous API/worker containers are stopped with restart disabled. PostgreSQL, Caddy and the browser gateway remain in Docker.

The six-platform `tos>hook` app is public, with both publication reviews approved. CLI 0.6.1 fixes unscoped Silicon status and passes anonymous installation and a live before/after regression using an isolated synthetic revoked session. The exact reported user session has not been tested. Linux and macOS smoke tests pass; Windows executables have architecture/import validation only. The earlier client/CLI 0.5.0 publication on crates.io is separate from Honeycomb distribution.

CLI and client 0.7.1 accept plain HTTP webhook recipients on any `*.localhost` name, which `silicon connect` uses for `http://<id>.localhost`; 0.7.0 rejected them and failed while registering the `tos>hook` webhook. The six-platform archive was built by the tag-triggered release workflow, validated, uploaded to Honeycomb, installed anonymously, published to crates.io and verified with a live `silicon connect`. See [the 0.7.1 record](docs/verification/localhost-recipients-0.7.1.json).

Database/configuration backups, including quiesced dumps before migration, are stored in the encrypted private bucket. See [native deployment](deploy/native/README.md) and [verification evidence](docs/verification/current.md).
