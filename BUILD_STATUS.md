# Hook implementation and verification

The September 16 Honeycomb lifecycle and CLI distribution changes are implemented locally. The human-owned requirements file was not edited.

- IAM 1.8 application-secret sandbox selection, empty isolated storage, online lifecycle validation, and separate browser/CLI identities.
- One prewarmed daemon WebSocket with independently authorized logical subscriptions and ACK cursors.
- Receiver metadata, optional HMAC signing and ISI, and explicit sandbox destination controls.
- Durable contract usage, deprecation/sunset management and compatibility documentation.
- Configurable telemetry with a private PostgreSQL outbox and the dedicated Space Station `tos/siliconhook` table; a live synthetic delivery passed.
- Honeycomb-managed CLI installation and updates, one six-platform prebuilt release workflow, and a stateless Rust dependency.
- Authenticated Honeycomb lifecycle operations, durable receipts, transactional cleanup, stale-write/delivery fences and retention activity reporting.
- Published docs at https://docs.hook.teamofsilicons.com.

The September 16 changes are not deployed or published; the six-platform `tos>hook` 0.6.0 archive is built locally and passes Honeycomb validation. Linux and macOS smoke tests pass; Windows executables have architecture/import validation only. Earlier September 13 production status follows. Validation and the exact release boundary are in [the verification guide](docs/verification/current.md). The API, worker, browser gateway and frontend are deployed; both databases are migrated through version 8. Client/CLI 0.5.0 are published on crates.io. Production telemetry export is verified. The Postmark workflow is configured with its server secret and existing verified sender.
