# Hook implementation and verification

The September 13 `UNDERSTANDING.md` update is implemented in this working tree. The human-owned requirements file was not edited.

- IAM 1.8 application-secret sandbox selection, empty isolated storage, online lifecycle validation, and separate browser/CLI identities.
- One prewarmed daemon WebSocket with independently authorized logical subscriptions and ACK cursors.
- Receiver metadata, optional HMAC signing and ISI, and explicit sandbox destination controls.
- Durable contract usage, deprecation/sunset management and compatibility documentation.
- Configurable telemetry with a private PostgreSQL outbox and the dedicated Space Station `tos/siliconhook` table; a live synthetic delivery passed.
- CLI configuration/help, hourly daemon updates, source installer, explicit bug reports and Postmark notification workflow.
- Published docs at https://docs.hook.teamofsilicons.com.

Validation and the exact release boundary are in [the verification guide](docs/verification/current.md). The API, worker, browser gateway and frontend are deployed; both databases are migrated through version 8. Client/CLI 0.5.0 are published on crates.io. Production telemetry export is verified. The Postmark workflow is configured with its server secret and existing verified sender.
