# Contract lifecycle and compatibility

## Integrate safely

1. Call unversioned `GET /api/version` with `Silicon-Hook-Supported-API-Versions: v1`.
2. Require `service: silicon-hook` and a shared `selected_api_version`.
3. Pin every versioned call with `Silicon-Hook-API-Version: v1`.
4. Handle additive JSON fields. Deduplicate deliveries and reuse mutation keys when retrying.
5. Read `GET /api/contracts` for lifecycle status and migration guidance. The official client performs negotiation before versioned operations.

The highest shared implemented major wins. Unsupported majors return `406 api_version_unsupported`; route/header disagreement returns `400 api_version_mismatch`. A sunset major returns `410 api_version_sunset`. Failed test selection never changes the request to production.

## Compatibility matrix

| Consumer | Backend API | Direct WebSocket | Shared relay | Testing |
| --- | --- | --- | --- | --- |
| Client/CLI through 0.4 | v1 | protocol 1 | unavailable | legacy Hook root-key selection |
| Updated client/CLI 0.5 | v1 | protocol 1 | relay protocol 1 | IAM app-secret selection; legacy root APIs retained |
| Updated browser gateway | v1 | protocol 1 | daemon owns its own connection | app-secret selector and separate encrypted sessions |
| Generic HTTP consumer | v1 | optional | optional | `X-Hook-Test-App-Secret` plus actor bearer |

Shared relay and app-secret selection require the updated backend. Upgrade the backend before the new CLI/browser. Existing direct WebSocket and root-key integrations remain available. The local receiver envelope adds a top-level `metadata` object while preserving the existing `type` and `data` fields. Consumers must accept additive fields; strict two-field validators must be updated.

## Version policy

Breaking HTTP route/field/permission semantics require a new API major and a compatibility adapter while the prior major remains supported. Additive endpoints and optional fields remain in v1. Direct and multiplexed WebSocket protocols have independently explicit version 1 ready frames. Client and CLI package versions follow semantic versioning; internal implementation versions are not API majors.

Consumer regression tests cover published wire shapes, SLT-only production login, sandbox selection, local delivery, heartbeat, replay, acknowledgment and legacy negotiation. Run `cargo test --workspace --all-targets` and OpenAPI validation before releasing a contract change.

## Deprecation and automatic sunset

A version first enters `deprecated` under operator control. It sunsets only after **seven complete days with zero requests**, measured from the later of deprecation and last activity. An active version never sunsets just because it is quiet. New admitted requests restart the idle window. Live authorized WebSocket sessions count as activity during authority revalidation, so a long-lived consumer is not retired underneath its connection.

State survives restarts in PostgreSQL. Each environment has separate lifecycle counters; no request content, credential, address or actor is collected. This is functional contract governance and does not use Space Station. Test requests never keep a production version alive.

The worker evaluates retirement periodically; request admission and catalog reads also evaluate it atomically. A request arriving after the idle deadline is rejected and cannot revive the retired version. Deprecated responses include a `Deprecation` timestamp and a link to this policy. A fixed future sunset date is not advertised while activity can extend the window.

## Operator commands

Build `hook-contract` from the backend workspace. It uses the privileged migration database configuration:

```sh
hook-contract status v1
hook-contract deprecate v1
hook-contract activate v1
# Scope an operation to one sandbox using HOOK_TEST_DATABASE_URL:
hook-contract status v1 <sandbox-uuid>
```

`deprecate` is idempotent while already deprecated. `activate` explicitly restores service after an operator has resolved compatibility concerns. Neither action is an end-user or root-key HTTP endpoint. Validate migration readiness and runtime grants before deployment; see [deployment](deployment.md).
