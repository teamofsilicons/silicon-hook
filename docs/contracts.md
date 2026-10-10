# API contracts and compatibility

## Negotiate before calling

1. Call unversioned `GET /api/version` with the majors your consumer implements:
   `Silicon-Hook-Supported-API-Versions: v3`.
2. Check that the answer names `service: silicon-hook` and the
   `selected_api_version` you implement.
3. Pin every versioned call to its route major:
   `Silicon-Hook-API-Version: v3` on `/api/v3/...`.

The highest shared, non-sunset major wins. Hook 1.0 implements v3 only.
Unsupported majors return `406 api_version_unsupported`; a pin that disagrees with
the route returns `400 api_version_mismatch`; a sunset major returns
`410 api_version_sunset`. The official client does all of this
([Rust client](client/README.md#call-hook)).

## Compatibility matrix

| Consumer | API | Sign-in | Delivery |
| --- | --- | --- | --- |
| Rust client and CLI 1.x, web console 1.x | v3 | Silicon Accounts access token issued to Hook (`aud` = `hook`) | Ting references with `silicon: {uuid, id}`, when the server delivers through Ting |
| Any HTTP consumer | v3 | the same bearer | the same |
| Clients and CLIs before 1.0 | v1 or v2: retired | the previous sign-in | not served: every management route answers `410 api_version_sunset` |

Provider ingress is not versioned for providers: `/silicon/{silicon}/{key}` and the
older `/api/v1/silicon/...` and `/api/v2/silicon/...` forms all keep working, so
URLs already registered with providers survive the upgrade.

## What v3 changed

v3 is a new major because the sign-in and the identity model changed:

- The bearer is a Silicon Accounts access token issued to Hook, verified locally;
  there is no organization header and no Hook-mediated token exchange.
- Hooks belong to a Silicon keyed by its uuid; responses show accounts as
  `{uuid, id}` and `created_by` adds `kind`.
- New: `GET /silicons`, access grants, allow-lists, the Silicon Accounts updates
  hook, sign-in discovery (`/auth/accounts`) and status (`/auth/status`).
- Ting references carry `silicon: {uuid, id}` and no tenant or environment fields;
  publication adds `delivery_disabled`, `not_queued` and `not_delivered_legacy`.
- Removed: test environments, publisher provisioning, separate Ting approval, the
  v1 WebSocket, relay and polling delivery.

## Version policy

Breaking changes to routes, fields or permission semantics require a new API
major. Additive endpoints and fields may ship within a major; consumers must
accept fields they do not know. Client and CLI packages follow semantic
versioning; internal implementation versions are not API majors.

Consumer tests cover the published wire shapes, the handshake, sign-in, hook
management, history and Ting reference hydration. Run
`cargo test --workspace --all-targets` and the OpenAPI lint before releasing a
contract change.

## Deprecation and automatic sunset

A deprecated major sunsets only after **seven complete days with zero
requests**, measured from the later of its deprecation and its last request. An
active major never sunsets because it is quiet. Requests restart the idle window;
a request after the deadline is refused and cannot revive the major. Deprecated
answers carry a `Deprecation` timestamp and a link to this policy. v1 and v2 are
sunset in Hook 1.0.

State survives restarts in PostgreSQL. No request content, credential, address or
account is collected; this is contract governance, not telemetry.

`GET /api/contracts` lists each major's `status`, deprecation and sunset Unix
timestamps and `delivery_transport`. It does not expose request counters.

## Operator commands

`hook-contract` uses the migration database configuration
(`HOOK_MIGRATOR_DATABASE_URL`):

```sh
hook-contract status v3
hook-contract deprecate v3
hook-contract activate v3
```

`deprecate` is idempotent while already deprecated; `activate` restores service
after an operator resolved compatibility concerns. v1 and v2 stay sunset;
activating them changes nothing the API serves. Neither action is an HTTP
endpoint. See [deployment](deployment.md).
