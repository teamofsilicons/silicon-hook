# Configure and inspect diagnostic telemetry

Hook collects diagnostic events by default into a private PostgreSQL outbox, `hook_private.telemetry_events`. The worker forwards them through the official `space-station` Rust package to the dedicated [siliconhook table](https://spacestation.teamofsilicons.com/o/tos/tables/siliconhook). CLI, daemon, SDK and browser events all enter the same authenticated Hook pipeline; the Space Station write key stays on worker hosts.

## Turn collection off

- CLI and daemon: `hook config set telemetry off` disables the selected profile. The daemon picks up the preference on its next refresh. `SILICON_HOOK_TELEMETRY=off` overrides collection in that process.
- Rust SDK: use `client.with_telemetry(false)` before login or registration.
- Web: in **Connections & setup**, disable **Share diagnostic events**. The preference is stored in this browser and accompanies HTTP and newly opened WebSocket connections.
- Operators: set `HOOK_TELEMETRY=off` on API and worker processes to disable collection globally. Retention cleanup still runs.

Opt-out stops future diagnostic collection; it does not erase existing events. Security audit logs and API contract usage accounting remain functional service records. Authentication is never replaced by a telemetry preference.

## What is recorded

Each event has a unique `event_id`, a `trace_id`, source, step, outcome, build version and server recording time. Optional fields include an allowlisted operation, elapsed milliseconds, progress count, response status, operating system and architecture. Backend request records use route templates, never concrete URLs. CLI commands and local deliveries carry a trace ID that also accompanies their backend requests. Web analytics records visits to known product sections while signed in.

Sources are `backend`, `worker`, `cli`, `daemon`, `client`, and `web`. Steps describe requests, commands, connection/subscription activity, deliveries, acknowledgments, refreshes, updates, maintenance, page views, interactions or errors. Report and user-input text is not a telemetry field. Unknown fields and arbitrary operation names are rejected.

Credentials, authentication headers, test selectors, webhook contents, destination URLs, query strings, IP addresses, cookies, page content and form input are excluded. Client events carry a server-derived hash of the authenticated organization and actor; clients cannot submit someone else's actor field.

## Storage and delivery behavior

The table has environment row-level security. Production and each sandbox have distinct rows; resetting a sandbox removes its telemetry. Duplicate event IDs in the same environment are ignored. Runtime API roles can insert events but cannot read their payloads. The worker can read records to export them and can update only the export marker. There is no public event-query API; operational inspection requires a privileged database role.

Writes are best-effort: at most 128 writes are in flight per process, each with a 500 ms limit. Client sends also time out after 500 ms and do not change the primary operation's result. Events may be dropped during overload, shutdown or a database outage. The worker deletes local records older than 30 days in batches of at most 1,000 per maintenance cycle. This local retention does not delete already exported Space Station records.

Set `HOOK_TELEMETRY_TABLE_KEY` on the worker and provide a persistent, private `HOOK_TELEMETRY_SPOOL_DIR`. Each export locks at most 100 pending rows, queues them through Space Station and waits up to three seconds for a flush. Failed batches remain pending. A crash between remote acceptance and local marking can produce duplicate records; group by `record.event.event_id` when counting unique events. A separate Space Station daemon may acknowledge durable spooling before the remote service accepts a record; its status is the authority for later rejections. The SDK supplies machine metadata such as hostname, operating system, architecture and resource gauges in its own metadata envelope.

Sandbox events stay local unless `HOOK_TEST_TELEMETRY_KEYS` explicitly maps their UUID to a separate test table key. The production `siliconhook` table and duplicate test destinations are refused for sandboxes. Exported records contain an explicit `environment_id`. Local sandbox resets clear the local outbox; separately exported diagnostic history follows the test table's lifecycle.

An authorized operator can inspect one trace with parameterized SQL:

```sql
SELECT recorded_at, source, step, data
FROM hook_private.telemetry_events
WHERE environment_id = $1 AND trace_id = $2
ORDER BY recorded_at;
```

## Sending a client event

`POST /api/v1/telemetry` requires the usual live IAM bearer and organization. For a sandbox, also supply `X-Hook-Test-App-Secret`. `X-Hook-Telemetry: off` makes the request a no-op. The body limit is 8 KiB; `202` means accepted for best-effort persistence, while `204` means collection is disabled.

```json
{"event_id":"019f405a-48b0-7000-8000-000000000001","trace_id":"019f405a-48b0-7000-8000-000000000002","source":"cli","step":"command","outcome":"succeeded","operation":"login","version":"0.5.0","duration_ms":120,"progress":1,"os":"linux","arch":"x86_64"}
```

Use the SDK's `emit_telemetry` helper for custom hosts. A backend must be upgraded through migration 0008 and runtime grants before enabling these source features.

## Space Station queries

```sql
SELECT record.event.source::String AS source, count() AS events
FROM siliconhook
GROUP BY source
```

See the [Space Station recording documentation](https://spacestation.teamofsilicons.com/docs/rust#recording) for daemon spooling and flush semantics.
