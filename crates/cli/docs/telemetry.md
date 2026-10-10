# Configure and inspect diagnostic telemetry

Hook collects diagnostic events by default into a private PostgreSQL outbox,
`hook_private.telemetry_events`. The worker forwards them through the official
`space-station` Rust package to the dedicated
[siliconhook table](https://spacestation.teamofsilicons.com/o/tos/tables/siliconhook).
CLI, SDK and web events all enter the same authenticated Hook pipeline; the Space
Station write key stays on worker hosts.

## Turn collection off

- CLI: `hook config set telemetry off` for the profile; `SILICON_HOOK_TELEMETRY=off`
  for one process.
- Rust SDK: `client.with_telemetry(false)`.
- Web: turn off diagnostic events in the console's settings (stored in the
  browser).
- Operators: `HOOK_TELEMETRY=off` on the API and worker turns collection off
  everywhere. Retention cleanup still runs.

Opting out stops future collection; it does not erase existing events. Security
audit logs and API contract accounting are service records, not telemetry. A
telemetry preference never affects authentication.

## What is recorded

Each event has a unique `event_id`, a `trace_id`, source, step, outcome, build
version and server recording time. Optional fields: an allow-listed operation,
elapsed milliseconds, progress, response status, operating system and
architecture. Backend request records use route templates, never concrete URLs.
A CLI command's trace id also accompanies its backend requests.

Sources are `backend`, `worker`, `cli`, `client` and `web`. The CLI sends one
event per command (its top-level name, outcome and duration), only while signed
in. Report text and user input are never telemetry fields; unknown fields and
arbitrary operation names are refused.

Credentials, authentication headers, webhook contents, destination URLs, query
strings, IP addresses, cookies, page content and form input are excluded. Client
events carry a server-derived hash of the authenticated account's uuid; clients
cannot name another account.

## Storage and delivery behaviour

Runtime API roles can insert events but cannot read them; the worker reads them
to export and updates only the export marker. There is no public query API.
Duplicate event ids are ignored.

Writes are best effort: at most 128 in flight per process, each limited to
500 ms. Client sends also give up after 500 ms and never change the command's
result. Events may be dropped during overload, shutdown or a database outage. The
worker deletes local records older than 30 days, at most 1,000 per maintenance
cycle; exported Space Station records are not affected.

Set `HOOK_TELEMETRY_TABLE_KEY` on the worker and give it a persistent, private
`HOOK_TELEMETRY_SPOOL_DIR`. Each export locks at most 100 pending rows, queues
them through Space Station and waits up to three seconds for a flush; failed
batches stay pending. A crash between remote acceptance and local marking can
duplicate records: count unique events by `record.event.event_id`.

An operator can inspect one trace:

```sql
SELECT recorded_at, source, step, data
FROM hook_private.telemetry_events
WHERE environment_id = '00000000-0000-0000-0000-000000000000' AND trace_id = $1
ORDER BY recorded_at;
```

## Sending a client event

`POST /api/v3/telemetry` takes the usual bearer token. `X-Hook-Telemetry: off`
makes it a no-op. The body limit is 8 KiB; `202` means accepted for best-effort
storage, `204` means collection is off.

```json
{"event_id":"019f405a-48b0-7000-8000-000000000001","trace_id":"019f405a-48b0-7000-8000-000000000002","source":"cli","step":"command","outcome":"succeeded","operation":"list","version":"1.0.0","duration_ms":120,"progress":1,"os":"linux","arch":"x86_64"}
```

Custom hosts use the SDK's `emit_telemetry`.

## Space Station queries

```sql
SELECT record.event.source::String AS source, count() AS events
FROM siliconhook
GROUP BY source
```

See the [Space Station recording documentation](https://spacestation.teamofsilicons.com/docs/rust#recording)
for spooling and flush semantics.
