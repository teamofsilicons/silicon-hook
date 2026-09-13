# Hook Space Windows

Four published Space Windows read `tos.siliconhook`. `windows.json` records their
IDs, URLs, versions and access lists. Access matches the telemetry table: `@saket`.

| Window | Contents |
| --- | --- |
| Hook Overview | Event volume, failures, source freshness, arrival delay and worker maintenance |
| Hook Requests | Application traffic, separate 4xx/5xx counts, route latency and recent requests |
| Hook Deliveries | Client delivery attempts, retries, acknowledgements and lifecycle signals |
| Hook Web & CLI | Browser pages, completed commands, errors and observed client versions |

Opening a window starts Space Station's live runtime. The server retains the last
snapshot when no runtime is connected. No Hook deployment or permanent local
runner is needed. Empty delivery/client sections will populate when updated
clients report activity; empty telemetry does not prove absence of deliveries.

## Metric definitions

- Each query covers production events recorded in the last 24 hours. Synthetic
  `verification` events are excluded. Export retries are deduplicated by Hook's
  `event.event_id`, not Space Station's transport record ID.
- Requests exclude health/readiness and `/api/version`, `/api/v1/version` probes.
  Overview includes these probes. The overall P95 uses all included requests,
  independently of the bounded route table. 4xx includes expected refusals.
- Arrival delay measures original event creation to first Space Station receipt.
  Source freshness is the last original event time. Neither metric proves service
  availability or measures the PostgreSQL outbox backlog.
- Worker signals count maintenance runs, not jobs or webhook deliveries. The
  failed-tasks column is the maximum reported failed-task count in a run.
- Delivery metrics count reported attempts/signals, not unique webhook events.
  Browser views are not unique visitors. Missing latency/status fields stay null.
- Queries and tables are bounded; window JSON stores rows once and trims large
  arrays below 60 KB. Filters affect displayed rows only. Aggregates remain based
  on the full query range. Hourly chart endpoints are partial buckets.
- `summary` returns the current cards. `trace_request` validates a UUID and reads
  at most 40 matching trace events. Cross-source correlation requires callers to
  propagate the same trace ID; it is not guaranteed for unrelated browser/API work.
- Snapshots refresh when records arrive. A quiet or disconnected window retains
  the last computed range, with its update timestamp and runtime status displayed.

## Rebuild and publish

Edit `build.py` and run `python3 observability/spacestation/build.py`.
`renderer.html` is shared and uses pinned Vue/D3 CDNs inside Space Station's
sandbox. Queries and code contain no credentials or production event fixtures.

Publish to the existing IDs through
`POST /api/orgs/tos/windows/{id}/versions`, with `name`, `processor` and `renderer`.
Use a Space Station session or organization access token kept outside the repo
and command arguments. The recording key cannot publish or query windows.
Verify every SQL query, processor initialization and subscription replay before
publishing; then compare saved code, inspect live state and open every renderer.

## Verification

On 2026-09-13 all 14 queries executed against live production data. All four
processors initialized, replayed snapshots consistently, rejected invalid trace
UUIDs, and produced state below 10 KB. Published code matched local sources.

The official runtime produced live state for all four windows, and the summary
tools and a production trace lookup succeeded. All four renderers were inspected
in the browser. Version `v1.1` corrects the freshness indicator tooltip.
