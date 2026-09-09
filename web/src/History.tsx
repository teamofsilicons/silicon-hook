import { createSignal, For, Show } from "solid-js";
import {
  api,
  scoped,
  query,
  download,
  type Context,
  type Page,
  type Event,
  type Hook,
} from "./api";
import { load } from "./resource";
import { Button, Empty, ErrorBox, EventDetail, EventTable, Field } from "./ui";
export default function History(p: { ctx: Context; blocked?: boolean }) {
  const [hook, setHook] = createSignal("");
  const [limit, setLimit] = createSignal(100);
  const [cursors, setCursors] = createSignal<string[]>([]);
  const [selected, setSelected] = createSignal<Event>();
  const hooks = load(
    () => p.ctx,
    () => api<Page<Hook>>(p.ctx, scoped(p.ctx, "/hooks?include_deleted=true")),
  );
  const data = load(
    () => [p.ctx, hook(), limit(), cursors().at(-1)],
    () =>
      api<Page<Event>>(
        p.ctx,
        scoped(
          p.ctx,
          (hook() ? "/hooks/" + hook() : "") +
            (p.blocked ? "/blocked-requests" : "/events"),
        ) + query({ limit: limit(), cursor: cursors().at(-1) }),
      ),
  );
  const reset = () => setCursors([]);
  return (
    <>
      <div class="page-heading">
        <div>
          <p class="eyebrow">REQUEST HISTORY</p>
          <h1>{p.blocked ? "Blocked requests" : "Events"}</h1>
          <p class="muted">
            {p.blocked
              ? "Withheld requests and the reasons verification failed."
              : "The complete requests your providers sent, newest first."}
          </p>
        </div>
        <Button
          disabled={!data.data()?.items.length}
          onClick={() =>
            download(
              "hook-" + (p.blocked ? "blocked" : "events") + ".json",
              JSON.stringify(data.data(), null, 2),
            )
          }
        >
          Export page ↓
        </Button>
      </div>
      <div class="notice subtle">
        Retained for 14 days.{" "}
        {p.blocked
          ? "20 unverified requests block the source IP for 24 hours."
          : "Reading history does not acknowledge delivery."}
      </div>
      <div class="panel">
        <div class="toolbar filters">
          <Field label="Connection">
            <select
              value={hook()}
              onChange={(e) => {
                setHook(e.currentTarget.value);
                reset();
              }}
            >
              <option value="">All connections</option>
              <For each={hooks.data()?.items || []}>
                {(h) => <option value={h.id}>{h.name}</option>}
              </For>
            </select>
          </Field>
          <Field label="Page size">
            <select
              value={limit()}
              onChange={(e) => {
                setLimit(Number(e.currentTarget.value));
                reset();
              }}
            >
              <For each={[25, 100, 1000, 10000]}>
                {(n) => <option value={n}>{n.toLocaleString()}</option>}
              </For>
            </select>
          </Field>
          <Button disabled={data.loading()} onClick={() => data.refresh()}>
            Refresh
          </Button>
        </div>
        <ErrorBox error={data.error()} />
        <Show
          when={!data.loading()}
          fallback={
            <p class="loading" role="status">
              Loading requests…
            </p>
          }
        >
          <Show
            when={data.data()?.items.length}
            fallback={
              <Show when={!data.error()}>
                <Empty
                  title={p.blocked ? "No blocked requests" : "No requests yet"}
                >
                  {p.blocked
                    ? "Requests that fail verification will appear here."
                    : "Send a request to a webhook URL to see its captured headers and body."}
                </Empty>
              </Show>
            }
          >
            <EventTable
              items={data.data()!.items}
              blocked={p.blocked}
              select={setSelected}
            />
          </Show>
        </Show>
        <div class="panel-footer">
          <span>
            {data.data()?.items.length || 0} requests · Page{" "}
            {cursors().length + 1}
          </span>
          <div class="actions">
            <Button
              disabled={data.loading() || !cursors().length}
              onClick={() => setCursors(cursors().slice(0, -1))}
            >
              ← Previous
            </Button>
            <Button
              disabled={data.loading() || !data.data()?.next_cursor}
              onClick={() =>
                setCursors([...cursors(), data.data()!.next_cursor!])
              }
            >
              Next →
            </Button>
          </div>
        </div>
      </div>
      <p class="footnote">
        Large bodies can reduce a page’s item count. Use Next to continue
        through all retained requests.
      </p>
      <Show when={selected()}>
        {(e) => (
          <EventDetail event={e()} close={() => setSelected(undefined)} />
        )}
      </Show>
    </>
  );
}
