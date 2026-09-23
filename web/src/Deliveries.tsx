import { createEffect, createSignal, For, Show, onCleanup } from "solid-js";
import {
  api,
  date,
  telemetryEnabled,
  scoped,
  query,
  gatewayOrigin,
  type Context,
  type Event,
  type Page,
  type Publication,
} from "./api";
import { load } from "./resource";
import {
  Badge,
  Button,
  Empty,
  ErrorBox,
  EventDetail,
  EventTable,
  Field,
} from "./ui";

const publicationLabel = (state: Publication["state"]) =>
  ({
    pending: "Waiting to send",
    accepted_by_ting: "Accepted for delivery",
    accepted_silently: "Accepted silently",
  })[state] || "Unknown";

export default function Deliveries(p: { ctx: Context }) {
  const [cursors, setCursors] = createSignal<string[]>([]);
  const [selected, setSelected] = createSignal<Event>();
  const [inspect, setInspect] = createSignal<Event>();
  const events = load(
    () => [p.ctx, cursors().at(-1)],
    () =>
      api<Page<Event>>(
        p.ctx,
        scoped(p.ctx, "/events") +
          query({ limit: 25, cursor: cursors().at(-1) }),
      ),
  );
  const publication = load(
    () => selected() && [p.ctx, selected()!.id],
    () =>
      api<Publication>(
        p.ctx,
        scoped(p.ctx, "/events/" + selected()!.id + "/publication"),
      ),
  );
  createEffect(() => {
    void p.ctx;
    setCursors([]);
    setSelected(undefined);
    setInspect(undefined);
  });
  return (
    <>
      <div class="page-heading">
        <div>
          <p class="eyebrow">DELIVERY STATUS</p>
          <h1>Deliveries</h1>
          <p class="muted">
            Select an event to inspect delivery to its Silicon.
          </p>
        </div>
        <Button
          onClick={() => {
            void events.refresh();
            if (selected()) void publication.refresh();
          }}
        >
          Refresh
        </Button>
      </div>
      <div class="notice subtle">
        Sending, receipt and destination acceptance are separate steps.
        Acceptance does not mean the Silicon has finished the work.
      </div>
      <div class="panel">
        <ErrorBox error={events.error()} />
        <Show
          when={!events.loading()}
          fallback={<p class="loading">Loading events…</p>}
        >
          <Show
            when={events.data()?.items.length}
            fallback={
              <Show when={!events.error()}>
                <Empty title="No events yet">
                  Accepted provider requests appear here for 14 days.
                </Empty>
              </Show>
            }
          >
            <EventTable items={events.data()!.items} select={setSelected} />
          </Show>
        </Show>
        <div class="panel-footer">
          <span>
            Page {cursors().length + 1} · {events.data()?.items.length || 0}{" "}
            events
          </span>
          <div class="actions">
            <Button
              disabled={events.loading() || !cursors().length}
              onClick={() => setCursors(cursors().slice(0, -1))}
            >
              ← Previous
            </Button>
            <Button
              disabled={events.loading() || !events.data()?.next_cursor}
              onClick={() =>
                setCursors([...cursors(), events.data()!.next_cursor!])
              }
            >
              Next →
            </Button>
          </div>
        </div>
      </div>
      <Show when={selected()}>
        {(event) => (
          <section class="panel" aria-label="Event delivery status">
            <div class="panel-title">
              <h3>
                {event().provider} · #{event().delivery_sequence}
              </h3>
              <Button onClick={() => setInspect(event())}>
                Inspect request
              </Button>
            </div>
            <div class="panel-body">
              <p class="mono small break">{event().id}</p>
              <ErrorBox error={publication.error()} />
              <Show
                when={!publication.loading()}
                fallback={<p class="loading">Checking delivery…</p>}
              >
                <Show when={publication.data()}>
                  {(status) => (
                    <>
                      <Badge value={publicationLabel(status().state)} />
                      <dl class="facts">
                        <dt>Recipient</dt>
                        <dd>{status().recipient_id}</dd>
                        <dt>Delivery policy</dt>
                        <dd>
                          {status().delivery === "required"
                            ? "Automation"
                            : "Notification"}
                        </dd>
                        <dt>Notifications</dt>
                        <dd>
                          {status().silent === null
                            ? "Not confirmed"
                            : status().silent
                              ? "Muted"
                              : "Visible"}
                        </dd>
                        <dt>Send attempts</dt>
                        <dd>{status().attempts}</dd>
                        <dt>Accepted for delivery</dt>
                        <dd>{date(status().accepted_at)}</dd>
                        <Show when={status().state === "pending"}>
                          <dt>Next attempt</dt>
                          <dd>{date(status().next_attempt_at)}</dd>
                        </Show>
                        <dt>Payload retained until</dt>
                        <dd>{date(status().expires_at)}</dd>
                        <Show when={status().last_error_code}>
                          <dt>Last send error</dt>
                          <dd class="mono">{status().last_error_code}</dd>
                        </Show>
                      </dl>
                      <Show
                        when={
                          status().last_error_code ===
                          "required_delivery_not_enabled"
                        }
                      >
                        <p class="notice">
                          Waiting for the recipient to enable webhook automation
                          in its app. Sending will retry automatically.
                        </p>
                      </Show>
                      <Show
                        when={
                          status().delivery === "required" &&
                          status().silent === true
                        }
                      >
                        <p class="notice">
                          Notifications are muted. Automation delivery is
                          handled separately; check destination acceptance
                          below.
                        </p>
                      </Show>
                      <Show when={status().state === "accepted_silently"}>
                        <p class="notice">
                          Recipient notification preferences suppressed
                          automatic delivery. This event has been stored, but
                          delivery is not confirmed.
                        </p>
                      </Show>
                      <Show when={status().recipient_status_error}>
                        <p class="notice">
                          Destination status is unavailable. The send status
                          above is still valid. Refresh to check again.
                        </p>
                      </Show>
                      <Show when={status().recipient_receipt}>
                        {(receipt) => (
                          <>
                            <h4>Destination receipts</h4>
                            <p class="muted small">
                              Receipt confirms durable delivery storage.
                              Acceptance confirms the destination accepted the
                              event; neither confirms completed work.
                            </p>
                            <Show
                              when={receipt().deliveries.length}
                              fallback={
                                <p class="muted">
                                  No destination receipt is available.
                                </p>
                              }
                            >
                              <div class="table-wrap">
                                <table>
                                  <thead>
                                    <tr>
                                      <th>Destination</th>
                                      <th>Received</th>
                                      <th>Accepted</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    <For each={receipt().deliveries}>
                                      {(destination) => (
                                        <tr>
                                          <td class="mono break">
                                            {destination.webhook_id}
                                          </td>
                                          <td>
                                            {destination.delivery_acked
                                              ? "Confirmed"
                                              : "Not confirmed"}
                                          </td>
                                          <td>
                                            {destination.read_acked
                                              ? "Confirmed"
                                              : "Not confirmed"}
                                          </td>
                                        </tr>
                                      )}
                                    </For>
                                  </tbody>
                                </table>
                              </div>
                            </Show>
                            <Show when={receipt().read}>
                              <p class="small">
                                The recipient has accepted or marked this
                                notification read.
                              </p>
                            </Show>
                            <Show when={receipt().more_destinations}>
                              <p class="notice subtle">
                                More destinations exist than are included in
                                this response.
                              </p>
                            </Show>
                          </>
                        )}
                      </Show>
                    </>
                  )}
                </Show>
              </Show>
            </div>
          </section>
        )}
      </Show>
      <Show when={inspect()}>
        {(event) => (
          <EventDetail event={event()} close={() => setInspect(undefined)} />
        )}
      </Show>
    </>
  );
}

export function Live(p: { ctx: Context }) {
  const [ids, setIds] = createSignal(p.ctx.silicon);
  const [state, setState] = createSignal("Disconnected");
  const [events, setEvents] = createSignal<Event[]>([]);
  const [error, setError] = createSignal<unknown>();
  const [selected, setSelected] = createSignal<Event>();
  const [auto, setAuto] = createSignal(true);
  const [attempt, setAttempt] = createSignal(0);
  let socket: WebSocket | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let running = false;
  let generation = 0;
  function stop() {
    running = false;
    generation++;
    clearTimeout(timer);
    socket?.close();
    socket = undefined;
    setState("Disconnected");
  }
  function open(retry = false) {
    if (!retry) {
      stop();
      setEvents([]);
      setAttempt(0);
    }
    const silicons = [
      ...new Set(
        ids()
          .split(/[\s,]+/)
          .filter(Boolean),
      ),
    ];
    if (!silicons.length || !p.ctx.org) {
      setError(new Error("Choose an organization and at least one Silicon."));
      return;
    }
    running = true;
    const gen = ++generation;
    setError(undefined);
    setState(retry ? "Reconnecting" : "Connecting");
    const url = new URL("/console/stream", gatewayOrigin());
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.searchParams.set("plane", p.ctx.plane);
    url.searchParams.set("telemetry", telemetryEnabled() ? "on" : "off");
    url.searchParams.set("org", p.ctx.org);
    silicons.forEach((id) => url.searchParams.append("silicon_id", id));
    const ws = new WebSocket(url);
    let retryAt = 0;
    socket = ws;
    ws.onmessage = (e) => {
      if (gen !== generation) return;
      try {
        const frame = JSON.parse(e.data);
        if (frame.type === "ready") {
          setState("Connected");
          setAttempt(0);
          retryAt = 0;
          setError(undefined);
        }
        if (frame.type === "new_event") {
          const event = frame.data?.event as Event;
          if (!event?.id || !silicons.includes(event.silicon_id))
            throw new Error("Invalid live event.");
          setEvents((previous) =>
            [event, ...previous.filter((item) => item.id !== event.id)]
              .sort(
                (a, b) =>
                  Date.parse(b.received_at) - Date.parse(a.received_at) ||
                  (a.silicon_id === b.silicon_id
                    ? (b.delivery_sequence || 0) - (a.delivery_sequence || 0)
                    : 0) ||
                  b.id.localeCompare(a.id),
              )
              .slice(0, 32),
          );
        }
        if (frame.type === "error") {
          const detail = frame.data;
          if (
            typeof detail?.retry_after === "number" &&
            Number.isFinite(detail.retry_after) &&
            detail.retry_after > 0
          ) {
            retryAt = Date.now() + detail.retry_after * 1000;
            if (!detail.fatal) setState("Waiting to retry");
          }
          setError(
            new Error(
              (detail?.code ? detail.code + ": " : "") +
                (detail?.message || "The live connection failed."),
            ),
          );
          if (detail?.fatal && !detail?.retryable) running = false;
        }
      } catch {
        setError(new Error("The live connection sent an unreadable event."));
      }
    };
    ws.onclose = (e) => {
      if (gen !== generation) return;
      setState("Disconnected");
      if (!running) return;
      if ([4001, 4003].includes(e.code)) {
        running = false;
        if (!error())
          setError(
            new Error(
              e.reason ||
                "Your session or access changed. Sign in before reconnecting.",
            ),
          );
        return;
      }
      if (auto()) {
        setAttempt((n) => n + 1);
        setState("Reconnecting");
        timer = setTimeout(
          () => {
            if (running && gen === generation) open(true);
          },
          Math.min(
            2147483647,
            Math.max(
              Math.min(30000, 1000 * 2 ** Math.min(attempt(), 5)),
              retryAt - Date.now(),
            ),
          ),
        );
      } else {
        running = false;
        if (!error())
          setError(new Error(e.reason || "The live connection closed."));
      }
    };
    ws.onerror = () => {
      if (gen === generation && !error())
        setError(
          new Error(
            "Could not reach the live stream. Check your session and try again.",
          ),
        );
    };
  }
  createEffect(() => {
    const ctx = p.ctx;
    stop();
    setIds(ctx.silicon);
    setEvents([]);
    setSelected(undefined);
    setError(undefined);
  });
  onCleanup(stop);
  return (
    <>
      <div class="page-heading">
        <div>
          <p class="eyebrow">REALTIME</p>
          <h1>Live stream</h1>
          <p class="muted">Watch events from Silicons you can access.</p>
        </div>
        <Badge value={state()} />
      </div>
      <div class="panel live-controls">
        <Field
          label="Silicon IDs"
          hint="Separate multiple IDs with a comma. Connecting enables future updates for your identity."
        >
          <input
            value={ids()}
            disabled={state() !== "Disconnected"}
            onInput={(e) => setIds(e.currentTarget.value)}
            placeholder="cos:tos, ops:tos"
          />
        </Field>
        <div class="actions">
          <Show
            when={state() === "Disconnected"}
            fallback={<Button onClick={stop}>Disconnect</Button>}
          >
            <Button primary onClick={() => open()}>
              Connect
            </Button>
          </Show>
          <label class="check">
            <input
              type="checkbox"
              checked={auto()}
              onChange={(e) => setAuto(e.currentTarget.checked)}
            />
            Reconnect automatically
          </label>
        </div>
      </div>
      <ErrorBox error={error()} />
      <div class="notice subtle">
        This view refreshes while open and does not acknowledge or complete
        work. Your app handles continuous delivery internally. Use Events for
        the full retained history.
      </div>
      <div class="panel">
        <div class="panel-title">
          <h3>Incoming events</h3>
          <span class="muted small">Most recent 32 in this browser</span>
        </div>
        <Show
          when={events().length}
          fallback={
            <Empty
              title={
                state() === "Connected"
                  ? "Listening for requests"
                  : "Ready when you are"
              }
            >
              {state() === "Connected"
                ? "New events will appear here as providers send requests."
                : "Choose a Silicon and connect to its live stream."}
            </Empty>
          }
        >
          <EventTable items={events()} select={setSelected} />
        </Show>
      </div>
      <Show when={selected()}>
        {(event) => (
          <EventDetail event={event()} close={() => setSelected(undefined)} />
        )}
      </Show>
    </>
  );
}
