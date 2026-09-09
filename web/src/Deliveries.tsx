import { createSignal, For, Show, onCleanup } from "solid-js";
import {
  api,
  scoped,
  query,
  gatewayOrigin,
  type Context,
  type Event,
} from "./api";
import { load } from "./resource";
import {
  Badge,
  Button,
  Confirm,
  Empty,
  ErrorBox,
  EventDetail,
  EventTable,
  Field,
} from "./ui";
export default function Deliveries(p: { ctx: Context }) {
  const [after, setAfter] = createSignal("");
  const [limit, setLimit] = createSignal(100);
  const [selected, setSelected] = createSignal<Event>();
  const [through, setThrough] = createSignal("");
  const [confirm, setConfirm] = createSignal(false);
  let ackKey = crypto.randomUUID();
  const cursor = load(
    () => p.ctx,
    () =>
      api<{ acknowledged_through: number; acknowledged_at?: string }>(
        p.ctx,
        scoped(p.ctx, "/deliveries/cursor"),
      ),
  );
  const batch = load(
    () => [p.ctx, after(), limit()],
    () =>
      api<{
        items: Event[];
        cursor: { acknowledged_through: number };
        latest_sequence: number;
      }>(
        p.ctx,
        scoped(p.ctx, "/deliveries") +
          query({ limit: limit(), after_sequence: after() || undefined }),
      ),
  );
  return (
    <>
      <div class="page-heading">
        <div>
          <p class="eyebrow">CONSUMER</p>
          <h1>Deliveries</h1>
          <p class="muted">
            Review pending events and confirm what has been processed.
          </p>
        </div>
        <Button
          onClick={() => {
            void cursor.refresh();
            void batch.refresh();
          }}
        >
          Refresh
        </Button>
      </div>
      <div class="notice">
        Acknowledgments are shared by every client using this Silicon identity.
        Confirm only events your consumer has processed.
      </div>
      <div class="stats compact">
        <div class="stat">
          <span>Acknowledged through</span>
          <strong>{cursor.data()?.acknowledged_through ?? "—"}</strong>
          <small class="mono">{p.ctx.silicon}</small>
        </div>
        <form
          class="ack-form"
          onSubmit={(e) => {
            e.preventDefault();
            ackKey = crypto.randomUUID();
            setConfirm(true);
          }}
        >
          <Field label="Acknowledge through sequence">
            <input
              required
              type="number"
              min="0"
              max={Number.MAX_SAFE_INTEGER}
              step="1"
              value={through()}
              onInput={(e) => setThrough(e.currentTarget.value)}
              placeholder="Sequence number"
            />
          </Field>
          <Button type="submit">Acknowledge</Button>
        </form>
      </div>
      <ErrorBox error={cursor.error()} />
      <div class="panel">
        <div class="toolbar filters">
          <Field label="After sequence (optional)">
            <input
              type="number"
              min="0"
              value={after()}
              placeholder="Current cursor"
              onChange={(e) => setAfter(e.currentTarget.value)}
            />
          </Field>
          <Field label="Page size">
            <select
              value={limit()}
              onChange={(e) => setLimit(Number(e.currentTarget.value))}
            >
              <For each={[25, 100, 1000]}>
                {(n) => <option value={n}>{n}</option>}
              </For>
            </select>
          </Field>
        </div>
        <ErrorBox error={batch.error()} />
        <Show
          when={!batch.loading()}
          fallback={<p class="loading">Loading deliveries…</p>}
        >
          <Show
            when={batch.data()?.items.length}
            fallback={
              <Show when={!batch.error()}>
                <Empty title="All caught up">
                  Unacknowledged events will appear here as providers send
                  requests.
                </Empty>
              </Show>
            }
          >
            <EventTable items={batch.data()!.items} select={setSelected} />
          </Show>
        </Show>
        <div class="panel-footer">
          <span>
            {batch.data()?.items.length || 0} pending events on this page
          </span>
          <Button
            disabled={
              !batch.data()?.items.length ||
              (batch.data()!.items.at(-1)?.delivery_sequence || 0) >=
                batch.data()!.latest_sequence
            }
            onClick={() =>
              setAfter(String(batch.data()!.items.at(-1)!.delivery_sequence))
            }
          >
            Next pending →
          </Button>
        </div>
      </div>
      <Show when={confirm()}>
        <Confirm
          title="Acknowledge deliveries?"
          description={
            "Every event through sequence " +
            through() +
            " will be marked processed for " +
            p.ctx.silicon +
            ". They will no longer replay automatically to this identity."
          }
          label="Acknowledge"
          action={() =>
            api(
              p.ctx,
              scoped(p.ctx, "/deliveries/ack"),
              "POST",
              { through_sequence: Number(through()) },
              ackKey,
            )
          }
          close={() => setConfirm(false)}
          done={() => {
            setConfirm(false);
            void cursor.refresh();
            void batch.refresh();
          }}
        />
      </Show>
      <Show when={selected()}>
        {(e) => (
          <EventDetail event={e()} close={() => setSelected(undefined)} />
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
  const [cursors, setCursors] = createSignal<Record<string, number>>({});
  const [target, setTarget] = createSignal(p.ctx.silicon);
  const [sequence, setSequence] = createSignal("");
  const [ack, setAck] = createSignal(false);
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
      running = true;
      setEvents([]);
      setCursors({});
      setAttempt(0);
    }
    const gen = generation;
    const silicons = ids()
      .split(/[\s,]+/)
      .filter(Boolean);
    if (!silicons.length) {
      setError(new Error("Enter at least one Silicon ID."));
      return;
    }
    setError(undefined);
    setState(retry ? "Reconnecting" : "Connecting");
    const url = new URL("/console/stream", gatewayOrigin());
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.searchParams.set("plane", p.ctx.plane);
    url.searchParams.set("org", p.ctx.org);
    silicons.forEach((id) => url.searchParams.append("silicon_id", id));
    const ws = new WebSocket(url);
    socket = ws;
    ws.onmessage = (e) => {
      if (gen !== generation) return;
      try {
        const f = JSON.parse(e.data);
        if (f.type === "ping") {
          ws.send(JSON.stringify({ type: "pong", ping_id: f.ping_id }));
          return;
        }
        if (f.type === "ready") {
          setState("Connected");
          setAttempt(0);
          setCursors(f.acknowledged_through);
        }
        if (f.type === "event")
          setEvents((prev) =>
            [f.event, ...prev.filter((x) => x.id !== f.event.id)].slice(0, 32),
          );
        if (f.type === "ack_recorded")
          setCursors({ ...cursors(), [f.silicon_id]: f.acknowledged_through });
        if (f.type === "error") setError(new Error(f.code + ": " + f.message));
      } catch {
        setError(new Error("Hook sent an unreadable stream frame."));
      }
    };
    ws.onclose = (e) => {
      if (gen !== generation) return;
      setState("Disconnected");
      if (!running) return;
      if ([4001, 4003].includes(e.code)) {
        running = false;
        setError(
          new Error(
            e.reason ||
              "The environment or authorization changed. Sign in or reattach the key before reconnecting.",
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
          Math.min(30000, 1000 * 2 ** Math.min(attempt(), 5)),
        );
      } else setError(new Error(e.reason || "The live connection closed."));
    };
    ws.onerror = () =>
      setError(
        new Error(
          "Could not connect to the live stream. Check your selected identity and backend availability.",
        ),
      );
  }
  function frame(type: "ack" | "resume") {
    if (socket?.readyState !== WebSocket.OPEN)
      throw new Error("Connect to the stream first.");
    socket.send(
      JSON.stringify({
        type,
        silicon_id: target(),
        ...(type === "ack"
          ? { through_sequence: Number(sequence()) }
          : { after_sequence: Number(sequence()) }),
      }),
    );
  }
  onCleanup(stop);
  return (
    <>
      <div class="page-heading">
        <div>
          <p class="eyebrow">REALTIME</p>
          <h1>Live stream</h1>
          <p class="muted">
            Watch one or more Silicons receive webhook events.
          </p>
        </div>
        <Badge value={state()} />
      </div>
      <div class="panel live-controls">
        <Field
          label="Silicon IDs"
          hint="Separate multiple IDs with a comma. Each must be visible to your identity."
        >
          <input
            value={ids()}
            disabled={state() === "Connected" || state() === "Connecting"}
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
        Viewing does not acknowledge events. Hook pauses after 32 outstanding
        events per Silicon. Heartbeats are answered while this page stays
        connected; use the CLI relay for continuous background delivery.
      </div>
      <details class="panel stream-actions">
        <summary>Acknowledgment & replay</summary>
        <div class="form-grid inset">
          <Field label="Silicon">
            <input
              value={target()}
              onInput={(e) => setTarget(e.currentTarget.value)}
            />
          </Field>
          <Field label="Sequence">
            <input
              type="number"
              min="0"
              max={Number.MAX_SAFE_INTEGER}
              step="1"
              value={sequence()}
              onInput={(e) => setSequence(e.currentTarget.value)}
            />
          </Field>
        </div>
        <div class="actions">
          <Button
            disabled={
              state() !== "Connected" || !sequence() || Number(sequence()) < 0
            }
            onClick={() => setAck(true)}
          >
            Acknowledge through
          </Button>
          <Button
            disabled={
              state() !== "Connected" || !sequence() || Number(sequence()) < 0
            }
            onClick={() => {
              try {
                frame("resume");
              } catch (e) {
                setError(e);
              }
            }}
          >
            Resume after
          </Button>
        </div>
        <p class="mono small">
          {Object.entries(cursors())
            .map(([sid, n]) => sid + ": " + n)
            .join(" · ") || "Cursor positions appear after connecting."}
        </p>
      </details>
      <div class="panel">
        <div class="panel-title">
          <h3>Incoming events</h3>
          <span class="muted small">
            Most recent 32 in this browser · retained history in Events
          </span>
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
                ? "Send a request to a webhook URL. New and unacknowledged events appear here."
                : "Choose a Silicon and connect to its live stream."}
            </Empty>
          }
        >
          <EventTable items={events()} select={setSelected} />
        </Show>
      </div>
      <Show when={selected()}>
        {(e) => (
          <EventDetail event={e()} close={() => setSelected(undefined)} />
        )}
      </Show>
      <Show when={ack()}>
        <Confirm
          title="Acknowledge this stream?"
          description={
            "Mark every delivery through " +
            sequence() +
            " processed for " +
            target() +
            ". This changes the shared consumer cursor."
          }
          label="Acknowledge"
          action={async () => frame("ack")}
          done={() => setAck(false)}
          close={() => setAck(false)}
        />
      </Show>
    </>
  );
}
