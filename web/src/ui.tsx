import {
  createSignal,
  For,
  Show,
  onMount,
  onCleanup,
  type JSX,
} from "solid-js";
import { ApiError, message, download, type Event, date } from "./api";
export function Brand() {
  return (
    <a class="brand" href="#overview">
      <img src="/brand/mark.svg" alt="" />
      silicon<span>HOOK</span>
    </a>
  );
}
export function Badge(p: { value: string }) {
  return (
    <span class={"badge " + p.value.toLowerCase().replace(/[^a-z]/g, "")}>
      {p.value}
    </span>
  );
}
export function ErrorBox(p: { error: unknown }) {
  return (
    <Show when={p.error}>
      <div class="notice error" role="alert">
        <strong>{message(p.error)}</strong>
        <Show when={p.error instanceof ApiError}>
          <p class="mono small">{(p.error as ApiError).code}</p>
          <Show when={(p.error as ApiError).details}>
            <p>{(p.error as ApiError).details}</p>
          </Show>
          <Show when={(p.error as ApiError).requestId}>
            <p class="small mono">Request: {(p.error as ApiError).requestId}</p>
          </Show>
          <Show when={(p.error as ApiError).retryAfter}>
            <p>Retry after {(p.error as ApiError).retryAfter} seconds.</p>
          </Show>
          <Show when={(p.error as ApiError).status === 401}>
            <p>Sign in again in the selected environment.</p>
          </Show>
          <Show when={(p.error as ApiError).status === 403}>
            <p>
              Your IAM identity does not have permission for this operation.
            </p>
          </Show>
        </Show>
      </div>
    </Show>
  );
}
export function Empty(p: { title: string; children?: JSX.Element }) {
  return (
    <div class="empty">
      <span class="empty-mark" aria-hidden="true">
        ◇
      </span>
      <h3>{p.title}</h3>
      <p>{p.children}</p>
    </div>
  );
}
export function Button(p: {
  children: JSX.Element;
  onClick?: () => void;
  primary?: boolean;
  danger?: boolean;
  disabled?: boolean;
  type?: "button" | "submit";
  class?: string;
}) {
  return (
    <button
      type={p.type || "button"}
      disabled={p.disabled}
      class={
        "button " +
        (p.primary ? "primary " : "") +
        (p.danger ? "danger " : "") +
        (p.class || "")
      }
      onClick={p.onClick}
    >
      {p.children}
    </button>
  );
}
export function Copy(p: { value: string; label?: string }) {
  const [status, setStatus] = createSignal("");
  return (
    <button
      type="button"
      class="copy"
      aria-label={"Copy " + (p.label || "value")}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(p.value);
          setStatus("Copied");
        } catch {
          setStatus("Select and copy manually");
        }
        setTimeout(() => setStatus(""), 2500);
      }}
    >
      {status() || p.label || "Copy"}
    </button>
  );
}
export function Field(p: {
  label: string;
  hint?: string;
  children: JSX.Element;
}) {
  return (
    <label class="field">
      <span>{p.label}</span>
      {p.children}
      <Show when={p.hint}>
        <small>{p.hint}</small>
      </Show>
    </label>
  );
}
export function Modal(p: {
  title: string;
  close: () => void;
  children: JSX.Element;
  wide?: boolean;
}) {
  let dialog!: HTMLDialogElement;
  onMount(() => {
    dialog.showModal();
  });
  onCleanup(() => dialog.close());
  return (
    <dialog
      ref={dialog}
      class={p.wide ? "wide" : ""}
      onCancel={(e) => {
        e.preventDefault();
        p.close();
      }}
    >
      <div class="dialog-header">
        <h2>{p.title}</h2>
        <button class="icon-button" aria-label="Close dialog" onClick={p.close}>
          ×
        </button>
      </div>
      {p.children}
    </dialog>
  );
}
export function SecretResult(p: {
  value: unknown;
  close: () => void;
  title?: string;
}) {
  const value = () =>
    typeof p.value === "string" ? p.value : JSON.stringify(p.value, null, 2);
  return (
    <Modal title={p.title || "Save your connection details"} close={p.close}>
      <p class="muted">
        Store these details somewhere safe. Signing secrets are only shown when
        created or rotated.
      </p>
      <pre class="secret" tabIndex={0}>
        {value()}
      </pre>
      <div class="actions">
        <Copy value={value()} label="Copy details" />
        <Button onClick={() => download("hook-connection.json", value())}>
          Download
        </Button>
        <Button primary onClick={p.close}>
          Done
        </Button>
      </div>
    </Modal>
  );
}
export function Confirm(p: {
  title: string;
  description: string;
  action: () => Promise<unknown>;
  done: () => unknown;
  close: () => void;
  label?: string;
  destructive?: boolean;
  typed?: string;
}) {
  const [error, setError] = createSignal<unknown>();
  const [busy, setBusy] = createSignal(false);
  const [typed, setTyped] = createSignal("");
  const run = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await p.action();
      await p.done();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title={p.title} close={() => !busy() && p.close()}>
      <p class="muted">{p.description}</p>
      <Show when={p.typed}>
        <Field label={"Type “" + p.typed + "” to confirm"}>
          <input
            value={typed()}
            onInput={(e) => setTyped(e.currentTarget.value)}
          />
        </Field>
      </Show>
      <ErrorBox error={error()} />
      <div class="actions end">
        <Button disabled={busy()} onClick={p.close}>
          Cancel
        </Button>
        <Button
          danger={p.destructive}
          primary={!p.destructive}
          disabled={busy() || (!!p.typed && typed() !== p.typed)}
          onClick={run}
        >
          {busy() ? "Working…" : p.label || "Confirm"}
        </Button>
      </div>
    </Modal>
  );
}
export function EventDetail(p: { event: Event; close: () => void }) {
  const [tab, setTab] = createSignal("body");
  const e = () => p.event;
  return (
    <Modal title={e().provider || "Request details"} close={p.close} wide>
      <div class="detail-meta">
        <Badge value={e().reason_code ? "Blocked" : "Verified"} />
        <span>{date(e().received_at)}</span>
        <code>{e().id}</code>
        <Copy value={e().id} />
      </div>
      <Show when={e().reason_code}>
        <div class="notice error">
          {e().reason_code}: {e().reason_detail}
        </div>
      </Show>
      <p class="mono request-url">
        {e().request.method} {e().request.url}
      </p>
      <div class="tabs">
        <For each={["body", "headers", "metadata", "json"]}>
          {(t) => (
            <button
              classList={{ selected: tab() === t }}
              onClick={() => setTab(t)}
            >
              {t === "json" ? "Full JSON" : t[0].toUpperCase() + t.slice(1)}
            </button>
          )}
        </For>
      </div>
      <Show when={tab() === "body"}>
        <p class="muted small">
          {e().request.body_base64
            ? "Binary request body · Base64"
            : "Original UTF-8 request body"}
        </p>
        <pre class="payload" tabIndex={0}>
          {e().request.body ?? e().request.body_base64 ?? "(empty)"}
        </pre>
      </Show>
      <Show when={tab() === "headers"}>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Header</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              <For each={e().request.headers}>
                {(h) => (
                  <tr>
                    <td class="mono">{h[0]}</td>
                    <td class="mono break">{h[1]}</td>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </Show>
      <Show when={tab() === "metadata"}>
        <dl class="facts">
          <dt>Silicon</dt>
          <dd>{e().silicon_id}</dd>
          <dt>Hook</dt>
          <dd>{e().hook_id}</dd>
          <dt>Sequence</dt>
          <dd>{e().delivery_sequence ?? "Not delivered"}</dd>
          <dt>Source IP</dt>
          <dd>{e().request.remote_ip}</dd>
          <dt>Content type</dt>
          <dd>{e().request.content_type || "—"}</dd>
          <dt>Summary</dt>
          <dd>{e().summary || "—"}</dd>
        </dl>
      </Show>
      <Show when={tab() === "json"}>
        <pre class="payload" tabIndex={0}>
          {JSON.stringify(e(), null, 2)}
        </pre>
      </Show>
      <div class="actions end">
        <Button
          onClick={() =>
            download(
              "hook-event-" + e().id + ".json",
              JSON.stringify(e(), null, 2),
            )
          }
        >
          Download request
        </Button>
        <Button onClick={p.close}>Close</Button>
      </div>
    </Modal>
  );
}
export function EventTable(p: {
  items: Event[];
  select: (e: Event) => void;
  blocked?: boolean;
}) {
  return (
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Provider / request</th>
            <th>{p.blocked ? "Reason" : "Sequence"}</th>
            <th>Received</th>
            <th>
              <span class="sr-only">Details</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <For each={p.items}>
            {(e) => (
              <tr>
                <td>
                  <button class="text-button" onClick={() => p.select(e)}>
                    {e.provider}
                  </button>
                  <span class="table-sub mono">
                    {e.request.method} {e.request.path}
                  </span>
                </td>
                <td>
                  {p.blocked ? (
                    <Badge value={e.reason_code || "blocked"} />
                  ) : (
                    <code>#{e.delivery_sequence}</code>
                  )}
                </td>
                <td class="nowrap">{date(e.received_at)}</td>
                <td>
                  <button class="text-button" onClick={() => p.select(e)}>
                    Inspect →
                  </button>
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}

export function CredentialFile(p: {
  label: string;
  receive: (value: string) => void;
}) {
  const [error, setError] = createSignal<unknown>();
  return (
    <div class="credential-file">
      <label class="field">
        <span>{p.label}</span>
        <input
          type="file"
          aria-label={p.label}
          onChange={async (e) => {
            const input = e.currentTarget;
            const file = input.files?.[0];
            if (!file) return;
            try {
              if (file.size > 8192)
                throw new Error("Credential files must be smaller than 8 KiB.");
              p.receive((await file.text()).trim());
              setError(undefined);
            } catch (error) {
              setError(error);
            } finally {
              input.value = "";
            }
          }}
        />
      </label>
      <ErrorBox error={error()} />
    </div>
  );
}
