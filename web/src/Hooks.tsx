import { createSignal, createMemo, For, Show } from "solid-js";
import {
  api,
  scoped,
  date,
  type Hook,
  type Context,
  type Page,
  type Signature,
} from "./api";
import { load } from "./resource";
import {
  Badge,
  Button,
  Confirm,
  Copy,
  Empty,
  ErrorBox,
  Field,
  Modal,
  SecretResult,
} from "./ui";
const algorithms = [
  "HMAC-SHA1",
  "HMAC-SHA256",
  "HMAC-SHA384",
  "HMAC-SHA512",
  "SHA1",
  "SHA256",
  "SHA384",
  "SHA512",
  "Ed25519",
  "ECDSA-SHA256",
  "RSA-SHA1",
  "RSA-SHA256",
];
const defaultSignature: Signature = {
  required: true,
  algorithm: "HMAC-SHA256",
  payload:
    'concat(request.headers["webhook-id"], ".", request.headers["webhook-timestamp"], ".", request.raw_body)',
  signature: 'request.headers["webhook-signature"]',
  signature_encoding: "base64",
  secret_encoding: "utf8",
  public_key: null,
};
export function HookForm(p: {
  ctx: Context;
  hook?: Hook;
  close: () => void;
  done: (result: Hook) => void | Promise<void>;
}) {
  const [name, setName] = createSignal(p.hook?.name || "");
  const [description, setDescription] = createSignal(p.hook?.description || "");
  const [zone, setZone] = createSignal(
    p.hook?.time_zone ||
      Intl.DateTimeFormat().resolvedOptions().timeZone ||
      "UTC",
  );
  const [sig, setSig] = createSignal({
    ...defaultSignature,
    ...p.hook?.signature,
  });
  const [secret, setSecret] = createSignal("");
  const [byos, setByos] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  let key = crypto.randomUUID();
  const change = (field: keyof Signature, value: unknown) => {
    setSig({ ...sig(), [field]: value });
    key = crypto.randomUUID();
  };
  const asymmetric = () => /^(Ed|ECDSA|RSA)/.test(sig().algorithm);
  async function save(e: SubmitEvent) {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const { has_secret, ...signature } = sig();
      const result = await api<Hook>(
        p.ctx,
        scoped(p.ctx, "/hooks" + (p.hook ? "/" + p.hook.id : "")),
        p.hook ? "PATCH" : "POST",
        {
          name: name().trim(),
          description: description() || null,
          time_zone: zone(),
          signature: {
            ...signature,
            public_key: asymmetric() ? signature.public_key : null,
            ...(!asymmetric() && byos() ? { secret: secret() } : {}),
          },
        },
        key,
      );
      setSecret("");
      await p.done(result);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title={p.hook ? "Edit connection" : "Create a webhook"}
      close={() => !busy() && p.close()}
      wide
    >
      <form
        onSubmit={save}
        onInput={() => (key = crypto.randomUUID())}
        class="stack"
      >
        <div class="form-grid">
          <Field label="Provider name">
            <input
              required
              maxLength={200}
              autofocus
              value={name()}
              onInput={(e) => setName(e.currentTarget.value)}
              placeholder="e.g. GitHub"
            />
          </Field>
          <Field
            label="Time zone"
            hint="Used in each delivery’s readable summary."
          >
            <input
              required
              value={zone()}
              onInput={(e) => setZone(e.currentTarget.value)}
              list="timezones"
            />
            <datalist id="timezones">
              <option>UTC</option>
              <option>Asia/Kolkata</option>
              <option>America/New_York</option>
              <option>Europe/London</option>
            </datalist>
          </Field>
        </div>
        <Field label="Description (optional)">
          <textarea
            rows={2}
            value={description()}
            onInput={(e) => setDescription(e.currentTarget.value)}
            placeholder="What should this connection listen for?"
          />
        </Field>
        <div class="section-rule">
          <h3>Signature verification</h3>
          <label class="check">
            <input
              type="checkbox"
              checked={sig().required}
              onChange={(e) => change("required", e.currentTarget.checked)}
            />
            Require a valid signature
          </label>
        </div>
        <Show when={!sig().required}>
          <div class="notice">
            Requests will be accepted without verifying a signature.
          </div>
        </Show>
        <details open={sig().required}>
          <summary>Signing policy</summary>
          <div class="stack inset">
            <div class="form-grid">
              <Field label="Algorithm">
                <select
                  value={sig().algorithm}
                  onChange={(e) => change("algorithm", e.currentTarget.value)}
                >
                  <For each={algorithms}>{(a) => <option>{a}</option>}</For>
                </select>
              </Field>
              <Field label="Signature encoding">
                <select
                  value={sig().signature_encoding}
                  onChange={(e) =>
                    change("signature_encoding", e.currentTarget.value)
                  }
                >
                  <For each={["hex", "base64", "base64url", "raw"]}>
                    {(a) => <option>{a}</option>}
                  </For>
                </select>
              </Field>
            </div>
            <Field
              label="Payload expression"
              hint="Combines the exact request values your provider signs."
            >
              <textarea
                required
                class="mono"
                rows={3}
                value={sig().payload}
                onInput={(e) => change("payload", e.currentTarget.value)}
              />
            </Field>
            <Field
              label="Signature expression"
              hint="Locates the signature in the incoming request."
            >
              <textarea
                required
                class="mono"
                rows={2}
                value={sig().signature}
                onInput={(e) => change("signature", e.currentTarget.value)}
              />
            </Field>
            <Show
              when={asymmetric()}
              fallback={
                <div class="form-grid">
                  <Field label="Secret encoding">
                    <select
                      value={sig().secret_encoding}
                      onChange={(e) =>
                        change("secret_encoding", e.currentTarget.value)
                      }
                    >
                      <For
                        each={[
                          "utf8",
                          "ascii",
                          "hex",
                          "base64",
                          "base64url",
                          "raw",
                        ]}
                      >
                        {(a) => <option>{a}</option>}
                      </For>
                    </select>
                  </Field>
                  <Field
                    label="Signing secret"
                    hint={
                      p.hook
                        ? "Keep the stored secret or replace it with your own."
                        : "Generate a secret now, or bring your own. You can replace it after creation."
                    }
                  >
                    <select
                      value={byos() ? "byos" : "default"}
                      onChange={(e) => {
                        setByos(e.currentTarget.value === "byos");
                        setSecret("");
                        key = crypto.randomUUID();
                      }}
                    >
                      <option value="default">
                        {p.hook ? "Keep current secret" : "Generate a secret"}
                      </option>
                      <option value="byos">Bring your own secret (BYOS)</option>
                    </select>
                  </Field>
                  <Show when={byos()}>
                    <Field
                      label={p.hook ? "Replacement secret" : "Your secret"}
                      hint={
                        p.hook
                          ? "The previous secret stops verifying as soon as you save. Match the secret encoding above."
                          : "Paste the exact provider secret and choose its encoding above."
                      }
                    >
                      <input
                        type="password"
                        autocomplete="new-password"
                        required
                        maxLength={4096}
                        value={secret()}
                        onInput={(e) => {
                          setSecret(e.currentTarget.value);
                          key = crypto.randomUUID();
                        }}
                      />
                    </Field>
                  </Show>
                </div>
              }
            >
              <Field label="Public key (PEM)">
                <textarea
                  required
                  class="mono"
                  rows={5}
                  value={sig().public_key || ""}
                  onInput={(e) => change("public_key", e.currentTarget.value)}
                  placeholder="-----BEGIN PUBLIC KEY-----"
                />
              </Field>
            </Show>
            <details>
              <summary>Expression reference</summary>
              <p class="muted small">
                Request blocks: raw_body, raw_body_bytes, body (JSON paths),
                form, multipart, method, url, scheme, authority, host, hostname,
                port, path, query_string, query, headers, cookies. Also hook.id,
                hook.url, secret and key.public.
              </p>
              <p class="mono small break">
                concat · join · sort · sort_keys · utf8 · ascii · url_encode ·
                url_decode · percent_encode · percent_decode · canonicalize_url
                · canonicalize_query · json_encode · form_encode · sha1 · sha256
                · sha384 · sha512 · hex · hex_decode · base64 · base64_decode ·
                base64url · base64url_decode · lowercase · uppercase · trim
              </p>
              <p class="muted small">
                Example: join(separator: ".", request.headers["webhook-id"],
                request.raw_body). Sorting accepts order: asc or desc. Raw
                signatures are exact bytes.
              </p>
            </details>
          </div>
        </details>
        <ErrorBox error={error()} />
        <div class="actions end">
          <Button disabled={busy()} onClick={p.close}>
            Cancel
          </Button>
          <Button primary type="submit" disabled={busy()}>
            {busy() ? "Saving…" : p.hook ? "Save changes" : "Create webhook"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
export default function Hooks(p: { ctx: Context }) {
  const [deleted, setDeleted] = createSignal(false);
  const [search, setSearch] = createSignal("");
  const [selection, setSelection] = createSignal<string[]>([]);
  const [editing, setEditing] = createSignal<Hook | "new">();
  const [detail, setDetail] = createSignal<Hook>();
  const [result, setResult] = createSignal<unknown>();
  const [confirmation, setConfirmation] = createSignal<{
    title: string;
    description: string;
    label: string;
    danger?: boolean;
    run: () => Promise<unknown>;
  }>();
  const data = load(
    () => [p.ctx, deleted()],
    () =>
      api<Page<Hook>>(
        p.ctx,
        scoped(p.ctx, "/hooks?include_deleted=" + deleted()),
      ),
  );
  const items = createMemo(
    () =>
      data
        .data()
        ?.items.filter((h) =>
          (h.name + " " + h.endpoint_key)
            .toLowerCase()
            .includes(search().toLowerCase()),
        ) || [],
  );
  function action(h: Hook, kind: string) {
    const key = crypto.randomUUID();
    const base = scoped(p.ctx, "/hooks/" + h.id);
    const actions: Record<
      string,
      {
        title: string;
        description: string;
        path: string;
        method: string;
        danger?: boolean;
      }
    > = {
      delete: {
        title: "Delete " + h.name + "?",
        description:
          "Incoming requests will stop. You can restore this webhook for 45 days.",
        path: base,
        method: "DELETE",
        danger: true,
      },
      restore: {
        title: "Restore " + h.name + "?",
        description: "Restore this connection from deleted history.",
        path: base + "/restore",
        method: "POST",
      },
      secret: {
        title: "Rotate signing secret?",
        description:
          "Update your provider with the replacement secret. Requests signed with the previous secret will be rejected immediately.",
        path: base + "/secret/rotate",
        method: "POST",
        danger: true,
      },
      endpoint: {
        title: "Rotate endpoint?",
        description:
          "The previous URL will be retired permanently. Update your provider to use the new URL.",
        path: base + "/endpoint/rotate",
        method: "POST",
        danger: true,
      },
    };
    const a = actions[kind];
    setConfirmation({
      ...a,
      label:
        kind === "delete"
          ? "Delete webhook"
          : kind === "restore"
            ? "Restore webhook"
            : "Rotate",
      run: async () => {
        const value = await api(p.ctx, a.path, a.method, undefined, key);
        if (kind === "secret" || kind === "endpoint") setResult(value);
      },
    });
  }
  function enabled(ids: string[], value: boolean) {
    const key = crypto.randomUUID();
    setConfirmation({
      title:
        (value ? "Enable" : "Disable") +
        " " +
        ids.length +
        " connection" +
        (ids.length === 1 ? "" : "s") +
        "?",
      description: value
        ? "These connections will accept incoming requests."
        : "Incoming requests will stop. URLs and history are preserved.",
      label: value ? "Enable" : "Disable",
      run: () =>
        api(
          p.ctx,
          scoped(p.ctx, "/hooks"),
          "PATCH",
          { hook_ids: ids, enabled: value },
          key,
        ),
    });
  }
  return (
    <>
      <div class="page-heading">
        <div>
          <p class="eyebrow">CONNECTIONS</p>
          <h1>Webhooks</h1>
          <p class="muted">
            Connect a provider. Give your Silicon something to listen for.
          </p>
        </div>
        <Button primary onClick={() => setEditing("new")}>
          ＋ Create webhook
        </Button>
      </div>
      <Show when={p.ctx.plane !== "production"}>
        <div class="notice subtle">
          Test environment · Up to 10 hooks, including recoverable deleted
          hooks.
        </div>
      </Show>
      <div class="panel">
        <div class="toolbar">
          <input
            class="search"
            aria-label="Search webhooks"
            placeholder="Search connections…"
            value={search()}
            onInput={(e) => setSearch(e.currentTarget.value)}
          />
          <label class="check">
            <input
              type="checkbox"
              checked={deleted()}
              onChange={(e) => {
                setDeleted(e.currentTarget.checked);
                setSelection([]);
              }}
            />
            Include deleted
          </label>
          <Button onClick={() => data.refresh()} disabled={data.loading()}>
            Refresh
          </Button>
        </div>
        <Show when={selection().length}>
          <div class="selection-bar">
            <span>{selection().length} selected</span>
            <Button onClick={() => enabled(selection(), true)}>
              Enable selected
            </Button>
            <Button onClick={() => enabled(selection(), false)}>
              Disable selected
            </Button>
            <button class="text-button" onClick={() => setSelection([])}>
              Clear
            </button>
          </div>
        </Show>
        <ErrorBox error={data.error()} />
        <Show
          when={!data.loading()}
          fallback={
            <p class="loading" role="status">
              Loading connections…
            </p>
          }
        >
          <Show
            when={items().length}
            fallback={
              <Show when={!data.error()}>
                <Empty
                  title={
                    search()
                      ? "No matching connections"
                      : "Your first connection starts here"
                  }
                >
                  {search()
                    ? "Try another provider name."
                    : "Create a webhook, add its URL to a provider, and watch requests arrive."}
                </Empty>
              </Show>
            }
          >
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>
                      <span class="sr-only">Select</span>
                    </th>
                    <th>Provider</th>
                    <th>Endpoint</th>
                    <th>Status</th>
                    <th>Last received</th>
                    <th>
                      <span class="sr-only">Open</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <For each={items()}>
                    {(h) => (
                      <tr>
                        <td>
                          <input
                            type="checkbox"
                            aria-label={"Select " + h.name}
                            disabled={h.status === "deleted"}
                            checked={selection().includes(h.id)}
                            onChange={(e) =>
                              setSelection(
                                e.currentTarget.checked
                                  ? [...selection(), h.id]
                                  : selection().filter((x) => x !== h.id),
                              )
                            }
                          />
                        </td>
                        <td>
                          <button
                            class="text-button strong"
                            onClick={() => setDetail(h)}
                          >
                            {h.name}
                          </button>
                          <span class="table-sub">
                            {h.signature.required
                              ? "Signed requests"
                              : "Signature not required"}
                          </span>
                        </td>
                        <td>
                          <code>{h.endpoint_key}</code>{" "}
                          <Copy value={h.endpoint_url} label="Copy URL" />
                        </td>
                        <td>
                          <Badge value={h.status} />
                        </td>
                        <td>{date(h.last_received_at)}</td>
                        <td>
                          <button
                            class="text-button"
                            onClick={() => setDetail(h)}
                          >
                            Manage →
                          </button>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        </Show>
        <div class="panel-footer">
          {items().length} connections shown{" "}
          <span class="muted">{p.ctx.silicon}</span>
        </div>
      </div>
      <Show when={editing()}>
        {(h) => (
          <HookForm
            ctx={p.ctx}
            hook={h() === "new" ? undefined : (h() as Hook)}
            close={() => setEditing(undefined)}
            done={async (value) => {
              await data.refresh();
              setEditing(undefined);
              if (value.signing_secret)
                setResult({
                  name: value.name,
                  endpoint_url: value.endpoint_url,
                  signing_secret: value.signing_secret,
                });
            }}
          />
        )}
      </Show>
      <Show when={detail()}>
        {(h) => (
          <Modal title={h().name} close={() => setDetail(undefined)} wide>
            <div class="detail-meta">
              <Badge value={h().status} />
              <code>{h().id}</code>
            </div>
            <p class="muted">{h().description || "No description."}</p>
            <Field label="Webhook URL">
              <div class="copy-field">
                <input readonly value={h().endpoint_url} />
                <Copy value={h().endpoint_url} />
              </div>
            </Field>
            <dl class="facts">
              <dt>Verification</dt>
              <dd>
                {h().signature.required
                  ? h().signature.algorithm
                  : "Not required"}
              </dd>
              <dt>Time zone</dt>
              <dd>{h().time_zone}</dd>
              <dt>Last received</dt>
              <dd>{date(h().last_received_at)}</dd>
              <dt>Last blocked</dt>
              <dd>{date(h().last_blocked_at)}</dd>
              <dt>Created</dt>
              <dd>{date(h().created_at)}</dd>
              <Show when={h().recoverable_until}>
                <dt>Recoverable until</dt>
                <dd>{date(h().recoverable_until)}</dd>
              </Show>
            </dl>
            <details>
              <summary>Current signing policy</summary>
              <pre tabIndex={0}>{JSON.stringify(h().signature, null, 2)}</pre>
            </details>
            <div class="actions wrap">
              <Show
                when={h().status !== "deleted"}
                fallback={
                  <Button
                    primary
                    onClick={() => {
                      action(h(), "restore");
                      setDetail(undefined);
                    }}
                  >
                    Restore webhook
                  </Button>
                }
              >
                <Button
                  primary
                  onClick={() => {
                    setEditing(h());
                    setDetail(undefined);
                  }}
                >
                  Edit connection
                </Button>
                <Button
                  onClick={() => {
                    enabled([h().id], h().status !== "active");
                    setDetail(undefined);
                  }}
                >
                  {h().status === "active" ? "Disable" : "Enable"}
                </Button>
                <Button
                  onClick={() => {
                    action(h(), "endpoint");
                    setDetail(undefined);
                  }}
                >
                  Rotate URL
                </Button>
                <Button
                  onClick={() => {
                    action(h(), "secret");
                    setDetail(undefined);
                  }}
                >
                  Rotate secret
                </Button>
                <Button
                  danger
                  onClick={() => {
                    action(h(), "delete");
                    setDetail(undefined);
                  }}
                >
                  Delete
                </Button>
              </Show>
            </div>
          </Modal>
        )}
      </Show>
      <Show when={confirmation()}>
        {(c) => (
          <Confirm
            title={c().title}
            description={c().description}
            label={c().label}
            destructive={c().danger}
            action={c().run}
            close={() => setConfirmation(undefined)}
            done={async () => {
              await data.refresh();
              setConfirmation(undefined);
              setSelection([]);
            }}
          />
        )}
      </Show>
      <Show when={result()}>
        <SecretResult value={result()} close={() => setResult(undefined)} />
      </Show>
    </>
  );
}
