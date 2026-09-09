import { createSignal, For, Show } from "solid-js";
import {
  api,
  date,
  type Context,
  type Environment,
  type Page,
  type Session,
} from "./api";
import { load } from "./resource";
import {
  Badge,
  Button,
  Confirm,
  CredentialFile,
  Empty,
  ErrorBox,
  Field,
  Modal,
  SecretResult,
} from "./ui";
export default function Environments(p: {
  ctx: Context;
  session: Session;
  refreshSession: () => Promise<unknown>;
  select: (id: string) => void;
  attach: () => void;
  login: () => void;
}) {
  const [status, setStatus] = createSignal("active");
  const [cursors, setCursors] = createSignal<string[]>([]);
  const [modal, setModal] = createSignal<"create" | "iam">();
  const [result, setResult] = createSignal<unknown>();
  const [confirm, setConfirm] = createSignal<{
    title: string;
    description: string;
    action: () => Promise<unknown>;
    typed?: string;
    danger?: boolean;
  }>();
  const production = (): Context => ({ ...p.ctx, plane: "production" });
  const canList = () =>
    p.session.planes.find((x) => x.id === "production")?.authenticated;
  const hasOrganization = () => !!p.ctx.org;
  const environments = load(
    () =>
      canList() && hasOrganization() && [p.ctx.org, status(), cursors().at(-1)],
    () =>
      api<Page<Environment>>(
        production(),
        "/api/v1/testing-environments?status=" +
          status() +
          "&limit=25" +
          (cursors().length ? "&after=" + cursors().at(-1) : ""),
      ),
  );
  const current = load(
    () => p.ctx.plane !== "production" && p.ctx.plane,
    () => api<Environment>(p.ctx, "/api/v1/testing-environment"),
  );
  function action(
    env: Environment,
    kind: "key" | "rotate" | "delete" | "restore",
  ) {
    const key = crypto.randomUUID();
    const map = {
      key: {
        title: "Retrieve environment key?",
        description:
          "The root key grants access to this sandbox. It will be displayed once in this view.",
        method: "GET",
        suffix: "/key",
      },
      rotate: {
        title: "Rotate environment key?",
        description:
          "The old key will stop working immediately. Active streams will disconnect. The replacement is saved for this browser session.",
        method: "POST",
        suffix: "/key/rotate",
      },
      delete: {
        title: "Delete " + env.name + "?",
        description:
          "This sandbox will stop accepting requests. It can be restored for 30 days before permanent removal.",
        method: "DELETE",
        suffix: "",
      },
      restore: {
        title: "Restore " + env.name + "?",
        description:
          "Restore this sandbox and attach its current key to this browser session.",
        method: "POST",
        suffix: "/restore",
      },
    }[kind];
    setConfirm({
      ...map,
      danger: kind === "delete" || kind === "rotate",
      action: async () => {
        let value = await api<Environment>(
          production(),
          "/api/v1/testing-environments/" + env.id + map.suffix,
          map.method,
          undefined,
          key,
        );
        if (kind === "restore")
          value = await api<Environment>(
            production(),
            "/api/v1/testing-environments/" + env.id + "/key",
          );
        if (value?.key)
          setResult({
            environment_id: value.id,
            name: value.name,
            key: value.key,
          });
        await p.refreshSession();
      },
    });
  }
  const clean = () => {
    const key = crypto.randomUUID();
    setConfirm({
      title: "Clean this environment?",
      description:
        "This permanently erases every Hook connection, request, blocked log and delivery cursor in this sandbox. Its name and IAM binding remain. Retired URLs stay reserved.",
      typed: current.data()?.name || "CLEAN",
      danger: true,
      action: () =>
        api(p.ctx, "/api/v1/testing-environment/clean", "POST", undefined, key),
    });
  };
  return (
    <>
      <div class="page-heading">
        <div>
          <p class="eyebrow">SANDBOXES</p>
          <h1>Testing environments</h1>
          <p class="muted">The same Hook features, isolated from production.</p>
        </div>
        <div class="actions">
          <Button onClick={p.attach}>Attach key</Button>
          <Button
            primary
            disabled={!canList() || !hasOrganization()}
            onClick={() => setModal("create")}
          >
            ＋ Create environment
          </Button>
        </div>
      </div>
      <div class="notice subtle">
        10 hooks per environment · Inactive environments retire after 15 days ·
        Deleted environments are recoverable for 30 days.
      </div>
      <Show when={p.ctx.plane !== "production"}>
        <div class="panel">
          <div class="panel-title">
            <h3>Selected sandbox</h3>
            <Badge value="Test" />
          </div>
          <ErrorBox error={current.error()} />
          <Show when={current.data()}>
            {(env) => (
              <div class="panel-body">
                <h2>{env().name}</h2>
                <p class="muted">{env().description || "No description."}</p>
                <dl class="facts">
                  <dt>Environment ID</dt>
                  <dd class="mono">{env().id}</dd>
                  <dt>Generation</dt>
                  <dd>{env().generation}</dd>
                  <dt>Last activity</dt>
                  <dd>{date(env().last_activity_at)}</dd>
                  <dt>Owner</dt>
                  <dd>{env().org_id}</dd>
                </dl>
                <div class="actions">
                  <Button onClick={() => setModal("iam")}>
                    Configure test IAM
                  </Button>
                  <Button danger onClick={clean}>
                    Clean environment
                  </Button>
                  <Button onClick={() => current.refresh()}>Refresh</Button>
                </div>
              </div>
            )}
          </Show>
        </div>
      </Show>
      <Show
        when={canList() && hasOrganization()}
        fallback={
          <div class="panel">
            <Empty
              title={
                canList()
                  ? "Choose an organization"
                  : "Production identity required"
              }
            >
              {canList()
                ? "Choose an organization shared through IAM in the sidebar to view and create testing environments."
                : "Sign in to production to create environments or manage their lifecycle. An attached test key can still inspect, configure and clean its selected sandbox."}
            </Empty>
            <Show when={!canList()}>
              <div class="actions centered">
                <Button onClick={() => p.select("production")}>
                  Switch to production
                </Button>
              </div>
            </Show>
          </div>
        }
      >
        <div class="panel">
          <div class="toolbar">
            <Field label="Status">
              <select
                value={status()}
                onChange={(e) => {
                  setStatus(e.currentTarget.value);
                  setCursors([]);
                }}
              >
                <option value="active">Active</option>
                <option value="deleted">Deleted</option>
                <option value="all">All environments</option>
              </select>
            </Field>
            <Button onClick={() => environments.refresh()}>Refresh</Button>
          </div>
          <ErrorBox error={environments.error()} />
          <Show when={environments.loading()}>
            <p class="loading">Loading environments…</p>
          </Show>
          <Show
            when={!environments.loading() && environments.data()?.items.length}
            fallback={
              <Show when={!environments.loading() && !environments.error()}>
                <Empty title="No environments here">
                  Create a sandbox linked to an IAM test environment, or attach
                  an existing Hook test key.
                </Empty>
              </Show>
            }
          >
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Environment</th>
                    <th>Status</th>
                    <th>Last activity</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={environments.data()?.items}>
                    {(env) => (
                      <tr>
                        <td>
                          <strong>{env.name}</strong>
                          <span class="table-sub mono">{env.id}</span>
                          <span class="table-sub">{env.description}</span>
                        </td>
                        <td>
                          <Badge
                            value={env.deleted_at ? "Deleted" : "Active"}
                          />
                        </td>
                        <td>{date(env.last_activity_at)}</td>
                        <td>
                          <div class="actions wrap">
                            <Show
                              when={!env.deleted_at}
                              fallback={
                                <Button onClick={() => action(env, "restore")}>
                                  Restore
                                </Button>
                              }
                            >
                              <Show
                                when={p.session.planes.some(
                                  (x) => x.id === env.id,
                                )}
                              >
                                <button
                                  class="text-button"
                                  onClick={() => p.select(env.id)}
                                >
                                  Open →
                                </button>
                              </Show>
                              <button
                                class="text-button"
                                onClick={() => action(env, "key")}
                              >
                                Get key
                              </button>
                              <button
                                class="text-button"
                                onClick={() => action(env, "rotate")}
                              >
                                Rotate key
                              </button>
                              <button
                                class="text-button danger-text"
                                onClick={() => action(env, "delete")}
                              >
                                Delete
                              </button>
                            </Show>
                          </div>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
          <div class="panel-footer">
            <span>
              Page {cursors().length + 1} ·{" "}
              {environments.data()?.items.length || 0} environments
            </span>
            <div class="actions">
              <Button
                disabled={!cursors().length || environments.loading()}
                onClick={() => setCursors(cursors().slice(0, -1))}
              >
                ← Previous
              </Button>
              <Button
                disabled={
                  environments.loading() ||
                  (environments.data()?.items.length || 0) < 25
                }
                onClick={() =>
                  setCursors([
                    ...cursors(),
                    environments.data()!.items.at(-1)!.id,
                  ])
                }
              >
                Next →
              </Button>
            </div>
          </div>
        </div>
      </Show>
      <Show when={modal()}>
        {(m) => (
          <EnvironmentForm
            kind={m()}
            ctx={m() === "create" ? production() : p.ctx}
            close={() => setModal(undefined)}
            done={(value) => {
              setModal(undefined);
              void environments.refresh();
              void current.refresh();
              void p.refreshSession();
              if (value.key)
                setResult({
                  name: value.name,
                  environment_id: value.id,
                  key: value.key,
                });
            }}
          />
        )}
      </Show>
      <Show when={confirm()}>
        {(c) => (
          <Confirm
            title={c().title}
            description={c().description}
            typed={c().typed}
            destructive={c().danger}
            action={c().action}
            close={() => setConfirm(undefined)}
            done={() => {
              setConfirm(undefined);
              void environments.refresh();
              void current.refresh();
            }}
          />
        )}
      </Show>
      <Show when={result()}>
        <SecretResult
          title="Environment key"
          value={result()}
          close={() => setResult(undefined)}
        />
      </Show>
    </>
  );
}
function EnvironmentForm(p: {
  kind: "create" | "iam";
  ctx: Context;
  close: () => void;
  done: (env: Environment) => void;
}) {
  const [name, setName] = createSignal("");
  const [description, setDescription] = createSignal("");
  const [iamKey, setIamKey] = createSignal("");
  const [configure, setConfigure] = createSignal(p.kind === "iam");
  const [appId, setAppId] = createSignal("tos>hook");
  const [appSecret, setAppSecret] = createSignal("");
  const [webhookSecret, setWebhookSecret] = createSignal("");
  const [version, setVersion] = createSignal(1);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  let key = crypto.randomUUID();
  async function save(e: SubmitEvent) {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const iam = configure()
        ? {
            app_id: appId(),
            app_secret: appSecret(),
            webhook_secret: webhookSecret(),
            webhook_secret_version: version(),
          }
        : undefined;
      const result = await api<Environment>(
        p.ctx,
        p.kind === "create"
          ? "/api/v1/testing-environments"
          : "/api/v1/testing-environment/iam",
        p.kind === "create" ? "POST" : "PUT",
        p.kind === "create"
          ? {
              name: name(),
              description: description() || null,
              iam_test_key: iamKey(),
              iam,
            }
          : iam,
        key,
      );
      setAppSecret("");
      setWebhookSecret("");
      setIamKey("");
      p.done(result);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title={
        p.kind === "create" ? "Create a test environment" : "Configure test IAM"
      }
      close={() => !busy() && p.close()}
    >
      <form
        class="stack"
        onSubmit={save}
        onInput={() => (key = crypto.randomUUID())}
      >
        <Show when={p.kind === "create"}>
          <Field label="Environment name">
            <input
              required
              maxLength={200}
              value={name()}
              onInput={(e) => setName(e.currentTarget.value)}
              placeholder="e.g. Provider integration tests"
            />
          </Field>
          <Field label="Description (optional)">
            <textarea
              rows={2}
              value={description()}
              onInput={(e) => setDescription(e.currentTarget.value)}
            />
          </Field>
          <Field
            label="IAM test environment key"
            hint="Use a real IAM test environment. Production IAM credentials cannot be used here."
          >
            <input
              required
              type="password"
              autocomplete="off"
              value={iamKey()}
              onInput={(e) => setIamKey(e.currentTarget.value)}
            />
          </Field>
          <CredentialFile
            label="Or load an IAM testing key file"
            receive={setIamKey}
          />
          <label class="check">
            <input
              type="checkbox"
              checked={configure()}
              onChange={(e) => setConfigure(e.currentTarget.checked)}
            />
            Configure the test IAM app now
          </label>
        </Show>
        <Show when={configure()}>
          <div class="notice">
            Use the app credentials from this IAM test world. Reconfiguring IAM
            disconnects active streams.
          </div>
          <Field label="Test app ID">
            <input
              required
              value={appId()}
              onInput={(e) => setAppId(e.currentTarget.value)}
            />
          </Field>
          <Field label="Test app secret">
            <input
              required
              type="password"
              autocomplete="new-password"
              value={appSecret()}
              onInput={(e) => setAppSecret(e.currentTarget.value)}
            />
          </Field>
          <Field label="Webhook signing secret">
            <input
              required
              type="password"
              autocomplete="new-password"
              value={webhookSecret()}
              onInput={(e) => setWebhookSecret(e.currentTarget.value)}
            />
          </Field>
          <Field label="Webhook key version">
            <input
              required
              type="number"
              min="1"
              step="1"
              value={version()}
              onInput={(e) => setVersion(Number(e.currentTarget.value))}
            />
          </Field>
        </Show>
        <ErrorBox error={error()} />
        <div class="actions end">
          <Button disabled={busy()} onClick={p.close}>
            Cancel
          </Button>
          <Button type="submit" primary disabled={busy()}>
            {busy()
              ? "Saving…"
              : p.kind === "create"
                ? "Create environment"
                : "Save IAM configuration"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
