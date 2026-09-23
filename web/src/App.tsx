import {
  createSignal,
  createMemo,
  createEffect,
  onCleanup,
  For,
  Show,
  Switch,
  Match,
} from "solid-js";
import {
  api,
  telemetryEnabled,
  setTelemetry,
  track,
  request,
  scoped,
  date,
  message,
  type Context,
  type Hook,
  type Page,
  type Session,
  type Event,
} from "./api";
import { load } from "./resource";
import {
  Badge,
  Brand,
  Button,
  Confirm,
  Copy,
  CredentialFile,
  Empty,
  ErrorBox,
  EventDetail,
  EventTable,
  Field,
  Modal,
  SecretResult,
} from "./ui";
import Hooks from "./Hooks";
import History from "./History";
import Deliveries, { Live } from "./Deliveries";
import Environments from "./Environments";
const sections = [
  ["overview", "Overview", "◫"],
  ["hooks", "Webhooks", "⌘"],
  ["events", "Events", "▤"],
  ["blocked", "Blocked requests", "⊘"],
  ["deliveries", "Deliveries", "⇥"],
  ["live", "Live stream", "◉"],
  ["testing", "Testing environments", "◇"],
  ["connections", "Connections & setup", "⚙"],
] as const;
function preferences(): Context {
  try {
    const p = JSON.parse(localStorage.getItem("hook.context") || "{}");
    return {
      plane: typeof p.plane === "string" ? p.plane : "production",
      org: typeof p.org === "string" ? p.org : "",
      silicon: typeof p.silicon === "string" ? p.silicon : "",
    };
  } catch {
    return { plane: "production", org: "", silicon: "" };
  }
}
export default function App() {
  const [ctx, setCtx] = createSignal<Context>(preferences());
  const [route, setRoute] = createSignal(
    location.hash.slice(1).split("?")[0] || "overview",
  );
  const [dialog, setDialog] = createSignal<"login" | "attach">();
  const [menu, setMenu] = createSignal(false);
  const [error, setError] = createSignal<unknown>(
    location.hash.includes("auth_error=1")
      ? new Error("IAM sign-in could not be completed. Please try again.")
      : undefined,
  );
  let iamReturned = location.hash.includes("iam_signed_in=1");
  const session = load(
    () => true,
    () => request<Session>("/console/session"),
  );
  const current = () =>
    session.data()?.planes.find((p) => p.id === ctx().plane);
  const ready = () => !!current()?.authenticated;
  const navigate = () => {
    setRoute(location.hash.slice(1).split("?")[0] || "overview");
    setMenu(false);
  };
  window.addEventListener("hashchange", navigate);
  onCleanup(() => window.removeEventListener("hashchange", navigate));
  const context = (patch: Partial<Context>) => {
    const next = { ...ctx(), ...patch };
    setCtx(next);
    try {
      localStorage.setItem("hook.context", JSON.stringify(next));
    } catch {}
  };
  const selectPlane = (id: string) => {
    const p = session.data()?.planes.find((x) => x.id === id);
    context({
      plane: id,
      org: p?.org_id || "",
      silicon: p?.actor?.type === "silicon" ? p.actor.id : "",
    });
    setDialog(undefined);
  };
  createEffect(() => {
    if (session.data() && iamReturned) {
      iamReturned = false;
      selectPlane("production");
      history.replaceState(null, "", "#overview");
    } else if (session.data() && !current())
      context({ plane: "production", org: "", silicon: "" });
  });
  const reload = async () => {
    await session.refresh();
  };
  async function signedIn() {
    setDialog(undefined);
    await reload();
    const p = current();
    context({
      org: p?.org_id || ctx().org,
      silicon: p?.actor?.type === "silicon" ? p.actor.id : ctx().silicon,
    });
  }
  const organizations = load(
    () =>
      (ready() || current()?.attached) &&
      ctx().plane + ":" + current()?.expires_at,
    () =>
      request<{ items: { id: string; name: string }[] }>(
        "/console/organizations?plane=" + encodeURIComponent(ctx().plane),
      ),
  );
  createEffect(() => {
    const items = organizations.data()?.items;
    if (!items || organizations.loading()) return;
    if (!items.some((org) => org.id === ctx().org)) {
      const org = items.length === 1 ? items[0].id : "";
      if (ctx().org !== org)
        context({
          org,
          silicon:
            current()?.actor?.type === "silicon" ? current()!.actor!.id : "",
        });
    }
  });
  createEffect(() => {
    if (ready()) void track(ctx(), "page_view", route());
  });
  const needsTarget = () =>
    ["hooks", "events", "blocked", "deliveries", "live"].includes(route());
  return (
    <div class="shell">
      <aside classList={{ sidebar: true, expanded: menu() }}>
        <Brand />
        <div class="context-controls">
          <Field label="ENVIRONMENT">
            <select
              aria-label="Environment"
              value={ctx().plane}
              onChange={(e) => selectPlane(e.currentTarget.value)}
            >
              <For
                each={
                  session.data()?.planes || [
                    { id: "production", name: "Production" },
                  ]
                }
              >
                {(p) => (
                  <option value={p.id}>
                    {p.name}
                    {p.id === "production" ? "" : " · Test"}
                  </option>
                )}
              </For>
            </select>
          </Field>
          <Field label="ORGANIZATION">
            <select
              aria-label="Organization"
              disabled={
                organizations.loading() || !organizations.data()?.items.length
              }
              onChange={(e) =>
                context({ org: e.currentTarget.value, silicon: "" })
              }
            >
              <option value="" selected={!ctx().org}>
                {organizations.loading()
                  ? "Loading organizations…"
                  : "Choose an organization"}
              </option>
              <For each={organizations.data()?.items || []}>
                {(org) => (
                  <option value={org.id} selected={ctx().org === org.id}>
                    {org.name} ({org.id})
                  </option>
                )}
              </For>
            </select>
            <Show when={organizations.error()}>
              <p class="small">
                Could not load organizations.{" "}
                <button
                  class="text-button"
                  onClick={() => organizations.refresh()}
                >
                  Retry
                </button>
              </p>
            </Show>
            <Show when={ready() && organizations.data()?.items.length === 0}>
              <p class="small muted">
                No organizations shared. Continue with IAM to choose
                organizations.
              </p>
            </Show>
          </Field>
          <Field label="SILICON">
            <input
              aria-label="Silicon"
              placeholder="e.g. si:cos"
              value={ctx().silicon}
              onChange={(e) =>
                context({ silicon: e.currentTarget.value.trim() })
              }
            />
          </Field>
        </div>
        <nav aria-label="Main navigation">
          <For each={sections}>
            {(s) => (
              <a
                classList={{ active: route() === s[0] }}
                href={"#" + s[0]}
                aria-current={route() === s[0] ? "page" : undefined}
              >
                <span aria-hidden="true">{s[2]}</span>
                {s[1]}
              </a>
            )}
          </For>
        </nav>
        <div class="sidebar-bottom">
          <a
            href="https://iam.teamofsilicons.com"
            target="_blank"
            rel="noreferrer"
          >
            Silicon IAM ↗
          </a>
          <div class="identity">
            <span class="avatar">
              {current()?.actor?.id[0]?.toUpperCase() || "S"}
            </span>
            <div>
              <strong>{current()?.actor?.id || "Not signed in"}</strong>
              <small>
                {current()?.actor?.type || "Connect an IAM identity"}
              </small>
            </div>
          </div>
        </div>
      </aside>
      <div class="main-shell">
        <header class="topbar">
          <div class="actions">
            <button
              class="icon-button mobile-menu"
              aria-label="Toggle navigation"
              aria-expanded={menu()}
              onClick={() => setMenu(!menu())}
            >
              ☰
            </button>
            <span>Silicon / Hook</span>
            <span class="topbar-separator" />
            <Badge
              value={ctx().plane === "production" ? "Production" : "Test"}
            />
            <Show when={ctx().plane !== "production"}>
              <span class="small muted truncate">
                Test environment: {current()?.name} ·{" "}
                {current()?.actor?.id || "Not signed in"}
              </span>
              <Button
                onClick={() =>
                  context({ plane: "production", org: "", silicon: "" })
                }
              >
                Exit testing mode
              </Button>
            </Show>
          </div>
          <Button onClick={() => setDialog("login")}>
            {ready() ? "Switch identity" : "Sign in"}
          </Button>
        </header>
        <main id="main-content">
          <ErrorBox error={session.error() || error()} />
          <Show
            when={!!session.data() || !session.loading()}
            fallback={<p class="loading">Loading your workspace…</p>}
          >
            <Show when={session.data()}>
              <Show
                when={!needsTarget() || (ready() && ctx().org && ctx().silicon)}
                fallback={
                  <div class="panel">
                    <Empty
                      title={
                        ready()
                          ? ctx().org
                            ? "Choose a Silicon"
                            : "Choose an organization"
                          : "Connect your identity"
                      }
                    >
                      {ready()
                        ? ctx().org
                          ? "Enter a Silicon ID in the sidebar to open its connections and requests."
                          : "Choose an organization shared through IAM in the sidebar."
                        : ctx().plane === "production"
                          ? "Continue with IAM to sign in and choose your organizations."
                          : "Sign in with an IAM test token for the selected environment."}
                    </Empty>
                    <Show when={!ready()}>
                      <div class="actions centered">
                        <Button onClick={() => setDialog("attach")}>
                          Use test app_secret
                        </Button>
                        <Button primary onClick={() => setDialog("login")}>
                          {ctx().plane === "production"
                            ? "Continue with IAM"
                            : "Sign in to sandbox"}
                        </Button>
                      </div>
                    </Show>
                  </div>
                }
              >
                <Show
                  when={ctx().plane + "|" + ctx().org + "|" + ctx().silicon}
                  keyed
                >
                  {(_key) => (
                    <Switch
                      fallback={
                        <Empty title="Page not found">
                          <a href="#overview">Return to overview</a>
                        </Empty>
                      }
                    >
                      <Match when={route() === "overview"}>
                        <Overview
                          ctx={ctx()}
                          signedIn={ready()}
                          login={() => setDialog("login")}
                        />
                      </Match>
                      <Match when={route() === "hooks"}>
                        <Hooks ctx={ctx()} />
                      </Match>
                      <Match when={route() === "events"}>
                        <History ctx={ctx()} />
                      </Match>
                      <Match when={route() === "blocked"}>
                        <History ctx={ctx()} blocked />
                      </Match>
                      <Match when={route() === "deliveries"}>
                        <Deliveries ctx={ctx()} />
                      </Match>
                      <Match when={route() === "live"}>
                        <Live ctx={ctx()} />
                      </Match>
                      <Match when={route() === "testing"}>
                        <Environments
                          ctx={ctx()}
                          session={session.data()!}
                          refreshSession={reload}
                          select={selectPlane}
                          attach={() => setDialog("attach")}
                          login={() => setDialog("login")}
                        />
                      </Match>
                      <Match when={route() === "connections"}>
                        <Connections
                          ctx={ctx()}
                          session={session.data()!}
                          refresh={reload}
                          login={() => setDialog("login")}
                          attach={() => setDialog("attach")}
                        />
                      </Match>
                    </Switch>
                  )}
                </Show>
              </Show>
            </Show>
          </Show>
        </main>
        <footer>
          <strong>Silicon Hook</strong>
          <span>Webhooks, delivered.</span>
          <a href="#connections">Connection settings ↗</a>
        </footer>
      </div>
      <Show when={dialog() === "login"}>
        <Login
          plane={ctx().plane}
          name={current()?.name || "Production"}
          close={() => setDialog(undefined)}
          done={signedIn}
        />
      </Show>
      <Show when={dialog() === "attach"}>
        <Attach
          close={() => setDialog(undefined)}
          done={async (id) => {
            setDialog(undefined);
            await reload();
            selectPlane(id);
          }}
        />
      </Show>
    </div>
  );
}
function Login(p: {
  plane: string;
  name: string;
  close: () => void;
  done: () => Promise<void>;
}) {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <Show when={p.plane === "production"} fallback={<TokenLogin {...p} />}>
      <Modal title="Sign in to Hook" close={() => !busy() && p.close()}>
        <form
          class="stack"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(undefined);
            try {
              const result = await request<{ authorize_url: string }>(
                "/console/login/start",
                "POST",
                {},
                crypto.randomUUID(),
              );
              location.assign(result.authorize_url);
            } catch (error) {
              setError(error);
              setBusy(false);
            }
          }}
        >
          <p class="muted">Sign in and choose your organizations in IAM.</p>
          <ErrorBox error={error()} />
          <Button type="submit" primary disabled={busy()}>
            {busy() ? "Continuing…" : "Continue with IAM"}
          </Button>
        </form>
      </Modal>
    </Show>
  );
}
function TokenLogin(p: {
  plane: string;
  name: string;
  close: () => void;
  done: () => Promise<void>;
}) {
  const [token, setToken] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  let key = crypto.randomUUID();
  return (
    <Modal title="Sign in to Hook" close={() => !busy() && p.close()}>
      <form
        class="stack"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          try {
            await request(
              "/console/login?plane=" + encodeURIComponent(p.plane),
              "POST",
              { slt: token() },
              key,
            );
            setToken("");
            await p.done();
          } catch (e) {
            setError(e);
          } finally {
            setBusy(false);
          }
        }}
      >
        <p class="muted">
          Use an IAM short-lived token issued for <code>tos&gt;hook</code>.
        </p>
        <div class="notice subtle">
          Signing in to <strong>{p.name}</strong>. Use a test SLT or an existing
          Carbon/Silicon ID from the IAM test world linked to this sandbox.
        </div>
        <Field label="Short-lived token">
          <input
            required
            autofocus
            type="password"
            autocomplete="off"
            value={token()}
            onInput={(e) => {
              setToken(e.currentTarget.value);
              key = crypto.randomUUID();
            }}
            placeholder="Paste your IAM token"
          />
        </Field>
        <CredentialFile
          label="Or load a short-lived token file"
          receive={(value) => {
            setToken(value);
            key = crypto.randomUUID();
          }}
        />
        <p class="small muted">
          Hook never asks for your IAM password. Your access and refresh tokens
          stay in the server-side browser session.
        </p>
        <ErrorBox error={error()} />
        <div class="actions end">
          <Button disabled={busy()} onClick={p.close}>
            Cancel
          </Button>
          <Button type="submit" primary disabled={busy()}>
            {busy() ? "Signing in…" : "Sign in"}
          </Button>
        </div>
        <a
          class="small"
          href="https://auth.iam.teamofsilicons.com"
          target="_blank"
          rel="noreferrer"
        >
          Open Silicon IAM ↗
        </a>
      </form>
    </Modal>
  );
}
function Attach(p: { close: () => void; done: (id: string) => Promise<void> }) {
  const [key, setKey] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<unknown>();
  return (
    <Modal title="Attach a test environment" close={() => !busy() && p.close()}>
      <form
        class="stack"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(undefined);
          try {
            const r = await request<{ id: string }>("/console/attach", "POST", {
              app_secret: key(),
            });
            setKey("");
            await p.done(r.id);
          } catch (e) {
            setError(e);
          } finally {
            setBusy(false);
          }
        }}
      >
        <p class="muted">
          Enter the IAM test application app_secret to select its sandbox. Then
          sign in with a test SLT or an existing test identity ID.
        </p>
        <Field
          label="IAM test app_secret"
          hint="Use the application secret from your IAM sandbox. No root key or manual pairing is needed."
        >
          <input
            autofocus
            required
            type="password"
            autocomplete="off"
            minLength={47}
            maxLength={47}
            value={key()}
            onInput={(e) => setKey(e.currentTarget.value)}
          />
        </Field>
        <CredentialFile label="Or load an app_secret file" receive={setKey} />
        <ErrorBox error={error()} />
        <div class="actions end">
          <Button disabled={busy()} onClick={p.close}>
            Cancel
          </Button>
          <Button primary type="submit" disabled={busy()}>
            {busy() ? "Attaching…" : "Attach environment"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
function Overview(p: { ctx: Context; signedIn: boolean; login: () => void }) {
  const active = () => p.signedIn && p.ctx.org && p.ctx.silicon;
  const hooks = load(
    () => active(),
    () => api<Page<Hook>>(p.ctx, scoped(p.ctx, "/hooks")),
  );
  const events = load(
    () => active(),
    () => api<Page<Event>>(p.ctx, scoped(p.ctx, "/events?limit=5")),
  );
  const [selected, setSelected] = createSignal<Event>();
  return (
    <>
      <div class="page-heading">
        <div>
          <p class="eyebrow">WORKSPACE</p>
          <h1>Your webhooks, in one place.</h1>
          <p class="muted">
            Connections, requests and deliveries for your Silicons.
          </p>
        </div>
        <Show when={active()}>
          <a class="button" href="#live">
            Open live stream →
          </a>
        </Show>
      </div>
      <Show
        when={active()}
        fallback={
          <div class="welcome panel">
            <div>
              <p class="eyebrow">LISTEN. VERIFY. DELIVER.</p>
              <h2>
                A home for every
                <br />
                incoming event.
              </h2>
              <p>
                Connect your providers and keep your Silicons in the loop. Hook
                verifies each request and keeps it ready for delivery.
              </p>
              <div class="actions">
                <Show
                  when={!p.signedIn}
                  fallback={
                    <a class="button primary" href="#connections">
                      Choose your Silicon →
                    </a>
                  }
                >
                  <Button primary onClick={p.login}>
                    Sign in to your workspace →
                  </Button>
                </Show>
                <a class="button" href="#testing">
                  Explore testing
                </a>
              </div>
            </div>
            <img class="welcome-mark" src="/brand/mark.svg" alt="" />
          </div>
        }
      >
        <ErrorBox error={hooks.error()} />
        <div class="stats">
          <a class="stat" href="#hooks">
            <span>Active connections</span>
            <strong>
              {hooks.loading()
                ? "—"
                : (hooks.data()?.items.filter((h) => h.status === "active")
                    .length ?? "—")}
            </strong>
            <small>Manage webhooks →</small>
          </a>
          <a class="stat" href="#hooks">
            <span>Signature required</span>
            <strong>
              {hooks.loading()
                ? "—"
                : (hooks.data()?.items.filter((h) => h.signature.required)
                    .length ?? "—")}
            </strong>
            <small>Verification policies →</small>
          </a>
          <a class="stat" href="#events">
            <span>Latest request</span>
            <strong class="stat-date">
              {events.loading()
                ? "—"
                : date(events.data()?.items[0]?.received_at)}
            </strong>
            <small>Inspect request history →</small>
          </a>
        </div>
        <div class="panel">
          <div class="panel-title">
            <h3>Recent events</h3>
            <a href="#events">View all events →</a>
          </div>
          <ErrorBox error={events.error()} />
          <Show when={events.loading()}>
            <p class="loading">Loading recent events…</p>
          </Show>
          <Show
            when={events.data()?.items.length}
            fallback={
              <Show when={!events.loading() && !events.error()}>
                <Empty title="Waiting for the first request">
                  Add a webhook URL to your provider. Its next request will
                  appear here.
                </Empty>
              </Show>
            }
          >
            <EventTable items={events.data()!.items} select={setSelected} />
          </Show>
        </div>
      </Show>
      <div class="quick-links">
        <a href="#hooks">
          <h3>
            Connect a provider <span>↗</span>
          </h3>
          <p>Create URLs and configure signature verification.</p>
        </a>
        <a href="#testing">
          <h3>
            Test in isolation <span>↗</span>
          </h3>
          <p>Try your integrations in a disposable sandbox.</p>
        </a>
        <a href="#connections">
          <h3>
            Keep delivery running <span>↗</span>
          </h3>
          <p>Inspect delivery status and manage your integration.</p>
        </a>
      </div>
      <Show when={selected()}>
        {(e) => (
          <EventDetail event={e()} close={() => setSelected(undefined)} />
        )}
      </Show>
    </>
  );
}
function Connections(p: {
  ctx: Context;
  session: Session;
  refresh: () => Promise<unknown>;
  login: () => void;
  attach: () => void;
}) {
  const [error, setError] = createSignal<unknown>();
  const [result, setResult] = createSignal<unknown>();
  const [confirm, setConfirm] = createSignal<{
    title: string;
    description: string;
    action: () => Promise<unknown>;
  }>();
  const [busy, setBusy] = createSignal(false);
  const system = load(
    () => true,
    async () => {
      const ctx = { ...p.ctx, plane: "production" };
      const [version, ready, live, negotiation] = await Promise.all([
        api(ctx, "/api/v2/version"),
        api(ctx, "/readyz"),
        api(ctx, "/healthz"),
        api(ctx, "/api/version"),
      ]);
      return { version, ready, live, negotiation };
    },
  );
  const current = () => p.session.planes.find((x) => x.id === p.ctx.plane);
  function action(type: "logout" | "forget" | "refresh") {
    const key = crypto.randomUUID();
    setConfirm({
      title:
        type === "logout"
          ? "Sign out of this identity?"
          : type === "forget"
            ? "Remove this local connection?"
            : "Refresh your session?",
      description:
        type === "logout"
          ? "Revoke the saved sign-in sessions and sign out here. IAM may also invalidate related tokens from the same sign-in."
          : type === "forget"
            ? "Remove this browser’s saved connection and revoke its sign-in sessions. This does not delete the backend environment."
            : "Renew the selected IAM session without changing environments.",
      action: async () => {
        try {
          await request(
            "/console/" + type + "?plane=" + p.ctx.plane,
            "POST",
            {},
            key,
          );
        } finally {
          await p.refresh();
        }
      },
    });
  }
  function connectIam() {
    const key = crypto.randomUUID();
    setConfirm({
      title: "Connect IAM notifications?",
      description:
        "Register this Silicon’s IAM webhook with Hook. IAM must authorize changing its webhook destination; existing integration restrictions may prevent this operation.",
      action: async () => {
        const r = await api(
          p.ctx,
          scoped(p.ctx, "/hooks/iam"),
          "POST",
          undefined,
          key,
        );
        setResult(r);
      },
    });
  }
  const [telemetry, changeTelemetry] = createSignal(telemetryEnabled());
  const command = () =>
    `hook ${p.ctx.plane !== "production" ? "--test " + p.ctx.plane + " " : ""}login --slt-file ./iam-token`;
  return (
    <>
      <section class="panel">
        <h2>Diagnostic telemetry</h2>
        <p>
          Share operational events to help diagnose Hook. Events exclude
          credentials, webhook payloads and form contents. This setting applies
          to this browser.
        </p>
        <label>
          <input
            type="checkbox"
            checked={telemetry()}
            onChange={(e) => {
              const enabled = e.currentTarget.checked;
              setTelemetry(enabled);
              changeTelemetry(enabled);
              void request("/console/session");
            }}
          />{" "}
          Share diagnostic events
        </label>
      </section>
      <div class="page-heading">
        <div>
          <p class="eyebrow">SETUP</p>
          <h1>Connections & setup</h1>
          <p class="muted">
            Your identity, backend connection and delivery tools.
          </p>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">
          <h3>Current identity</h3>
          <Badge
            value={
              current()?.logout_pending
                ? "Sign-out pending"
                : current()?.authenticated
                  ? "Connected"
                  : "Signed out"
            }
          />
        </div>
        <div class="panel-body">
          <dl class="facts">
            <dt>Environment</dt>
            <dd>{current()?.name || "Production"}</dd>
            <dt>Identity</dt>
            <dd>{current()?.actor?.id || "Not signed in"}</dd>
            <dt>Organization</dt>
            <dd>{p.ctx.org || "Choose in the sidebar"}</dd>
            <dt>Silicon</dt>
            <dd>{p.ctx.silicon || "Choose in the sidebar"}</dd>
            <dt>Backend</dt>
            <dd class="mono">{p.session.upstream}</dd>
          </dl>
          <Show when={current()?.logout_pending}>
            <p class="notice">
              This session is disabled here. Retry sign out to finish revoking
              its saved sign-in sessions.
            </p>
          </Show>
          <div class="actions wrap">
            <Button primary onClick={p.login}>
              {current()?.authenticated ? "Switch identity" : "Sign in"}
            </Button>
            <Button onClick={p.attach}>Select test environment</Button>
            <Show when={current()?.authenticated}>
              <Button onClick={() => action("refresh")}>Refresh session</Button>
              <Button onClick={() => action("logout")}>Sign out</Button>
            </Show>
            <Show when={current()?.logout_pending}>
              <Button onClick={() => action("logout")}>Retry sign out</Button>
            </Show>
            <Button danger onClick={() => action("forget")}>
              Forget connection
            </Button>
          </div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">
          <h3>IAM notifications</h3>
        </div>
        <div class="panel-body">
          <p class="muted">
            Route this Silicon’s IAM notifications into Hook so its identity
            events arrive alongside other provider requests.
          </p>
          <Button
            disabled={!current()?.authenticated || !p.ctx.silicon}
            onClick={connectIam}
          >
            Connect IAM
          </Button>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">
          <h3>Integration tools</h3>
          <Badge value="CLI / SDK" />
        </div>
        <div class="panel-body">
          <p>
            Your application handles continuous delivery internally. Use the CLI
            or Rust SDK to manage webhooks and inspect retained events.
          </p>
          <Field label="CLI sign-in">
            <div class="command">
              <code>{command()}</code>
              <Copy value={command()} />
            </div>
          </Field>
          <Show when={p.ctx.plane !== "production"}>
            <p class="small muted">
              First attach the sandbox with{" "}
              <code>hook env use --app-secret-file ./hook-test-app-secret</code>
              .
            </p>
          </Show>
          <pre tabIndex={0}>
            {"hook login status --json\nhook --silicon " +
              (p.ctx.silicon || "si:cos") +
              " list\nhook docs ting-delivery"}
          </pre>
          <details>
            <summary>Rust SDK setup</summary>
            <pre tabIndex={0}>
              {
                "let tokens = client.login(&slt, &Mutation::new()).await?;\nlet client = client\n    .with_token(tokens.access_token.expose())\n    .with_organization(&org);\nlet hooks = client.list_hooks(&silicon, false).await?;"
              }
            </pre>
            <p class="muted small">
              The host owns secure token storage and refresh for the stateless
              SDK. The CLI and browser keep their own separate sessions.
            </p>
          </details>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">
          <h3>Backend status</h3>
          <Button onClick={() => system.refresh()}>Check again</Button>
        </div>
        <div class="panel-body">
          <ErrorBox error={system.error()} />
          <Show when={system.loading()}>
            <p>Checking backend…</p>
          </Show>
          <Show when={system.data()}>
            <Badge value="Ready" />
            <details>
              <summary>Version & compatibility</summary>
              <pre tabIndex={0}>{JSON.stringify(system.data(), null, 2)}</pre>
            </details>
          </Show>
        </div>
      </div>
      <Show when={confirm()}>
        {(c) => (
          <Confirm
            title={c().title}
            description={c().description}
            action={c().action}
            done={() => setConfirm(undefined)}
            close={() => setConfirm(undefined)}
          />
        )}
      </Show>
      <Show when={result()}>
        <SecretResult
          title="IAM connection"
          value={result()}
          close={() => setResult(undefined)}
        />
      </Show>
    </>
  );
}
