import { Show } from "solid-js";
import { api, date, type Context, type Environment, type Session } from "./api";
import { load } from "./resource";
import { Badge, Button, ErrorBox } from "./ui";

export default function Environments(p: {
  ctx: Context;
  session: Session;
  refreshSession: () => Promise<unknown>;
  select: (id: string) => void;
  attach: () => void;
  login: () => void;
}) {
  const current = load(
    () => p.ctx.plane !== "production" && p.ctx.plane,
    () => api<Environment>(p.ctx, "/api/v2/testing-session"),
  );
  return (
    <div class="stack">
      <div class="page-heading">
        <div>
          <h1>Test environments</h1>
          <p class="muted">
            Use the same Hook workflows and permissions with isolated sandbox
            data.
          </p>
        </div>
        <Button primary onClick={p.attach}>
          Select with app_secret
        </Button>
      </div>
      <div class="panel">
        <div class="panel-body stack">
          <h2>Start testing</h2>
          <ol>
            <li>
              Create a sandbox and import Hook in{" "}
              <a href="https://iam.teamofsilicons.com">Silicon IAM</a>.
            </li>
            <li>
              Select it here using its Hook application <code>app_secret</code>.
            </li>
            <li>
              Sign in with a test SLT or the public ID of an active Carbon or
              Silicon in that sandbox.
            </li>
          </ol>
          <p>
            The application secret selects a sandbox. Your signed-in identity
            controls what you can do. Production and test sessions stay
            separate.
          </p>
          <p>
            <a href="https://docs.iam.teamofsilicons.com/api/testing-environments/">
              Manage sandbox identities and lifecycle in IAM ↗
            </a>
          </p>
        </div>
      </div>
      <Show when={p.ctx.plane !== "production"}>
        <div class="panel">
          <div class="panel-title">
            <h2>Selected sandbox</h2>
            <Badge value="Test" />
          </div>
          <div class="panel-body stack">
            <ErrorBox error={current.error()} />
            <Show when={current.data()}>
              {(env) => (
                <>
                  <h3>{env().name}</h3>
                  <p>{env().description || "No description."}</p>
                  <dl class="facts">
                    <dt>Environment</dt>
                    <dd class="mono">{env().id}</dd>
                    <dt>Organization</dt>
                    <dd>{env().org_id}</dd>
                    <dt>Last activity</dt>
                    <dd>{date(env().last_activity_at)}</dd>
                  </dl>
                </>
              )}
            </Show>
            <div class="actions">
              <Button onClick={p.login}>Sign in as test identity</Button>
              <Button onClick={() => current.refresh()}>Refresh</Button>
              <Button onClick={() => p.select("production")}>
                Exit testing mode
              </Button>
            </div>
          </div>
        </div>
      </Show>
      <div class="notice subtle">
        Live updates are currently unavailable in test environments. You can
        still create webhooks and inspect received events. Invalid or revoked
        sandbox secrets return an error.
      </div>
    </div>
  );
}
