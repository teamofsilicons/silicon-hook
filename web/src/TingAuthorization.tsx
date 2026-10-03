import { createSignal, createEffect, onCleanup, Show } from "solid-js";
import { api, ApiError, message, type Context } from "./api";

type Pending = { authorization_id: string; authorization_url: string };
export function TingAuthorization(p: { ctx: Context }) {
  const [pending, setPending] = createSignal<Pending>();
  const [code, setCode] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [notice, setNotice] = createSignal("");
  let active = true;
  onCleanup(() => {
    active = false;
  });
  let beginKey = crypto.randomUUID(),
    finishKey = crypto.randomUUID();
  createEffect(() => {
    p.ctx.contextId;
    p.ctx.org;
    p.ctx.plane;
    setPending(undefined);
    setCode("");
    setNotice("");
    beginKey = crypto.randomUUID();
    finishKey = crypto.randomUUID();
  });
  async function act(action: () => Promise<void>) {
    setBusy(true);
    setNotice("");
    try {
      await action();
    } catch (e) {
      if (active) {
        if (e instanceof ApiError && e.status === 412) {
          setPending(undefined);
          setCode("");
          beginKey = crypto.randomUUID();
          finishKey = crypto.randomUUID();
        }
        setNotice(message(e));
      }
    } finally {
      if (active) setBusy(false);
    }
  }
  async function start() {
    const result = await api<Pending>(
      p.ctx,
      "/api/v2/delivery/authorization",
      "POST",
      undefined,
      beginKey,
    );
    if (!active) return;
    const url = new URL(result.authorization_url);
    if (
      url.username ||
      url.password ||
      (url.protocol !== "https:" &&
        !(
          url.protocol === "http:" &&
          ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
        ))
    )
      throw new Error("IAM returned an invalid authorization link.");
    setPending(result);
  }
  async function finish() {
    await api(
      p.ctx,
      "/api/v2/delivery/authorization/complete",
      "POST",
      {
        authorization_id: pending()!.authorization_id,
        authorization_code: code().trim(),
      },
      finishKey,
    );
    if (!active) return;
    setCode("");
    setPending(undefined);
    setNotice("Ting authorization saved for this account and organization.");
    beginKey = crypto.randomUUID();
    finishKey = crypto.randomUUID();
  }
  return (
    <section class="panel" aria-label="Ting authorization">
      <div class="panel-title">
        <h3>Ting authorization</h3>
      </div>
      <div class="panel-body">
        <p>
          Approve delivery, registration and receipt access separately in IAM.
          Testing also asks for receiver setup. Use the same account and
          organization in Ting.
        </p>
        <p class="small muted">
          A publisher Silicon must approve from its own account. Manage or
          revoke grants in IAM; signing out keeps approved grants.
        </p>
        <Show
          when={pending()}
          fallback={
            <button disabled={busy() || !p.ctx.org} onClick={() => act(start)}>
              Authorize Ting
            </button>
          }
        >
          <p>
            <a
              href={pending()!.authorization_url}
              target="_blank"
              rel="noopener noreferrer"
            >
              Review permissions in IAM ↗
            </a>
          </p>
          <label>
            Authorization code
            <input
              type="password"
              autocomplete="off"
              value={code()}
              onInput={(e) => setCode(e.currentTarget.value)}
            />
          </label>
          <button
            disabled={busy() || !code().trim()}
            onClick={() => act(finish)}
          >
            Save authorization
          </button>
          <button
            disabled={busy()}
            onClick={() => {
              setPending(undefined);
              setCode("");
              beginKey = crypto.randomUUID();
              finishKey = crypto.randomUUID();
            }}
          >
            Cancel
          </button>
        </Show>
        <p>
          <button
            disabled={busy() || !p.ctx.org}
            onClick={() =>
              act(async () => {
                const result = await api<{ status: string }>(
                  p.ctx,
                  "/api/v2/delivery/authorization",
                );
                if (!active) return;
                setNotice(
                  result.status === "authorized"
                    ? "Ting grants are stored. Every action is verified by Ting."
                    : "Separate Ting authorization is required.",
                );
              })
            }
          >
            Check authorization
          </button>
        </p>
        <Show when={notice()}>
          <p role="status">{notice()}</p>
        </Show>
      </div>
    </section>
  );
}
