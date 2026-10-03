import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, request as httpRequest } from "node:http";
import { config, gateway } from "./gateway.ts";
import { SessionStore } from "./session.ts";
const oldContext = "00000000-0000-4000-8000-000000000001";
const otherContext = "00000000-0000-4000-8000-000000000002";
const nonce = "a".repeat(64);
async function fixture(t: TestContext) {
  const folder = await mkdtemp(join(tmpdir(), "hook-popup-"));
  const cfg = config({
    HOOK_WEB_ORIGIN: "https://gateway.example",
    HOOK_FRONTEND_ORIGIN: "https://hook.example",
    HOOK_API_UPSTREAM: "https://api.example",
    HOOK_TING_UPSTREAM: "https://ting.example",
    HOOK_IAM_API_UPSTREAM: "https://iam.example",
    HOOK_IAM_AUTHORIZE_ORIGIN: "https://auth.example",
    HOOK_SESSION_DIR: folder,
  });
  const store = new SessionStore(folder, cfg.sessionKey),
    id = store.newId(),
    session = await store.read(id);
  const tokens = (type = "carbon", name = "c:old") => ({
    access_token: "access-" + name,
    refresh_token: "refresh-" + name,
    expires_in: 3600,
    actor: { type, id: name },
    org_id: "tos",
    scopes: ["self.identity.read"],
  });
  session.planes.production = {
    contextId: oldContext,
    name: "Production",
    tokens: tokens(),
    expiresAt: Date.now() + 3600000,
  };
  session.contexts = {
    [otherContext]: {
      planeId: "production",
      plane: {
        contextId: otherContext,
        name: "Production",
        tokens: tokens("carbon", "c:other"),
        expiresAt: Date.now() + 3600000,
      },
    },
  };
  await store.save(id, session);
  const state = {
    hookKind: "carbon",
    tingKind: "carbon",
    loginStatus: 200,
    tingStatus: 200,
    statusStatus: 200,
    statusActor: undefined as string | undefined,
    beforeLogin: undefined as (() => Promise<void>) | undefined,
  };
  const calls: {
    path: string;
    method: string;
    key: string | null;
    body: any;
  }[] = [];
  t.mock.method(
    globalThis,
    "fetch",
    async (input: URL | string, init: RequestInit = {}) => {
      const url = new URL(input);
      assert(
        ["api.example", "ting.example", "iam.example"].includes(url.hostname),
      );
      const headers = new Headers(init.headers),
        method = init.method || "GET";
      calls.push({
        path: url.pathname,
        method,
        key: headers.get("idempotency-key"),
        body: init.body ? JSON.parse(String(init.body)) : undefined,
      });
      if (url.pathname === "/api/version")
        return Response.json({
          service: "silicon-hook",
          selected_api_version: "v2",
        });
      if (url.pathname === "/api/v2/auth/iam")
        return Response.json({ app_id: "hook", testing: false });
      if (url.pathname === "/v1/iam") return Response.json({ app_id: "ting" });
      if (url.pathname === "/api/v2/auth/login") {
        await state.beforeLogin?.();
        return Response.json(
          state.loginStatus === 200
            ? tokens(
                state.hookKind,
                state.hookKind === "carbon" ? "c:new" : "si:new",
              )
            : { error: { code: "iam_unavailable", message: "Retry" } },
          { status: state.loginStatus },
        );
      }
      if (url.pathname === "/v1/session" && method === "POST")
        return Response.json(
          state.tingStatus === 200
            ? {
                authenticated: true,
                id: state.tingKind === "carbon" ? "c:new" : "si:new",
                kind: state.tingKind,
                session_token: "ting-session",
              }
            : { error: { code: "unavailable" } },
          { status: state.tingStatus },
        );
      if (url.pathname === "/v1/me")
        return Response.json({
          authenticated: true,
          id: state.tingKind === "carbon" ? "c:new" : "si:new",
          kind: state.tingKind,
          environment: { kind: "production" },
        });
      if (url.pathname === "/api/v1/organizations")
        return Response.json({
          items: [{ id: "org-uuid", org_id: "tos", name: "Team" }],
          page: { has_more: false },
        });
      if (url.pathname === "/v1/orgs")
        return Response.json({
          items: [{ id: "org-uuid", handle: "tos", name: "Team" }],
        });
      if (url.pathname === "/api/v2/auth/status")
        return Response.json(
          {
            authenticated: true,
            actor: {
              type: state.hookKind,
              id:
                state.statusActor ||
                (state.hookKind === "carbon" ? "c:new" : "si:new"),
            },
            org_id: "tos",
          },
          { status: state.statusStatus },
        );
      if (
        (url.pathname === "/v1/session" && method === "DELETE") ||
        url.pathname === "/api/v2/auth/logout"
      )
        return Response.json({});
      throw new Error("Unexpected upstream " + url.pathname);
    },
  );
  let app = gateway(cfg);
  const server = createServer((req, res) => void app.handle(req, res));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  t.after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(folder, { recursive: true, force: true });
  });
  const call = (
    path: string,
    body?: unknown,
    context: string | undefined = oldContext,
    key = "login-request-one",
  ) =>
    new Promise<{ status: number; data: any }>((resolve, reject) => {
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path,
          method: body === undefined ? "GET" : "POST",
          headers: {
            host: "gateway.example",
            origin:
              path === "/auth/callback/complete"
                ? cfg.origin
                : cfg.frontendOrigin,
            "x-hook-frontend": "1",
            "x-hook-telemetry": "off",
            cookie: "__Host-hook-session=" + id,
            ...(context ? { "x-hook-context": context } : {}),
            "content-type": "application/json",
            "idempotency-key": key,
          },
        },
        (res) => {
          let raw = "";
          res.on("data", (chunk) => {
            raw += chunk;
          });
          res.on("end", () =>
            resolve({ status: res.statusCode!, data: JSON.parse(raw) }),
          );
        },
      );
      req.on("error", reject);
      req.end(body === undefined ? undefined : JSON.stringify(body));
    });
  const start = async (
    kind: "carbon" | "silicon",
    popup = true,
    key = "login-request-one",
  ) => {
    const result = await call(
      "/console/login/start",
      { identity_kind: kind, ...(popup ? { popup_nonce: nonce } : {}) },
      oldContext,
      key,
    );
    assert.equal(result.status, 200, JSON.stringify(result.data));
    const url = new URL(result.data.authorize_url);
    assert.equal(url.searchParams.get("identity_kind"), kind);
    assert.equal(url.searchParams.get("display"), popup ? "popup" : null);
    assert.equal(url.searchParams.get("app_ids"), "hook,ting");
    const callback = new URL(url.searchParams.get("redirect_uri")!);
    return {
      state: callback.searchParams.get("state"),
      slts: [
        { app_id: "hook", slt: "hook-slt" },
        { app_id: "ting", slt: "ting-slt" },
      ],
    };
  };
  return {
    cfg,
    store,
    id,
    state,
    calls,
    call,
    start,
    restart: () => {
      app = gateway(cfg);
    },
  };
}
for (const kind of ["carbon", "silicon"] as const) {
  for (const popup of [true, false])
    test(`${kind} paired ${popup ? "popup" : "full-page"} login pins kind and replays exact completion after restart`, async (t) => {
      const f = await fixture(t);
      f.state.hookKind = kind;
      f.state.tingKind = kind;
      const body = await f.start(kind, popup),
        result = await f.call("/auth/callback/complete", body);
      assert.equal(result.status, 200, JSON.stringify(result.data));
      const url = new URL(result.data.redirect_url),
        saved = await f.store.read(f.id),
        context = saved.planes.production.contextId!;
      assert.equal(saved.planes.production.tokens!.actor.type, kind);
      assert(saved.contexts![oldContext]);
      assert.equal(url.searchParams.get("context_id"), popup ? context : null);
      assert.equal(url.searchParams.get("nonce"), popup ? nonce : null);
      assert(!result.data.redirect_url.includes("slt"));
      f.restart();
      const replay = await f.call("/auth/callback/complete", body);
      assert.deepEqual(replay, result);
      assert.equal(
        f.calls.filter((c) => c.path === "/api/v2/auth/login").length,
        1,
      );
      assert.equal(
        f.calls.filter((c) => c.path === "/v1/session" && c.method === "POST")
          .length,
        1,
      );
      const status = await f.call(
        "/console/login/status?identity_kind=" + kind,
        undefined,
        context,
      );
      assert.equal(status.status, 200);
      assert.equal(status.data.planes[0].context_id, context);
      assert.equal(
        (
          await f.call(
            "/console/login/status?identity_kind=" + kind,
            undefined,
            oldContext,
          )
        ).status,
        409,
      );
    });
}
for (const status of [429, 503])
  test(`paired login ${status} retries the stable exchange without issuing another Hook session`, async (t) => {
    const f = await fixture(t),
      body = await f.start("carbon");
    f.state.tingStatus = status;
    assert.equal(
      (await f.call("/auth/callback/complete", body)).status,
      status,
    );
    assert.equal(
      (await f.store.read(f.id)).planes.production.contextId,
      oldContext,
    );
    f.restart();
    f.state.tingStatus = 200;
    assert.equal(
      (await f.call("/auth/callback/complete", { state: body.state })).status,
      200,
    );
    const exchanges = f.calls.filter(
      (c) => c.path === "/v1/session" && c.method === "POST",
    );
    assert.equal(exchanges.length, 2);
    assert.equal(exchanges[0].key, exchanges[1].key);
    assert.deepEqual(exchanges[0].body, exchanges[1].body);
    assert.equal(
      f.calls.filter((c) => c.path === "/api/v2/auth/login").length,
      1,
    );
  });
test("typed pair rejects a different kind before installing either session", async (t) => {
  const f = await fixture(t),
    body = await f.start("silicon");
  assert.equal((await f.call("/auth/callback/complete", body)).status, 403);
  assert.equal(
    (await f.store.read(f.id)).planes.production.contextId,
    oldContext,
  );
});
test("context switch away and back invalidates pending paired login", async (t) => {
  const f = await fixture(t),
    body = await f.start("carbon");
  assert.equal(
    (await f.call("/console/context", { context_id: otherContext })).status,
    200,
  );
  assert.equal(
    (await f.call("/console/context", { context_id: oldContext }, otherContext))
      .status,
    200,
  );
  assert.equal((await f.call("/auth/callback/complete", body)).status, 409);
  assert(!f.calls.some((c) => c.path === "/api/v2/auth/login"));
});
test("nonce cancellation preserves saved accounts and prevents completion replay", async (t) => {
  const f = await fixture(t),
    body = await f.start("carbon");
  assert.equal((await f.call("/auth/callback/complete", body)).status, 200);
  const completed = (await f.store.read(f.id)).planes.production.contextId!;
  assert.equal(
    (await f.call("/console/login/cancel", { nonce }, undefined)).status,
    200,
  );
  const saved = await f.store.read(f.id);
  assert.equal(saved.planes.production.contextId, oldContext);
  assert(saved.contexts![completed]);
  assert.equal((await f.call("/auth/callback/complete", body)).status, 409);
});
test("live popup status fails closed on provider outage and changed identity", async (t) => {
  const f = await fixture(t),
    body = await f.start("carbon");
  assert.equal((await f.call("/auth/callback/complete", body)).status, 200);
  const context = (await f.store.read(f.id)).planes.production.contextId!;
  f.state.statusStatus = 503;
  assert.equal(
    (
      await f.call(
        "/console/login/status?identity_kind=carbon",
        undefined,
        context,
      )
    ).status,
    503,
  );
  f.state.statusStatus = 200;
  f.state.statusActor = "c:wrong";
  assert.equal(
    (
      await f.call(
        "/console/login/status?identity_kind=carbon",
        undefined,
        context,
      )
    ).status,
    409,
  );
});
test("typed start rejects malformed nonce and changed payload under the same key", async (t) => {
  const f = await fixture(t);
  assert.equal(
    (await f.call("/console/login/start", { identity_kind: "robot" })).status,
    422,
  );
  assert.equal(
    (
      await f.call("/console/login/start", {
        identity_kind: "carbon",
        popup_nonce: "short",
      })
    ).status,
    422,
  );
  await f.start("carbon");
  assert.equal(
    (
      await f.call("/console/login/start", {
        identity_kind: "silicon",
        popup_nonce: nonce,
      })
    ).status,
    409,
  );
});
test("same-key start replay retains the original durable attempt", async (t) => {
  const f = await fixture(t),
    first = await f.start("carbon"),
    second = await f.start("carbon");
  assert.equal(first.state, second.state);
  assert.equal(f.calls.filter((c) => c.path === "/api/v2/auth/iam").length, 1);
});
test("cancellation queued behind paired completion restores the previous context", async (t) => {
  const f = await fixture(t),
    body = await f.start("carbon");
  let entered!: () => void, release!: () => void;
  const waiting = new Promise<void>((r) => {
      entered = r;
    }),
    released = new Promise<void>((r) => {
      release = r;
    });
  f.state.beforeLogin = async () => {
    entered();
    await released;
  };
  const completion = f.call("/auth/callback/complete", body);
  await waiting;
  const cancellation = f.call("/console/login/cancel", { nonce }, undefined);
  release();
  assert.equal((await completion).status, 200);
  assert.equal((await cancellation).status, 200);
  assert.equal(
    (await f.store.read(f.id)).planes.production.contextId,
    oldContext,
  );
  assert.equal((await f.call("/auth/callback/complete", body)).status, 409);
});
test("nonce cancellation remains available while interrupted retirement is pending", async (t) => {
  const f = await fixture(t),
    body = await f.start("carbon"),
    saved = await f.store.read(f.id);
  saved.planes.production.logout = { key: "interrupted-retirement" };
  await f.store.save(f.id, saved);
  assert.equal(
    (await f.call("/console/login/cancel", { nonce }, undefined)).status,
    200,
  );
  assert.equal((await f.call("/auth/callback/complete", body)).status, 409);
  assert((await f.store.read(f.id)).planes.production.logout);
});
