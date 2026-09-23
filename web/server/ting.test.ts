import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { WebSocket, WebSocketServer } from "ws";
import { config, gateway, allowed } from "./gateway.ts";
import { SessionStore } from "./session.ts";
import {
  PRODUCTION,
  reference,
  matchesEvent,
  type DeliveryContext,
  type Notification,
} from "./ting.ts";

const actor = { type: "carbon", id: "ca_test" },
  silicon = "si_test",
  org = "tos";
const orgUuid = "a044c552-2e3f-4012-9672-72d1b1518401";
const eid = "00000000-0000-7000-8000-000000000001",
  hid = "00000000-0000-7000-8000-000000000002";
const context: DeliveryContext = {
  appId: "tos>hook",
  org,
  tingOrg: orgUuid,
  actor,
  environmentId: PRODUCTION,
  silicons: [silicon],
};
function event(id = eid) {
  return {
    id,
    org_id: org,
    silicon_id: silicon,
    hook_id: hid,
    delivery_sequence: 1,
    received_at: "2026-09-23T10:00:00Z",
    summary: "stripe triggered at 10:00:00 23-09-2026 Etc/UTC",
    provider: "stripe",
    request: { body: "unaltered provider body" },
  };
}
function notification(id = eid, tingId = "msg_one"): Notification {
  const { provider, request, ...ref } = event(id);
  return {
    id: tingId,
    created_at: "2026-09-23T10:00:01Z",
    type: "tos>hook.webhook.received",
    for: actor.id,
    key: `hook:${id}:${createHash("sha256").update(actor.id).digest("hex")}`,
    data: {
      type: "new_event",
      data: {
        sender: provider,
        metadata: {
          ...ref,
          environment_id: PRODUCTION,
          environment_generation: 0,
        },
      },
    },
    metadata: {},
    read: false,
    silent: false,
  };
}
async function listen(server: Server) {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}
async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), "hook-ting-web-"));
  const state = {
    calls: [] as {
      path: string;
      method: string;
      body: any;
      headers: Record<string, any>;
    }[],
    frames: [] as any[],
    inbox: [] as Notification[],
    events: new Map([[eid, event()]]),
    tingActor: { ...actor },
    tingEnvironment: { kind: "production" } as unknown,
    tingOrgs: [orgUuid],
    contract: "v2",
    service: "silicon-hook",
    failTingOnce: false,
    tingCreated: 0,
    hookLogins: 0,
    refreshes: 0,
    failTingLogout: false,
    failHookLogout: false,
    rejectTingRecovery: false,
    testId: "00000000-0000-7000-8000-000000000099",
    expiredAccess: false,
    denyEventRead: false,
    eventQuota: undefined as number | undefined,
    rateResetAt: 0,
    rateRetryAfter: 12,
    rateGate: undefined as Promise<void> | undefined,
    rateStarted: undefined as (() => void) | undefined,
    limitReceiverScope: false,
    receiverGeneration: 7,
    sourceGeneration: 3,
    receiverLifetime: 25000,
    receiverFailures: 0,
    failReceiverRevoke: false,
    receiverCreated: 0,
    receiverRevoked: [] as string[],
    receiverResults: [] as any[],
    subscriptionGate: undefined as Promise<void> | undefined,
    subscriptionStarted: undefined as (() => void) | undefined,
  };
  const tokens = (access = "hook-access") => ({
    access_token: access,
    refresh_token: "hook-refresh",
    expires_in: 3600,
    actor,
    scopes: [],
  });
  const sessions = new Map<string, any>();
  const hookSessions = new Map<string, any>();
  const receiverOperations = new Map<string, any>();
  const receiverSockets = new Map<WebSocket, any>();
  const receiverScope = () => ({
    app_id: "tos>hook",
    for: actor.id,
    kind: actor.type,
    hook_org_id: org,
    org_id: orgUuid,
    environment: {
      kind: "testing",
      id: state.testId,
      generation: state.receiverGeneration,
    },
  });
  const upstream = createServer(async (req, res) => {
    const url = new URL(req.url!, "http://127.0.0.1");
    let raw = "";
    for await (const part of req) raw += part;
    const body = raw ? JSON.parse(raw) : undefined;
    state.calls.push({
      path: url.pathname + url.search,
      method: req.method!,
      body,
      headers: req.headers,
    });
    const reply = (value: unknown, status = 200) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(value));
    };
    const fail = (status = 404, code = "not_found") =>
      reply({ error: { code } }, status);
    switch (url.pathname) {
      case "/api/version":
        if (
          req.headers["x-hook-test-app-secret"] ||
          req.headers["x-hook-test-key"]
        )
          return fail(403, "forbidden");
        assert.equal(req.headers.authorization, undefined);
        assert.equal(req.headers["silicon-hook-supported-api-versions"], "v2");
        return reply({
          service: state.service,
          selected_api_version: state.contract,
        });
      case "/api/v2/auth/iam":
        return reply({
          app_id: "tos>hook",
          testing: !!(
            req.headers["x-hook-test-key"] ||
            req.headers["x-hook-test-app-secret"]
          ),
          iam_url: upstreamOrigin,
        });
      case "/v1/iam":
        return reply({ app_id: "tos>ting" });
      case "/api/v2/auth/login": {
        state.hookLogins++;
        if (body.slt === "invalid-token") return fail(401, "invalid_slt");
        const key = String(req.headers["idempotency-key"]);
        if (!hookSessions.has(key)) {
          const suffix = hookSessions.size ? `-${hookSessions.size + 1}` : "";
          hookSessions.set(key, {
            ...tokens(`hook-access${suffix}`),
            refresh_token: `hook-refresh${suffix}`,
          });
        }
        return reply(hookSessions.get(key));
      }
      case "/api/v2/auth/refresh":
        state.refreshes++;
        return reply(tokens(`renewed-${state.refreshes}`));
      case "/api/v2/auth/status":
        if (
          state.expiredAccess &&
          req.headers.authorization === "Bearer hook-access"
        )
          return fail(401, "unauthenticated");
        return reply({ authenticated: true, actor, org_id: org });
      case "/api/v2/testing-session":
        return reply({ id: state.testId, name: "Sandbox", org_id: org });
      case "/api/v1/organizations":
        return reply({
          items: [{ id: orgUuid, org_id: org, name: "TOS" }],
          page: { has_more: false },
        });
      case "/v1/session": {
        if (req.method === "DELETE")
          return state.failTingLogout
            ? fail(503, "unavailable")
            : reply({ authenticated: false });
        if (state.rejectTingRecovery) return fail(401, "session_expired");
        const key = String(req.headers["idempotency-key"]);
        if (!sessions.has(key)) {
          state.tingCreated++;
          sessions.set(key, {
            authenticated: true,
            id: state.tingActor.id,
            kind: state.tingActor.type,
            session_token: `ting-private-session${state.tingCreated === 1 ? "" : `-${state.tingCreated}`}`,
          });
        }
        if (state.failTingOnce) {
          state.failTingOnce = false;
          return fail(503, "unavailable");
        }
        return reply(sessions.get(key));
      }
      case "/v1/me":
        return reply({
          authenticated: true,
          id: state.tingActor.id,
          kind: state.tingActor.type,
          environment: state.tingEnvironment,
        });
      case "/v1/orgs":
        return reply({
          items: state.tingOrgs.map((id) => ({ id, name: id, handle: org })),
        });
      case `/api/v2/silicons/${silicon}/delivery/subscription`:
        assert.equal(body, undefined);
        state.subscriptionStarted?.();
        if (state.subscriptionGate) await state.subscriptionGate;
        if (req.method === "DELETE") {
          res.writeHead(204);
          res.end();
          return;
        }
        return reply({
          receiving: true,
          subscription: {
            id: hid,
            recipient_id: actor.id,
            silicon_id: silicon,
            org_id: org,
            created_at: event().received_at,
          },
        });
      case "/api/v2/delivery/receiver": {
        assert.ok(req.headers["x-hook-test-app-secret"]);
        assert.equal(req.headers["x-hook-test-key"], undefined);
        assert.match(
          String(req.headers.authorization),
          /^Bearer hook-access(?:-\d+)?$/,
        );
        if (req.method === "GET") {
          if (state.limitReceiverScope) {
            res.setHeader("retry-after", String(state.rateRetryAfter));
            return fail(429, "rate_limited");
          }
          return reply(receiverScope());
        }
        if (
          body.environment_id !== state.testId ||
          body.generation !== state.receiverGeneration
        )
          return fail(409, "receiver_environment_changed");
        const key = String(req.headers["idempotency-key"]);
        if (!receiverOperations.has(key)) {
          state.receiverCreated++;
          const result = {
            ...receiverScope(),
            receiver_id:
              body.receiver_id || `receiver_${state.receiverCreated}`,
            receiver_token: `ting_recv_${state.receiverCreated.toString(16).padStart(64, "0")}`,
            expires_at: new Date(
              Date.now() + state.receiverLifetime,
            ).toISOString(),
          };
          receiverOperations.set(key, { body: JSON.stringify(body), result });
          state.receiverResults.push(result);
        }
        const operation = receiverOperations.get(key);
        assert.equal(operation.body, JSON.stringify(body));
        if (state.receiverFailures > 0) {
          state.receiverFailures--;
          return fail(503, "unavailable");
        }
        return reply(operation.result);
      }
      case "/v1/receivers/session":
        assert.equal(req.method, "DELETE");
        if (state.failReceiverRevoke) return fail(503, "unavailable");
        state.receiverRevoked.push(String(req.headers.authorization));
        return reply({ revoked: true });
      case "/v1/receivers/inbox": {
        const capability = state.receiverResults.find(
          (item) =>
            `Bearer ${item.receiver_token}` === req.headers.authorization,
        );
        if (
          !capability ||
          capability.environment.generation !== state.receiverGeneration ||
          Date.parse(capability.expires_at) <= Date.now()
        )
          return fail(401, "receiver_expired");
        assert.equal(url.searchParams.get("app_id"), null);
        assert.equal(url.searchParams.get("type"), "tos>hook.webhook.received");
        assert.ok(
          String(req.headers.authorization).startsWith("Bearer ting_recv_"),
        );
        return reply({ items: state.inbox.slice(0, 32) });
      }
      case `/v1/orgs/${orgUuid}/inbox`:
        assert.equal(url.searchParams.get("app_id"), "tos>hook");
        assert.equal(url.searchParams.get("type"), "tos>hook.webhook.received");
        return reply({
          items: state.inbox.slice(0, Number(url.searchParams.get("limit"))),
          ...(state.inbox.length > 32
            ? { next_cursor: "older-notifications" }
            : {}),
        });
      case "/api/v2/auth/logout":
        assert.equal(body, undefined);
        if (state.failHookLogout) return fail(503, "unavailable");
        res.writeHead(204);
        res.end();
        return;
      default:
        if (url.pathname.startsWith(`/api/v2/silicons/${silicon}/events/`)) {
          if (state.denyEventRead) return fail(403, "forbidden");
          if (state.eventQuota !== undefined) {
            if (state.eventQuota === 0) {
              state.rateStarted?.();
              if (state.rateGate) await state.rateGate;
              state.rateResetAt ||= Date.now() + state.rateRetryAfter * 1000;
              if (Date.now() < state.rateResetAt) {
                res.setHeader("retry-after", String(state.rateRetryAfter));
                return fail(429, "rate_limited");
              }
              state.eventQuota = undefined;
            } else state.eventQuota--;
          }
          const id = url.pathname.split("/").pop()!;
          const scoped = !!req.headers["x-hook-test-app-secret"];
          assert.equal(
            url.searchParams.get("environment_id"),
            scoped ? state.testId : PRODUCTION,
          );
          assert.equal(
            url.searchParams.get("environment_generation"),
            scoped ? String(state.sourceGeneration) : "0",
          );
          return state.events.has(id) ? reply(state.events.get(id)) : fail();
        }
        return fail();
    }
  });
  const upstreamOrigin = await listen(upstream);
  const ws = new WebSocketServer({ server: upstream });
  ws.on("connection", (socket) => {
    socket.send(
      JSON.stringify({ op: "ready", receiver_id: "receiver", protocol: "v1" }),
    );
    socket.on("message", (raw) => {
      const frame = JSON.parse(raw.toString());
      state.frames.push(frame);
      if (frame.op === "watch") {
        const capability = state.receiverResults.find(
          (item) => item.receiver_token === frame.receiver_token,
        );
        assert.ok(capability);
        receiverSockets.set(socket, capability);
        const {
          receiver_token: _token,
          hook_org_id: _handle,
          ...description
        } = capability;
        socket.send(
          JSON.stringify({
            ...description,
            op: "watching_inbox",
            request_id: frame.request_id,
          }),
        );
      }
      if (frame.op === "watch_inbox")
        socket.send(
          JSON.stringify({
            op: "watching_inbox",
            request_id: frame.request_id,
            org_id: frame.org_id,
          }),
        );
    });
  });
  const cfg = config({
    HOOK_WEB_ORIGIN: "http://127.0.0.1:1",
    HOOK_API_UPSTREAM: upstreamOrigin,
    HOOK_TING_UPSTREAM: upstreamOrigin,
    HOOK_IAM_API_UPSTREAM: upstreamOrigin,
    HOOK_IAM_AUTHORIZE_ORIGIN: upstreamOrigin,
    HOOK_SESSION_DIR: dir,
  });
  const server = createServer();
  cfg.origin = cfg.frontendOrigin = await listen(server);
  const restart = () => {
    server.removeAllListeners("request");
    server.removeAllListeners("upgrade");
    const app = gateway(cfg);
    server.on("request", app.handle);
    app.attachWs(server);
  };
  restart();
  let cookie = "";
  const call = async (
    path: string,
    method = "GET",
    body?: unknown,
    headers: Record<string, string> = {},
  ) => {
    const res = await fetch(cfg.origin + path, {
      method,
      headers: {
        origin: cfg.frontendOrigin,
        "x-hook-frontend": "1",
        "idempotency-key": "test-operation-key",
        ...(cookie ? { cookie } : {}),
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.headers.has("set-cookie"))
      cookie = res.headers.get("set-cookie")!.split(";")[0];
    const text = await res.text();
    return { status: res.status, data: text ? JSON.parse(text) : undefined };
  };
  const start = async () => {
    const result = await call("/console/login/start", "POST");
    assert.equal(result.status, 200);
    const url = new URL(result.data.authorize_url);
    assert.equal(url.searchParams.get("app_ids"), "tos>hook,tos>ting");
    return new URL(url.searchParams.get("redirect_uri")!).searchParams.get(
      "state",
    )!;
  };
  const pair = [
    { app_id: "tos>hook", slt: "private-hook-slt" },
    { app_id: "tos>ting", slt: "private-ting-slt" },
  ];
  const signIn = async () => {
    const state = await start();
    const result = await call("/auth/callback/complete", "POST", {
      state,
      slts: pair,
    });
    assert.equal(result.status, 200);
    return state;
  };
  const store = new SessionStore(dir, cfg.sessionKey);
  const id = () => cookie.split("=")[1];
  const open = (plane = "production", silicons = [silicon]) => {
    const address = new URL(
      `/console/stream?plane=${plane}&org=${org}&silicon_id=${silicon}`,
      cfg.origin,
    );
    address.protocol = "ws:";
    address.searchParams.delete("silicon_id");
    silicons.forEach((id) => address.searchParams.append("silicon_id", id));
    const remoteClosed = new Promise<void>((resolve) =>
      server.once("upgrade", (_req, socket) =>
        socket.once("close", () => resolve()),
      ),
    );
    const client = new WebSocket(address, {
      headers: { cookie, origin: cfg.frontendOrigin },
    });
    const frames: any[] = [];
    const waiting = new Set<() => void>();
    client.on("message", (raw) => {
      frames.push(JSON.parse(raw.toString()));
      for (const resolve of waiting) resolve();
    });
    const until = async (
      predicate: (frame: any) => boolean,
      timeout = 5000,
    ): Promise<any> => {
      const found = frames.find(predicate);
      if (found) return found;
      return new Promise((resolve, reject) => {
        const done = () => {
          const match = frames.find(predicate);
          if (match) {
            clearTimeout(timer);
            waiting.delete(done);
            resolve(match);
          }
        };
        const timer = setTimeout(() => {
          waiting.delete(done);
          reject(new Error("Expected observer frame was not received"));
        }, timeout);
        waiting.add(done);
      });
    };
    return { client, frames, until, remoteClosed };
  };
  const hint = () => {
    for (const socket of ws.clients) {
      const capability = receiverSockets.get(socket);
      socket.send(
        JSON.stringify(
          capability
            ? {
                op: "inbox_changed",
                org_id: orgUuid,
                app_id: capability.app_id,
                receiver_id: capability.receiver_id,
                environment: capability.environment,
              }
            : { op: "inbox_changed", org_id: orgUuid },
        ),
      );
    }
  };
  const close = async () => {
    for (const socket of ws.clients) socket.terminate();
    server.closeAllConnections();
    upstream.closeAllConnections();
    await Promise.all([
      new Promise<void>((resolve) => server.close(() => resolve())),
      new Promise<void>((resolve) => upstream.close(() => resolve())),
    ]);
    await rm(dir, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 20,
    });
  };
  return {
    state,
    cfg,
    call,
    start,
    pair,
    signIn,
    store,
    id,
    open,
    hint,
    close,
    restart,
    dir,
  };
}

test("paired callback binds exact applications, state and origin before consuming tokens", async () => {
  const f = await fixture();
  try {
    const state = await f.start();
    assert.equal(
      (
        await f.call("/auth/callback/complete", "POST", {
          state: "wrong",
          slts: f.pair,
        })
      ).status,
      403,
    );
    assert.equal(
      (
        await f.call(
          "/auth/callback/complete",
          "POST",
          { state, slts: f.pair },
          { origin: "https://wrong.example" },
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await f.call("/auth/callback/complete", "POST", {
          state,
          slts: [f.pair[0], f.pair[0]],
        })
      ).status,
      422,
    );
    assert.equal(f.state.hookLogins, 0);
    assert.equal(f.state.tingCreated, 0);
    assert.equal(
      (await f.call("/auth/callback/complete", "POST", { state, slts: f.pair }))
        .status,
      200,
    );
    const status = await f.call("/console/session");
    assert.equal(status.data.planes[0].authenticated, true);
    assert.equal(JSON.stringify(status).includes("private"), false);
    const saved = await f.store.read(f.id());
    assert.equal(saved.planes.production.ting?.id, actor.id);
    assert.equal(saved.login?.items, undefined);
    assert.equal(
      (await readFile(join(f.dir, f.id()))).includes(
        Buffer.from("ting-private-session"),
      ),
      false,
    );
    assert.equal(
      (await f.call("/auth/callback/complete", "POST", { state })).status,
      200,
    );
    assert.equal(f.state.hookLogins, 1);
    assert.equal(f.state.tingCreated, 1);
  } finally {
    await f.close();
  }
});

const unverifiedEnvironments: [string, unknown][] = [
  ["missing", undefined],
  ["null", null],
  ["array", [{ kind: "production" }]],
  ["missing kind", {}],
  ["unknown kind", { kind: "unknown" }],
  ["testing", { kind: "testing", id: hid, generation: 1 }],
  ["invalid testing generation", { kind: "testing", id: hid, generation: 0 }],
  ["production with test ID", { kind: "production", id: hid }],
  ["production with generation", { kind: "production", generation: 1 }],
];

test("paired login requires explicit production attestation and retains rejected sessions for cleanup", async () => {
  for (const [name, environment] of unverifiedEnvironments) {
    const f = await fixture();
    try {
      const state = await f.start();
      f.state.tingEnvironment = environment;
      const result = await f.call("/auth/callback/complete", "POST", {
        state,
        slts: f.pair,
      });
      assert.equal(result.status, 409, name);
      assert.equal(
        result.data.error.code,
        "delivery_environment_unverified",
        name,
      );
      let saved = await f.store.read(f.id());
      assert.equal(saved.planes.production.tokens, undefined, name);
      assert.equal(saved.planes.production.ting, undefined, name);
      assert.ok(saved.login?.hook?.tokens, name);
      assert.equal(saved.login?.ting?.token, "ting-private-session", name);
      assert.equal(
        f.state.calls.some((call) =>
          call.path.endsWith("/delivery/subscription"),
        ),
        false,
        name,
      );
      assert.equal(f.state.frames.length, 0, name);
      assert.equal((await f.call("/console/logout", "POST")).status, 200, name);
      saved = await f.store.read(f.id());
      assert.equal(saved.login, undefined, name);
      assert.ok(
        f.state.calls.some(
          (call) =>
            call.path === "/v1/session" &&
            call.method === "DELETE" &&
            call.headers.authorization === "Bearer ting-private-session",
        ),
        name,
      );
      assert.ok(
        f.state.calls.some(
          (call) =>
            call.path === "/api/v2/auth/logout" &&
            call.headers.authorization === "Bearer hook-refresh",
        ),
        name,
      );
    } finally {
      await f.close();
    }
  }
});

test("cached sessions recheck production attestation before registering or opening a delivery watch", async () => {
  const f = await fixture();
  let observer: ReturnType<typeof f.open> | undefined;
  try {
    await f.signIn();
    f.restart();
    for (const [name, environment] of unverifiedEnvironments) {
      f.state.tingEnvironment = environment;
      observer = f.open();
      const error = await observer.until((frame) => frame.type === "error");
      assert.equal(error.data.code, "delivery_environment_unverified", name);
      assert.equal(error.data.retryable, false, name);
      assert.equal(error.data.fatal, true, name);
      await observer.remoteClosed;
      assert.equal(
        observer.frames.some((frame) => frame.type === "ready"),
        false,
        name,
      );
      assert.equal(
        f.state.calls.some((call) =>
          call.path.endsWith("/delivery/subscription"),
        ),
        false,
        name,
      );
      assert.equal(f.state.frames.length, 0, name);
      assert.equal(
        (await f.store.read(f.id())).planes.production.ting?.token,
        "ting-private-session",
        name,
      );
    }
    assert.equal((await f.call("/console/logout", "POST")).status, 200);
  } finally {
    observer?.client.terminate();
    await f.close();
  }
});

test("uncertain paired exchange resumes from encrypted partial state after gateway restart", async () => {
  const f = await fixture();
  try {
    f.state.failTingOnce = true;
    const state = await f.start();
    assert.equal(
      (await f.call("/auth/callback/complete", "POST", { state, slts: f.pair }))
        .status,
      503,
    );
    const partial = await f.store.read(f.id());
    assert.equal(partial.planes.production.tokens, undefined);
    assert.ok(partial.login?.hook?.tokens);
    const started = partial.login!.started!;
    f.restart();
    assert.equal(
      (
        await f.call("/auth/callback/complete", "POST", {
          state,
          slts: [f.pair[0], { ...f.pair[1], slt: "different" }],
        })
      ).status,
      409,
    );
    assert.equal(
      (await f.call("/auth/callback/complete", "POST", { state })).status,
      200,
    );
    assert.equal(f.state.hookLogins, 1);
    assert.equal(f.state.tingCreated, 1);
    const attempts = f.state.calls.filter(
      (call) => call.path === "/v1/session",
    );
    assert.equal(attempts.length, 2);
    assert.equal(
      attempts[0].headers["idempotency-key"],
      attempts[1].headers["idempotency-key"],
    );
    assert.deepEqual(attempts[0].body, attempts[1].body);
    assert.equal(
      (await f.store.read(f.id())).planes.production.expiresAt,
      started + 3600000,
    );
  } finally {
    await f.close();
  }
});

test("paired replacement retains new credentials while failed retirement disables old session locally", async () => {
  const f = await fixture();
  try {
    await f.signIn();
    const state = await f.start();
    f.state.failTingLogout = true;
    const pair = f.pair.map((item) => ({ ...item, slt: item.slt + "-new" }));
    assert.equal(
      (await f.call("/auth/callback/complete", "POST", { state, slts: pair }))
        .status,
      503,
    );
    let saved = await f.store.read(f.id());
    assert.equal(saved.planes.production.tokens?.refresh_token, "hook-refresh");
    assert.equal(saved.login?.hook?.tokens?.refresh_token, "hook-refresh-2");
    assert.ok(saved.planes.production.logout);
    const session = await f.call("/console/session");
    assert.equal(session.data.planes[0].authenticated, false);
    assert.equal(session.data.planes[0].logout_pending, true);
    const before = f.state.calls.length;
    for (const [path, method] of [
      ["/console/organizations", "GET"],
      ["/console/refresh", "POST"],
      ["/console/proxy/api/v2/silicons/si_test/hooks", "GET"],
    ])
      assert.equal(
        (await f.call(path, method)).data.error.code,
        "logout_pending",
      );
    assert.equal(f.state.calls.length, before);
    f.state.failTingLogout = false;
    assert.equal(
      (await f.call("/auth/callback/complete", "POST", { state })).status,
      200,
    );
    saved = await f.store.read(f.id());
    assert.equal(
      saved.planes.production.tokens?.refresh_token,
      "hook-refresh-2",
    );
    assert.equal(saved.planes.production.ting?.token, "ting-private-session-2");
    assert.equal(saved.planes.production.logout, undefined);
    assert.equal(f.state.hookLogins, 2);
    assert.equal(f.state.tingCreated, 2);
    const revocations = f.state.calls.filter(
      (call) =>
        call.path === "/api/v2/auth/logout" ||
        (call.path === "/v1/session" && call.method === "DELETE"),
    );
    assert.ok(
      revocations.every(
        (call) => !String(call.headers.authorization).endsWith("-2"),
      ),
    );
  } finally {
    await f.close();
  }
});

test("logout settles an uncertain paired exchange and revokes both recovered credentials", async () => {
  const f = await fixture();
  try {
    const state = await f.start();
    f.state.failTingOnce = true;
    assert.equal(
      (await f.call("/auth/callback/complete", "POST", { state, slts: f.pair }))
        .status,
      503,
    );
    assert.equal((await f.call("/console/logout", "POST")).status, 200);
    const saved = await f.store.read(f.id());
    assert.equal(saved.login, undefined);
    assert.equal(saved.planes.production.tokens, undefined);
    assert.equal(f.state.tingCreated, 1);
    assert.equal(
      f.state.calls.filter(
        (call) => call.path === "/v1/session" && call.method === "POST",
      ).length,
      2,
    );
    assert.ok(
      f.state.calls.some(
        (call) => call.path === "/v1/session" && call.method === "DELETE",
      ),
    );
    assert.ok(
      f.state.calls.some(
        (call) =>
          call.path === "/api/v2/auth/logout" &&
          call.headers.authorization === "Bearer hook-refresh",
      ),
    );
  } finally {
    await f.close();
  }
});

test("a crash before the exchange reply preserves uncertainty after Ting's replay window expires", async () => {
  const f = await fixture();
  try {
    const state = await f.start();
    f.state.failTingOnce = true;
    assert.equal(
      (await f.call("/auth/callback/complete", "POST", { state, slts: f.pair }))
        .status,
      503,
    );
    const crashed = await f.store.read(f.id());
    // This is the durable state written before the request; no catch handler
    // runs when the process dies after Ting creates the session.
    crashed.login!.tingOutcome = { inFlight: true };
    await f.store.save(f.id(), crashed);
    f.restart();
    f.state.rejectTingRecovery = true;
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = await f.call("/console/logout", "POST");
      assert.equal(result.status, 409);
      assert.equal(result.data.error.code, "login_cleanup_pending");
      const saved = await f.store.read(f.id());
      assert.equal(saved.login?.tingOutcome?.uncertain, true);
      assert.notEqual(saved.login?.tingOutcome?.rejected, true);
      assert.ok(saved.login?.hook?.tokens);
      assert.ok(saved.login?.items);
    }
    assert.equal(
      f.state.calls.some(
        (call) => call.path === "/v1/session" && call.method === "DELETE",
      ),
      false,
    );
  } finally {
    await f.close();
  }
});

test("manual replacement persists its result and logout also revokes that unfinished new family", async () => {
  const f = await fixture();
  try {
    await f.signIn();
    f.state.failHookLogout = true;
    assert.equal(
      (
        await f.call(
          "/console/login",
          "POST",
          { slt: "new-manual-token" },
          { "idempotency-key": "manual-new-attempt" },
        )
      ).status,
      503,
    );
    let saved = await f.store.read(f.id());
    assert.equal(
      saved.manual?.production.result?.tokens?.refresh_token,
      "hook-refresh-2",
    );
    assert.equal(saved.planes.production.ting, undefined);
    f.state.failHookLogout = false;
    assert.equal((await f.call("/console/logout", "POST")).status, 200);
    saved = await f.store.read(f.id());
    assert.equal(saved.manual?.production, undefined);
    assert.equal(saved.planes.production.tokens, undefined);
    const revoked = f.state.calls
      .filter((call) => call.path === "/api/v2/auth/logout")
      .map((call) => call.headers.authorization);
    assert.ok(revoked.includes("Bearer hook-refresh"));
    assert.ok(revoked.includes("Bearer hook-refresh-2"));
  } finally {
    await f.close();
  }
});

test("rejected SLTs do not trap later logins and successful manual replay uses a secret-free receipt", async () => {
  const f = await fixture();
  try {
    assert.equal(
      (
        await f.call(
          "/console/login",
          "POST",
          { slt: "invalid-token" },
          { "idempotency-key": "manual-invalid-key" },
        )
      ).status,
      401,
    );
    // An error response does not set a new cookie, so first establish the
    // browser session before exercising persistent failed-attempt recovery.
    await f.call("/console/session");
    assert.equal(
      (
        await f.call(
          "/console/login",
          "POST",
          { slt: "invalid-token" },
          { "idempotency-key": "manual-invalid-key" },
        )
      ).status,
      401,
    );
    const headers = { "idempotency-key": "manual-valid-key" };
    assert.equal(
      (await f.call("/console/login", "POST", { slt: "valid-token" }, headers))
        .status,
      200,
    );
    const calls = f.state.hookLogins;
    assert.equal(
      (await f.call("/console/login", "POST", { slt: "valid-token" }, headers))
        .status,
      200,
    );
    assert.equal(f.state.hookLogins, calls);
    const receipt = (await f.store.read(f.id())).manual?.production;
    assert.equal(receipt?.complete, true);
    assert.equal(receipt?.slt, undefined);
    assert.equal(receipt?.result, undefined);
    const state = await f.start();
    assert.equal(
      (
        await f.call("/auth/callback/complete", "POST", {
          state,
          slts: [{ ...f.pair[0], slt: "invalid-token" }, f.pair[1]],
        })
      ).status,
      401,
    );
    assert.equal(
      (
        await f.call("/console/login/start", "POST", undefined, {
          "idempotency-key": "next-batch-attempt",
        })
      ).status,
      200,
    );
  } finally {
    await f.close();
  }
});

test("login rejects mismatched identities, organization grants and incompatible backend contracts", async () => {
  for (const mode of ["actor", "org", "major", "service"]) {
    const f = await fixture();
    try {
      if (mode === "major") f.state.contract = "v1";
      if (mode === "service") f.state.service = "another-service";
      if (mode === "major" || mode === "service") {
        const result = await f.call("/console/login/start", "POST");
        assert.equal(result.status, 502);
        assert.equal(f.state.hookLogins, 0);
        assert.equal(f.state.tingCreated, 0);
        continue;
      }
      if (mode === "actor") f.state.tingActor.id = "another-carbon";
      if (mode === "org") f.state.tingOrgs = ["another-org"];
      const state = await f.start();
      assert.equal(
        (
          await f.call("/auth/callback/complete", "POST", {
            state,
            slts: f.pair,
          })
        ).status,
        403,
      );
      assert.equal(
        (await f.store.read(f.id())).planes.production.tokens,
        undefined,
      );
    } finally {
      await f.close();
    }
  }
});

test("browser watcher validates references, continues after unavailable events, hydrates once and never ACKs", async () => {
  const f = await fixture();
  let observer: ReturnType<typeof f.open> | undefined;
  try {
    await f.signIn();
    const gone = "00000000-0000-7000-8000-000000000003";
    const wrong = notification(eid, "msg_wrong");
    wrong.for = "another-carbon";
    f.state.inbox = [notification(gone, "msg_gone"), wrong, notification()];
    observer = f.open();
    const ready = await observer.until((frame) => frame.type === "ready");
    assert.equal(ready.data.transport, "ting_inbox");
    const received = await observer.until(
      (frame) => frame.type === "new_event",
    );
    assert.deepEqual(received.data.event, event());
    assert.ok(
      observer.frames.some(
        (frame) =>
          frame.data?.code === "event_unavailable" && !frame.data.fatal,
      ),
    );
    assert.ok(
      observer.frames.some(
        (frame) => frame.data?.code === "invalid_notification",
      ),
    );
    assert.equal(
      f.state.calls.filter((call) => call.path.includes(`/events/${eid}`))
        .length,
      1,
    );
    const second = "00000000-0000-7000-8000-000000000004";
    f.state.events.set(second, event(second));
    f.state.inbox.unshift(notification(second, "msg_two"));
    const saved = await f.store.read(f.id());
    saved.planes.production.expiresAt = 0;
    await f.store.save(f.id(), saved);
    f.hint();
    await observer.until(
      (frame) => frame.type === "new_event" && frame.data.ting_id === "msg_two",
    );
    assert.equal(f.state.refreshes, 1);
    assert.ok(
      f.state.calls.some(
        (call) =>
          call.path.endsWith("/delivery/subscription") &&
          call.headers.authorization === "Bearer renewed-1",
      ),
    );
    assert.equal(
      observer.frames.filter(
        (frame) =>
          frame.type === "new_event" && frame.data.ting_id === "msg_one",
      ).length,
      1,
    );
    assert.ok(f.state.frames.every((frame) => frame.op === "watch_inbox"));
    assert.equal(
      f.state.calls.some(
        (call) =>
          call.path.includes("/inbox/read") ||
          call.path.includes("/deliveries"),
      ),
      false,
    );
    const closed = new Promise<void>((resolve) =>
      observer!.client.once("close", () => resolve()),
    );
    assert.equal((await f.call("/console/logout", "POST")).status, 200);
    await closed;
    assert.equal(
      (await f.store.read(f.id())).planes.production.ting,
      undefined,
    );
  } finally {
    observer?.client.terminate();
    await f.close();
  }
});

test("test selector and Hook-only login report unavailable receiving without contacting Ting", async () => {
  const f = await fixture();
  const observers: ReturnType<typeof f.open>[] = [];
  try {
    await f.call("/console/session");
    const saved = await f.store.read(f.id());
    const plane = {
      name: "Production",
      tokens: {
        access_token: "hook-access",
        refresh_token: "hook-refresh",
        expires_in: 3600,
        actor,
        scopes: [],
      },
      expiresAt: Date.now() + 3600000,
    };
    saved.planes.production = plane;
    saved.planes[f.state.testId] = {
      ...plane,
      name: "Sandbox",
      key: "test-selector",
    };
    await f.store.save(f.id(), saved);
    for (const [id, code] of [
      ["production", "delivery_login_required"],
      [f.state.testId, "test_app_selector_required"],
    ]) {
      const observer = f.open(id);
      observers.push(observer);
      const error = await observer.until((frame) => frame.type === "error");
      assert.equal(error.data.code, code);
      assert.equal(error.data.retryable, false);
      assert.equal(
        observer.frames.some((frame) => frame.type === "ready"),
        false,
      );
    }
    assert.equal(
      f.state.calls.some((call) => call.path.startsWith("/v1/")),
      false,
    );
  } finally {
    observers.forEach((observer) => observer.client.terminate());
    await f.close();
  }
});

test("live catchup is bounded and closing during registration stops the remaining Silicon mutations", async () => {
  const f = await fixture();
  const observers: ReturnType<typeof f.open>[] = [];
  let release = () => {};
  try {
    await f.signIn();
    for (let i = 1; i <= 40; i++) {
      const id = `00000000-0000-7000-8000-${String(i).padStart(12, "0")}`;
      f.state.inbox.push(notification(id, `bounded-${i}`));
      f.state.events.set(id, event(id));
    }
    const observer = f.open();
    observers.push(observer);
    await observer.until((frame) => frame.data?.code === "inbox_catchup_limit");
    await observer.until(
      (frame) =>
        frame.type === "new_event" && frame.data.ting_id === "bounded-32",
    );
    assert.equal(
      observer.frames.filter((frame) => frame.type === "new_event").length,
      32,
    );
    assert.equal(
      f.state.calls.filter((call) => call.path.includes("/inbox?")).length,
      1,
    );
    observer.client.terminate();
    await observer.remoteClosed;
    let entered!: () => void;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    f.state.subscriptionStarted = entered;
    f.state.subscriptionGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const before = f.state.calls.filter((call) =>
      call.path.endsWith("/delivery/subscription"),
    ).length;
    const closing = f.open("production", [
      silicon,
      ...Array.from({ length: 99 }, (_, index) => `si_other_${index}`),
    ]);
    observers.push(closing);
    await started;
    closing.client.terminate();
    await closing.remoteClosed;
    release();
    // The session lock provides a deterministic barrier behind the stopped
    // registration task, without timing guesses about fetch completion.
    await f.call("/console/session");
    assert.equal(
      f.state.calls.filter((call) =>
        call.path.endsWith("/delivery/subscription"),
      ).length - before,
      1,
    );
    assert.equal(
      closing.frames.some((frame) => frame.type === "ready"),
      false,
    );
  } finally {
    release();
    observers.forEach((observer) => observer.client.terminate());
    await f.close();
  }
});

test("reference checks reject context and immutable-payload mismatches before hydration", () => {
  const valid = notification();
  const parsed = reference(context, valid);
  assert.equal(matchesEvent(event(), parsed.metadata, parsed.sender), true);
  for (const mutate of [
    (item: any) => {
      item.for = "wrong";
    },
    (item: any) => {
      item.key = "wrong";
    },
    (item: any) => {
      item.type = "tos>other.webhook.received";
    },
    (item: any) => {
      item.data.type = "wrong";
    },
    (item: any) => {
      item.data.data.metadata.org_id = "wrong";
    },
    (item: any) => {
      item.data.data.metadata.environment_id = hid;
    },
    (item: any) => {
      item.data.data.metadata.environment_generation = 1;
    },
    (item: any) => {
      item.data.data.metadata.delivery_sequence = 0;
    },
    (item: any) => {
      item.data.data.metadata.url = "https://evil.example";
    },
  ]) {
    const item = structuredClone(valid);
    mutate(item);
    assert.throws(() => reference(context, item));
  }
  for (const key of [
    "id",
    "org_id",
    "silicon_id",
    "hook_id",
    "delivery_sequence",
    "received_at",
    "summary",
    "provider",
  ])
    assert.equal(
      matchesEvent(
        { ...event(), [key]: "different" },
        parsed.metadata,
        parsed.sender,
      ),
      false,
      key,
    );
  assert.equal(allowed("/api/v1/silicons/si_test/hooks", "GET"), false);
  for (const path of ["deliveries", "deliveries/ack", "deliveries/cursor"])
    for (const method of ["GET", "POST"])
      assert.equal(allowed(`/api/v2/silicons/si_test/${path}`, method), false);
});

async function signInTest(f: Awaited<ReturnType<typeof fixture>>) {
  const tingBefore = f.state.tingCreated;
  const attached = await f.call("/console/attach", "POST", {
    app_secret: `ask_${"a".repeat(43)}`,
  });
  assert.equal(attached.status, 200);
  const login = await f.call(`/console/login?plane=${f.state.testId}`, "POST", {
    slt: "private-test-hook-slt",
  });
  assert.equal(login.status, 200);
  assert.equal(f.state.tingCreated, tingBefore);
}
function testNotification(
  f: Awaited<ReturnType<typeof fixture>>,
  id = eid,
  tingId = "scoped_event",
) {
  const value = notification(id, tingId);
  const ref = (value.data as any).data.metadata;
  ref.environment_id = f.state.testId;
  ref.environment_generation = f.state.sourceGeneration;
  return value;
}

test("app-secret scoped watch hydrates original generation, renews same receiver and keeps capabilities private", async () => {
  const f = await fixture();
  let observer: ReturnType<typeof f.open> | undefined;
  try {
    f.state.receiverLifetime = 11500;
    await signInTest(f);
    f.state.inbox = [testNotification(f)];
    observer = f.open(f.state.testId);
    await observer.until((frame) => frame.type === "new_event");
    await observer.until(
      (frame) =>
        frame.type === "ready" &&
        observer!.frames.filter((x) => x.type === "ready").length >= 2,
    );
    const results = f.state.receiverResults;
    assert.ok(results.length >= 2);
    assert.equal(results[1].receiver_id, results[0].receiver_id);
    assert.notEqual(results[1].receiver_token, results[0].receiver_token);
    const operations = f.state.calls.filter(
      (call) =>
        call.path === "/api/v2/delivery/receiver" && call.method === "POST",
    );
    assert.equal(operations[0].body.generation, 7);
    assert.equal(operations[1].body.receiver_id, results[0].receiver_id);
    assert.notEqual(
      operations[1].headers["idempotency-key"],
      operations[0].headers["idempotency-key"],
    );
    const publicState = await f.call("/console/session");
    assert.ok(
      !JSON.stringify([publicState.data, observer.frames]).includes(
        "ting_recv_",
      ),
    );
    assert.ok(
      !(await readFile(join(f.dir, f.id()))).includes(
        Buffer.from("ting_recv_"),
      ),
    );
    for (const method of ["GET", "POST"])
      assert.equal(allowed("/api/v2/delivery/receiver", method), false);
    assert.ok(f.state.frames.every((frame) => frame.op === "watch"));
    assert.equal(
      f.state.calls.some((call) => call.path === "/v1/session"),
      false,
    );
    assert.equal(
      (await f.call(`/console/logout?plane=${f.state.testId}`, "POST")).status,
      200,
    );
    assert.ok(
      f.state.receiverRevoked.some((value) =>
        value.includes(results.at(-1).receiver_token),
      ),
    );
    const saved = await f.store.read(f.id());
    assert.equal(saved.planes[f.state.testId].receivers, undefined);
    assert.equal(saved.planes[f.state.testId].tokens, undefined);
  } finally {
    observer?.client.terminate();
    await f.close();
  }
});

test("orphaned uncertain bootstrap is recovered and revoked after restart before creating another receiver", async () => {
  const f = await fixture();
  const observers: ReturnType<typeof f.open>[] = [];
  try {
    await signInTest(f);
    f.state.receiverFailures = 2;
    const first = f.open(f.state.testId);
    observers.push(first);
    await first.until((frame) => frame.type === "error");
    await first.remoteClosed;
    await f.call("/console/session"); // Serialize behind the failed close cleanup.
    const pending = await f.store.read(f.id());
    assert.equal(
      Object.keys(pending.planes[f.state.testId].receivers!).length,
      1,
    );
    f.restart();
    const second = f.open(f.state.testId);
    observers.push(second);
    await second.until((frame) => frame.type === "ready");
    const posts = f.state.calls.filter(
      (call) =>
        call.path === "/api/v2/delivery/receiver" && call.method === "POST",
    );
    assert.equal(posts.length, 4);
    for (const retry of posts.slice(1, 3)) {
      assert.equal(
        retry.headers["idempotency-key"],
        posts[0].headers["idempotency-key"],
      );
      assert.deepEqual(retry.body, posts[0].body);
    }
    assert.equal(f.state.receiverCreated, 2);
    assert.equal(f.state.receiverRevoked.length, 1);
    second.client.terminate();
    await second.remoteClosed;
    await f.call("/console/session");
    assert.equal(
      (await f.store.read(f.id())).planes[f.state.testId].receivers,
      undefined,
    );
  } finally {
    observers.forEach((observer) => observer.client.terminate());
    await f.close();
  }
});

test("failed scoped logout retains capability and Hook authority until revocation succeeds", async () => {
  const f = await fixture();
  let observer: ReturnType<typeof f.open> | undefined;
  try {
    await signInTest(f);
    observer = f.open(f.state.testId);
    await observer.until((frame) => frame.type === "ready");
    f.state.failReceiverRevoke = true;
    assert.equal(
      (await f.call(`/console/logout?plane=${f.state.testId}`, "POST")).status,
      503,
    );
    const pending = (await f.store.read(f.id())).planes[f.state.testId];
    assert.ok(pending.logout);
    assert.ok(pending.tokens);
    assert.ok(Object.values(pending.receivers!)[0].capability);
    assert.equal(
      f.state.calls.filter((call) => call.path === "/api/v2/auth/logout")
        .length,
      0,
    );
    f.state.failReceiverRevoke = false;
    assert.equal(
      (await f.call(`/console/logout?plane=${f.state.testId}`, "POST")).status,
      200,
    );
    assert.equal(
      (await f.store.read(f.id())).planes[f.state.testId].receivers,
      undefined,
    );
  } finally {
    observer?.client.terminate();
    await f.close();
  }
});

test("a live scoped generation change stops hydration and revokes its private capability", async () => {
  const f = await fixture();
  let observer: ReturnType<typeof f.open> | undefined;
  try {
    await signInTest(f);
    observer = f.open(f.state.testId);
    await observer.until((frame) => frame.type === "ready");
    f.state.receiverGeneration = 8;
    f.state.inbox = [testNotification(f)];
    f.hint();
    const error = await observer.until((frame) => frame.type === "error");
    assert.equal(error.data.code, "receiver_expired");
    await observer.remoteClosed;
    await f.call("/console/session");
    assert.equal(
      observer.frames.some((frame) => frame.type === "new_event"),
      false,
    );
    assert.equal(f.state.receiverRevoked.length, 1);
  } finally {
    observer?.client.terminate();
    await f.close();
  }
});

test("both observer transports reconcile silent ordinary arrivals without hints or acknowledgments", async () => {
  const f = await fixture();
  const observers: ReturnType<typeof f.open>[] = [];
  try {
    await f.signIn();
    await signInTest(f);
    const production = f.open();
    observers.push(production);
    const scoped = f.open(f.state.testId);
    observers.push(scoped);
    await Promise.all(
      observers.map((observer) =>
        observer.until((frame) => frame.type === "ready"),
      ),
    );
    await f.call("/console/session");
    assert.equal(
      f.state.calls.filter((call) => call.path.includes("/inbox?")).length,
      2,
    );
    const selectedBefore = f.state.calls.filter(
      (call) => call.headers["x-hook-test-app-secret"],
    ).length;
    const normal = notification(eid, "silent_production"),
      test = testNotification(f, eid, "silent_testing");
    normal.silent = test.silent = true;
    f.state.inbox = [normal, test];
    await Promise.all([
      production.until(
        (frame) =>
          frame.type === "new_event" &&
          frame.data.ting_id === "silent_production",
        14000,
      ),
      scoped.until(
        (frame) =>
          frame.type === "new_event" && frame.data.ting_id === "silent_testing",
        14000,
      ),
    ]);
    assert.equal(
      f.state.calls.filter(
        (call) =>
          call.path === "/api/v2/delivery/receiver" && call.method === "GET",
      ).length,
      1,
      "idle inbox reconciliation must reuse the bounded scoped authority",
    );
    assert.equal(
      f.state.calls.filter((call) => call.headers["x-hook-test-app-secret"])
        .length - selectedBefore,
      2,
      "one current Hook auth check plus one authorized payload hydration; no redundant scope lookups",
    );
    assert.ok(
      f.state.frames.every((frame) =>
        ["watch", "watch_inbox"].includes(frame.op),
      ),
    );
    assert.equal(
      f.state.calls.some((call) =>
        /\/inbox\/read|\/deliveries/.test(call.path),
      ),
      false,
    );
  } finally {
    observers.forEach((observer) => observer.client.terminate());
    await Promise.all(observers.map((observer) => observer.remoteClosed));
    await f.call("/console/session");
    await f.close();
  }
});

test("scoped inbox authority never bypasses current Hook payload authorization", async () => {
  const f = await fixture();
  let observer: ReturnType<typeof f.open> | undefined;
  try {
    await signInTest(f);
    observer = f.open(f.state.testId);
    await observer.until((frame) => frame.type === "ready");
    await f.call("/console/session");
    f.state.denyEventRead = true;
    f.state.inbox = [testNotification(f)];
    f.hint();
    const error = await observer.until((frame) => frame.type === "error");
    assert.equal(error.data.code, "forbidden");
    assert.equal(
      observer.frames.some((frame) => frame.type === "new_event"),
      false,
    );
    await observer.remoteClosed;
    await f.call("/console/session");
    assert.equal(f.state.receiverRevoked.length, 1);
  } finally {
    observer?.client.terminate();
    await f.close();
  }
});

test("scoped burst catch-up pauses on quota, renews expired receiver and resumes without repeating emitted rows", async () => {
  const f = await fixture();
  let observer: ReturnType<typeof f.open> | undefined;
  let releaseRate!: () => void;
  f.state.rateGate = new Promise((resolve) => {
    releaseRate = resolve;
  });
  const rateStarted = new Promise<void>((resolve) => {
    f.state.rateStarted = resolve;
  });
  try {
    f.state.receiverLifetime = 11500;
    f.state.eventQuota = 3;
    await signInTest(f);
    const ids = Array.from(
      { length: 32 },
      (_, index) =>
        `00000000-0000-7000-8000-${String(index + 10).padStart(12, "0")}`,
    );
    f.state.inbox = ids.map((id, index) => {
      f.state.events.set(id, event(id));
      return testNotification(f, id, `burst_${index}`);
    });
    observer = f.open(f.state.testId);
    await rateStarted;
    // Queue the scheduled renewal behind the rate-limited hydration's lock.
    // The pause must become visible before that queued operation can proceed.
    await new Promise((resolve) => setTimeout(resolve, 1800));
    releaseRate();
    const limited = await observer.until(
      (frame) => frame.type === "error" && frame.data.code === "rate_limited",
    );
    assert.equal(limited.data.fatal, false);
    assert.equal(limited.data.retryable, true);
    assert.equal(limited.data.retry_after, 12);
    assert.equal(
      observer.frames.filter((frame) => frame.type === "new_event").length,
      3,
    );
    assert.equal(observer.client.readyState, WebSocket.OPEN);
    const callsBefore = f.state.calls.length;
    // The queued lease renewal must not reach upstream during Retry-After.
    await new Promise((resolve) => setTimeout(resolve, 200));
    assert.equal(f.state.calls.length, callsBefore);
    const saved = await f.store.read(f.id());
    assert.equal(
      Object.keys(saved.planes[f.state.testId].receivers!).length,
      1,
    );
    assert.equal(f.state.receiverRevoked.length, 0);
    f.state.receiverLifetime = 30000;
    await observer.until(
      (frame) =>
        frame.type === "new_event" && frame.data.ting_id === "burst_31",
      14000,
    );
    const received = observer.frames.filter(
      (frame) => frame.type === "new_event",
    );
    assert.equal(received.length, 32);
    assert.equal(new Set(received.map((frame) => frame.data.ting_id)).size, 32);
    for (const id of ids.slice(0, 3))
      assert.equal(
        f.state.calls.filter((call) => call.path.includes(`/events/${id}?`))
          .length,
        1,
      );
    const capabilities = f.state.receiverResults;
    assert.equal(capabilities.length, 2);
    assert.ok(Date.parse(capabilities[0].expires_at) < Date.now());
    assert.equal(capabilities[1].receiver_id, capabilities[0].receiver_id);
    assert.notEqual(
      capabilities[1].receiver_token,
      capabilities[0].receiver_token,
    );
    assert.equal(
      f.state.calls.filter(
        (call) =>
          call.path === "/api/v2/delivery/receiver" && call.method === "GET",
      ).length,
      2,
    );
    assert.ok(f.state.frames.every((frame) => frame.op === "watch"));
    assert.equal(JSON.stringify(observer.frames).includes("ting_recv_"), false);
    assert.equal(
      f.state.calls.some((call) =>
        /\/inbox\/read|\/deliveries/.test(call.path),
      ),
      false,
    );
    const silentId = "00000000-0000-7000-8000-000000000090";
    f.state.events.set(silentId, event(silentId));
    const silent = testNotification(f, silentId, "silent_after_backoff");
    silent.silent = true;
    f.state.inbox = [silent];
    // No watch hint or lease renewal: ready must have rearmed periodic scanning.
    await observer.until(
      (frame) =>
        frame.type === "new_event" &&
        frame.data.ting_id === "silent_after_backoff",
      14000,
    );
    assert.equal(f.state.receiverResults.length, 2);
    assert.equal(
      observer.frames.filter((frame) => frame.type === "ready").length,
      2,
    );
  } finally {
    releaseRate();
    observer?.client.terminate();
    if (observer) await observer.remoteClosed;
    await f.call("/console/session");
    await f.close();
  }
});

test("logout cancels scoped quota recovery and revokes the retained receiver", async () => {
  const f = await fixture();
  let observer: ReturnType<typeof f.open> | undefined;
  try {
    f.state.eventQuota = 0;
    f.state.rateRetryAfter = 1;
    await signInTest(f);
    f.state.inbox = [testNotification(f)];
    observer = f.open(f.state.testId);
    await observer.until(
      (frame) => frame.type === "error" && frame.data.code === "rate_limited",
    );
    assert.equal(
      (await f.call(`/console/logout?plane=${f.state.testId}`, "POST")).status,
      200,
    );
    await observer.remoteClosed;
    const calls = f.state.calls.length;
    await new Promise((resolve) => setTimeout(resolve, 1300));
    assert.equal(f.state.calls.length, calls);
    assert.equal(f.state.receiverResults.length, 1);
    assert.equal(f.state.receiverRevoked.length, 1);
    const saved = await f.store.read(f.id());
    assert.equal(saved.planes[f.state.testId].receivers, undefined);
    assert.equal(saved.planes[f.state.testId].tokens, undefined);
  } finally {
    observer?.client.terminate();
    await f.close();
  }
});

test("scoped initial quota failure includes the server retry delay before reconnect", async () => {
  const f = await fixture();
  let observer: ReturnType<typeof f.open> | undefined;
  try {
    await signInTest(f);
    f.state.limitReceiverScope = true;
    observer = f.open(f.state.testId);
    const failure = await observer.until((frame) => frame.type === "error");
    assert.equal(failure.data.code, "rate_limited");
    assert.equal(failure.data.fatal, true);
    assert.equal(failure.data.retryable, true);
    assert.equal(failure.data.retry_after, 12);
    await observer.remoteClosed;
    assert.equal(f.state.receiverCreated, 0);
  } finally {
    observer?.client.terminate();
    await f.close();
  }
});
