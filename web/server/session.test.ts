import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, stat, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { SessionStore } from "./session.ts";
import { allowed, config, gateway } from "./gateway.ts";
import { createServer, request as httpRequest } from "node:http";

test("separate frontend origin can use private gateway sessions; foreign origins cannot", async () => {
  const folder = await mkdtemp(join(tmpdir(), "hook-cors-"));
  const cfg = config({
    HOOK_WEB_ORIGIN: "https://backend.hook.example",
    HOOK_FRONTEND_ORIGIN: "https://hook.example",
    HOOK_SESSION_DIR: folder,
  });
  const app = gateway(cfg);
  const server = createServer(app.handle);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as { port: number };
  const call = (origin: string, method = "GET") =>
    new Promise<{ status: number; headers: Record<string, unknown> }>(
      (resolve) => {
        const req = httpRequest(
          {
            host: "127.0.0.1",
            port: address.port,
            path: "/console/session",
            method,
            headers: {
              host: "backend.hook.example",
              origin,
              "x-hook-frontend": "1",
              "sec-fetch-site": "same-site",
            },
          },
          (res) => {
            res.resume();
            res.on("end", () =>
              resolve({ status: res.statusCode!, headers: res.headers }),
            );
          },
        );
        req.end();
      },
    );
  try {
    const ok = await call(cfg.frontendOrigin);
    assert.equal(ok.status, 200);
    assert.equal(ok.headers["access-control-allow-origin"], cfg.frontendOrigin);
    assert.match(
      String(ok.headers["set-cookie"]),
      /HttpOnly.*SameSite=Lax.*Secure/,
    );
    assert.equal((await call(cfg.frontendOrigin, "OPTIONS")).status, 204);
    const forbidden = await call("https://evil.example");
    assert.equal(forbidden.status, 403);
    assert.equal(forbidden.headers["access-control-allow-origin"], undefined);
    assert.equal((await call("https://evil.example", "OPTIONS")).status, 403);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(folder, { recursive: true, force: true });
  }
});

test("stored credentials are encrypted, bound to the session and owner-only", async () => {
  const folder = await mkdtemp(join(tmpdir(), "hook-web-"));
  try {
    const key = randomBytes(32),
      store = new SessionStore(folder, key),
      id = store.newId(),
      other = store.newId();
    const session = await store.read(id);
    session.planes.test = { name: "Test", key: "example-test-key-secret" };
    await store.save(id, session);
    const raw = await readFile(join(folder, id));
    assert.equal(raw.includes(Buffer.from("example-test-key-secret")), false);
    assert.equal((await stat(join(folder, id))).mode & 0o777, 0o600);
    assert.equal((await stat(folder)).mode & 0o777, 0o700);
    assert.equal(
      (await new SessionStore(folder, key).read(id)).planes.test.key,
      "example-test-key-secret",
    );
    await writeFile(join(folder, other), raw);
    assert.equal((await store.read(other)).planes.test, undefined);
    raw[raw.length - 1] ^= 1;
    await writeFile(join(folder, id), raw);
    assert.equal((await store.read(id)).planes.test, undefined);
  } finally {
    await rm(folder, { recursive: true, force: true });
  }
});

test("concurrent session updates serialize without losing environment isolation", async () => {
  const folder = await mkdtemp(join(tmpdir(), "hook-web-"));
  try {
    const store = new SessionStore(folder, randomBytes(32)),
      id = store.newId();
    await Promise.all(
      ["sandbox-a", "sandbox-b"].map((name) =>
        store.locked(id, async () => {
          const s = await store.read(id);
          s.planes[name] = { name, key: name };
          await store.save(id, s);
        }),
      ),
    );
    const s = await store.read(id);
    assert.equal(s.planes["sandbox-a"].key, "sandbox-a");
    assert.equal(s.planes["sandbox-b"].key, "sandbox-b");
    assert.equal(s.planes.production.key, undefined);
  } finally {
    await rm(folder, { recursive: true, force: true });
  }
});

test("expired sessions cannot recover saved tokens or keys", async () => {
  const folder = await mkdtemp(join(tmpdir(), "hook-web-"));
  try {
    const store = new SessionStore(folder, randomBytes(32)),
      id = store.newId();
    await store.save(id, {
      expires: Date.now() - 1,
      planes: { production: { name: "Production", key: "must-not-survive" } },
    });
    assert.equal((await store.read(id)).planes.production.key, undefined);
    await assert.rejects(store.read("../outside"));
  } finally {
    await rm(folder, { recursive: true, force: true });
  }
});

test("gateway does not expose ingress, IAM receivers, arbitrary auth or unsupported methods", () => {
  for (const path of [
    "/webhook/",
    "/api/v1/auth/login",
    "/api/v1/auth/refresh",
    "/api/v1/iam/events",
    "/silicon/cos:tos/ABC12345",
    "https://example.com/",
    "//example.com/",
  ])
    for (const method of ["GET", "POST", "DELETE"])
      assert.equal(allowed(path, method), false, path);
  assert.equal(allowed("/api/v1/testing-environment/clean", "GET"), false);
  assert.equal(allowed("/api/v1/silicons/cos%3Atos/hooks", "PUT"), false);
  assert.equal(allowed("/api/v1/silicons/cos%3Atos/hooks", "POST"), true);
});

test("production cannot start with insecure or missing session configuration", () => {
  assert.throws(() => config({ NODE_ENV: "production" }));
  const common = {
    NODE_ENV: "production",
    HOOK_SESSION_DIR: "/private/sessions",
    HOOK_SESSION_KEY: randomBytes(32).toString("base64"),
    HOOK_WEB_ORIGIN: "https://hook.example",
    HOOK_API_UPSTREAM: "https://backend.example",
  };
  assert.equal(config(common).origin, "https://hook.example");
  for (const HOOK_API_UPSTREAM of [
    "http://remote.example",
    "https://user:pass@backend.example",
    "https://backend.example/path",
    "https://backend.example?token=bad",
  ])
    assert.throws(() => config({ ...common, HOOK_API_UPSTREAM }));
  assert.throws(() =>
    config({ ...common, HOOK_WEB_ORIGIN: "http://127.0.0.1:4317" }),
  );
});

test("organization discovery uses the selected private session and IAM grant pagination", async (t) => {
  const folder = await mkdtemp(join(tmpdir(), "hook-orgs-"));
  const cfg = config({
    HOOK_WEB_ORIGIN: "https://hook.example",
    HOOK_SESSION_DIR: folder,
  });
  const store = new SessionStore(folder, cfg.sessionKey);
  const id = store.newId();
  const session = await store.read(id);
  session.planes.production.tokens = {
    access_token: "private-production-token",
    refresh_token: "private-refresh",
    expires_in: 3600,
    actor: { type: "carbon", id: "test-user" },
    scopes: [],
  };
  session.planes.production.expiresAt = Date.now() + 3600000;
  const testId = "00000000-0000-7000-8000-000000000001";
  session.planes[testId] = { name: "Sandbox", key: "sandbox-root" };
  await store.save(id, session);
  let calls = 0;
  const fetchMock = t.mock.method(
    globalThis,
    "fetch",
    async (input: URL | string, init: RequestInit) => {
      calls++;
      const url = new URL(input);
      const headers = init.headers as Record<string, string>;
      if (url.pathname === "/api/v1/testing-environment") {
        assert.equal(headers["x-hook-test-key"], "sandbox-root");
        assert.equal(headers.authorization, undefined);
        return Response.json({ org_id: "sandbox-org" });
      }
      assert.equal(url.origin, "https://backend.iam.teamofsilicons.com");
      assert.equal(url.pathname, "/api/v1/organizations");
      assert.equal(headers.authorization, "Bearer private-production-token");
      assert.equal(headers["silicon-iam-api-version"], "v1");
      assert.equal(headers["x-org-id"], undefined);
      assert.equal(headers["x-hook-test-key"], undefined);
      return Response.json(
        url.searchParams.has("cursor")
          ? {
              items: [{ org_id: "second", name: "Second" }],
              page: { has_more: false },
            }
          : {
              items: [
                { org_id: "first", name: "First", private_field: "omit" },
              ],
              page: { has_more: true, next_cursor: "page-two" },
            },
      );
    },
  );
  const app = gateway(cfg),
    server = createServer(app.handle);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  const call = (plane = "production", cookie = true) =>
    new Promise<{ status: number; data: any }>((resolve, reject) => {
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/console/organizations?plane=" + plane,
          headers: {
            host: "hook.example",
            origin: cfg.origin,
            "x-hook-frontend": "1",
            ...(cookie ? { cookie: "__Host-hook-session=" + id } : {}),
          },
        },
        (res) => {
          let body = "";
          res.on("data", (chunk) => (body += chunk));
          res.on("end", () =>
            resolve({ status: res.statusCode!, data: JSON.parse(body) }),
          );
        },
      );
      req.on("error", reject);
      req.end();
    });
  try {
    assert.equal((await call("production", false)).status, 401);
    assert.equal(calls, 0);
    const result = await call();
    assert.equal(result.status, 200);
    assert.deepEqual(result.data, {
      items: [
        { id: "first", name: "First" },
        { id: "second", name: "Second" },
      ],
    });
    assert.equal(calls, 2);
    assert.deepEqual((await call(testId)).data, {
      items: [{ id: "sandbox-org", name: "sandbox-org" }],
    });
    assert.equal(calls, 3);
  } finally {
    fetchMock.mock.restore();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(folder, { recursive: true, force: true });
  }
});
