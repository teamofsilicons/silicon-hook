import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { freshSession } from "../lib/server/fresh";
import { endSession, locateSession } from "../lib/server/refresh-state";
import { setRefreshStoreForTests } from "../lib/server/refresh-store";
import { refreshSession } from "../lib/server/tokens";
import type { StoredSession } from "../lib/server/session";
import { applyTestEnv, json, mockFetch, tokenBody, TEST_ENV } from "./env";

const account = { uuid: "nln", kind: "carbon" as const, id: "c:ada", display_name: "Ada", pfp_url: null, custodian: null };
const session = (): StoredSession => ({ v: 1, at: "old", rt: "sar_old", ae: Date.now() - 1, re: Date.now() + 86400000, scope: "profile", acct: account });
let restore = () => {};
beforeEach(() => applyTestEnv());
afterEach(() => restore());

test("competing servers share one persisted random operation and converge on one session", async () => {
  const old = session();
  const keys = new Set<string>();
  restore = mockFetch(async (_url, init) => {
    const key = new Headers(init.headers).get("Idempotency-Key")!;
    assert.match(key, /^[0-9a-f-]{36}$/);
    const state = await locateSession(old);
    assert.equal(state.entry.value.operation?.key, key, "the key was committed before the network call");
    keys.add(key);
    await new Promise(resolve => setTimeout(resolve, 15));
    return json(200, tokenBody(1));
  }).restore;
  const results = await Promise.all(Array.from({ length: 8 }, () => refreshSession(old, {})));
  assert.equal(keys.size, 1);
  for (const result of results) assert.ok(result.ok && result.session.rt === "sar_refresh_1");
  assert.equal(new Set(results.map(r => r.ok && r.session.sid)).size, 1);
});

test("a lost response preserves the operation for retry, including after the process cache is gone", async () => {
  const old = session();
  const keys: string[] = [];
  restore = mockFetch((_url, init) => {
    keys.push(new Headers(init.headers).get("Idempotency-Key")!);
    if (keys.length === 1) throw new TypeError("response lost after rotation");
    return json(200, tokenBody(2));
  }).restore;
  assert.equal((await freshSession(old, "api", {})).kind, "unavailable");
  const result = await refreshSession(old, {});
  assert.ok(result.ok && result.session.rt === "sar_refresh_2");
  assert.equal(keys[0], keys[1]);
});

test("expired recovery is saved, then its successor rotates with a new operation key", async () => {
  const old = session();
  const calls: Array<{ token: string; key: string }> = [];
  restore = mockFetch((_url, init) => {
    calls.push({ token: new URLSearchParams(String(init.body)).get("refresh_token")!, key: new Headers(init.headers).get("Idempotency-Key")! });
    if (calls.length === 1) return json(200, { ...tokenBody(3), expires_in: 0, access_token_expires_at: new Date(Date.now() - 60000).toISOString() });
    return json(200, tokenBody(4));
  }).restore;
  const result = await refreshSession(old, {});
  assert.ok(result.ok && result.session.rt === "sar_refresh_4");
  assert.deepEqual(calls.map(c => c.token), ["sar_old", "sar_refresh_3"]);
  assert.notEqual(calls[0].key, calls[1].key);
  const stale = await refreshSession(old, {});
  assert.ok(stale.ok && stale.session.rt === "sar_refresh_4", "a delayed old cookie resolves the latest session");
  assert.equal(calls.length, 2);
});

test("sign-out wins against an in-flight refresh and against a late cookie", async () => {
  const old = session();
  restore = mockFetch(async () => {
    await endSession(old);
    return json(200, tokenBody(5));
  }).restore;
  const result = await freshSession(old, "api", {});
  assert.equal(result.kind, "signed_out");
  assert.equal((await freshSession(old, "api", {})).kind, "signed_out");
});

test("storage failure never sends the refresh token and never clears the cookie", async () => {
  const mock = mockFetch(() => { throw new Error("must not be called"); });
  restore = mock.restore;
  setRefreshStoreForTests({ async read() { throw new Error("database unavailable"); }, async write() { throw new Error("database unavailable"); } });
  assert.equal((await freshSession(session(), "api", {})).kind, "unavailable");
  assert.equal(mock.calls.length, 0);
});

test("app configuration errors and recovery conflicts do not sign the person out", async () => {
  for (const error of ["invalid_client", "unauthorized_client", "refresh_result_unavailable", "idempotency_key_reused"]) {
    applyTestEnv();
    const mock = mockFetch(() => json(error.endsWith("client") ? 401 : 409, { error }));
    try { assert.equal((await freshSession(session(), "api", {})).kind, "unavailable", error); }
    finally { mock.restore(); }
  }
});

test("independent Node processes recover a committed rotation after a lost HTTP response", async () => {
  const dir = await mkdtemp(join(tmpdir(), "refresh-recovery-"));
  const keys: string[] = [];
  const server = createServer(async (req, res) => {
    for await (const chunk of req) { void chunk; }
    keys.push(String(req.headers["idempotency-key"]));
    if (keys.length === 1) { req.socket.destroy(); return; }
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(tokenBody(6)));
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const input = session();
  const run = () => new Promise<{ ok: boolean; session?: StoredSession }>((resolve, reject) => {
    const script = `import { refreshSession } from './lib/server/tokens.ts'; const result = await refreshSession(${JSON.stringify(input)}, {}); console.log(JSON.stringify(result));`;
    const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
      cwd: process.cwd(), env: { ...process.env, ...TEST_ENV, ACCOUNTS_API_URL: `http://127.0.0.1:${address.port}`, REFRESH_STATE_TABLE: "", REFRESH_STATE_PATH: join(dir, "state.sqlite") }, stdio: ["ignore", "pipe", "pipe"],
    });
    let output = ""; let errors = "";
    child.stdout.on("data", b => { output += b; });
    child.stderr.on("data", b => { errors += b; });
    child.on("error", reject);
    child.on("close", code => { if (code) reject(new Error(errors)); else { try { resolve(JSON.parse(output)); } catch (error) { reject(error); } } });
  });
  try {
    assert.equal((await run()).ok, false);
    const recovered = await run();
    assert.ok(recovered.ok && recovered.session?.rt === "sar_refresh_6");
    assert.equal(keys.length, 2);
    assert.equal(keys[0], keys[1]);
    const late = await run();
    assert.equal(late.session?.rt, "sar_refresh_6");
    assert.equal(keys.length, 2, "a third cold process uses durable state");
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()));
    await rm(dir, { recursive: true, force: true });
  }
});
