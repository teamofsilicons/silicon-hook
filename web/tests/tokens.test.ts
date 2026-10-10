/**
 * The token endpoint calls: the exchange and revoke send the app's credentials; refreshing is single-flight per refresh
 * token, so concurrent requests never present a used refresh token (Silicon Accounts would end the whole sign-in).
 */
import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { freshSession } from "../lib/server/fresh";
import type { StoredSession } from "../lib/server/session";
import { exchangeCode, forgetRefreshes, refreshSession, revokeSession } from "../lib/server/tokens";
import { json, mockFetch, tokenBody, applyTestEnv } from "./env";

const BASIC = `Basic ${Buffer.from("webkit:sa_app_webkit_testtesttesttesttesttest").toString("base64")}`;
const ACCOUNT = { uuid: "nln", kind: "carbon" as const, id: "c:ada", display_name: "Ada", pfp_url: null, custodian: null };
const session = (overrides: Partial<StoredSession> = {}): StoredSession => ({ v: 1, at: "eyJ.old.sig", rt: "sar_old", ae: Date.now() + 10_000, re: Date.now() + 86_400_000, scope: "profile", acct: ACCOUNT, ...overrides });
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
const form = (init: RequestInit) => Object.fromEntries(new URLSearchParams(String(init.body)));

let restore: () => void = () => undefined;
beforeEach(() => {
  applyTestEnv();
  forgetRefreshes();
});
afterEach(() => restore());

test("the code exchange sends the code, the PKCE verifier and the exact redirect URI with HTTP Basic", async () => {
  const mock = mockFetch(() => json(200, tokenBody(1)));
  restore = mock.restore;
  const result = await exchangeCode("sac_code", "verifier-123", { "User-Agent": "test" });
  assert.equal(result.ok, true);
  assert.equal(mock.calls.length, 1);
  assert.equal(mock.calls[0]!.url, "http://127.0.0.1:9589/v1/oauth/token");
  const headers = mock.calls[0]!.init.headers as Record<string, string>;
  assert.equal(headers.Authorization, BASIC);
  assert.equal(headers["User-Agent"], "test");
  assert.deepEqual(form(mock.calls[0]!.init), { grant_type: "authorization_code", code: "sac_code", redirect_uri: "http://127.0.0.1:4260/auth/callback", code_verifier: "verifier-123" });
  if (!result.ok) return;
  assert.equal(result.session.rt, "sar_refresh_1");
  assert.equal(result.session.acct.id, "c:ada");
  assert.equal(result.session.acct.display_name, "Ada Lovelace");
  assert.equal(result.session.re, Date.parse("2029-03-27T21:53:58.705Z"));
  assert.ok(result.session.ae > Date.now() + 29 * 60_000);
});

test("a refused exchange keeps the RFC 6749 error, and an unreachable Accounts says so", async () => {
  let mock = mockFetch(() => json(400, { error: "invalid_grant", error_description: "The code was already used." }));
  restore = mock.restore;
  assert.deepEqual(await exchangeCode("sac_used", "v", {}), { ok: false, status: 400, error: "invalid_grant", description: "The code was already used." });
  restore();
  mock = mockFetch(() => Promise.reject(new TypeError("fetch failed")));
  restore = mock.restore;
  const down = await exchangeCode("sac_x", "v", {});
  assert.equal(down.ok, false);
  if (!down.ok) {
    assert.equal(down.error, "accounts_unreachable");
    assert.match(down.description, /could not be reached at http:\/\/127\.0\.0\.1:9589: fetch failed/);
  }
});

test("concurrent refreshes of one sign-in make one request, and late requests get the same answer", async () => {
  let served = 0;
  const mock = mockFetch(async () => {
    served += 1;
    await delay(40);
    return json(200, tokenBody(served));
  });
  restore = mock.restore;
  const old = session();
  const results = await Promise.all([1, 2, 3, 4, 5].map(() => refreshSession(old, {})));
  assert.equal(mock.calls.length, 1, "one request for five callers");
  assert.deepEqual(form(mock.calls[0]!.init), { grant_type: "refresh_token", refresh_token: "sar_old" });
  assert.equal((mock.calls[0]!.init.headers as Record<string, string>).Authorization, BASIC);
  const tokens = new Set(results.map(result => (result.ok ? result.session.rt : "failed")));
  assert.deepEqual([...tokens], ["sar_refresh_1"]);
  // A request that still carried the old cookie a moment later gets the same new tokens: the used one is never sent again.
  const late = await refreshSession(old, {});
  assert.equal(mock.calls.length, 1);
  assert.equal(late.ok && late.session.rt, "sar_refresh_1");
  // The next sign-in (another refresh token) refreshes on its own.
  await refreshSession(session({ rt: "sar_other" }), {});
  assert.equal(mock.calls.length, 2);
});

test("a failed refresh is remembered only briefly, so a network blip does not end the session for a minute", async () => {
  let fail = true;
  const mock = mockFetch(() => (fail ? Promise.reject(new TypeError("socket hang up")) : json(200, tokenBody(7))));
  restore = mock.restore;
  const first = await refreshSession(session(), {});
  assert.equal(first.ok, false);
  const second = await refreshSession(session(), {});
  assert.equal(mock.calls.length, 1, "the failure is shared for a moment");
  assert.equal(second.ok, false);
  fail = false;
  await delay(2_100);
  const third = await refreshSession(session(), {});
  assert.equal(mock.calls.length, 2);
  assert.equal(third.ok && third.session.rt, "sar_refresh_7");
});

test("a refresh keeps the account when the answer has none, and the sign-in's end when it gives none", async () => {
  const body = tokenBody(3) as Record<string, unknown>;
  delete body.account;
  delete body.refresh_token_expires_at;
  const mock = mockFetch(() => json(200, body));
  restore = mock.restore;
  const old = session();
  const result = await refreshSession(old, {});
  assert.ok(result.ok);
  if (result.ok) {
    assert.deepEqual(result.session.acct, ACCOUNT);
    assert.equal(result.session.re, old.re);
  }
});

test("freshSession refreshes only inside the lead time, and tells an ended sign-in from a passing failure", async () => {
  let answer: () => Response | Promise<Response> = () => json(200, tokenBody(9));
  const mock = mockFetch(() => answer());
  restore = mock.restore;
  const plenty = session({ ae: Date.now() + 20 * 60_000 });
  assert.deepEqual(await freshSession(plenty, "page", {}), { kind: "fresh", session: plenty, rotated: false });
  assert.equal(mock.calls.length, 0);
  const keeper = await freshSession(session({ ae: Date.now() + 4 * 60_000, rt: "sar_k" }), "keeper", {});
  assert.equal(keeper.kind === "fresh" && keeper.rotated, true);
  // The API proxy waits until the last 30 seconds.
  assert.equal((await freshSession(session({ ae: Date.now() + 60_000, rt: "sar_api" }), "api", {})).kind, "fresh");
  assert.equal(mock.calls.length, 1);

  answer = () => json(400, { error: "invalid_grant", error_description: "The sign-in this refresh token belongs to was revoked." });
  const ended = await freshSession(session({ ae: Date.now() - 1, rt: "sar_revoked" }), "page", {});
  assert.deepEqual(ended, { kind: "signed_out", message: "Your sign-in ended: The sign-in this refresh token belongs to was revoked.", clear: true });

  answer = () => Promise.reject(new TypeError("fetch failed"));
  const blip = await freshSession(session({ ae: Date.now() + 60_000, rt: "sar_blip" }), "page", {});
  assert.equal(blip.kind === "unavailable" && blip.code, "accounts_unreachable");
  answer = () => json(503, { error: "temporarily_unavailable", error_description: "Busy." });
  const busy = session({ ae: Date.now() + 60_000, rt: "sar_busy" });
  assert.deepEqual(await freshSession(busy, "page", {}), { kind: "fresh", session: busy, rotated: false }, "a token that still works keeps working");
  assert.equal((await freshSession(null, "page", {})).kind, "signed_out");
});

test("revoking sends the refresh token with the app's credentials and never throws", async () => {
  let mock = mockFetch(() => json(200, { revoked: true }));
  restore = mock.restore;
  assert.equal(await revokeSession({ rt: "sar_end" }, {}), true);
  assert.equal(mock.calls[0]!.url, "http://127.0.0.1:9589/v1/oauth/revoke");
  assert.deepEqual(form(mock.calls[0]!.init), { token: "sar_end" });
  assert.equal((mock.calls[0]!.init.headers as Record<string, string>).Authorization, BASIC);
  restore();
  mock = mockFetch(() => Promise.reject(new Error("down")));
  restore = mock.restore;
  assert.equal(await revokeSession({ rt: "sar_end" }, {}), false);
});
