/**
 * The API proxy: which headers cross in each direction, which paths are forwarded, and the route handler itself with
 * the app's service replaced by a recording fetch (bearer added, body streamed, refresh when due, 401 ends the session).
 */
import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { NextRequest } from "next/server";
import { GET, POST } from "../app/api/[...path]/route";
import { forwardRequestHeaders, relayResponseHeaders, upstreamPath } from "../lib/server/forward";
import { sealSession, type StoredSession } from "../lib/server/session";
import { forgetRefreshes } from "../lib/server/tokens";
import { json, mockFetch, tokenBody, applyTestEnv } from "./env";

const ACCOUNT = { uuid: "nln", kind: "carbon" as const, id: "c:ada", display_name: "Ada", pfp_url: null, custodian: null };
const session = (overrides: Partial<StoredSession> = {}): StoredSession => ({ v: 1, at: "eyJ.live.sig", rt: "sar_live", ae: Date.now() + 20 * 60_000, re: Date.now() + 86_400_000, scope: "profile", acct: ACCOUNT, ...overrides });
const cookieFor = (value: StoredSession) => `webkit_session=${sealSession(value)}; theme=dark`;

let restore: () => void = () => undefined;
beforeEach(() => {
  applyTestEnv();
  forgetRefreshes();
});
afterEach(() => restore());

test("forwarded: what describes the request; never cookies, the browser's Authorization, Origin or unknown headers", () => {
  const incoming = new Headers({
    accept: "application/json", "accept-language": "en", "content-type": "application/json", "content-length": "12", "if-none-match": '"v1"', "idempotency-key": "k1",
    "x-request-id": "r1", cookie: "webkit_session=v1.secret", authorization: "Bearer forged", origin: "http://127.0.0.1:4260", host: "127.0.0.1:4260", "x-custom": "no", "sec-fetch-site": "same-origin",
  });
  const out = forwardRequestHeaders(incoming, "eyJ.token.sig", { "X-Forwarded-For": "203.0.113.9", "User-Agent": "Browser/1" }, []);
  assert.deepEqual(Object.fromEntries(out), {
    accept: "application/json", "accept-language": "en", authorization: "Bearer eyJ.token.sig", "content-length": "12", "content-type": "application/json", "idempotency-key": "k1",
    "if-none-match": '"v1"', "user-agent": "Browser/1", "x-forwarded-for": "203.0.113.9", "x-request-id": "r1",
  });
  const extra = forwardRequestHeaders(incoming, "t", {}, ["X-Custom", "cookie", "authorization"]);
  assert.equal(extra.get("x-custom"), "no", "appConfig.api.forwardHeaders adds names");
  assert.equal(extra.get("cookie"), null, "never cookies, even if listed");
  assert.equal(extra.get("authorization"), "Bearer t", "never the browser's Authorization, even if listed");
});

test("relayed: the allowlist, never Set-Cookie or framing, always private and no-store", () => {
  const upstream = new Headers({
    "content-type": "application/json", "content-length": "99", "content-encoding": "gzip", etag: '"e"', location: "/v1/items/itm_1", "retry-after": "5", "x-request-id": "r",
    "set-cookie": "stub=1", "cache-control": "public, max-age=600", "x-total-count": "3", server: "stub",
  });
  assert.deepEqual(Object.fromEntries(relayResponseHeaders(upstream, [])), {
    "cache-control": "private, no-store", "content-type": "application/json", etag: '"e"', location: "/v1/items/itm_1", "retry-after": "5", "x-content-type-options": "nosniff", "x-request-id": "r",
  });
  assert.equal(relayResponseHeaders(upstream, ["X-Total-Count", "set-cookie"]).get("x-total-count"), "3");
  assert.equal(relayResponseHeaders(upstream, ["set-cookie"]).get("set-cookie"), null);
});

test("paths are passed on exactly, except ones that could climb out of the service's path", () => {
  assert.equal(upstreamPath("v1/items"), "v1/items");
  assert.equal(upstreamPath("v1/accounts/by-id/c%3Aada"), "v1/accounts/by-id/c%3Aada");
  assert.equal(upstreamPath("v1/files/..."), "v1/files/...", "three dots are a name, not a parent");
  for (const bad of ["", "v1//items", "v1/./items", "v1/../admin", "v1/%2e%2e/admin", "v1/.%2E/x", "v1/%2E/x", "v1/a%2fb", "v1/a%5Cb", "v1/a\\b"]) assert.equal(upstreamPath(bad), null, bad);
});

test("a GET reaches the service with the bearer token, the query as sent, and the answer comes back streamed", async () => {
  const mock = mockFetch(() => new Response('{"items":[]}', { status: 200, headers: { "content-type": "application/json", "set-cookie": "x=1", etag: '"a"' } }));
  restore = mock.restore;
  const response = await GET(new NextRequest("http://127.0.0.1:4260/api/v1/items?q=a%20b&status=done", { headers: { cookie: cookieFor(session()), accept: "application/json", "x-forwarded-for": "198.51.100.1, 203.0.113.7" } }));
  assert.equal(response.status, 200);
  assert.equal(await response.text(), '{"items":[]}');
  assert.equal(response.headers.get("set-cookie"), null);
  assert.equal(response.headers.get("etag"), '"a"');
  assert.equal(response.headers.get("cache-control"), "private, no-store");
  assert.equal(mock.calls.length, 1);
  assert.equal(mock.calls[0]!.url, "http://127.0.0.1:4261/v1/items?q=a%20b&status=done");
  const headers = new Headers(mock.calls[0]!.init.headers);
  assert.equal(headers.get("authorization"), "Bearer eyJ.live.sig");
  assert.equal(headers.get("cookie"), null);
  assert.equal(headers.get("x-forwarded-for"), "203.0.113.7", "the right-most address: the one this server's own proxy added");
  assert.equal(mock.calls[0]!.init.redirect, "manual");
});

test("a POST streams its body through and needs this site's Origin", async () => {
  const mock = mockFetch(async (_url, init) => {
    const text = await new Response(init.body as BodyInit).text();
    return json(201, { got: text.length, duplex: (init as RequestInit & { duplex?: string }).duplex ?? null });
  });
  restore = mock.restore;
  const body = JSON.stringify({ title: "x".repeat(100_000) });
  const headers = { cookie: cookieFor(session()), origin: "http://127.0.0.1:4260", "content-type": "application/json" };
  const response = await POST(new NextRequest("http://127.0.0.1:4260/api/v1/items", { method: "POST", headers, body }));
  assert.equal(response.status, 201);
  assert.deepEqual(await response.json(), { got: body.length, duplex: "half" });
  assert.ok(mock.calls[0]!.init.body instanceof ReadableStream, "the body is a stream, not a buffered copy");

  const crossSite = await POST(new NextRequest("http://127.0.0.1:4260/api/v1/items", { method: "POST", headers: { ...headers, origin: "https://evil.example" }, body }));
  assert.equal(crossSite.status, 403);
  assert.equal((await crossSite.json()).error.code, "cross_site_request");
  assert.equal(mock.calls.length, 1, "a refused request never reaches the service");
});

test("an access token in its last 30 seconds is refreshed first, and the new session is written back", async () => {
  const mock = mockFetch(url => (url.endsWith("/v1/oauth/token") ? json(200, tokenBody(2)) : json(200, { ok: true })));
  restore = mock.restore;
  const response = await GET(new NextRequest("http://127.0.0.1:4260/api/v1/me", { headers: { cookie: cookieFor(session({ ae: Date.now() + 10_000, rt: "sar_due" })) } }));
  assert.equal(response.status, 200);
  assert.deepEqual(mock.calls.map(call => call.url), ["http://127.0.0.1:9589/v1/oauth/token", "http://127.0.0.1:4261/v1/me"]);
  assert.equal(new Headers(mock.calls[1]!.init.headers).get("authorization"), "Bearer eyJ.access-2.sig");
  assert.match(response.headers.get("set-cookie") ?? "", /^webkit_session=v1\./);
});

test("a 401 from the service ends the session here too; no session is a 401 without a call", async () => {
  let mock = mockFetch(() => json(401, { error: { code: "token_revoked", message: "The sign-in was revoked.", hint: "Sign in again." } }));
  restore = mock.restore;
  const response = await GET(new NextRequest("http://127.0.0.1:4260/api/v1/items", { headers: { cookie: cookieFor(session()) } }));
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error.code, "token_revoked");
  assert.match(response.headers.get("set-cookie") ?? "", /webkit_session=;.*Max-Age=0/i);
  restore();

  mock = mockFetch(() => new Response("nope", { status: 401 }));
  restore = mock.restore;
  const plain = await GET(new NextRequest("http://127.0.0.1:4260/api/v1/items", { headers: { cookie: cookieFor(session()) } }));
  assert.equal((await plain.json()).error.code, "signed_out", "a 401 without the error shape still reads as signed out");
  restore();

  mock = mockFetch(() => json(200, {}));
  restore = mock.restore;
  const none = await GET(new NextRequest("http://127.0.0.1:4260/api/v1/items"));
  assert.equal(none.status, 401);
  assert.equal((await none.json()).error.code, "signed_out");
  assert.equal(mock.calls.length, 0);
});

test("a service that cannot be reached is a 502 in the kit's error shape", async () => {
  const mock = mockFetch(() => Promise.reject(Object.assign(new TypeError("fetch failed"), { cause: new Error("connect ECONNREFUSED 127.0.0.1:4261") })));
  restore = mock.restore;
  const response = await GET(new NextRequest("http://127.0.0.1:4260/api/v1/items", { headers: { cookie: cookieFor(session()) } }));
  assert.equal(response.status, 502);
  const body = await response.json();
  assert.equal(body.error.code, "service_unreachable");
  assert.match(body.error.message, /could not reach its service for GET \/v1\/items: connect ECONNREFUSED/);
});
