/** The sign-in routes: PKCE and state in a sealed cookie, the callback's checks, sign-out revoking, the session view. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { afterEach, beforeEach, test } from "node:test";
import { NextRequest } from "next/server";
import { GET as callback } from "../app/auth/callback/route";
import { POST as refresh } from "../app/auth/refresh/route";
import { GET as sessionRoute } from "../app/auth/session/route";
import { GET as signIn } from "../app/auth/sign-in/route";
import { POST as signOut } from "../app/auth/sign-out/route";
import { readPending, sealSession, type StoredSession } from "../lib/server/session";
import { forgetRefreshes } from "../lib/server/tokens";
import { json, mockFetch, tokenBody, applyTestEnv } from "./env";

const ACCOUNT = { uuid: "nln", kind: "carbon" as const, id: "c:ada", display_name: "Ada", pfp_url: null, custodian: null };
const session = (overrides: Partial<StoredSession> = {}): StoredSession => ({ v: 1, at: "eyJ.a.b", rt: "sar_current", ae: Date.now() + 20 * 60_000, re: Date.now() + 86_400_000, scope: "profile", acct: ACCOUNT, ...overrides });
const cookieValue = (setCookie: string, name: string) => new RegExp(`${name}=([^;]*)`).exec(setCookie)?.[1] ?? "";

let restore: () => void = () => undefined;
beforeEach(() => {
  applyTestEnv();
  forgetRefreshes();
});
afterEach(() => restore());

async function startSignIn(returnTo = "/settings") {
  const response = signIn(new NextRequest(`http://127.0.0.1:4260/auth/sign-in?return_to=${encodeURIComponent(returnTo)}&prompt=login`, { headers: { host: "127.0.0.1:4260" } }));
  const location = new URL(response.headers.get("location")!);
  const pending = cookieValue(response.headers.get("set-cookie") ?? "", "webkit_signin");
  return { response, location, pending };
}

test("starting a sign-in sends the browser to the hosted pages with PKCE S256 and a state only it holds", async () => {
  const { response, location, pending } = await startSignIn();
  assert.equal(response.status, 303);
  assert.equal(`${location.origin}${location.pathname}`, "http://localhost:9590/authorize");
  const params = Object.fromEntries(location.searchParams);
  assert.equal(params.app_id, "webkit");
  assert.equal(params.redirect_uri, "http://127.0.0.1:4260/auth/callback");
  assert.equal(params.response_type, "code");
  assert.equal(params.scope, undefined);
  assert.equal(params.code_challenge_method, "S256");
  assert.equal(params.prompt, "login");
  const [entry] = readPending(new NextRequest("http://127.0.0.1:4260/auth/callback", { headers: { cookie: `webkit_signin=${pending}` } }));
  assert.equal(entry!.s, params.state);
  assert.equal(entry!.r, "/settings");
  assert.equal(createHash("sha256").update(entry!.v).digest("base64url"), params.code_challenge, "the challenge is the S256 of the verifier kept here");
  assert.ok(!pending.includes(entry!.v), "the verifier is sealed, never readable in the cookie");
});

test("a sign-in started on another host goes to PUBLIC_URL first (once), and a prefetch starts nothing", () => {
  const bounced = signIn(new NextRequest("http://localhost:4260/auth/sign-in?return_to=/items", { headers: { host: "localhost:4260" } }));
  assert.equal(bounced.status, 307);
  assert.equal(bounced.headers.get("location"), "http://127.0.0.1:4260/auth/sign-in?return_to=%2Fitems&bounced=1");
  const again = signIn(new NextRequest("http://localhost:4260/auth/sign-in?return_to=/items&bounced=1", { headers: { host: "localhost:4260" } }));
  assert.equal(again.status, 303, "never a loop");
  const prefetch = signIn(new NextRequest("http://127.0.0.1:4260/auth/sign-in", { headers: { host: "127.0.0.1:4260", "next-router-prefetch": "1" } }));
  assert.equal(prefetch.status, 204);
  assert.equal(prefetch.headers.get("set-cookie"), null);
});

test("the callback exchanges the code with its verifier, seals the session, and revokes the sign-in it replaces", async () => {
  const { location, pending } = await startSignIn("/items/itm_1?tab=sharing");
  const mock = mockFetch(url => (url.endsWith("/v1/oauth/token") ? json(200, tokenBody(5)) : json(200, { revoked: true })));
  restore = mock.restore;
  const state = location.searchParams.get("state")!;
  const response = await callback(new NextRequest(`http://127.0.0.1:4260/auth/callback?code=sac_good&state=${state}`, { headers: { cookie: `webkit_signin=${pending}; webkit_session=${sealSession(session({ rt: "sar_previous" }))}` } }));
  assert.equal(response.status, 303);
  assert.equal(response.headers.get("location"), "http://127.0.0.1:4260/items/itm_1?tab=sharing");
  const body = new URLSearchParams(String(mock.calls[0]!.init.body));
  assert.equal(body.get("code"), "sac_good");
  assert.equal(body.get("code_verifier")!.length, 43);
  assert.equal(mock.calls[1]!.url, "http://127.0.0.1:9589/v1/oauth/revoke");
  assert.equal(new URLSearchParams(String(mock.calls[1]!.init.body)).get("token"), "sar_previous");
  const cookies = response.headers.get("set-cookie") ?? "";
  assert.match(cookies, /webkit_session=v1\.[^;]+;.*HttpOnly/i);
  assert.match(cookies, /webkit_signin=;/, "the finished sign-in is forgotten");
});

test("the callback refuses a state this browser did not start, and turns errors into fixed words", async () => {
  const forged = await callback(new NextRequest("http://127.0.0.1:4260/auth/callback?code=sac_x&state=forged"));
  assert.equal(forged.headers.get("location"), "http://127.0.0.1:4260/sign-in?error=state_mismatch");
  const { location, pending } = await startSignIn();
  const state = location.searchParams.get("state")!;
  const cancelled = await callback(new NextRequest(`http://127.0.0.1:4260/auth/callback?error=access_denied&error_description=Click%20evil.example&state=${state}`, { headers: { cookie: `webkit_signin=${pending}` } }));
  assert.equal(cancelled.headers.get("location"), "http://127.0.0.1:4260/sign-in?error=access_denied&return_to=%2Fsettings");
  const weird = await callback(new NextRequest(`http://127.0.0.1:4260/auth/callback?error=%3Cscript%3E&state=${state}`, { headers: { cookie: `webkit_signin=${pending}` } }));
  assert.equal(new URL(weird.headers.get("location")!).searchParams.get("error"), "sign_in_failed");
  const mock = mockFetch(() => json(400, { error: "invalid_grant", error_description: "The code was already used." }));
  restore = mock.restore;
  const refused = await callback(new NextRequest(`http://127.0.0.1:4260/auth/callback?code=sac_used&state=${state}`, { headers: { cookie: `webkit_signin=${pending}` } }));
  assert.equal(new URL(refused.headers.get("location")!).searchParams.get("error"), "exchange_failed");
});

test("signing out revokes the refresh token and clears the cookie; only from this site", async () => {
  const mock = mockFetch(() => json(200, { revoked: true }));
  restore = mock.restore;
  const cookie = `webkit_session=${sealSession(session())}`;
  const refused = await signOut(new NextRequest("http://127.0.0.1:4260/auth/sign-out", { method: "POST", headers: { cookie, origin: "https://evil.example" } }));
  assert.equal(refused.status, 403);
  assert.equal(mock.calls.length, 0);
  const fetched = await signOut(new NextRequest("http://127.0.0.1:4260/auth/sign-out", { method: "POST", headers: { cookie, origin: "http://127.0.0.1:4260" } }));
  assert.equal(fetched.status, 204);
  assert.equal(new URLSearchParams(String(mock.calls[0]!.init.body)).get("token"), "sar_current");
  assert.match(fetched.headers.get("set-cookie") ?? "", /webkit_session=;.*Max-Age=0/i);
  const form = await signOut(new NextRequest("http://127.0.0.1:4260/auth/sign-out", { method: "POST", headers: { cookie, origin: "http://127.0.0.1:4260", accept: "text/html", "sec-fetch-mode": "navigate" } }));
  assert.equal(form.status, 303);
  assert.equal(form.headers.get("location"), "http://127.0.0.1:4260/sign-in?signed_out=1");
});

test("the session view never shows a token, and the keeper's refresh only acts inside its lead time", async () => {
  const view = await sessionRoute(new NextRequest("http://127.0.0.1:4260/auth/session", { headers: { cookie: `webkit_session=${sealSession(session())}` } })).json();
  assert.equal(view.signed_in, true);
  assert.equal(view.account.id, "c:ada");
  assert.ok(!JSON.stringify(view).includes("sar_") && !JSON.stringify(view).includes("eyJ"));
  assert.deepEqual(await sessionRoute(new NextRequest("http://127.0.0.1:4260/auth/session")).json(), { signed_in: false });

  const mock = mockFetch(() => json(200, tokenBody(8)));
  restore = mock.restore;
  const headers = (value: StoredSession) => ({ cookie: `webkit_session=${sealSession(value)}`, origin: "http://127.0.0.1:4260" });
  const early = await refresh(new NextRequest("http://127.0.0.1:4260/auth/refresh", { method: "POST", headers: headers(session()) }));
  assert.equal(early.status, 200);
  assert.equal(mock.calls.length, 0, "20 minutes left: nothing to do");
  assert.equal(early.headers.get("set-cookie"), null);
  const due = await refresh(new NextRequest("http://127.0.0.1:4260/auth/refresh", { method: "POST", headers: headers(session({ ae: Date.now() + 4 * 60_000, rt: "sar_due" })) }));
  assert.equal(due.status, 200);
  assert.equal(mock.calls.length, 1);
  assert.match(due.headers.get("set-cookie") ?? "", /^webkit_session=v1\./);
  assert.ok(Date.parse((await due.json()).expires_at) > Date.now() + 29 * 60_000);
});
