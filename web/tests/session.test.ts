/** The session cookie, return paths and the same-origin guard. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { NextRequest, NextResponse } from "next/server";
import { seal } from "../lib/server/seal";
import {
  accountFrom, clearSession, readPending, readSession, safeReturnPath, sameOriginProblem, sealSession, sessionCookieName, sessionFromCookie,
  signinCookieName, writePending, writeSession, type StoredSession,
} from "../lib/server/session";
import { SECRET, applyTestEnv } from "./env";

applyTestEnv();

const ACCOUNT = { uuid: "nln", kind: "carbon" as const, id: "c:ada", display_name: "Ada", pfp_url: null, custodian: null };
const session = (overrides: Partial<StoredSession> = {}): StoredSession => ({ v: 1, at: "eyJ.a.b", rt: "sar_1", ae: Date.now() + 30 * 60_000, re: Date.now() + 86_400_000, scope: "profile", acct: ACCOUNT, ...overrides });

test("return paths stay on this site and off the sign-in routes", () => {
  assert.equal(safeReturnPath("/items/itm_1?tab=sharing#top"), "/items/itm_1?tab=sharing#top");
  assert.equal(safeReturnPath("/"), "/");
  for (const hostile of ["https://evil.example/x", "//evil.example/x", "/\\evil.example", "/\t/evil.example/x", "/\n/evil", "javascript:alert(1)", "evil.example", "", null, undefined]) {
    assert.equal(safeReturnPath(hostile), "/", String(hostile));
  }
  assert.equal(safeReturnPath("/auth/callback?code=x"), "/");
  assert.equal(safeReturnPath("/api/v1/items"), "/");
  assert.equal(safeReturnPath("/sign-in?error=x"), "/");
  assert.equal(safeReturnPath("/authority"), "/authority", "only the routes themselves, not lookalike paths");
});

test("the session cookie holds a sealed session and nothing readable", () => {
  const sealed = sealSession(session());
  assert.ok(!sealed.includes("sar_1") && !sealed.includes("eyJ"));
  assert.deepEqual(sessionFromCookie(sealed)?.acct, ACCOUNT);
  assert.equal(sessionFromCookie(sealSession(session({ re: Date.now() - 1 }))), null, "a sign-in past its end is gone");
  assert.equal(sessionFromCookie(seal({ v: 2 }, "session", SECRET)), null, "an unknown shape is refused");
  assert.equal(sessionFromCookie(seal(session(), "signin", SECRET)), null, "a value sealed for another cookie is refused");
  assert.equal(sessionFromCookie("v1.forged"), null);
});

test("cookies are httpOnly, SameSite=Lax, named after the app, and __Host- over https", () => {
  assert.equal(sessionCookieName(), "webkit_session");
  assert.equal(signinCookieName(), "webkit_signin");
  const response = NextResponse.next();
  writeSession(response, session());
  const header = response.headers.get("set-cookie") ?? "";
  assert.match(header, /^webkit_session=v1\./);
  assert.match(header, /HttpOnly/i);
  assert.match(header, /SameSite=lax/i);
  assert.match(header, /Path=\//);
  assert.doesNotMatch(header, /Secure/i, "plain http in development");
  const request = new NextRequest("http://127.0.0.1:4260/items", { headers: { cookie: `webkit_session=${header.split(";")[0]!.split("=").slice(1).join("=")}` } });
  assert.equal(readSession(request)?.rt, "sar_1");
  const cleared = NextResponse.next();
  clearSession(cleared);
  assert.match(cleared.headers.get("set-cookie") ?? "", /webkit_session=;.*Max-Age=0/i);

  applyTestEnv({ PUBLIC_URL: "https://webkit.example" });
  try {
    assert.equal(sessionCookieName(), "__Host-webkit_session");
    const secure = NextResponse.next();
    writeSession(secure, session());
    assert.match(secure.headers.get("set-cookie") ?? "", /^__Host-webkit_session=.*; Secure/i);
  } finally {
    applyTestEnv();
  }
});

test("up to three sign-ins wait at once, each for ten minutes", () => {
  const response = NextResponse.next();
  const now = Date.now();
  writePending(response, [1, 2, 3, 4].map(n => ({ s: `state${n}`, v: `verifier${n}`, r: "/items", t: now })));
  const value = /webkit_signin=([^;]+)/.exec(response.headers.get("set-cookie") ?? "")![1]!;
  const kept = readPending(new NextRequest("http://127.0.0.1:4260/auth/callback", { headers: { cookie: `webkit_signin=${value}` } }));
  assert.deepEqual(kept.map(entry => entry.s), ["state2", "state3", "state4"]);
  const old = NextResponse.next();
  writePending(old, [{ s: "stale", v: "v", r: "/", t: now - 11 * 60_000 }]);
  const stale = /webkit_signin=([^;]+)/.exec(old.headers.get("set-cookie") ?? "")![1]!;
  assert.deepEqual(readPending(new NextRequest("http://127.0.0.1:4260/auth/callback", { headers: { cookie: `webkit_signin=${stale}` } })), []);
});

test("state-changing requests must come from this site", () => {
  const at = (method: string, headers: Record<string, string>) => new Request("http://127.0.0.1:4260/api/v1/items", { method, headers });
  assert.equal(sameOriginProblem(at("GET", {})), null);
  assert.equal(sameOriginProblem(at("POST", { origin: "http://127.0.0.1:4260", "sec-fetch-site": "same-origin" })), null);
  assert.equal(sameOriginProblem(at("POST", { origin: "http://localhost:4260" })), null, "the loopback twin in development");
  assert.match(sameOriginProblem(at("POST", {}))!, /carried no Origin header/);
  assert.match(sameOriginProblem(at("DELETE", { origin: "https://evil.example" }))!, /not from https:\/\/evil\.example/);
  assert.match(sameOriginProblem(at("PATCH", { origin: "null" }))!, /carried no Origin header/);
  assert.match(sameOriginProblem(at("PUT", { origin: "http://127.0.0.1:4260", "sec-fetch-site": "cross-site" }))!, /Sec-Fetch-Site was cross-site/);
});

test("the account from a token response keeps what the shell shows", () => {
  assert.deepEqual(accountFrom({ uuid: "K1E", kind: "silicon", id: "si:scout", display_name: "Scout", pfp_url: "https://iris.teamofsilicons.com/pfp/silicon?id=K1E", custodian: { uuid: "8HV", id: "c:ada" }, email: "x@example.test" }), {
    uuid: "K1E", kind: "silicon", id: "si:scout", display_name: "Scout", pfp_url: "https://iris.teamofsilicons.com/pfp/silicon?id=K1E", custodian: { uuid: "8HV", id: "c:ada" },
  });
  assert.equal(accountFrom({ uuid: "K1E", kind: "robot", id: "x" }), null);
  assert.equal(accountFrom(null), null);
  assert.equal(accountFrom({ uuid: "K1E", kind: "carbon", id: "c:x", display_name: "  " })?.display_name, "c:x", "a blank name shows the id");
});
