/**
 * The session, held by the Next server (a BFF): the signed-in account's Silicon Accounts tokens for this app live in one
 * sealed, httpOnly, SameSite=Lax cookie (Secure and `__Host-` prefixed over https). The browser never sees a token;
 * route handlers and proxy.ts read the cookie, refresh the access token when it is about to expire (lib/server/tokens.ts),
 * and call the app's service with `Authorization: Bearer`.
 *
 * This file is the cookie side: the session and pending sign-in cookies, PKCE, return paths, the same-origin guard and
 * error bodies. Adapted from the developer site (silicon-accounts/developer/lib/server/session.ts).
 */
import { createHash, randomBytes } from "node:crypto";
import type { NextRequest, NextResponse } from "next/server";
import { allowedOrigins, secureCookies, serverEnv } from "./env";
import type { SessionAccount } from "../account";
import { seal, unseal } from "./seal";

export type { AccountKind, SessionAccount } from "../account";

/* ------------------------------------------------------------------------------------------------------------------ */
/* What a session holds                                                                                                */
/* ------------------------------------------------------------------------------------------------------------------ */

/** What the session cookie holds (sealed). */
export interface StoredSession {
  v: 1;
  /** Access token (an EdDSA JWT, aud = this app, 30 minutes). */
  at: string;
  /** Refresh token (sar_…, rotates on every use). */
  rt: string;
  /** When the access token expires (epoch ms). */
  ae: number;
  /** When the refresh token, and so the sign-in, ends (epoch ms). */
  re: number;
  scope: string;
  acct: SessionAccount;
}

/** Refresh ahead of expiry: page loads (proxy.ts) at 2 minutes, the browser's session keeper at 5, /api/* only at 30 s. */
export const REFRESH_AHEAD = { page: 2 * 60_000, keeper: 5 * 60_000, api: 30_000 } as const;

/** Reads an `account` object from a token response into what the session keeps; null when it is not one. */
export function accountFrom(value: unknown): SessionAccount | null {
  if (!value || typeof value !== "object") return null;
  const raw = value as Record<string, unknown>;
  if (typeof raw.uuid !== "string" || typeof raw.id !== "string" || (raw.kind !== "carbon" && raw.kind !== "silicon")) return null;
  const custodian = raw.custodian as Record<string, unknown> | null | undefined;
  return {
    uuid: raw.uuid,
    kind: raw.kind,
    id: raw.id,
    display_name: typeof raw.display_name === "string" && raw.display_name.trim() ? raw.display_name : raw.id,
    pfp_url: typeof raw.pfp_url === "string" && raw.pfp_url ? raw.pfp_url : null,
    custodian: custodian && typeof custodian.uuid === "string" && typeof custodian.id === "string" ? { uuid: custodian.uuid, id: custodian.id } : null,
  };
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* Cookies                                                                                                             */
/* ------------------------------------------------------------------------------------------------------------------ */

/** Browsers keep a cookie at most 400 days. */
const MAX_COOKIE_SECONDS = 400 * 24 * 60 * 60;
/** A pending sign-in (state + PKCE verifier) lives 10 minutes; at most three run at once (three browser tabs). */
export const SIGNIN_TTL_MS = 10 * 60_000;
const MAX_PENDING = 3;

/** Cookie names carry the app id: every app on a local machine shares the cookies of `localhost`, whatever the port. */
const cookieName = (suffix: string) => {
  const env = serverEnv();
  const base = `${env.appId.replace(/-/g, "_")}_${suffix}`;
  return secureCookies(env) ? `__Host-${base}` : base;
};
export const sessionCookieName = () => cookieName("session");
export const signinCookieName = () => cookieName("signin");
const SESSION_PURPOSE = "session";
const SIGNIN_PURPOSE = "signin";

const cookieOptions = (maxAge: number) => ({ httpOnly: true, secure: secureCookies(), sameSite: "lax" as const, path: "/", maxAge });

/** The sign-in a session cookie's value holds, or null (also for Server Components, which read cookies themselves). */
export function sessionFromCookie(cookie: string | undefined | null, now = Date.now()): StoredSession | null {
  const value = unseal<StoredSession>(cookie, SESSION_PURPOSE);
  if (!value || value.v !== 1 || typeof value.at !== "string" || typeof value.rt !== "string" || typeof value.ae !== "number") return null;
  if (typeof value.re !== "number" || value.re <= now) return null;
  if (!value.acct || typeof value.acct.uuid !== "string") return null;
  return value;
}

export function readSession(request: NextRequest): StoredSession | null {
  return sessionFromCookie(request.cookies.get(sessionCookieName())?.value);
}

/** The sealed cookie value for a session (proxy.ts also hands it to the page render as a request cookie). */
export const sealSession = (session: StoredSession) => seal(session, SESSION_PURPOSE);

export function writeSession(response: NextResponse, session: StoredSession, sealed: string = sealSession(session)): void {
  const seconds = Math.max(60, Math.min(MAX_COOKIE_SECONDS, Math.floor((session.re - Date.now()) / 1000)));
  response.cookies.set(sessionCookieName(), sealed, cookieOptions(seconds));
}

export function clearSession(response: NextResponse): void {
  response.cookies.set(sessionCookieName(), "", cookieOptions(0));
}

/** One sign-in started in this browser and not finished yet. */
export interface PendingSignIn {
  /** state */
  s: string;
  /** PKCE code verifier */
  v: string;
  /** Where to go afterwards (a same-site path). */
  r: string;
  /** Started at (epoch ms). */
  t: number;
}

export function readPending(request: NextRequest): PendingSignIn[] {
  const list = unseal<PendingSignIn[]>(request.cookies.get(signinCookieName())?.value, SIGNIN_PURPOSE);
  if (!Array.isArray(list)) return [];
  return list.filter(entry => entry && typeof entry.s === "string" && typeof entry.v === "string" && Date.now() - entry.t < SIGNIN_TTL_MS);
}

export function writePending(response: NextResponse, list: PendingSignIn[]): void {
  const kept = list.slice(-MAX_PENDING);
  if (!kept.length) response.cookies.set(signinCookieName(), "", cookieOptions(0));
  else response.cookies.set(signinCookieName(), seal(kept, SIGNIN_PURPOSE), cookieOptions(SIGNIN_TTL_MS / 1000));
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* PKCE and return paths                                                                                               */
/* ------------------------------------------------------------------------------------------------------------------ */

export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");
export const s256 = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");

/** Paths a sign-in never returns to. */
const NO_RETURN = ["/sign-in", "/auth", "/api"];

/**
 * A path on this site to come back to after signing in, or "/". Anything that could be read as another origin
 * (`//evil.example`, `/\evil`, `https://…`, a tab or newline smuggled in) is dropped, and so are the sign-in routes.
 */
export function safeReturnPath(value: string | null | undefined): string {
  if (!value || /[\u0000-\u001f\u007f]/.test(value)) return "/";
  if (!value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return "/";
  let url: URL;
  try {
    url = new URL(value, "http://kit.invalid");
  } catch {
    return "/";
  }
  if (url.origin !== "http://kit.invalid") return "/";
  const path = `${url.pathname}${url.search}${url.hash}`;
  if (!path.startsWith("/") || path.startsWith("//")) return "/";
  if (NO_RETURN.some(prefix => url.pathname === prefix || url.pathname.startsWith(`${prefix}/`))) return "/";
  return path;
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* Guards and errors                                                                                                   */
/* ------------------------------------------------------------------------------------------------------------------ */

/**
 * The same-origin guard (CSRF): a state-changing request must carry an Origin of this site, and, when the browser sends
 * it, Sec-Fetch-Site: same-origin. Browsers send Origin on every non-GET fetch and form post, so a page on another site
 * can never make one, whatever cookies ride along. Returns the reason it was refused, or null.
 */
export function sameOriginProblem(request: Request): string | null {
  const method = request.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return null;
  const origin = request.headers.get("origin");
  if (!origin || origin === "null") return `${method} requests must come from this site's own pages, and this one carried no Origin header.`;
  if (!allowedOrigins().has(origin)) return `${method} requests must come from this site's own pages, not from ${origin}.`;
  const site = request.headers.get("sec-fetch-site");
  if (site && site !== "same-origin") return `${method} requests must come from this site's own pages (Sec-Fetch-Site was ${site}).`;
  return null;
}

/** An error in the API's own shape, so the browser handles every failure the same way. */
export function errorBody(code: string, message: string, hint?: string, details?: Record<string, unknown>) {
  return { error: { code, message, ...(hint ? { hint } : {}), ...(details ? { details } : {}) } };
}

/**
 * Headers that describe the browser to Silicon Accounts and the app's service: the client address (the right-most
 * X-Forwarded-For entry this server received, which its own proxy appended) and the user agent.
 */
export function clientHeaders(request: { headers: Pick<Headers, "get"> }): Record<string, string> {
  const out: Record<string, string> = {};
  const forwarded = request.headers.get("x-forwarded-for");
  const ip = forwarded?.split(",").map(part => part.trim()).filter(Boolean).pop();
  if (ip) out["X-Forwarded-For"] = ip;
  const agent = request.headers.get("user-agent");
  if (agent) out["User-Agent"] = agent;
  return out;
}
