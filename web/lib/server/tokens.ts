/**
 * Calls to the Silicon Accounts token endpoints with this app's credentials (HTTP Basic app_id:app_secret, server side
 * only): the code exchange at the end of a sign-in, refreshing, and revoking on sign-out.
 *
 * Refresh tokens rotate on every use, and presenting a used one revokes the whole sign-in (Accounts treats it as theft).
 * So refreshing is single-flight per refresh token in this process, and the answer is remembered for a minute: requests
 * the browser sent with the old cookie before the new one arrived get the same new tokens instead of presenting the
 * used refresh token again. Across server instances nothing is shared; see README.md (Refresh) for how the kit keeps
 * concurrent refreshes rare (the browser's session keeper refreshes ahead, one tab at a time).
 */
import { basicAuth, callbackUrl, serverEnv } from "./env";
import { accountFrom, type StoredSession } from "./session";

/** An OAuth answer from the token endpoint: tokens, or the RFC 6749 error. */
export type TokenResult =
  | { ok: true; session: StoredSession }
  | { ok: false; status: number; error: string; description: string };

interface TokenBody {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  refresh_token_expires_at?: string;
  scope?: string;
  account?: unknown;
  error?: string;
  error_description?: string;
}

const NINE_HUNDRED_DAYS = 900 * 24 * 60 * 60 * 1000;

async function tokenCall(form: Record<string, string>, headers: Record<string, string>, previous?: StoredSession): Promise<TokenResult> {
  const env = serverEnv();
  let response: Response;
  try {
    response = await fetch(`${env.accountsApiUrl}/v1/oauth/token`, {
      method: "POST",
      headers: { ...headers, Authorization: basicAuth(env), "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams(form).toString(),
      cache: "no-store",
      signal: AbortSignal.timeout(20_000),
    });
  } catch (error) {
    return { ok: false, status: 502, error: "accounts_unreachable", description: `Silicon Accounts could not be reached at ${env.accountsApiUrl}: ${error instanceof Error ? error.message : String(error)}.` };
  }
  const body = (await response.json().catch(() => ({}))) as TokenBody;
  if (!response.ok || !body.access_token || !body.refresh_token) {
    return {
      ok: false,
      status: response.status,
      error: body.error ?? "token_failed",
      description: body.error_description ?? `The token endpoint answered HTTP ${response.status}.`,
    };
  }
  const account = accountFrom(body.account) ?? previous?.acct ?? null;
  if (!account) {
    return { ok: false, status: 502, error: "token_failed", description: "The token endpoint answered without the account the tokens belong to." };
  }
  const now = Date.now();
  const refreshEnds = body.refresh_token_expires_at ? Date.parse(body.refresh_token_expires_at) : NaN;
  return {
    ok: true,
    session: {
      v: 1,
      at: body.access_token,
      rt: body.refresh_token,
      ae: now + Math.max(60, body.expires_in ?? 1800) * 1000,
      re: Number.isFinite(refreshEnds) ? refreshEnds : previous?.re ?? now + NINE_HUNDRED_DAYS,
      scope: body.scope ?? previous?.scope ?? "profile",
      acct: account,
    },
  };
}

/** Exchanges the code from /auth/callback (PKCE: the verifier proves this server started the sign-in). */
export function exchangeCode(code: string, verifier: string, headers: Record<string, string>): Promise<TokenResult> {
  return tokenCall({ grant_type: "authorization_code", code, redirect_uri: callbackUrl(), code_verifier: verifier }, headers);
}

interface RefreshMemo {
  promise: Promise<TokenResult>;
  /** Until when a finished refresh is handed to requests that still carry the old refresh token. */
  until: number;
}

/** One refresh per refresh token per process (on globalThis: every route handler bundle and proxy.ts share it). */
const shared = globalThis as typeof globalThis & { __siliconWebKitRefreshes?: Map<string, RefreshMemo> };
const memos: Map<string, RefreshMemo> = (shared.__siliconWebKitRefreshes ??= new Map<string, RefreshMemo>());

/** How long a finished refresh is remembered for requests still carrying the old refresh token. */
export const REFRESH_MEMO_MS = 60_000;

/** Rotates the refresh token (single-flight; see the module comment). */
export function refreshSession(session: StoredSession, headers: Record<string, string>): Promise<TokenResult> {
  const now = Date.now();
  for (const [key, memo] of memos) if (memo.until < now) memos.delete(key);
  const existing = memos.get(session.rt);
  if (existing) return existing.promise;
  const promise = tokenCall({ grant_type: "refresh_token", refresh_token: session.rt }, headers, session);
  const memo: RefreshMemo = { promise, until: now + 2 * REFRESH_MEMO_MS };
  memos.set(session.rt, memo);
  void promise.then(result => {
    // A failure is not remembered for long: a network blip must not end the session for a minute.
    memo.until = result.ok ? Date.now() + REFRESH_MEMO_MS : Date.now() + 2_000;
  });
  return promise;
}

/** Codes from the token endpoint that mean the sign-in is over (sign in again), as opposed to a passing failure. */
export function signInEnded(result: Extract<TokenResult, { ok: false }>): boolean {
  return result.error === "invalid_grant" || result.error === "invalid_client" || result.error === "unauthorized_client";
}

/** Ends the sign-in at Silicon Accounts (best effort: the cookie is cleared either way). RFC 7009: 200 whatever happened. */
export async function revokeSession(session: Pick<StoredSession, "rt">, headers: Record<string, string>): Promise<boolean> {
  const env = serverEnv();
  try {
    const response = await fetch(`${env.accountsApiUrl}/v1/oauth/revoke`, {
      method: "POST",
      headers: { ...headers, Authorization: basicAuth(env), "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({ token: session.rt }).toString(),
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });
    const body = (await response.json().catch(() => null)) as { revoked?: unknown } | null;
    return response.ok && body?.revoked === true;
  } catch {
    // The cookie goes anyway; the refresh token then simply expires unused.
    return false;
  }
}

/** Forgets every remembered refresh (tests). */
export function forgetRefreshes(): void {
  memos.clear();
}
