/** Accounts refreshes use a durable random operation key shared by every server and retry. */
import { randomUUID } from "node:crypto";
import { createSession, endSession, locateSession } from "./refresh-state";
import { refreshStore } from "./refresh-store";
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
  access_token_expires_at?: string;
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
  const accessEnds = body.access_token_expires_at ? Date.parse(body.access_token_expires_at) : now + (body.expires_in ?? 1800) * 1000;
  if (!Number.isFinite(accessEnds)) return { ok: false, status: 502, error: "token_failed", description: "Accounts returned an invalid access-token expiry." };
  const refreshEnds = body.refresh_token_expires_at ? Date.parse(body.refresh_token_expires_at) : NaN;
  return {
    ok: true,
    session: {
      v: 1,
      ...(previous?.sid ? { sid: previous.sid } : {}),
      at: body.access_token,
      rt: body.refresh_token,
      ae: accessEnds,
      re: Number.isFinite(refreshEnds) ? refreshEnds : previous?.re ?? now + NINE_HUNDRED_DAYS,
      scope: body.scope ?? previous?.scope ?? "profile",
      acct: account,
    },
  };
}

/** Exchanges the code from /auth/callback (PKCE: the verifier proves this server started the sign-in). */
export async function exchangeCode(code: string, verifier: string, headers: Record<string, string>): Promise<TokenResult> {
  try {
    await refreshStore();
    const result = await tokenCall({ grant_type: "authorization_code", code, redirect_uri: callbackUrl(), code_verifier: verifier }, headers);
    return result.ok ? { ok: true, session: await createSession(result.session) } : result;
  } catch (error) {
    console.error("Browser session storage failed", error instanceof Error ? error.name : "UnknownError");
    return storageUnavailable();
  }
}

function storageUnavailable(): TokenResult {
  return { ok: false, status: 503, error: "session_storage_unavailable", description: "Your sign-in could not be read or saved. Please retry shortly; your session has not been cleared." };
}
const ended = (): TokenResult => ({ ok: false, status: 400, error: "invalid_grant", description: "This sign-in has ended." });
const pending = (): TokenResult => ({ ok: false, status: 503, error: "refresh_in_progress", description: "Your sign-in is being refreshed. Please retry shortly." });

/** Resolves the current server session, rotating only when necessary. Cookie tokens are never authoritative. */
export async function refreshSession(session: StoredSession, headers: Record<string, string>, ahead = 30_000): Promise<TokenResult> {
  try {
    for (let attempt = 0; attempt < 12; attempt++) {
      const { store, key, entry } = await locateSession(session);
      const current = entry.value;
      if (current.revoked || current.session.re <= Date.now()) return ended();
      if (!current.operation && current.session.ae > Date.now() + ahead) return { ok: true, session: current.session };
      if (!current.operation) {
        // Persist BEFORE sending: a crash, timeout, second process or second tab reuses this random key.
        if (!await store.write(key, entry.version, { ...current, operation: { key: randomUUID(), token: current.session.rt } }, current.session.re)) continue;
        continue;
      }
      if (current.operation.token !== current.session.rt) return storageUnavailable();
      const result = await tokenCall({ grant_type: "refresh_token", refresh_token: current.session.rt }, { ...headers, "Idempotency-Key": current.operation.key }, current.session);
      if (!result.ok) {
        // A winner may have committed while this request was waiting, or sign-out may have won.
        const latest = await store.read<typeof current>(key);
        if (!latest || latest.version !== entry.version) continue;
        if (["refresh_in_progress", "refresh_superseded"].includes(result.error)) {
          await new Promise(resolve => setTimeout(resolve, 1_000));
          continue;
        }
        return result; // 409, transport errors, app configuration errors and 5xx never clear the session.
      }
      // Save even an already-expired recovered access token: its successor refresh token is still needed.
      // CAS loses to sign-out or a newer rotation; neither can be overwritten by a late response.
      await store.write(key, entry.version, { session: result.session }, result.session.re);
      // Read again even after success: every caller gets the current generation, never its stale reply.
    }
    return pending();
  } catch (error) {
    console.error("Browser session storage failed", error instanceof Error ? error.name : "UnknownError");
    return storageUnavailable();
  }
}

/** Codes from the token endpoint that mean the sign-in is over (sign in again), as opposed to a passing failure. */
export function signInEnded(result: Extract<TokenResult, { ok: false }>): boolean {
  return result.error === "invalid_grant";
}

/** Ends the sign-in at Silicon Accounts (best effort: the cookie is cleared either way). RFC 7009: 200 whatever happened. */
export async function revokeSession(session: Pick<StoredSession, "rt"> & Partial<StoredSession>, headers: Record<string, string>): Promise<boolean> {
  const env = serverEnv();
  // A failed durable sign-out must be retried; clearing only the cookie lets an in-flight response restore it.
  if (session.acct && session.re) await endSession(session as StoredSession);
  try {
    const response = await fetch(`${env.accountsApiUrl}/v1/oauth/revoke`, {
      method: "POST",
      headers: { ...headers, Authorization: basicAuth(env), "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({ token: session.rt }).toString(),
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });
    return response.ok;
  } catch {
    // The cookie goes anyway; the refresh token then simply expires unused.
    return false;
  }
}

/** Compatibility for callers that previously reset the process-local cache. State is now durable. */
export function forgetRefreshes(): void {}
