/**
 * "Give me a session whose access token is good for a while": the one decision proxy.ts (page loads), /auth/refresh (the
 * browser's session keeper) and /api/* make before using a session, each with its own lead time (REFRESH_AHEAD).
 * Every lookup resolves durable state; refreshing uses a saved random operation key in tokens.ts.
 */
import { REFRESH_AHEAD, type StoredSession } from "./session";
import { refreshSession, signInEnded } from "./tokens";

export type Freshness =
  /** Good to use; `rotated` means the cookie must be written with the new session. */
  | { kind: "fresh"; session: StoredSession; rotated: boolean }
  /** No sign-in, or it ended at Silicon Accounts (`clear`: the cookie holds a dead sign-in). */
  | { kind: "signed_out"; message: string; clear: boolean }
  /** Silicon Accounts could not answer; the session may still be fine later. */
  | { kind: "unavailable"; status: 502 | 503; code: string; message: string };

export async function freshSession(session: StoredSession | null, ahead: keyof typeof REFRESH_AHEAD, headers: Record<string, string>, now = Date.now()): Promise<Freshness> {
  if (!session) return { kind: "signed_out", message: "This browser is not signed in (no session, or it ended).", clear: false };
  const result = await refreshSession(session, headers, REFRESH_AHEAD[ahead]);
  if (result.ok) return { kind: "fresh", session: result.session, rotated: result.session.rt !== session.rt || result.session.sid !== session.sid };
  if (result.error === "accounts_unreachable") return { kind: "unavailable", status: 502, code: "accounts_unreachable", message: result.description };
  if (signInEnded(result)) return { kind: "signed_out", message: `Your sign-in ended: ${result.description}`, clear: true };
  // A token that is still valid keeps working while Silicon Accounts has a moment.
  if (result.error !== "session_storage_unavailable" && session.ae > now + 5_000) return { kind: "fresh", session, rotated: false };
  return { kind: "unavailable", status: 503, code: "refresh_failed", message: `Refreshing the sign-in failed: ${result.description}` };
}
