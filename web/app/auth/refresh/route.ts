/**
 * /auth/refresh: rotates the session's tokens when the access token is close to expiring, and does nothing otherwise.
 *
 * - POST (the browser's session keeper, lib/client/session.ts; same-origin only): answers like /auth/session, after
 *   refreshing when under 5 minutes are left. 401 `signed_out` (and the cookie cleared) when the sign-in ended.
 * - GET ?return_to=/items (a Server Component found the access token expired and cannot write cookies itself):
 *   refreshes and goes back; a sign-in that ended goes to /sign-in?reason=session_ended.
 */
import type { NextRequest } from "next/server";
import { EnvError, serverEnv } from "@/lib/server/env";
import { freshSession } from "@/lib/server/fresh";
import { json, misconfigured, redirectTo } from "@/lib/server/responses";
import { clearSession, clientHeaders, errorBody, readSession, safeReturnPath, sameOriginProblem, writeSession } from "@/lib/server/session";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  try {
    serverEnv();
  } catch (error) {
    if (error instanceof EnvError) return misconfigured(error);
    throw error;
  }
  const problem = sameOriginProblem(request);
  if (problem) return json(403, errorBody("cross_site_request", problem, "Refresh from this site's own pages."));
  const state = await freshSession(readSession(request), "keeper", clientHeaders(request));
  if (state.kind === "signed_out") return json(401, errorBody("signed_out", state.message, "Sign in again."), state.clear ? clearSession : undefined);
  if (state.kind === "unavailable") return json(state.status, errorBody(state.code, state.message, "Wait a moment and try again."));
  return json(200, { signed_in: true, account: state.session.acct, expires_at: new Date(state.session.ae).toISOString() }, response => {
    if (state.rotated) writeSession(response, state.session);
  });
}

export async function GET(request: NextRequest) {
  let env;
  try {
    env = serverEnv();
  } catch (error) {
    if (error instanceof EnvError) return misconfigured(error);
    throw error;
  }
  const back = safeReturnPath(request.nextUrl.searchParams.get("return_to"));
  const state = await freshSession(readSession(request), "page", clientHeaders(request));
  if (state.kind === "fresh") {
    const response = redirectTo(new URL(back, env.publicUrl));
    if (state.rotated) writeSession(response, state.session);
    return response;
  }
  if (state.kind === "signed_out" && !state.clear) {
    // Never signed in here: straight to the hosted sign-in.
    return redirectTo(new URL(`/auth/sign-in?return_to=${encodeURIComponent(back)}`, env.publicUrl));
  }
  const target = new URL("/sign-in", env.publicUrl);
  if (state.kind === "signed_out") target.searchParams.set("reason", "session_ended");
  else target.searchParams.set("error", "accounts_unreachable");
  if (back !== "/") target.searchParams.set("return_to", back);
  const response = redirectTo(target);
  if (state.kind === "signed_out" && state.clear) clearSession(response);
  return response;
}
