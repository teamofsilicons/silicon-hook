/**
 * POST /auth/sign-out: ends this browser's sign-in to the app. The refresh token is revoked at Silicon Accounts
 * (POST /v1/oauth/revoke with the app's credentials; every token of the sign-in dies with it) and the session cookie is
 * cleared. Same-origin only (CSRF guard). The Carbon's own sign-in at Silicon Accounts is untouched.
 *
 * A fetch (the account menu) gets 204; a plain form post (no script) is sent to /sign-in?signed_out=1.
 */
import { NextResponse, type NextRequest } from "next/server";
import { EnvError, serverEnv } from "@/lib/server/env";
import { json, misconfigured, redirectTo } from "@/lib/server/responses";
import { clearSession, clientHeaders, errorBody, readSession, sameOriginProblem } from "@/lib/server/session";
import { revokeSession } from "@/lib/server/tokens";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  let env;
  try {
    env = serverEnv();
  } catch (error) {
    if (error instanceof EnvError) return misconfigured(error);
    throw error;
  }
  const problem = sameOriginProblem(request);
  if (problem) return json(403, errorBody("cross_site_request", problem, "Sign out from this site's own account menu."));
  const session = readSession(request);
  if (session) await revokeSession(session, clientHeaders(request));
  const wantsPage = (request.headers.get("accept") ?? "").includes("text/html") && request.headers.get("sec-fetch-mode") === "navigate";
  const response = wantsPage ? redirectTo(new URL("/sign-in?signed_out=1", env.publicUrl)) : new NextResponse(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  clearSession(response);
  return response;
}
