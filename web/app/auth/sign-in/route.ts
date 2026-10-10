/**
 * GET /auth/sign-in?return_to=/items: starts signing a Carbon in. A fresh state and PKCE verifier are sealed into a
 * short-lived httpOnly cookie (up to three at once, for three tabs), and the browser goes to the hosted sign-in:
 *
 *   {ACCOUNTS_URL}/authorize?app_id=…&redirect_uri={PUBLIC_URL}/auth/callback&response_type=code&scope=…&state=…
 *     &code_challenge=…&code_challenge_method=S256
 *
 * `prompt=login|select_account` and `intent=signup` pass through. A request that reached this site under another host
 * than PUBLIC_URL's (127.0.0.1 for localhost, a deployment URL for the custom domain) is sent to PUBLIC_URL first:
 * the pending cookie must live on the host the callback comes back to.
 */
import { NextResponse, type NextRequest } from "next/server";
import { appConfig } from "@/lib/app.config";
import { callbackUrl, EnvError, serverEnv } from "@/lib/server/env";
import { randomToken, readPending, s256, safeReturnPath, writePending } from "@/lib/server/session";
import { misconfigured } from "@/lib/server/responses";

export const dynamic = "force-dynamic";

export function GET(request: NextRequest) {
  // A router prefetch must not start a sign-in (it would set a pending cookie nobody uses).
  if (request.headers.get("next-router-prefetch") || request.headers.get("purpose") === "prefetch" || request.headers.get("rsc")) {
    return new NextResponse(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  }
  let env;
  try {
    env = serverEnv();
  } catch (error) {
    if (error instanceof EnvError) return misconfigured(error);
    throw error;
  }
  const params = request.nextUrl.searchParams;
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  const own = new URL(env.publicUrl);
  if (host && host !== own.host && params.get("bounced") !== "1") {
    const there = new URL(`/auth/sign-in${request.nextUrl.search}`, env.publicUrl);
    there.searchParams.set("bounced", "1");
    return NextResponse.redirect(there, { status: 307, headers: { "Cache-Control": "no-store" } });
  }

  const state = randomToken(16);
  const verifier = randomToken(32);
  const query = new URLSearchParams({
    app_id: env.appId,
    redirect_uri: callbackUrl(env),
    response_type: "code",
    state,
    code_challenge: s256(verifier),
    code_challenge_method: "S256",
  });
  const scopes = appConfig.signIn.scopes.filter(scope => /^[a-z_]+$/.test(scope));
  if (scopes.length) query.set("scope", scopes.join(" "));
  const prompt = params.get("prompt");
  if (prompt === "login" || prompt === "select_account") query.set("prompt", prompt);
  if (params.get("intent") === "signup") query.set("intent", "signup");

  const response = NextResponse.redirect(`${env.accountsUrl}/authorize?${query.toString()}`, 303);
  writePending(response, [...readPending(request), { s: state, v: verifier, r: safeReturnPath(params.get("return_to") ?? appConfig.home), t: Date.now() }]);
  response.headers.set("Cache-Control", "no-store");
  return response;
}
