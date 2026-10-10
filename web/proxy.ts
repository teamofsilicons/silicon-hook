/**
 * Next 16 proxy (formerly middleware), run before every page, prefetches included (route handlers under /api and /auth,
 * the agent files and static files set their own headers and never pass through here, so request bodies stream):
 *
 * - Keeps the session fresh: under 2 minutes left on the access token, it refreshes (single-flight, lib/server/tokens.ts),
 *   writes the new cookie on the response and hands it to the page render as a request cookie, so Server Components
 *   (which cannot write cookies) see a token that is good for the render. A sign-in that ended is cleared.
 * - Sends `/` to the workspace (appConfig.home) when signed in, and a workspace address to the hosted sign-in when not.
 * - A fresh CSP nonce per request and the security headers: script-src 'self' 'nonce-…' 'strict-dynamic' (Next adds the
 *   nonce to its own scripts, the root layout to the theme boot script), img-src for Silicon Accounts and Iris profile
 *   photos (plus EXTRA_IMG_ORIGINS), connect-src 'self' (the browser talks to this site only), frame-ancestors 'none'.
 *   X-Frame-Options DENY, nosniff, a strict referrer policy, HSTS in production over https.
 */
import { NextResponse, type NextRequest } from "next/server";
import { appConfig } from "./lib/app.config";
import { EnvError, serverEnv, type ServerEnv } from "./lib/server/env";
import { freshSession } from "./lib/server/fresh";
import { clearSession, clientHeaders, readSession, sealSession, sessionCookieName, writeSession } from "./lib/server/session";

const isDev = process.env.NODE_ENV === "development";
const IRIS = "https://iris.teamofsilicons.com";

function contentSecurityPolicy(nonce: string, env: ServerEnv): string {
  const images = [...new Set([env.accountsUrl, IRIS, ...env.extraImgOrigins])].join(" ");
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    `img-src 'self' data: blob: ${images}`,
    "font-src 'self' data:",
    "connect-src 'self'",
    "media-src 'self' blob:",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'none'",
  ].join("; ");
}

/** Workspace addresses: the nav's sections and everything under them. */
function inWorkspace(pathname: string): boolean {
  return appConfig.nav.some(item => pathname === item.href || pathname.startsWith(`${item.href}/`)) || pathname === appConfig.home;
}

export async function proxy(request: NextRequest) {
  let env: ServerEnv;
  try {
    env = serverEnv();
  } catch (error) {
    if (!(error instanceof EnvError)) throw error;
    console.error(error.message);
    return new NextResponse(`${error.message}\n`, { status: 500, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
  }
  const { pathname } = request.nextUrl;
  // The address as the reader sees it: a client navigation's own `_rsc` marker is not part of it.
  const query = new URLSearchParams(request.nextUrl.search);
  query.delete("_rsc");
  const here = `${pathname}${query.size ? `?${query.toString()}` : ""}`;
  const state = await freshSession(readSession(request), "page", clientHeaders(request));
  const signedIn = state.kind === "fresh" || state.kind === "unavailable";

  let response: NextResponse;
  if (pathname === "/" && signedIn) {
    response = NextResponse.redirect(new URL(appConfig.home, request.url), 307);
  } else if (!signedIn && inWorkspace(pathname)) {
    response = NextResponse.redirect(new URL(`/auth/sign-in?return_to=${encodeURIComponent(here)}`, request.url), 307);
  } else {
    const nonce = btoa(crypto.randomUUID());
    const csp = contentSecurityPolicy(nonce, env);
    // The render sees the refreshed (or cleared) session as if the browser had sent it.
    if (state.kind === "fresh" && state.rotated) request.cookies.set(sessionCookieName(), sealSession(state.session));
    if (state.kind === "signed_out" && state.clear) request.cookies.delete(sessionCookieName());
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set("x-nonce", nonce);
    requestHeaders.set("x-kit-path", here);
    requestHeaders.set("Content-Security-Policy", csp);
    response = NextResponse.next({ request: { headers: requestHeaders } });
    response.headers.set("Content-Security-Policy", csp);
    response.headers.set("X-Frame-Options", "DENY");
    response.headers.set("X-Content-Type-Options", "nosniff");
    response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
    response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
    const https = request.nextUrl.protocol === "https:" || request.headers.get("x-forwarded-proto") === "https";
    if (env.production && https) response.headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  }
  if (state.kind === "fresh" && state.rotated) writeSession(response, state.session);
  if (state.kind === "signed_out" && state.clear) clearSession(response);
  return response;
}

export const config = {
  matcher: [
    {
      // Route handlers (the BFF under /api and /auth, the agent files, the icons and the social image) and static files
      // set their own headers.
      source: "/((?!api/|auth/|_next/static|_next/image|fonts/|favicon\\.ico|icon|apple-icon|og\\.png|robots\\.txt|sitemap\\.xml|llms\\.txt|manifest\\.webmanifest).*)",
    },
  ],
};
