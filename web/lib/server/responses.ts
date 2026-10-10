/** Small response helpers shared by the route handlers: JSON that is never cached, and the misconfiguration answer. */
import { NextResponse } from "next/server";
import type { EnvError } from "./env";
import { errorBody } from "./session";

export function json(status: number, body: unknown, extra?: (response: NextResponse) => void): NextResponse {
  const response = NextResponse.json(body, { status });
  response.headers.set("Cache-Control", "no-store");
  response.headers.set("X-Content-Type-Options", "nosniff");
  extra?.(response);
  return response;
}

/** The server's environment cannot run the kit: say exactly what is missing (never a secret's value). */
export function misconfigured(error: EnvError): NextResponse {
  console.error(error.message);
  return json(500, errorBody("misconfigured", `This site is not set up yet: ${error.problems.join(" ")}`, "The site's maintainers need to set the environment variables listed in its README (Environment)."));
}

/** A redirect that is never cached, to an absolute address on this site (behind a proxy the request's own URL may name the loopback listener). */
export function redirectTo(url: string | URL, status: 303 | 307 = 303): NextResponse {
  const response = NextResponse.redirect(url, status);
  response.headers.set("Cache-Control", "no-store");
  return response;
}
