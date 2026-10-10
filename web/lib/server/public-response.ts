/**
 * Responses for the public files (robots.txt, the sitemap, llms.txt, the manifest), copied from the store: the right
 * content type, open to any origin (they are public reads), cacheable with an ETag (a matching If-None-Match answers
 * 304), and nosniff. Structured errors share one shape: {"error": {"code", "message", "hint"}}.
 */
import { createHash } from "node:crypto";

export interface PublicResponseOptions {
  /** Content-Type, with its charset. */
  type: string;
  /** Seconds browsers and caches may keep it. */
  maxAge?: number;
  /** When the content last changed (ISO 8601), for Last-Modified. */
  modified?: string | null;
  status?: number;
  headers?: Record<string, string>;
}

/** A strong validator from the body itself (hashing even the 500 KB llms-full.txt takes about a millisecond). */
function etagOf(body: string): string {
  return `"${createHash("sha256").update(body).digest("base64url").slice(0, 27)}"`;
}

export const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Expose-Headers": "ETag, Retry-After",
};

export function publicResponse(request: Request, body: string, { type, maxAge = 300, modified, status = 200, headers = {} }: PublicResponseOptions): Response {
  const base: Record<string, string> = {
    "Content-Type": type,
    "Cache-Control": `public, max-age=${maxAge}, stale-while-revalidate=86400`,
    "X-Content-Type-Options": "nosniff",
    Vary: "Accept-Encoding",
    ...CORS_HEADERS,
    ...headers,
  };
  if (status === 200) {
    const etag = etagOf(body);
    base.ETag = etag;
    if (modified) base["Last-Modified"] = new Date(modified).toUTCString();
    const match = request.headers.get("if-none-match");
    if (match && match.split(",").some(value => value.trim().replace(/^W\//, "") === etag)) return new Response(null, { status: 304, headers: base });
  }
  return new Response(request.method === "HEAD" ? null : body, { status, headers: base });
}

export function jsonResponse(request: Request, value: unknown, options: Omit<PublicResponseOptions, "type"> = {}): Response {
  return publicResponse(request, `${JSON.stringify(value, null, 2)}\n`, { type: "application/json; charset=utf-8", ...options });
}

export interface ApiError {
  code: string;
  message: string;
  hint: string;
}

/** A structured error: never cached, always JSON. */
export function errorResponse(status: number, error: ApiError, headers: Record<string, string> = {}): Response {
  return new Response(`${JSON.stringify({ error }, null, 2)}\n`, {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...CORS_HEADERS, ...headers },
  });
}

/** The answer to a CORS preflight for the public endpoints. */
export function preflight(methods = "GET, HEAD, OPTIONS"): Response {
  return new Response(null, {
    status: 204,
    headers: {
      ...CORS_HEADERS,
      "Access-Control-Allow-Methods": methods,
      "Access-Control-Allow-Headers": "Accept, Authorization, Content-Type, If-None-Match",
      "Access-Control-Max-Age": "86400",
    },
  });
}
