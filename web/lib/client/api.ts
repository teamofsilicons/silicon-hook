/**
 * The browser's way to the app's service: same-origin calls to the API proxy, JSON in and out, errors as ApiError
 * (the service's code, message and hint). Paths are the service's own (`/v1/items`); this sends them to `/api/v1/items`,
 * where the server adds the bearer token from the sealed session. The browser never holds a token.
 *
 *   const items = await api.get<Item[]>("/v1/items", { query: { q: "notes" } });
 *   await api.post("/v1/items", { title: "Write the report" }, { idempotencyKey: true });
 *
 * Before a call, the session keeper (lib/client/session.ts) refreshes the sign-in once if it is about to expire, so
 * many calls at once never race to refresh it. A 401 means the sign-in ended (the proxy cleared it): the keeper sends
 * the Carbon to /sign-in, which explains and signs them in again. Framework-free: React Query hooks and plain code use it.
 */
import { ApiError, errorFromResponse, networkError } from "../errors";
import { ensureFreshSession, markSignedOut } from "./session";

export type QueryValue = string | number | boolean | null | undefined | readonly (string | number)[];

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  query?: Record<string, QueryValue>;
  /** A JSON body (serialised for you). */
  body?: unknown;
  /** A raw body (a file, a form) sent as is with `contentType`. */
  raw?: BodyInit;
  contentType?: string;
  headers?: Record<string, string>;
  /** Sends `Idempotency-Key`: `true` makes a fresh key; pass your own to make retries of one action safe. */
  idempotencyKey?: string | true;
  signal?: AbortSignal;
}

/** A fresh Idempotency-Key. Keep it for the retries of one logical action. */
export function newIdempotencyKey(): string {
  return crypto.randomUUID();
}

export function queryString(query: Record<string, QueryValue> | undefined): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) for (const item of value) params.append(key, String(item));
    else params.set(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

/** Encodes one path segment (ids such as `c:ada`). */
export const seg = (value: string | number): string => encodeURIComponent(String(value));

async function readBody(response: Response): Promise<unknown> {
  if (response.status === 204 || response.status === 205) return null;
  const text = await response.text();
  if (!text) return null;
  if ((response.headers.get("content-type") ?? "").includes("json") || /^\s*[[{]/.test(text)) {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
  return text;
}

/** Performs one call. Resolves with the parsed body (null for 204); rejects with ApiError. */
export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  if (!path.startsWith("/") || path.startsWith("//")) throw new ApiError({ status: 0, code: "client_error", message: `The page asked for "${path}", which is not a path of the service.`, hint: "Pass the service's own path, starting with /." });
  const method = options.method ?? (options.body !== undefined || options.raw !== undefined ? "POST" : "GET");
  const headers: Record<string, string> = { Accept: "application/json", ...options.headers };
  let body: BodyInit | undefined;
  if (options.raw !== undefined) {
    body = options.raw;
    if (options.contentType) headers["Content-Type"] = options.contentType;
  } else if (options.body !== undefined) {
    body = JSON.stringify(options.body);
    headers["Content-Type"] = options.contentType ?? "application/json";
  }
  if (options.idempotencyKey) headers["Idempotency-Key"] = options.idempotencyKey === true ? newIdempotencyKey() : options.idempotencyKey;

  await ensureFreshSession();
  let response: Response;
  try {
    response = await fetch(`/api${path}${queryString(options.query)}`, { method, headers, body, credentials: "same-origin", cache: "no-store", signal: options.signal });
  } catch (error) {
    throw networkError(error, method, path, "this site");
  }
  const parsed = await readBody(response).catch(() => null);
  if (!response.ok) {
    const error = errorFromResponse(response, parsed, method, path);
    if (error.status === 401) markSignedOut();
    throw error;
  }
  return parsed as T;
}

export const api = {
  get: <T>(path: string, options?: Omit<RequestOptions, "method" | "body">) => request<T>(path, { ...options, method: "GET" }),
  post: <T>(path: string, body?: unknown, options?: Omit<RequestOptions, "method" | "body">) => request<T>(path, { ...options, method: "POST", body }),
  put: <T>(path: string, body?: unknown, options?: Omit<RequestOptions, "method" | "body">) => request<T>(path, { ...options, method: "PUT", body }),
  patch: <T>(path: string, body?: unknown, options?: Omit<RequestOptions, "method" | "body">) => request<T>(path, { ...options, method: "PATCH", body }),
  delete: <T = null>(path: string, options?: Omit<RequestOptions, "method" | "body">) => request<T>(path, { ...options, method: "DELETE" }),
};
