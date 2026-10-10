/**
 * The session and the app's service for Server Components (pages, layouts) and Server Functions:
 *
 *   const session = await getSession();          // { account, expiresAt, scope } | null, from the cookie alone
 *   const session = await requireSession();      // the same, or a redirect to the hosted sign-in (back here after)
 *   const items = await apiFetch<Item[]>("/v1/items");            // the app's service, with the bearer token
 *   const item = await apiFetch<Item>(`/v1/items/${id}`, { notFound: true });  // 404 → notFound()
 *
 * Server Components cannot write cookies, so nothing here refreshes: proxy.ts refreshes on every page load when under
 * 2 minutes are left, and an access token that still expired (Silicon Accounts was unreachable a moment ago) is sent
 * through /auth/refresh, which can. Errors are ApiError with the service's own code, message and hint; a 401 sends the
 * Carbon to /sign-in?reason=session_ended (the page explains, nothing loops).
 */
import "server-only";
import { cookies, headers } from "next/headers";
import { notFound, redirect } from "next/navigation";
import { ApiError, errorFromResponse, networkError, type ApiErrorInit } from "../errors";
import { serverEnv } from "./env";
import { clientHeaders, safeReturnPath, sessionCookieName, sessionFromCookie, type SessionAccount, type StoredSession } from "./session";

/** What a page may know about the session: never the tokens. */
export interface PublicSession {
  account: SessionAccount;
  /** When the access token expires (epoch ms); the browser's session keeper refreshes ahead of it. */
  expiresAt: number;
  scope: string;
}

/** The path being rendered (proxy.ts passes it as x-kit-path), for return_to. */
async function currentPath(): Promise<string> {
  return safeReturnPath((await headers()).get("x-kit-path"));
}

async function storedSession(): Promise<StoredSession | null> {
  const store = await cookies();
  return sessionFromCookie(store.get(sessionCookieName())?.value);
}

const toPublic = (session: StoredSession): PublicSession => ({ account: session.acct, expiresAt: session.ae, scope: session.scope });

/** The signed-in account, or null. Reads the sealed cookie only (no network). */
export async function getSession(): Promise<PublicSession | null> {
  const session = await storedSession();
  return session ? toPublic(session) : null;
}

/** The signed-in account; without one, a redirect to the hosted sign-in that comes back to `returnTo` (this page). */
export async function requireSession(returnTo?: string): Promise<PublicSession> {
  const session = await storedSession();
  if (session) return toPublic(session);
  const back = safeReturnPath(returnTo ?? (await currentPath()));
  redirect(`/auth/sign-in?return_to=${encodeURIComponent(back)}`);
}

export interface ApiFetchInit {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** A JSON body (serialised for you). */
  body?: unknown;
  query?: Record<string, string | number | boolean | null | undefined>;
  headers?: Record<string, string>;
  /** A 404 from the service renders the nearest not-found page instead of throwing. */
  notFound?: boolean;
  signal?: AbortSignal;
}

function queryString(query: ApiFetchInit["query"]): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  const text = params.toString();
  return text ? `?${text}` : "";
}

/**
 * Calls the app's service as the signed-in account: `{APP_API_URL}{path}` with `Authorization: Bearer`. Resolves with
 * the parsed JSON (null for 204); rejects with ApiError. `path` is the service's own path, starting with "/".
 */
export async function apiFetch<T>(path: string, init: ApiFetchInit = {}): Promise<T> {
  if (!path.startsWith("/") || path.startsWith("//")) throw new Error(`apiFetch needs the service's own path, starting with one "/": got "${path}".`);
  const session = await storedSession();
  if (!session) await requireSession();
  const live = session as StoredSession;
  if (live.ae <= Date.now() + 5_000) redirect(`/auth/refresh?return_to=${encodeURIComponent(await currentPath())}`);

  const env = serverEnv();
  const method = init.method ?? (init.body === undefined ? "GET" : "POST");
  const outgoing: Record<string, string> = { Accept: "application/json", ...clientHeaders({ headers: await headers() }), ...init.headers, Authorization: `Bearer ${live.at}` };
  if (init.body !== undefined) outgoing["Content-Type"] = "application/json";
  const url = `${env.appApiUrl}${path}${queryString(init.query)}`;
  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers: outgoing,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      cache: "no-store",
      redirect: "manual",
      signal: init.signal ?? AbortSignal.timeout(30_000),
    });
  } catch (error) {
    throw networkError(error, method, path, "the service");
  }
  const text = response.status === 204 ? "" : await response.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }
  if (response.ok) return body as T;
  if (response.status === 401) redirect(`/sign-in?reason=session_ended&return_to=${encodeURIComponent(await currentPath())}`);
  if (response.status === 404 && init.notFound) notFound();
  throw errorFromResponse(response, body, method, path);
}

export type ApiResult<T> = { data: T; error: null } | { data: null; error: ApiErrorInit };

/**
 * apiFetch for a page that shows a failure inline (an Arc alert with the service's own words) instead of the error
 * page: production builds hide a thrown error's message from the page, so pass the failure on as data. Redirects
 * (signed out) and notFound() still happen.
 *
 *   const { data, error } = await tryApiFetch<Item[]>("/v1/items");
 *   if (error) return <ErrorAlert error={error} />;
 */
export async function tryApiFetch<T>(path: string, init: ApiFetchInit = {}): Promise<ApiResult<T>> {
  try {
    return { data: await apiFetch<T>(path, init), error: null };
  } catch (failure) {
    if (failure instanceof ApiError) return { data: null, error: failure.toJSON() };
    throw failure;
  }
}

export { ApiError };
