export interface Actor {
  type: string;
  id: string;
}
export interface Plane {
  id: string;
  name: string;
  attached: boolean;
  authenticated: boolean;
  actor?: Actor;
  org_id?: string;
  expires_at?: number;
}
export interface Session {
  planes: Plane[];
  upstream: string;
}
export interface Signature {
  required: boolean;
  algorithm: string;
  payload: string;
  signature: string;
  signature_encoding: string;
  secret_encoding: string;
  public_key: string | null;
  has_secret?: boolean;
}
export interface Hook {
  id: string;
  org_id: string;
  silicon_id: string;
  name: string;
  description: string | null;
  endpoint_url: string;
  endpoint_key: string;
  status: string;
  signature: Signature;
  time_zone: string;
  created_at: string;
  deleted_at: string | null;
  recoverable_until: string | null;
  last_received_at: string | null;
  last_blocked_at: string | null;
  signing_secret?: string;
}
export interface Captured {
  method: string;
  url: string;
  path: string;
  query_string: string;
  headers: [string, string][];
  content_type: string | null;
  body: string | null;
  body_base64: string | null;
  remote_ip: string;
}
export interface Event {
  id: string;
  hook_id: string;
  silicon_id: string;
  provider: string;
  summary?: string;
  received_at: string;
  delivery_sequence?: number;
  reason_code?: string;
  reason_detail?: string;
  request: Captured;
}
export interface Page<T> {
  items: T[];
  next_cursor?: string | null;
}
export interface Environment {
  id: string;
  name: string;
  description: string | null;
  org_id: string;
  generation: number;
  created_at: string;
  last_activity_at: string;
  deleted_at: string | null;
  creator_id: string;
  key?: string;
}
export interface Context {
  plane: string;
  org: string;
  silicon: string;
}
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: string,
    public requestId?: string,
    public retryAfter?: string,
  ) {
    super(message);
  }
}
export async function request<T>(
  path: string,
  method = "GET",
  body?: unknown,
  key?: string,
  org?: string,
): Promise<T> {
  const headers: Record<string, string> = {
    "X-Hook-Frontend": "1",
    accept: "application/json",
  };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (key) headers["idempotency-key"] = key;
  if (org) headers["x-org-id"] = org;
  let response: Response;
  try {
    response = await fetch(new URL(path, gatewayOrigin()), {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "include",
      cache: "no-store",
      signal: AbortSignal.timeout(45000),
    });
  } catch {
    throw new ApiError(
      0,
      "connection_failed",
      "Could not reach Hook. Check your connection and try again.",
    );
  }
  const result = await response.json();
  if (!response.ok)
    throw new ApiError(
      response.status,
      result.error?.code || "request_failed",
      result.error?.message || "Request failed.",
      result.error?.details,
      result.error?.request_id,
      result.error?.retry_after,
    );
  return result;
}
export function api<T>(
  ctx: Context,
  path: string,
  method = "GET",
  body?: unknown,
  key?: string,
) {
  if (
    !ctx.org &&
    (path.startsWith("/api/v1/testing-environments") ||
      path.startsWith("/api/v1/silicons/"))
  )
    throw new Error(
      "Choose an organization shared through IAM in the sidebar first.",
    );
  const u = new URL("/console/proxy" + path, location.origin);
  u.searchParams.set("plane", ctx.plane);
  return request<T>(u.pathname + u.search, method, body, key, ctx.org);
}
export function gatewayOrigin(): string {
  return import.meta.env.VITE_HOOK_GATEWAY_ORIGIN || location.origin;
}
export function scoped(ctx: Context, suffix = "") {
  if (!ctx.silicon) throw new Error("Choose a Silicon in the sidebar first.");
  return "/api/v1/silicons/" + encodeURIComponent(ctx.silicon) + suffix;
}
export const query = (
  params: Record<string, string | number | boolean | undefined>,
) => {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params))
    if (v !== undefined && v !== "") q.set(k, String(v));
  return q.size ? "?" + q : "";
};
export const date = (value?: string | null) =>
  value
    ? new Date(value).toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      })
    : "—";
export const message = (error: unknown) =>
  error instanceof Error ? error.message : String(error);
export function download(
  name: string,
  data: string,
  type = "application/json",
) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
