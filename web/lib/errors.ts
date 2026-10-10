/**
 * One error type for every failed call, in the browser and on the server: the service's own words. Every Silicon service
 * answers errors as `{"error": {"code", "message", "hint", "details"?}}`; `message` says exactly what went wrong and
 * why, `hint` says what to do next. Show both (toasts, inline alerts).
 *
 * Adapted from the developer site (silicon-accounts/developer/lib/api/errors.ts). Isomorphic: no browser or Node APIs.
 */

export interface ApiErrorInit {
  status: number;
  code: string;
  message: string;
  hint?: string | null;
  details?: Record<string, unknown>;
  requestId?: string | null;
  /** Seconds from a Retry-After header or `details.retry_after_seconds`. */
  retryAfter?: number | null;
  method?: string;
  path?: string;
  cause?: unknown;
}

/** The shape every Silicon service answers errors in. */
export interface ApiErrorBody {
  error: { code: string; message: string; hint?: string; details?: Record<string, unknown> };
}

export class ApiError extends Error {
  /** HTTP status; 0 when the request never reached the server. */
  readonly status: number;
  /** Stable machine code: `not_found`, `validation_failed`, `signed_out`, `network_error`… */
  readonly code: string;
  readonly hint: string | undefined;
  readonly details: Record<string, unknown>;
  readonly requestId: string | null;
  readonly retryAfter: number | null;
  readonly method: string | undefined;
  readonly path: string | undefined;

  constructor(init: ApiErrorInit) {
    super(init.message, init.cause === undefined ? undefined : { cause: init.cause });
    this.name = "ApiError";
    this.status = init.status;
    this.code = init.code;
    this.hint = init.hint ?? undefined;
    this.details = init.details ?? {};
    this.requestId = init.requestId ?? null;
    this.retryAfter = init.retryAfter ?? null;
    this.method = init.method;
    this.path = init.path;
  }

  /** True when `error` is an ApiError, optionally with one of `codes`. */
  static is(error: unknown, ...codes: string[]): error is ApiError {
    return error instanceof ApiError && (codes.length === 0 || codes.includes(error.code));
  }

  /** Wraps anything thrown into an ApiError so callers handle one shape. */
  static from(error: unknown): ApiError {
    if (error instanceof ApiError) return error;
    if (error && typeof error === "object" && (error as { name?: unknown }).name === "AbortError") {
      return new ApiError({ status: 0, code: "aborted", message: "The request was cancelled before it finished.", cause: error });
    }
    if (error && typeof error === "object" && !(error instanceof Error)) {
      const value = error as Partial<ApiErrorInit>;
      if (typeof value.code === "string" && typeof value.message === "string") {
        return new ApiError({ status: typeof value.status === "number" ? value.status : 0, code: value.code, message: value.message, hint: value.hint, details: value.details });
      }
    }
    const text = error instanceof Error ? error.message : String(error);
    return new ApiError({ status: 0, code: "client_error", message: `Something in this page failed before the request finished: ${text}`, hint: "Reload the page and try again.", cause: error });
  }

  /** The request never reached the server (offline, DNS, the service down). */
  get isNetwork(): boolean {
    return this.code === "network_error";
  }

  /** Field-level messages from a 422 (`details.fields`), keyed by field. */
  get fields(): Record<string, string> {
    const fields = this.details.fields;
    if (!fields || typeof fields !== "object") return {};
    const out: Record<string, string> = {};
    for (const [key, value] of Object.entries(fields as Record<string, unknown>)) out[key] = Array.isArray(value) ? value.map(String).join(" ") : String(value);
    return out;
  }

  /** One line for logs and fallbacks: message, hint and request id. */
  describe(): string {
    return [this.message, this.hint, this.requestId ? `(request ${this.requestId})` : ""].filter(Boolean).join(" ");
  }

  /** A plain object (Server Components hand errors to client components as data, never as class instances). */
  toJSON(): ApiErrorInit {
    return { status: this.status, code: this.code, message: this.message, hint: this.hint ?? null, details: this.details, requestId: this.requestId, retryAfter: this.retryAfter };
  }
}

/**
 * A 401 means the sign-in is gone, whoever said it: the kit's own routes answer 401 `signed_out`, and the API proxy
 * clears the session whenever the app's service answers 401 (README.md: The API proxy), so the browser signs in again.
 */
export function isSignedOutError(error: unknown): boolean {
  return ApiError.from(error).status === 401;
}

function isApiErrorBody(value: unknown): value is ApiErrorBody {
  if (!value || typeof value !== "object") return false;
  const error = (value as { error?: unknown }).error;
  return !!error && typeof error === "object" && typeof (error as { code?: unknown }).code === "string" && typeof (error as { message?: unknown }).message === "string";
}

function retryAfterFrom(headers: Headers, details: Record<string, unknown> | undefined): number | null {
  const fromDetails = details?.retry_after_seconds;
  if (typeof fromDetails === "number" && Number.isFinite(fromDetails)) return fromDetails;
  const header = headers.get("retry-after");
  if (!header) return null;
  const seconds = Number(header);
  if (Number.isFinite(seconds)) return seconds;
  const at = Date.parse(header);
  return Number.isFinite(at) ? Math.max(0, Math.round((at - Date.now()) / 1000)) : null;
}

const STATUS_WORDS: Record<number, string> = {
  400: "the request was not valid",
  401: "you are not signed in",
  403: "this account is not allowed to do that",
  404: "it does not exist",
  409: "it conflicts with the current state",
  410: "it is gone",
  413: "the request is too large",
  422: "the input was not accepted",
  429: "too many requests were made",
  500: "the service hit an internal error",
  502: "the service could not be reached",
  503: "the service is temporarily unavailable",
  504: "the service took too long to answer",
};

/** Builds the ApiError for a non-2xx response from its (already parsed, possibly null) body. */
export function errorFromResponse(response: Response, body: unknown, method: string, path: string): ApiError {
  const requestId = response.headers.get("x-request-id");
  if (isApiErrorBody(body)) {
    const { code, message, hint, details } = body.error;
    return new ApiError({ status: response.status, code, message, hint, details, requestId, retryAfter: retryAfterFrom(response.headers, details), method, path });
  }
  const reason = STATUS_WORDS[response.status] ?? `the server answered ${response.status}`;
  return new ApiError({
    status: response.status,
    code: response.status === 401 ? "signed_out" : response.status >= 500 ? "server_unavailable" : "unexpected_response",
    message: `${method} ${path} failed: ${reason} (HTTP ${response.status}), and the answer had no error details.`,
    hint: response.status === 401 ? "Sign in again." : response.status >= 500 ? "Wait a moment and try again." : "Reload the page and try again.",
    requestId,
    retryAfter: retryAfterFrom(response.headers, undefined),
    method,
    path,
  });
}

/** The error for a request that never got a response. */
export function networkError(error: unknown, method: string, path: string, service = "the service"): ApiError {
  if (error && typeof error === "object" && (error as { name?: unknown }).name === "AbortError") return ApiError.from(error);
  const reason = error instanceof Error && error.message ? error.message : "the network request failed";
  return new ApiError({ status: 0, code: "network_error", message: `Could not reach ${service} for ${method} ${path}: ${reason}.`, hint: "Check your connection, then try again.", method, path, cause: error });
}
