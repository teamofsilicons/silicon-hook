/**
 * Toasts for results of background work and API failures, callable from anywhere (components, query caches, plain
 * functions). A foreground action still confirms in place (Arc rule); use these for what happens out of view, and for
 * errors in addition to an inline message near the cause.
 *
 *   notifyError(error, "Could not save the item")      // title + the service's message and hint
 *   notify.success("Shared", "si:scout can see this item now")
 *
 * The Arc toast stack (components/arc/toast-stack) lives in the providers; <ToastBridge> hands its API to this module.
 * Toasts raised before it mounts are queued and shown once it does. Adapted from the developer site's lib/notify.ts.
 */
import type { ToastOptions, ToastStackApi } from "@/components/arc/toast-stack/toast-stack";
import { ApiError } from "./errors";
import { durationText, readableTimes } from "./format";

let stack: ToastStackApi | null = null;
const queue: ToastOptions[] = [];
let counter = 0;

const newId = () => {
  counter += 1;
  return `toast-${Date.now().toString(36)}-${counter}`;
};

/** Connects the mounted toast stack (called by ToastBridge). Returns a disconnect function. */
export function connectToasts(next: ToastStackApi): () => void {
  stack = next;
  for (const options of queue.splice(0)) next.toast(options);
  return () => {
    if (stack === next) stack = null;
  };
}

function show(options: ToastOptions): string {
  const id = options.id ?? newId();
  const full = { ...options, id };
  if (stack) stack.toast(full);
  else queue.push(full);
  return id;
}

function titleFor(error: ApiError): string {
  if (error.isNetwork) return "The service is unreachable";
  if (error.status === 401) return "You are signed out";
  if (error.status === 403) return "Not allowed";
  if (error.status === 404) return "Not found";
  if (error.status === 409) return "That conflicts with what is there";
  if (error.status === 422) return "Check the details";
  if (error.status === 429) return "Slow down for a moment";
  if (error.status >= 500) return "The service had a problem";
  return "That did not work";
}

/** Shows a failure: the service's message says what and why, the hint what to do next. Returns the toast id. */
export function notifyError(error: unknown, title?: string): string {
  const failure = ApiError.from(error);
  const retry = failure.retryAfter && !failure.hint ? ` Try again in ${durationText(failure.retryAfter)}.` : "";
  const description = readableTimes([failure.message, failure.hint].filter(Boolean).join(" ") + retry);
  // One network toast at a time: every failing request would otherwise stack its own.
  return show({ type: "error", title: title ?? titleFor(failure), description, id: failure.isNetwork ? "network_error" : undefined });
}

export const notify = {
  success: (title: string, description?: string) => show({ type: "success", title, description }),
  info: (title: string, description?: string) => show({ type: "info", title, description }),
  warning: (title: string, description?: string) => show({ type: "warning", title, description }),
  error: notifyError,
  /** A toast that stays until updated: `const id = notify.loading("Importing"); notify.update(id, { type: "success", … })`. */
  loading: (title: string, description?: string) => show({ type: "loading", title, description }),
  update: (id: string, patch: Partial<Omit<ToastOptions, "id">>) => stack?.update(id, patch),
  dismiss: (id?: string) => stack?.dismiss(id),
};
