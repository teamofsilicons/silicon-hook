/**
 * The browser's view of its session (who is signed in, and when the access token expires: never a token) and the
 * session keeper that refreshes it ahead of time.
 *
 * Why the browser coordinates refreshing: refresh tokens rotate on every use, and two refreshes with the same one end
 * the whole sign-in. The server refreshes single-flight per process, but serverless instances share nothing. So the
 * keeper asks POST /auth/refresh once, 5 minutes before expiry, one tab at a time (navigator.locks), tells the other tabs
 * (BroadcastChannel), and makes API calls wait for it when the token is about to run out (ensureFreshSession). Page
 * loads refresh at 2 minutes and the API proxy only at 30 seconds, so in practice one refresh happens at a time.
 */
import { useCallback, useState, useSyncExternalStore } from "react";
import { appConfig } from "../app.config";
import type { SessionAccount, SessionView } from "../account";
import { ApiError } from "../errors";

/** The keeper refreshes this long before the access token expires; API calls wait for a refresh inside the last minute. */
const KEEPER_AHEAD_MS = 5 * 60_000;
const CALL_AHEAD_MS = 60_000;
const RETRY_MS = 30_000;
const LOCK = `${appConfig.appId}:session-refresh`;
const CHANNEL = `${appConfig.appId}:session`;

const SIGNED_OUT: SessionView = { signedIn: false, account: null, expiresAt: null };
let state: SessionView = SIGNED_OUT;
const listeners = new Set<() => void>();
let timer: ReturnType<typeof setTimeout> | null = null;
let refreshing: Promise<SessionView> | null = null;
let channel: BroadcastChannel | null = null;
let started = false;
let signedOutHandler: () => void = () => sendToSignIn("session_ended");

function emit() {
  for (const listener of listeners) listener();
}

/** What other tabs hear: the new view, and why a sign-in ended (a sign-out here, or the session running out). */
interface TabMessage {
  view: SessionView;
  reason?: "signed_out" | "session_ended";
}

function set(next: SessionView, broadcast: false | TabMessage["reason"] | true = false) {
  state = next;
  emit();
  schedule();
  if (broadcast) channel?.postMessage({ view: next, ...(typeof broadcast === "string" ? { reason: broadcast } : {}) } satisfies TabMessage);
}

function schedule(delay?: number) {
  if (timer) clearTimeout(timer);
  timer = null;
  if (typeof window === "undefined" || !state.signedIn || !state.expiresAt) return;
  const wait = delay ?? state.expiresAt - KEEPER_AHEAD_MS - Date.now() + Math.random() * 20_000;
  timer = setTimeout(() => void refreshSessionNow(), Math.min(Math.max(0, wait), 2 ** 31 - 1));
}

/** Runs `task` while holding the cross-tab refresh lock (where the browser has one). */
function withLock<T>(task: () => Promise<T>): Promise<T> {
  const locks = (navigator as Navigator & { locks?: LockManager }).locks;
  return locks ? (locks.request(LOCK, task) as Promise<T>) : task();
}

interface SessionAnswer {
  signed_in?: boolean;
  account?: SessionAccount;
  expires_at?: string;
}

const viewOf = (body: SessionAnswer): SessionView =>
  body.signed_in && body.account ? { signedIn: true, account: body.account, expiresAt: body.expires_at ? Date.parse(body.expires_at) : null } : SIGNED_OUT;

/**
 * Refreshes the sign-in now if it needs it (the server decides: under 5 minutes left). One at a time in this tab and
 * across tabs; a tab that waited for another finds the cookie already renewed and the server does nothing.
 */
export function refreshSessionNow(): Promise<SessionView> {
  if (refreshing) return refreshing;
  refreshing = withLock(async () => {
    let response: Response;
    try {
      response = await fetch("/auth/refresh", { method: "POST", credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
    } catch {
      schedule(RETRY_MS);
      return state;
    }
    if (response.status === 401) {
      set(SIGNED_OUT, "session_ended");
      signedOutHandler();
      return state;
    }
    if (!response.ok) {
      schedule(RETRY_MS);
      return state;
    }
    set(viewOf((await response.json().catch(() => ({}))) as SessionAnswer), true);
    return state;
  }).finally(() => {
    refreshing = null;
  });
  return refreshing;
}

/** API calls wait here: a token inside its last minute is refreshed once for all of them. */
export async function ensureFreshSession(): Promise<void> {
  if (refreshing) {
    await refreshing;
    return;
  }
  if (!state.signedIn || !state.expiresAt) return;
  if (state.expiresAt - Date.now() < CALL_AHEAD_MS) await refreshSessionNow();
}

/**
 * Starts the keeper with what the server rendered (the workspace layout passes the session's account and expiry), and
 * keeps it in step with other tabs and with the page coming back from the background.
 */
export function startSessionKeeper(initial: SessionView): void {
  if (typeof window === "undefined") return;
  if (!started) {
    started = true;
    if (typeof BroadcastChannel !== "undefined") {
      channel = new BroadcastChannel(CHANNEL);
      channel.onmessage = event => {
        const { view, reason } = event.data as TabMessage;
        state = view;
        emit();
        schedule();
        if (view.signedIn) return;
        // Signed out in another tab: this one follows to the same page; an ended session explains itself.
        if (reason === "signed_out") window.location.replace(new URL("/sign-in?signed_out=1", window.location.origin).href);
        else signedOutHandler();
      };
    }
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible" && state.signedIn && state.expiresAt && state.expiresAt - Date.now() < KEEPER_AHEAD_MS) void refreshSessionNow();
    });
  }
  // A later render may carry a newer expiry (proxy.ts refreshed during a page load).
  if (!state.expiresAt || !initial.expiresAt || initial.expiresAt >= state.expiresAt || initial.account?.uuid !== state.account?.uuid) set(initial);
}

/** What happens when the sign-in turns out to be over (the API proxy answered 401, a refresh was refused). */
export function setSignedOutHandler(handler: () => void): void {
  signedOutHandler = handler;
}

/** Marks the session gone (an API call answered 401) and runs the signed-out handler once. */
export function markSignedOut(): void {
  if (!state.signedIn) return;
  set(SIGNED_OUT, "session_ended");
  signedOutHandler();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** The session as the browser knows it. */
export function useSessionView(): SessionView {
  return useSyncExternalStore(subscribe, () => state, () => SIGNED_OUT);
}

/** A same-site path to come back to, or null (the server checks the same again). */
export function sameSitePath(value: string | null | undefined): string | null {
  if (!value || !value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\") || /[\u0000-\u001f]/.test(value)) return null;
  if (["/sign-in", "/auth", "/api"].some(prefix => value === prefix || value.startsWith(`${prefix}/`) || value.startsWith(`${prefix}?`))) return null;
  return value;
}

const here = () => (typeof window === "undefined" ? "/" : `${window.location.pathname}${window.location.search}`);

/** Starts a sign-in (a full navigation: the hosted pages live on Silicon Accounts), coming back to `returnTo`. */
export function beginSignIn(returnTo: string = here()): void {
  const back = sameSitePath(returnTo);
  window.location.assign(new URL(`/auth/sign-in${back && back !== "/" ? `?return_to=${encodeURIComponent(back)}` : ""}`, window.location.origin).href);
}

/** The sign-in page with a reason ("session_ended"), coming back here afterwards. */
export function sendToSignIn(reason: "session_ended", returnTo: string = here()): void {
  const back = sameSitePath(returnTo);
  // A full load on purpose: nothing of the signed-in page may stay mounted.
  window.location.assign(new URL(`/sign-in?reason=${reason}${back && back !== "/" ? `&return_to=${encodeURIComponent(back)}` : ""}`, window.location.origin).href);
}

/**
 * Signing this browser out: waits for the server (the sign-in is revoked at Silicon Accounts and the cookie cleared),
 * tells the other tabs, then leaves with a full load, so no page stays mounted without a session.
 */
export function useSignOut(): { signOut: () => Promise<void>; pending: boolean } {
  const [pending, setPending] = useState(false);
  const signOut = useCallback(async () => {
    setPending(true);
    let response: Response;
    try {
      response = await fetch("/auth/sign-out", { method: "POST", credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
    } catch (error) {
      setPending(false);
      throw new ApiError({ status: 0, code: "network_error", message: `Could not reach this site to sign out: ${error instanceof Error ? error.message : String(error)}.`, hint: "Check your connection, then try again." });
    }
    if (!response.ok && response.status !== 401) {
      setPending(false);
      const body = (await response.json().catch(() => null)) as { error?: { code?: string; message?: string; hint?: string } } | null;
      throw new ApiError({ status: response.status, code: body?.error?.code ?? "sign_out_failed", message: body?.error?.message ?? `Signing out failed (HTTP ${response.status}).`, hint: body?.error?.hint ?? "Reload the page and try again." });
    }
    signedOutHandler = () => undefined;
    set(SIGNED_OUT, "signed_out");
    window.location.replace(new URL("/sign-in?signed_out=1", window.location.origin).href);
  }, []);
  return { signOut, pending };
}
