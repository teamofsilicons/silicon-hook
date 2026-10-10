/**
 * Helpers for the browser tests: signing in through the real hosted pages of the Accounts stack (the email code comes
 * from the stack's mock sender, as silicon-accounts/web/e2e does), and reading the session the kit holds.
 */
import { readFileSync } from "node:fs";
import { expect, test, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { appConfig } from "../lib/app.config";
import { seal, unseal } from "../lib/server/seal";
import type { StoredSession } from "../lib/server/session";

export { appConfig };

export const BASE = process.env.E2E_BASE_URL ?? "http://127.0.0.1:4200";
export const ACCOUNTS = process.env.E2E_ACCOUNTS_URL ?? "http://localhost:9590";
const MESSAGING = process.env.E2E_MESSAGING_URL ?? "http://127.0.0.1:9592";

/** A fresh address per run, named after the app: the stack is shared by every app's tests. */
export const uniqueEmail = (purpose: string) => `${appConfig.appId}-${purpose}-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}@example.test`;

async function json<T>(url: string): Promise<{ status: number; body: T }> {
  const response = await fetch(url);
  return { status: response.status, body: (await response.json().catch(() => ({}))) as T };
}

/** The newest message sequence number of the mock sender (read before asking for a code). */
async function lastSeq(): Promise<number> {
  const { body } = await json<{ last_seq?: number }>(`${MESSAGING}/_messages?limit=1`);
  return body.last_seq ?? 0;
}

/** Waits for the next message to `to` after `after` and returns its 6-digit code. */
async function codeFor(to: string, after: number): Promise<string> {
  const { status, body } = await json<{ code?: string | null }>(`${MESSAGING}/_messages/wait?to=${encodeURIComponent(to)}&after=${after}&timeout_ms=20000`);
  if (status !== 200 || !body.code) throw new Error(`no code reached ${to} after message ${after} (${status} ${JSON.stringify(body)})`);
  return body.code;
}

const atApp = (url: URL | string) => String(url).startsWith(BASE) && !String(url).includes("/auth/");

/**
 * Presses Continue on the email step and returns the code that arrives. The stack is shared by every app's tests and
 * limits codes per network (30 in 10 minutes): when the page counts down ("Try again in 4:12"), this waits it out,
 * giving the test the time, and asks again.
 */
async function requestCode(page: Page, email: string): Promise<string> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const after = await lastSeq();
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    const codeStep = page.getByRole("group", { name: /^Code from the/ }).first();
    const waiting = page.getByRole("button", { name: /^Try again in \d+:\d\d$/ });
    const outcome = await Promise.race([
      codeStep.waitFor({ timeout: 30_000 }).then(() => "code" as const),
      waiting.waitFor({ timeout: 30_000 }).then(() => "limited" as const),
    ]);
    if (outcome === "code") return codeFor(email, after);
    const [minutes, seconds] = /(\d+):(\d\d)/.exec(await waiting.innerText())!.slice(1).map(Number) as [number, number];
    const waitMs = (minutes * 60 + seconds) * 1000;
    test.info().setTimeout(test.info().timeout + waitMs + 60_000);
    console.log(`the shared stack's code limit for this network: waiting ${Math.round(waitMs / 1000)} s before asking again`);
    await page.getByRole("button", { name: "Continue", exact: true }).waitFor({ timeout: waitMs + 20_000 });
  }
  throw new Error(`no code could be sent to ${email}: the stack kept refusing (its limit on codes per network)`);
}

/**
 * On the hosted sign-in (the page is on {ACCOUNTS}/authorize…). A browser already signed in to Silicon Accounts as the
 * account wanted (a context made with `accountsSession()`) continues as it, with no code; otherwise this types the
 * email, the code that arrives, creates the account when it is new, shares what the details pages ask with their
 * defaults, and waits to be back at the kit.
 */
export async function signInOnHostedPages(page: Page, email: string): Promise<void> {
  await page.waitForURL(url => url.href.startsWith(ACCOUNTS), { timeout: 30_000 });
  const emailMethod = page.getByRole("button", { name: "Email", exact: true });
  if (await emailMethod.isVisible().catch(() => false)) await emailMethod.click();
  const field = page.getByRole("textbox", { name: "Email" });
  const continueAs = page.getByRole("button", { name: /^Continue as / });
  const first = await Promise.race([
    continueAs.waitFor({ timeout: 30_000 }).then(() => "account" as const),
    field.waitFor({ timeout: 30_000 }).then(() => "email" as const),
  ]);
  if (first === "account") {
    await continueAs.click();
  } else {
    await field.fill(email);
    const code = await requestCode(page, email.toLowerCase());
    await page.keyboard.type(code, { delay: 25 });
  }
  // Then: "Create account" for a new address, the app's details page(s), maybe a review page, and back to the app.
  const next = page.getByRole("button", { name: /^(Create account|Finish setup|Share and continue|Review)$/ });
  for (let step = 0; step < 8; step++) {
    const stop = await Promise.race([
      page.waitForURL(atApp, { timeout: 60_000 }).then(() => "app" as const),
      next.first().waitFor({ state: "visible", timeout: 60_000 }).then(() => "button" as const),
    ]);
    if (stop === "app" || atApp(page.url())) break;
    const button = await next.first().elementHandle({ timeout: 5_000 }).catch(() => null);
    if (!button) continue;
    // The page may move on under the click (the last step sends the browser back to the app).
    await button.click({ timeout: 15_000 }).catch(() => undefined);
    // Wait for this step to leave (its button goes) or for the app, so the same button is never pressed twice.
    await Promise.race([page.waitForURL(atApp, { timeout: 30_000 }), button.waitForElementState("hidden", { timeout: 30_000 })]).catch(() => undefined);
  }
  await page.waitForURL(atApp, { timeout: 45_000 });
}

/** Starts at a workspace page signed out, signs in, and comes back to it. */
export async function signIn(page: Page, email: string, path = appConfig.home): Promise<void> {
  await page.goto(path);
  await signInOnHostedPages(page, email);
  await expect(page).toHaveURL(new RegExp(`${path.replace(/\//g, "\\/")}$`));
}

export interface SessionAnswer {
  signed_in: boolean;
  account?: { uuid: string; id: string; kind: "carbon" | "silicon"; display_name: string; pfp_url: string | null };
  expires_at?: string;
}

/** What /auth/session says (from the sealed cookie alone). */
export async function sessionOf(context: BrowserContext): Promise<SessionAnswer> {
  const response = await context.request.get(`${BASE}/auth/session`);
  return (await response.json()) as SessionAnswer;
}

/** A state-changing call the way the pages make it (same-origin, with Origin). */
export function sameOrigin(extra: Record<string, string> = {}): Record<string, string> {
  return { Origin: BASE, "Sec-Fetch-Site": "same-origin", ...extra };
}

const SESSION_COOKIE = `${appConfig.appId.replace(/-/g, "_")}_session`;

/** The session the browser's cookie holds (opened with the server's secret, as only a test may). */
export async function storedSession(context: BrowserContext): Promise<{ session: StoredSession; raw: string }> {
  const cookie = (await context.cookies(BASE)).find(entry => entry.name === SESSION_COOKIE);
  const session = unseal<StoredSession>(cookie?.value, "session", process.env.E2E_SESSION_SECRET!);
  if (!cookie || !session) throw new Error(`no ${SESSION_COOKIE} cookie this test can open`);
  return { session, raw: cookie.value };
}

/** Puts a session back into the browser's cookie, optionally with its access token expiring in `ms`. */
export async function putSession(context: BrowserContext, session: StoredSession, expiresInMs?: number): Promise<void> {
  const cookie = (await context.cookies(BASE)).find(entry => entry.name === SESSION_COOKIE)!;
  const value = expiresInMs === undefined ? session : { ...session, ae: Date.now() + expiresInMs };
  await context.addCookies([{ ...cookie, value: seal(value, "session", process.env.E2E_SESSION_SECRET!) }]);
}

/**
 * Collects what a page reports as broken: uncaught errors and console errors (hydration mismatches among them). A test
 * ends with `expect(errors).toEqual([])`.
 */
export function watchErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(`pageerror: ${error.message.split("\n")[0]}`));
  page.on("console", message => {
    if (message.type() !== "error") return;
    const text = message.text();
    // A failed request already fails its own assertion; the browser's own log line for it is not a page error.
    if (/^Failed to load resource/.test(text)) return;
    errors.push(`console: ${text.split("\n")[0]}`);
  });
  return errors;
}

/* ---------------------------------------------------------------------------------------------------------------- */
/* Accounts signed in once per run (e2e/accounts.setup.ts)                                                           */
/* ---------------------------------------------------------------------------------------------------------------- */

/**
 * The shared stack allows 30 email codes per network in 10 minutes, for every app's tests together. So a run signs two
 * Carbons in with a code once (the setup project) and keeps their Silicon Accounts browser sign-in; every spec then
 * signs in to the kit with "Continue as", a sign-in of its own (its own tokens) without spending a code.
 */
export type Who = "carbon" | "friend";
const AUTH_DIR = "test-results/.auth";
export const statePath = (who: Who) => `${AUTH_DIR}/${who}.json`;
export const accountsFile = `${AUTH_DIR}/accounts.json`;

/** The emails and ids of the run's Carbons. */
export function runAccounts(): Record<Who, { email: string; id: string }> {
  return JSON.parse(readFileSync(accountsFile, "utf8")) as Record<Who, { email: string; id: string }>;
}

/** A browser context signed in to Silicon Accounts as `who` and to nothing else (the kit's own cookies left out). */
export async function accountsSession(browser: Browser, who: Who, options: Parameters<Browser["newContext"]>[0] = {}): Promise<BrowserContext> {
  const state = JSON.parse(readFileSync(statePath(who), "utf8")) as { cookies: Array<{ domain: string; name: string }>; origins: Array<{ origin: string }> };
  const accountsHost = new URL(ACCOUNTS).hostname;
  const kitCookie = new RegExp(`^(__Host-)?${appConfig.appId.replace(/-/g, "_")}_`);
  const cookies = state.cookies.filter(cookie => cookie.domain.replace(/^\./, "") === accountsHost && !kitCookie.test(cookie.name));
  const storageState = { cookies, origins: state.origins.filter(origin => origin.origin === ACCOUNTS) };
  return browser.newContext({ baseURL: BASE, ...options, storageState: storageState as never });
}
