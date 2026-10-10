/**
 * Signing in and out through the real hosted pages of the Accounts stack, and the shell around the workspace. Generic:
 * everything comes from lib/app.config.ts, so an app keeps this file when it adopts the kit.
 */
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { accountsSession, appConfig, BASE, runAccounts, sessionOf, signIn, watchErrors } from "./support";

test.describe.configure({ mode: "serial" });

const cookieBase = appConfig.appId.replace(/-/g, "_");
let context: BrowserContext;
let page: Page;
let me = "";
let errors: string[] = [];

test.beforeAll(async ({ browser }) => {
  context = await accountsSession(browser, "carbon", { viewport: { width: 1440, height: 900 } });
  page = await context.newPage();
  errors = watchErrors(page);
});

test.afterAll(async () => {
  await context?.close();
});

test("signing in through the hosted pages leaves only a sealed cookie in the browser", async () => {
  await signIn(page, runAccounts().carbon.email, appConfig.home);
  const session = await sessionOf(context);
  expect(session.signed_in).toBe(true);
  expect(session.account?.kind).toBe("carbon");
  expect(session.account?.id).toMatch(/^c:/);
  me = session.account!.id;
  expect(Date.parse(session.expires_at!)).toBeGreaterThan(Date.now() + 20 * 60_000);

  const cookie = (await context.cookies(BASE)).find(entry => entry.name === `${cookieBase}_session`);
  expect(cookie?.httpOnly).toBe(true);
  expect(cookie?.sameSite).toBe("Lax");
  expect(cookie?.value).toMatch(/^v1\.[A-Za-z0-9_-]+$/);
  expect(cookie?.value).not.toContain("sar_");
  expect(await page.evaluate(() => document.cookie)).not.toContain(`${cookieBase}_session`);
  expect((await context.cookies(BASE)).some(entry => entry.name === `${cookieBase}_signin` && entry.value)).toBe(false);
});

test("the shell: the app's sections, the account menu and the ⌘K palette", async () => {
  const nav = page.getByRole("navigation", { name: appConfig.name, exact: true });
  await expect(nav).toBeVisible();
  for (const item of appConfig.nav) await expect(nav.getByRole("link", { name: item.label })).toHaveAttribute("href", item.href);
  await expect(nav.getByRole("link", { name: appConfig.nav[0]!.label })).toHaveAttribute("aria-current", "page");

  await page.getByRole("button", { name: /^Account menu, / }).click();
  const menu = page.getByRole("menu");
  await expect(menu).toContainText(me);
  await expect(menu).toContainText("Carbon");
  await expect(menu.getByRole("menuitemradio", { name: "System" })).toBeVisible();
  await page.keyboard.press("Escape");

  const target = appConfig.nav[appConfig.nav.length - 1]!;
  await page.keyboard.press(process.platform === "darwin" ? "Meta+K" : "Control+K");
  await expect(page.getByRole("dialog", { name: "Search and jump" })).toBeVisible();
  await page.keyboard.type(target.label);
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(new RegExp(`${target.href}$`));
  await expect(nav.getByRole("link", { name: target.label })).toHaveAttribute("aria-current", "page");
});

test("the session keeper's refresh does nothing while the token has time left", async () => {
  const before = await sessionOf(context);
  const response = await page.request.post("/auth/refresh", { headers: { Origin: BASE } });
  expect(response.status()).toBe(200);
  const after = await response.json();
  expect(after.expires_at).toBe(before.expires_at);
  expect(response.headers()["set-cookie"]).toBeUndefined();
});

test("signing out revokes the sign-in, closes every door, and other tabs follow", async () => {
  const other = await context.newPage();
  await other.goto(appConfig.home);
  await expect(other.getByRole("navigation", { name: appConfig.name, exact: true })).toBeVisible();
  await page.getByRole("button", { name: /^Account menu, / }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/sign-in\?signed_out=1$/);
  // The other tab heard it (BroadcastChannel) and left the workspace too.
  await expect(other).toHaveURL(/\/sign-in\?signed_out=1$/);
  await other.close();
  await expect(page.getByRole("main").getByRole("status")).toContainText(`You are signed out of ${appConfig.name}`);
  expect(await sessionOf(context)).toEqual({ signed_in: false });
  const api = await page.request.get("/api/v1/anything");
  expect(api.status()).toBe(401);
  await page.goto(appConfig.home);
  await page.waitForURL(url => !url.href.startsWith(BASE), { timeout: 30_000 });
  expect(new URL(page.url()).pathname).toBe("/authorize");
  expect(errors.filter(error => !error.includes("401"))).toEqual([]);
});
