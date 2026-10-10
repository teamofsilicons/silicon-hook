/**
 * Refreshing against the real Accounts stack: the session cookie is resealed with an access token about to expire (as
 * if time had passed), and each way the kit refreshes rotates the tokens: a page load (proxy.ts), the session keeper
 * (POST /auth/refresh). A request that still carries the spent refresh token right after gets the same new tokens, so
 * Accounts never sees a used refresh token (which would end the whole sign-in). Generic: an app keeps this file.
 */
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { accountsSession, appConfig, putSession, runAccounts, sameOrigin, sessionOf, signIn, storedSession } from "./support";

test.describe.configure({ mode: "serial" });

let context: BrowserContext;
let page: Page;

test.beforeAll(async ({ browser }) => {
  context = await accountsSession(browser, "carbon");
  page = await context.newPage();
  await signIn(page, runAccounts().carbon.email, appConfig.home);
});

test.afterAll(async () => {
  await context?.close();
});

test("a page load refreshes a token in its last two minutes, and the render uses the new one", async () => {
  const { session: before } = await storedSession(context);
  await putSession(context, before, 60_000);
  const response = await page.goto(appConfig.home);
  expect(response?.status()).toBe(200);
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  const { session: after } = await storedSession(context);
  expect(after.rt).not.toBe(before.rt);
  expect(after.at).not.toBe(before.at);
  expect(after.ae).toBeGreaterThan(Date.now() + 25 * 60_000);
  expect(after.acct.uuid).toBe(before.acct.uuid);
});

test("a request still carrying the spent refresh token gets the same new tokens, and the sign-in lives on", async () => {
  const { session: current } = await storedSession(context);
  await putSession(context, current, 60_000);
  await page.goto(appConfig.home);
  const { session: rotated } = await storedSession(context);
  expect(rotated.rt).not.toBe(current.rt);
  // A tab that sent the old cookie a moment later: the server answers from its memo instead of presenting it again.
  await putSession(context, current, 60_000);
  await page.goto(appConfig.home);
  const { session: again } = await storedSession(context);
  expect(again.rt).toBe(rotated.rt);
  // Had the spent token reached Accounts, the whole sign-in would be revoked now; it is not.
  await putSession(context, again, 60_000);
  await page.goto(appConfig.home);
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  expect((await sessionOf(context)).signed_in).toBe(true);
});

test("the session keeper refreshes inside its five minutes, and only then", async () => {
  const { session: before } = await storedSession(context);
  await putSession(context, before, 4 * 60_000);
  const response = await page.request.post("/auth/refresh", { headers: sameOrigin() });
  expect(response.status()).toBe(200);
  const body = await response.json();
  expect(Date.parse(body.expires_at)).toBeGreaterThan(Date.now() + 25 * 60_000);
  const { session: after } = await storedSession(context);
  expect(after.rt).not.toBe(before.rt);
  const quiet = await page.request.post("/auth/refresh", { headers: sameOrigin() });
  expect((await quiet.json()).expires_at).toBe(body.expires_at);
});
