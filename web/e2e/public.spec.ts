/**
 * The public side, signed out: the landing page, the public files, the headers, and every door to the workspace.
 * Everything is read from lib/app.config.ts, so these tests keep working when an app adopts the kit.
 */
import { expect, test } from "@playwright/test";
import { ACCOUNTS, appConfig, BASE, sameOrigin } from "./support";

const home = appConfig.home;

test("the landing page says what the app is, how to install it and how to sign in", async ({ page }) => {
  const response = await page.goto("/");
  expect(response?.status()).toBe(200);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(appConfig.landing.headline);
  await expect(page.getByRole("figure", { name: "As a Silicon" })).toContainText(`silicon-apps install ${appConfig.appId}`);
  await expect(page.getByRole("button", { name: "Copy As a Silicon" })).toBeVisible();
  await expect(page.getByRole("link", { name: `Sign in to ${appConfig.name}` }).first()).toHaveAttribute("href", "/auth/sign-in");
  await expect(page.getByRole("main").getByRole("heading", { name: "For Silicons" })).toBeVisible();
  // One h1, landmarks, a skip link and the theme choice.
  await expect(page.locator("h1")).toHaveCount(1);
  await expect(page.getByRole("main")).toHaveCount(1);
  await expect(page.getByRole("link", { name: "Skip to content" })).toHaveAttribute("href", "#main");
  await expect(page.getByRole("group", { name: "Theme" })).toBeVisible();

  const headers = response!.headers();
  expect(headers["content-security-policy"]).toMatch(/script-src 'self' 'nonce-[^']+' 'strict-dynamic'/);
  expect(headers["content-security-policy"]).toContain(`img-src 'self' data: blob: ${ACCOUNTS} https://iris.teamofsilicons.com`);
  expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers["x-content-type-options"]).toBe("nosniff");
  // The theme boot script carries the nonce, so it runs under the CSP (browsers hide nonces from the DOM: read the HTML).
  const nonce = /'nonce-([^']+)'/.exec(headers["content-security-policy"]!)![1];
  const html = await response!.text();
  expect(html).toContain(`<script nonce="${nonce}">`);
  // And it ran: the theme is on <html> before React does anything.
  await expect(page.locator("html")).toHaveAttribute("data-theme", /^(light|dark)$/);
});

test("the theme switch works without a flash and is remembered", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "light" });
  await page.goto("/");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.getByRole("button", { name: "Dark", exact: true }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.reload();
  // Painted by the boot script before the first frame, from the stored choice.
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.getByRole("button", { name: "System", exact: true }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
});

test("the public files answer for crawlers and Silicons", async ({ request }) => {
  const robots = await request.get("/robots.txt");
  expect(robots.status()).toBe(200);
  const text = await robots.text();
  expect(text).toContain("Disallow: /api/");
  for (const item of appConfig.nav) expect(text).toContain(`Disallow: ${item.href}`);
  expect(text).toContain(`Sitemap: ${BASE}/sitemap.xml`);

  const sitemap = await request.get("/sitemap.xml");
  expect(sitemap.headers()["content-type"]).toContain("application/xml");
  expect(await sitemap.text()).toContain(`<loc>${BASE}/</loc>`);

  const llms = await request.get("/llms.txt");
  expect(await llms.text()).toMatch(new RegExp(`^# ${appConfig.name}\\n\\n> `));

  const manifest = await request.get("/manifest.webmanifest");
  expect((await manifest.json()).name).toBe(appConfig.name);

  for (const path of ["/og.png", "/icon", "/apple-icon"]) {
    const image = await request.get(path);
    expect(image.status(), path).toBe(200);
    expect(image.headers()["content-type"], path).toBe("image/png");
  }
});

test("every door to the workspace leads to sign-in while signed out", async ({ page, request }) => {
  const workspace = await request.get(home, { maxRedirects: 0 });
  expect(workspace.status()).toBe(307);
  expect(new URL(workspace.headers().location!, BASE).href).toBe(`${BASE}/auth/sign-in?return_to=${encodeURIComponent(home)}`);

  const start = await request.get(`/auth/sign-in?return_to=${encodeURIComponent(home)}`, { maxRedirects: 0 });
  expect(start.status()).toBe(303);
  const authorize = new URL(start.headers().location!);
  expect(`${authorize.origin}${authorize.pathname}`).toBe(`${ACCOUNTS}/authorize`);
  expect(authorize.searchParams.get("app_id")).toBe(appConfig.appId);
  expect(authorize.searchParams.get("redirect_uri")).toBe(`${BASE}/auth/callback`);
  expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
  expect(authorize.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
  if (appConfig.signIn.scopes.length) expect(authorize.searchParams.get("scope")).toBe(appConfig.signIn.scopes.join(" "));
  const cookie = start.headers()["set-cookie"] ?? "";
  expect(cookie).toMatch(new RegExp(`^${appConfig.appId.replace(/-/g, "_")}_signin=v1\\.`));
  expect(cookie.toLowerCase()).toContain("httponly");
  expect(cookie.toLowerCase()).toContain("samesite=lax");

  const api = await request.get("/api/v1/anything");
  expect(api.status()).toBe(401);
  expect((await api.json()).error.code).toBe("signed_out");

  const session = await request.get("/auth/session");
  expect(await session.json()).toEqual({ signed_in: false });

  // A callback this browser did not start is refused, with fixed words on the sign-in page.
  await page.goto("/auth/callback?code=sac_forged&state=forged");
  await expect(page).toHaveURL(/\/sign-in\?error=state_mismatch$/);
  await expect(page.getByRole("main").getByRole("alert")).toContainText("started in another tab");
});

test("a Carbon who cancels signing in gets a friendly page", async ({ page }) => {
  await page.goto("/sign-in?error=access_denied");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("You cancelled signing in");
  await expect(page.getByText(`Nothing was shared with ${appConfig.name}`)).toBeVisible();
  await expect(page.getByRole("link", { name: `Sign in to ${appConfig.name}` })).toHaveAttribute("href", /^\/auth\/sign-in/);
});

test("state-changing requests from another site are refused", async ({ request }) => {
  const signOut = await request.post("/auth/sign-out", { headers: { Origin: "https://evil.example" } });
  expect(signOut.status()).toBe(403);
  expect((await signOut.json()).error.code).toBe("cross_site_request");
  const write = await request.post("/api/v1/anything", { headers: { Origin: "https://evil.example", "Content-Type": "application/json" }, data: { title: "x" } });
  expect(write.status()).toBe(403);
  const fine = await request.post("/auth/sign-out", { headers: sameOrigin() });
  expect(fine.status()).toBe(204);
});

test("an unknown address is a real 404 in the site's frame", async ({ page }) => {
  const response = await page.goto("/no/such/page");
  expect(response?.status()).toBe(404);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Nothing lives at this address");
});
