/** Browser journeys use the real Hook service and hosted Silicon Accounts. */
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { defineConfig } from "@playwright/test";

function dotenv(path: string): Record<string, string> {
  if (!existsSync(path)) return {};
  const out: Record<string, string> = {};
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const match = /^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (match && !line.trimStart().startsWith("#")) out[match[1]!] = match[2]!.replace(/^(['"])(.*)\1$/, "$2");
  }
  return out;
}

const local = dotenv(".env.local");
const pick = (name: string, fallback?: string) => process.env[name] || local[name] || fallback;

function appSecret(): string {
  const direct = pick("APP_SECRET");
  if (direct) return direct;
  const stack = process.env.TEST_STACK_JSON;
  if (stack && existsSync(stack)) {
    const secret = (JSON.parse(readFileSync(stack, "utf8")) as { apps?: Record<string, { app_secret?: string }> }).apps?.[pick("APP_ID", "hook")!]?.app_secret;
    if (secret) return secret;
  }
  throw new Error("The browser tests need the Hook app secret on the Accounts stack: set APP_SECRET (or put it in .env.local), or TEST_STACK_JSON=<path to test-stack.json>.");
}

// One session secret for the whole run: workers inherit it from the main process, so the tests can open the cookie.
const sessionSecret = process.env.E2E_SESSION_SECRET || pick("SESSION_SECRET") || randomBytes(48).toString("base64");
process.env.E2E_SESSION_SECRET = sessionSecret;

const PORT = Number(process.env.E2E_PORT || 4200);
const API_PORT = Number(process.env.API_PORT || 4201);
const env = {
  APP_ID: pick("APP_ID", "hook")!,
  APP_SECRET: appSecret(),
  ACCOUNTS_URL: pick("ACCOUNTS_URL", "http://localhost:9590")!,
  ACCOUNTS_API_URL: pick("ACCOUNTS_API_URL", "http://127.0.0.1:9589")!,
  APP_API_URL: pick("APP_API_URL", `http://127.0.0.1:${API_PORT}`)!,
  SESSION_SECRET: sessionSecret,
  PUBLIC_URL: `http://127.0.0.1:${PORT}`,
  EXTRA_IMG_ORIGINS: pick("EXTRA_IMG_ORIGINS", "http://127.0.0.1:9594")!,
};
// The tests read these too (e2e/support.ts).
process.env.E2E_BASE_URL = env.PUBLIC_URL;
process.env.E2E_ACCOUNTS_URL = env.ACCOUNTS_URL;
process.env.E2E_MESSAGING_URL = pick("MOCK_MESSAGING_URL", "http://127.0.0.1:9592");

export default defineConfig({
  testDir: "./e2e",
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: { baseURL: env.PUBLIC_URL, headless: true, viewport: { width: 1440, height: 900 }, trace: "retain-on-failure", locale: "en-US", timezoneId: "Asia/Kolkata" },
  projects: [
    // Two Carbons sign in with an email code once per run; the specs continue as them (e2e/accounts.setup.ts).
    { name: "setup", testMatch: /accounts\.setup\.ts/, use: { browserName: "chromium" } },
    { name: "e2e", testIgnore: [/screens\.spec\.ts/, /\.setup\.ts/], dependencies: ["setup"], use: { browserName: "chromium" } },
    { name: "screens", testMatch: /screens\.spec\.ts/, dependencies: ["setup"], use: { browserName: "chromium" } },
  ],
  webServer: [
    { command: `./node_modules/.bin/next dev --port ${PORT}`, url: `http://127.0.0.1:${PORT}/robots.txt`, env: { ...env, PORT: String(PORT), NEXT_DIST_DIR: ".next-e2e" }, reuseExistingServer: true, timeout: 180_000 },
  ],
});
