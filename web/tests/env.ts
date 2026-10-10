/** A complete, valid environment for the unit tests (nothing here reaches a real service: fetch is replaced per test). */
export const SECRET = "test-session-secret-test-session-secret-0001";

export const TEST_ENV: Record<string, string> = {
  NODE_ENV: "test",
  APP_ID: "webkit",
  APP_SECRET: "sa_app_webkit_testtesttesttesttesttest",
  ACCOUNTS_URL: "http://localhost:9590",
  ACCOUNTS_API_URL: "http://127.0.0.1:9589",
  APP_API_URL: "http://127.0.0.1:4261",
  SESSION_SECRET: SECRET,
  PUBLIC_URL: "http://127.0.0.1:4260",
};

/** Puts the test environment in place (call before the code under test reads it). */
export function applyTestEnv(overrides: Record<string, string | undefined> = {}): void {
  const env = process.env as Record<string, string | undefined>;
  for (const key of ["APP_ID", "APP_SECRET", "ACCOUNTS_URL", "ACCOUNTS_API_URL", "APP_API_URL", "SESSION_SECRET", "PUBLIC_URL", "EXTRA_IMG_ORIGINS", "EXTRA_ORIGINS"]) delete env[key];
  Object.assign(env, TEST_ENV);
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete env[key];
    else env[key] = value;
  }
}

/** Replaces global fetch for one test; returns the calls it saw and a restore function. */
export function mockFetch(handler: (url: string, init: RequestInit) => Promise<Response> | Response) {
  const original = globalThis.fetch;
  const calls: Array<{ url: string; init: RequestInit }> = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    calls.push({ url, init });
    return handler(url, init);
  }) as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = original; } };
}

export const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

/** A token response from Silicon Accounts. */
export function tokenBody(n: number, account: Record<string, unknown> = {}) {
  return {
    access_token: `eyJ.access-${n}.sig`,
    token_type: "Bearer",
    expires_in: 1800,
    refresh_token: `sar_refresh_${n}`,
    refresh_token_expires_at: "2029-03-27T21:53:58.705Z",
    scope: "profile email",
    account: { uuid: "nln", membership_id: "webkit:nln", kind: "carbon", id: "c:ada", display_name: "Ada Lovelace", pfp_url: "http://127.0.0.1:9594/pfp/carbon?id=nln", ...account },
  };
}
