/** The boot check: every setting read at once, one exact sentence per problem, never a secret's value. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { allowedOrigins, callbackUrl, EnvError, readEnv, secureCookies } from "../lib/server/env";
import { TEST_ENV } from "./env";

const read = (overrides: Record<string, string | undefined>) => {
  const source: Record<string, string | undefined> = { ...TEST_ENV, ...overrides };
  for (const [key, value] of Object.entries(overrides)) if (value === undefined) delete source[key];
  return readEnv(source);
};

const problemsOf = (overrides: Record<string, string | undefined>): string[] => {
  try {
    read(overrides);
  } catch (error) {
    assert.ok(error instanceof EnvError, `expected an EnvError, got ${error}`);
    return error.problems;
  }
  assert.fail("expected the environment to be refused");
};

test("a complete environment is read and normalised", () => {
  const env = read({ ACCOUNTS_URL: "http://localhost:9590/", APP_API_URL: "http://127.0.0.1:4261/base/" });
  assert.equal(env.appId, "webkit");
  assert.equal(env.accountsUrl, "http://localhost:9590");
  assert.equal(env.accountsApiUrl, "http://127.0.0.1:9589");
  assert.equal(env.appApiUrl, "http://127.0.0.1:4261/base");
  assert.equal(env.publicUrl, "http://127.0.0.1:4260");
  assert.equal(callbackUrl(env), "http://127.0.0.1:4260/auth/callback");
  assert.equal(secureCookies(env), false);
});

test("APP_ID defaults to lib/app.config.ts and ACCOUNTS_API_URL to ACCOUNTS_URL", () => {
  const env = read({ APP_ID: undefined, ACCOUNTS_API_URL: undefined });
  assert.equal(env.appId, "hook");
  assert.equal(env.accountsApiUrl, "http://localhost:9590");
});

test("every missing setting is named at once, with what to set", () => {
  const problems = problemsOf({ APP_SECRET: undefined, ACCOUNTS_URL: undefined, APP_API_URL: undefined, SESSION_SECRET: undefined, PUBLIC_URL: undefined });
  assert.equal(problems.length, 5);
  assert.match(problems[0]!, /^APP_SECRET is not set\. It is the app secret of "webkit" \(sa_app_…\)/);
  assert.match(problems[1]!, /^ACCOUNTS_URL is not set\. Set it to the public origin of Silicon Accounts: https:\/\/accounts\.teamofsilicons\.com/);
  assert.match(problems[2]!, /^APP_API_URL is not set\./);
  assert.match(problems[3]!, /^SESSION_SECRET is not set\. .*openssl rand -base64 48$/);
  assert.match(problems[4]!, /^PUBLIC_URL is not set\. .*\{PUBLIC_URL\}\/auth\/callback\.$/);
  const error = (() => { try { read({ PUBLIC_URL: undefined }); } catch (failure) { return failure as EnvError; } })()!;
  assert.match(error.message, /^Hook cannot start: one setting is missing or wrong\.\n {2}- PUBLIC_URL is not set\./);
});

test("malformed values are refused with the reason, and secrets are never echoed", () => {
  const secret = "not-a-secret-value-123";
  const problems = problemsOf({ APP_SECRET: secret, SESSION_SECRET: "too short", APP_ID: "Web Kit!" });
  assert.ok(problems.some(problem => problem.startsWith('APP_ID is "Web Kit!"; an app_id is 2 to 40 characters')));
  assert.ok(problems.includes('APP_SECRET does not look like a Silicon Accounts app secret: those start with "sa_app_". Copy the secret of "Web Kit!" exactly.'));
  assert.ok(problems.includes("SESSION_SECRET is 9 bytes; it must be at least 32. Generate one with: openssl rand -base64 48"));
  assert.ok(!problems.join(" ").includes(secret), "the secret's value never appears");
  assert.ok(!problems.join(" ").includes("too short"), "the session secret's value never appears");
});

test("URLs must be http(s) origins where an origin is meant", () => {
  assert.deepEqual(problemsOf({ ACCOUNTS_URL: "accounts.teamofsilicons.com" }), ['ACCOUNTS_URL is "accounts.teamofsilicons.com", which is not a URL. Set it to something like https://accounts.teamofsilicons.com.']);
  assert.deepEqual(problemsOf({ PUBLIC_URL: "https://example.test/app" }), ['PUBLIC_URL is "https://example.test/app"; it must be an origin alone (scheme://host[:port]) without the path "/app", like https://example.teamofsilicons.com.']);
  assert.deepEqual(problemsOf({ ACCOUNTS_URL: "ftp://accounts.example" }), ['ACCOUNTS_URL is "ftp://accounts.example"; it must start with https:// (or http:// for a local stack), like https://accounts.teamofsilicons.com.']);
  assert.deepEqual(problemsOf({ APP_API_URL: "https://user:pw@api.example" }), ['APP_API_URL is "https://user:pw@api.example"; it must not carry credentials, a query or a #fragment. Set it to something like https://api.example.com.']);
  assert.deepEqual(problemsOf({ EXTRA_IMG_ORIGINS: "http://127.0.0.1:9594, nope" }), ['EXTRA_IMG_ORIGINS has "nope", which is not an origin; each entry must look like https://example.com.']);
});

test("production needs https outside loopback", () => {
  assert.deepEqual(problemsOf({ NODE_ENV: "production", PUBLIC_URL: "http://remind.example" }), ['PUBLIC_URL is "http://remind.example"; in production it must use https:// (plain http is only for localhost and 127.0.0.1).']);
  const env = read({ NODE_ENV: "production", PUBLIC_URL: "https://remind.teamofsilicons.com", ACCOUNTS_URL: "https://accounts.teamofsilicons.com", ACCOUNTS_API_URL: undefined });
  assert.equal(secureCookies(env), true);
  assert.equal(env.production, true);
  // A local production run (next start on a loopback address) is fine.
  assert.equal(read({ NODE_ENV: "production" }).publicUrl, "http://127.0.0.1:4260");
});

test("the same-origin guard accepts this site, EXTRA_ORIGINS and, in development, its loopback twin", () => {
  const dev = allowedOrigins(read({ EXTRA_ORIGINS: "https://webkit.example" }));
  assert.ok(dev.has("http://127.0.0.1:4260"));
  assert.ok(dev.has("http://localhost:4260"));
  assert.ok(dev.has("https://webkit.example"));
  assert.ok(!dev.has("http://localhost:4261"));
  const production = allowedOrigins(read({ NODE_ENV: "production", PUBLIC_URL: "https://webkit.example" }));
  assert.deepEqual([...production], ["https://webkit.example"]);
});
