/**
 * The server's settings, read from the environment at request time (never baked into the build, so one build serves any
 * stack) and checked together: instrumentation.ts stops the server at boot when anything is missing or malformed, with
 * one exact line per problem, and a route that needs a setting answers the same words instead of guessing.
 *
 *   APP_ID             this app's Silicon Accounts app_id                   [default: appConfig.appId]
 *   APP_SECRET         the app secret (sa_app_…). Server only: the code exchange, refresh and revoke send it (HTTP Basic)
 *   ACCOUNTS_URL       the public origin of Silicon Accounts: the hosted sign-in, and the issuer of every token
 *                      (https://accounts.teamofsilicons.com; a local stack: http://localhost:9590)
 *   ACCOUNTS_API_URL   the Accounts API, server to server                   [default: ACCOUNTS_URL]
 *   APP_API_URL        this app's own service; /api/* and apiFetch() call it with Authorization: Bearer
 *   SESSION_SECRET     at least 32 bytes of randomness; seals the session cookies (openssl rand -base64 48)
 *   PUBLIC_URL         this site's origin; the redirect URI registered at Accounts is exactly {PUBLIC_URL}/auth/callback
 *   EXTRA_IMG_ORIGINS  optional, comma separated: more origins the CSP lets images load from (a local mock Iris)
 *   EXTRA_ORIGINS      optional, comma separated: more origins allowed to send state-changing requests (CSRF guard)
 *
 * Framework-free (no Next imports), so the unit tests and the boot check use it directly.
 */
import { appConfig } from "../app.config";

export interface ServerEnv {
  appId: string;
  appSecret: string;
  /** Origin of the hosted sign-in and the token issuer (no trailing slash). */
  accountsUrl: string;
  /** Where this server calls the Accounts API (no trailing slash). */
  accountsApiUrl: string;
  /** Base URL of the app's own service (no trailing slash; may carry a path prefix). */
  appApiUrl: string;
  sessionSecret: string;
  /** This site's origin (no trailing slash). */
  publicUrl: string;
  extraImgOrigins: string[];
  extraOrigins: string[];
  production: boolean;
}

/** Thrown when the environment cannot run the kit; `problems` has one exact sentence per setting. */
export class EnvError extends Error {
  readonly problems: string[];
  constructor(problems: string[]) {
    super(
      `${appConfig.name} cannot start: ${problems.length === 1 ? "one setting is" : `${problems.length} settings are`} missing or wrong.\n` +
        problems.map(problem => `  - ${problem}`).join("\n") +
        "\nSee .env.example and README.md (Environment) for what each one is.",
    );
    this.name = "EnvError";
    this.problems = problems;
  }
}

export const APP_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{1,39}$/;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

type Source = Record<string, string | undefined>;

function value(source: Source, name: string): string | undefined {
  const raw = source[name];
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  return trimmed === "" ? undefined : trimmed;
}

/**
 * A URL setting: http(s), no query or fragment, https outside loopback in production. `origin` settings must be an
 * origin alone (no path). Returns the normalised value (no trailing slash) or pushes a problem.
 */
function url(name: string, raw: string, kind: "origin" | "base", production: boolean, problems: string[], example: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    problems.push(`${name} is "${raw}", which is not a URL. Set it to something like ${example}.`);
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    problems.push(`${name} is "${raw}"; it must start with https:// (or http:// for a local stack), like ${example}.`);
    return null;
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    problems.push(`${name} is "${raw}"; it must not carry credentials, a query or a #fragment. Set it to something like ${example}.`);
    return null;
  }
  if (kind === "origin" && parsed.pathname !== "/") {
    problems.push(`${name} is "${raw}"; it must be an origin alone (scheme://host[:port]) without the path "${parsed.pathname}", like ${example}.`);
    return null;
  }
  if (production && parsed.protocol === "http:" && !LOOPBACK.has(parsed.hostname)) {
    problems.push(`${name} is "${raw}"; in production it must use https:// (plain http is only for localhost and 127.0.0.1).`);
    return null;
  }
  return kind === "origin" ? parsed.origin : `${parsed.origin}${parsed.pathname}`.replace(/\/+$/, "");
}

function origins(name: string, raw: string | undefined, problems: string[]): string[] {
  if (!raw) return [];
  const out: string[] = [];
  for (const entry of raw.split(",").map(part => part.trim()).filter(Boolean)) {
    try {
      const parsed = new URL(entry);
      if ((parsed.protocol === "http:" || parsed.protocol === "https:") && parsed.pathname === "/" && !parsed.search && !parsed.hash) out.push(parsed.origin);
      else problems.push(`${name} has "${entry}"; each entry must be an origin (scheme://host[:port]), separated by commas.`);
    } catch {
      problems.push(`${name} has "${entry}", which is not an origin; each entry must look like https://example.com.`);
    }
  }
  return out;
}

/** Reads and checks every setting at once. Throws EnvError listing every problem (never a secret's value). */
export function readEnv(source: Source = process.env): ServerEnv {
  const problems: string[] = [];
  const production = source.NODE_ENV === "production";

  const appId = value(source, "APP_ID") ?? appConfig.appId;
  if (!APP_ID_PATTERN.test(appId)) {
    problems.push(`APP_ID is "${appId}"; an app_id is 2 to 40 characters of a-z, 0-9, "-" and "_" (the one Silicon Apps gave this app).`);
  }

  const appSecret = value(source, "APP_SECRET");
  if (!appSecret) {
    problems.push(`APP_SECRET is not set. It is the app secret of "${appId}" (sa_app_…), shown once when the app was created in Silicon Apps; set it on the server only.`);
  } else if (!appSecret.startsWith("sa_app_")) {
    problems.push(`APP_SECRET does not look like a Silicon Accounts app secret: those start with "sa_app_". Copy the secret of "${appId}" exactly.`);
  }

  const accountsRaw = value(source, "ACCOUNTS_URL");
  const accountsUrl = accountsRaw
    ? url("ACCOUNTS_URL", accountsRaw, "origin", production, problems, "https://accounts.teamofsilicons.com")
    : (problems.push("ACCOUNTS_URL is not set. Set it to the public origin of Silicon Accounts: https://accounts.teamofsilicons.com (a local stack: http://localhost:9590)."), null);

  const accountsApiRaw = value(source, "ACCOUNTS_API_URL");
  const accountsApiUrl = accountsApiRaw ? url("ACCOUNTS_API_URL", accountsApiRaw, "base", production, problems, "http://127.0.0.1:9589") : accountsUrl;

  const appApiRaw = value(source, "APP_API_URL");
  const appApiUrl = appApiRaw
    ? url("APP_API_URL", appApiRaw, "base", false, problems, "https://api.example.com")
    : (problems.push(`APP_API_URL is not set. Set it to the origin of ${appConfig.name}'s own service (the API that /api/* forwards to), for example http://127.0.0.1:4261.`), null);

  const sessionSecret = value(source, "SESSION_SECRET");
  if (!sessionSecret) {
    problems.push("SESSION_SECRET is not set. It seals the session cookies: at least 32 random bytes, for example the output of: openssl rand -base64 48");
  } else {
    const bytes = Buffer.byteLength(sessionSecret, "utf8");
    if (bytes < 32) problems.push(`SESSION_SECRET is ${bytes} bytes; it must be at least 32. Generate one with: openssl rand -base64 48`);
  }

  const publicRaw = value(source, "PUBLIC_URL");
  const publicUrl = publicRaw
    ? url("PUBLIC_URL", publicRaw, "origin", production, problems, "https://example.teamofsilicons.com")
    : (problems.push("PUBLIC_URL is not set. Set it to this site's own origin, for example http://127.0.0.1:4260; Silicon Accounts sends sign-ins back to {PUBLIC_URL}/auth/callback."), null);

  const extraImgOrigins = origins("EXTRA_IMG_ORIGINS", value(source, "EXTRA_IMG_ORIGINS"), problems);
  const extraOrigins = origins("EXTRA_ORIGINS", value(source, "EXTRA_ORIGINS"), problems);

  if (problems.length || !appSecret || !accountsUrl || !accountsApiUrl || !appApiUrl || !sessionSecret || !publicUrl) {
    throw new EnvError(problems.length ? problems : ["The environment could not be read."]);
  }
  return { appId, appSecret, accountsUrl, accountsApiUrl, appApiUrl, sessionSecret, publicUrl, extraImgOrigins, extraOrigins, production };
}

const KEYS = ["NODE_ENV", "APP_ID", "APP_SECRET", "ACCOUNTS_URL", "ACCOUNTS_API_URL", "APP_API_URL", "SESSION_SECRET", "PUBLIC_URL", "EXTRA_IMG_ORIGINS", "EXTRA_ORIGINS"];
let cached: { fingerprint: string; env: ServerEnv } | null = null;

/** The checked settings (cached until the environment changes). Throws EnvError like readEnv. */
export function serverEnv(): ServerEnv {
  const fingerprint = KEYS.map(key => process.env[key] ?? "").join("\u0000");
  if (cached?.fingerprint === fingerprint) return cached.env;
  const env = readEnv(process.env);
  cached = { fingerprint, env };
  return env;
}

/** The redirect URI registered for this app at Silicon Accounts: exactly {PUBLIC_URL}/auth/callback. */
export const callbackUrl = (env: ServerEnv = serverEnv()) => `${env.publicUrl}/auth/callback`;

/** Cookies are Secure and `__Host-` prefixed when this site is served over https. */
export const secureCookies = (env: ServerEnv = serverEnv()) => env.publicUrl.startsWith("https://");

/** HTTP Basic credentials of this app (the code exchange, refresh, revoke). */
export function basicAuth(env: ServerEnv = serverEnv()): string {
  return `Basic ${Buffer.from(`${env.appId}:${env.appSecret}`, "utf8").toString("base64")}`;
}

/** Origins allowed to send state-changing requests: this site, EXTRA_ORIGINS, and its loopback twin in development. */
export function allowedOrigins(env: ServerEnv = serverEnv()): Set<string> {
  const out = new Set<string>([env.publicUrl, ...env.extraOrigins]);
  if (!env.production) {
    const own = new URL(env.publicUrl);
    if (LOOPBACK.has(own.hostname)) for (const host of ["localhost", "127.0.0.1"]) out.add(`${own.protocol}//${host}${own.port ? `:${own.port}` : ""}`);
  }
  return out;
}
