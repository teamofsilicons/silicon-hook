/**
 * Next.js config of a Silicon app's web frontend, built from the web kit.
 *
 * Topology: this site is a BFF ("backend for frontend"). The browser only ever talks to this origin; the Next server
 * holds the account's Silicon Accounts tokens in a sealed httpOnly cookie and calls the app's own service itself:
 *   /api/*          → ${APP_API_URL}/* with Authorization: Bearer (app/api/[...path]/route.ts)
 *   /auth/sign-in   → the hosted sign-in on ${ACCOUNTS_URL}/authorize (PKCE S256, state in a sealed cookie)
 *   /auth/callback  → exchanges the code with the app secret, seals the tokens into the session cookie
 *   /auth/sign-out  → revokes the refresh token and clears the cookie
 * No rewrites and nothing from the environment at build time: every value is read per request (lib/server/env.ts), so
 * one build serves any stack.
 *
 * NEXT_DIST_DIR gives a build its own directory (`.next-<name>`), so the e2e run never shares a build with `next dev`.
 * NEXT_OUTPUT=standalone builds a self-contained server for self-hosting (Vercel needs nothing).
 */
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { NextConfig } from "next";

const root = dirname(fileURLToPath(import.meta.url));

function distDirFromEnv(): string {
  const wanted = process.env.NEXT_DIST_DIR?.trim() || ".next";
  if (!/^\.next(-[A-Za-z0-9_.-]+)?$/.test(wanted)) {
    throw new Error(`NEXT_DIST_DIR must look like .next-<name> (a directory next to package.json, e.g. .next-e2e), got "${wanted}"`);
  }
  return wanted;
}

const distDir = distDirFromEnv();

/**
 * A build in its own directory runs beside the others: point Next's TypeScript setup at a per-directory config that
 * only extends tsconfig.json, so tsconfig.json is never rewritten, and skip the type pass (`pnpm typecheck` is the type
 * gate). As the developer site does.
 */
function isolatedBuild(dir: string): NextConfig["typescript"] {
  const tsconfig = `${dir}.tsconfig.json`;
  const content = `${JSON.stringify({ extends: "./tsconfig.json" }, null, 2)}\n`;
  const path = join(root, tsconfig);
  if (!existsSync(path) || readFileSync(path, "utf8") !== content) {
    const temporary = `${path}.${process.pid}.tmp`;
    writeFileSync(temporary, content);
    renameSync(temporary, path);
  }
  return { tsconfigPath: tsconfig, ignoreBuildErrors: true };
}

const nextConfig: NextConfig = {
  distDir,
  ...(distDir === ".next" ? {} : { typescript: isolatedBuild(distDir) }),
  ...(process.env.NEXT_OUTPUT === "standalone" ? { output: "standalone" as const } : {}),
  reactStrictMode: true,
  poweredByHeader: false,
  devIndicators: false,
  // AGENTS.md is kept by hand; `next dev` must not rewrite it.
  agentRules: false,
  // Keep the listener's exact origin for internal rewrites behind a TLS-terminating proxy.
  skipProxyUrlNormalize: true,
  // The kit lives in an app repository's web/ next to other lockfiles: this directory is its own root.
  turbopack: { root },
  outputFileTracingRoot: root,
  // Profile photos are arbitrary https URLs from Silicon Accounts and Iris: shown as they are, never fetched here.
  images: { unoptimized: true },
  // `next dev` answers its dev assets to localhost only by default; a local stack is also opened on 127.0.0.1.
  allowedDevOrigins: ["127.0.0.1", "localhost"],
  experimental: {
    ...(distDir === ".next" ? {} : { turbopackFileSystemCacheForBuild: false }),
  },
  async headers() {
    return [
      // The font files never change in place (a new cut gets a new name).
      { source: "/fonts/:path*", headers: [{ key: "Cache-Control", value: "public, max-age=31536000, immutable" }] },
    ];
  },
};

export default nextConfig;
