/**
 * This site's public addresses for metadata and the public files (robots.txt, the sitemap, llms.txt, the social image).
 * They never throw: a server without its environment still answers its public files (the boot check and proxy.ts
 * report the missing settings), with this machine's address in place of PUBLIC_URL.
 */
import { serverEnv } from "./env";

export function publicOrigin(): string {
  try {
    return serverEnv().publicUrl;
  } catch {
    return `http://localhost:${process.env.PORT || "4260"}`;
  }
}

/** Silicon Accounts' public origin (where a Carbon manages their account). */
export function accountsOrigin(): string {
  try {
    return serverEnv().accountsUrl;
  } catch {
    return "https://accounts.teamofsilicons.com";
  }
}
