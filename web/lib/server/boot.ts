/**
 * The boot check (instrumentation.ts): every setting is read and checked before the server answers anything. A
 * production server (`next start`, a serverless cold start) exits with the exact problems; `next dev` keeps running so
 * the message stays on screen, and every page and route answers the same words until the environment is fixed.
 */
import { EnvError, readEnv } from "./env";

export function checkAtBoot(): void {
  try {
    const env = readEnv();
    console.log(`${env.appId}: ${env.publicUrl} signs Carbons in on ${env.accountsUrl} and calls its service at ${env.appApiUrl}`);
  } catch (error) {
    if (!(error instanceof EnvError)) throw error;
    console.error(`\n${error.message}\n`);
    if (process.env.NODE_ENV === "production") process.exit(1);
  }
}
