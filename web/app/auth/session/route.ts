/**
 * GET /auth/session: whether this browser is signed in, who as, and when the access token expires, answered from the
 * sealed cookie alone (no call to Silicon Accounts, never a token). The browser's session keeper reads `expires_at` to
 * refresh ahead of time; a signed-out visit gets a plain `{"signed_in": false}` instead of a 401.
 */
import type { NextRequest } from "next/server";
import { EnvError } from "@/lib/server/env";
import { json, misconfigured } from "@/lib/server/responses";
import { readSession } from "@/lib/server/session";

export const dynamic = "force-dynamic";

export function GET(request: NextRequest) {
  try {
    const session = readSession(request);
    if (!session) return json(200, { signed_in: false });
    return json(200, { signed_in: true, account: session.acct, expires_at: new Date(session.ae).toISOString() });
  } catch (error) {
    if (error instanceof EnvError) return misconfigured(error);
    throw error;
  }
}
