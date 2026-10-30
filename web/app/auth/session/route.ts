/** The session keeper reads durable state, so old cookies and late responses cannot revive a signed-out session. */
import type { NextRequest } from "next/server";
import { EnvError } from "@/lib/server/env";
import { freshSession } from "@/lib/server/fresh";
import { json, misconfigured } from "@/lib/server/responses";
import { clearSession, clientHeaders, errorBody, readSession, writeSession } from "@/lib/server/session";

export const dynamic = "force-dynamic";
export async function GET(request: NextRequest) {
  try {
    const state = await freshSession(readSession(request), "api", clientHeaders(request));
    if (state.kind === "unavailable") return json(state.status, errorBody(state.code, state.message));
    if (state.kind === "signed_out") {
      const response = json(200, { signed_in: false });
      if (state.clear) clearSession(response);
      return response;
    }
    const response = json(200, { signed_in: true, account: state.session.acct, expires_at: new Date(state.session.ae).toISOString() });
    if (state.rotated) writeSession(response, state.session);
    return response;
  } catch (error) {
    if (error instanceof EnvError) return misconfigured(error);
    throw error;
  }
}
