/** Compare-and-set session state prevents stale responses and sign-out races from restoring older tokens. */
import { randomUUID } from "node:crypto";
import type { StoredSession } from "./session";
import { legacyKey, refreshStore, stateKey, type Entry, type RefreshStore } from "./refresh-store";

export interface SessionState {
  session: StoredSession;
  revoked?: boolean;
  operation?: { key: string; token: string };
}
export interface LocatedState { key: string; entry: Entry<SessionState>; store: RefreshStore }

export async function createSession(session: StoredSession): Promise<StoredSession> {
  const store = await refreshStore();
  const next = { ...session, sid: randomUUID() };
  if (!await store.write(stateKey("session", next.sid), null, { session: next }, next.re)) throw new Error("Session identifier collision.");
  return next;
}

export async function locateSession(session: StoredSession): Promise<LocatedState> {
  const store = await refreshStore();
  let sid = session.sid;
  if (!sid) {
    // Adopt old sealed cookies without generating a different refresh operation on each replica.
    const key = legacyKey(session.rt);
    let mapping = await store.read<{ sid: string }>(key);
    if (!mapping) {
      await store.write(key, null, { sid: randomUUID() }, session.re);
      mapping = await store.read<{ sid: string }>(key);
    }
    if (!mapping) throw new Error("Session adoption is unavailable.");
    sid = mapping.value.sid;
    await store.write(stateKey("session", sid), null, { session: { ...session, sid } }, session.re);
  }
  const key = stateKey("session", sid);
  const entry = await store.read<SessionState>(key);
  if (!entry) throw new Error("Session state is unavailable.");
  if (entry.value.session.acct.uuid !== session.acct.uuid || entry.value.session.sid !== sid) throw new Error("Session state does not match its cookie.");
  return { key, entry, store };
}

export async function endSession(session: StoredSession): Promise<void> {
  for (let attempt = 0; attempt < 12; attempt++) {
    const { store, key, entry } = await locateSession(session);
    if (entry.value.revoked) return;
    if (await store.write(key, entry.version, { session: entry.value.session, revoked: true }, entry.value.session.re)) return;
  }
  throw new Error("Sign-out could not be saved; retry it.");
}
