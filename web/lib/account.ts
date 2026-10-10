/**
 * The signed-in account as this app may show it, shared by the server (the sealed session) and the browser (the shell,
 * the account menu). It comes from the token response's `account` and is renewed with every refresh.
 */
import type { AccountKind } from "./format";

export type { AccountKind } from "./format";

export interface SessionAccount {
  /** Permanent, case-sensitive key (the JWT `sub`). Key everything on it. */
  uuid: string;
  kind: AccountKind;
  /** The current public id, `c:handle` or `si:handle`. It can change: show it, never key on it. */
  id: string;
  display_name: string;
  /** The profile photo (Iris or Silicon Accounts); null shows initials. */
  pfp_url: string | null;
  /** A Silicon's custodian (a Carbon). */
  custodian: { uuid: string; id: string } | null;
}

/** What the browser may know about its session: never a token. */
export interface SessionView {
  signedIn: boolean;
  account: SessionAccount | null;
  /** When the access token expires (epoch ms), so the browser can ask for a refresh ahead of it. */
  expiresAt: number | null;
}
