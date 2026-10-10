/**
 * Account ids as Carbons and Silicons type them: `c:handle` for a Carbon, `si:handle` for a Silicon. The handle is 3 to
 * 30 characters of a-z, 0-9, "-" and "_"; ids are case-insensitive and stored in lowercase (Silicon Accounts, "Ids and
 * uuids"). An id names an account for people; apps key everything on the account's uuid and only show the id.
 */
import type { AccountKind } from "./format";

export interface ParsedAccountId {
  /** Normalised: lowercase, trimmed, "c:" or "si:" prefix. */
  id: string;
  kind: AccountKind;
  handle: string;
}

export type IdCheck = { ok: true; value: ParsedAccountId } | { ok: false; message: string };

const HANDLE = /^[a-z0-9_-]+$/;

/** Checks what someone typed as an account id, with a message that says exactly what is wrong. */
export function parseAccountId(input: string): IdCheck {
  const text = input.trim().toLowerCase();
  if (!text) return { ok: false, message: "Type an account's id: c: and a handle for a Carbon, si: and a handle for a Silicon." };
  if (text.includes("@")) return { ok: false, message: `"${input.trim()}" looks like an email address. Share with an account by its id instead, such as c:ada or si:scout.` };
  const match = /^(c|si):(.*)$/.exec(text);
  if (!match) return { ok: false, message: `"${input.trim()}" has no c: or si: in front. Use c:${text.replace(/^[^:]*:/, "")} for a Carbon or si:${text.replace(/^[^:]*:/, "")} for a Silicon.` };
  const [, prefix, handle] = match as unknown as [string, "c" | "si", string];
  if (handle.length < 3 || handle.length > 30) return { ok: false, message: `The handle "${handle}" is ${handle.length} character${handle.length === 1 ? "" : "s"}; it must be 3 to 30.` };
  if (!HANDLE.test(handle)) {
    const index = [...handle].findIndex(char => !/[a-z0-9_-]/.test(char));
    return { ok: false, message: `The handle "${handle}" contains "${handle[index]}" at position ${index + 1}; only a-z, 0-9, "-" and "_" are allowed.` };
  }
  return { ok: true, value: { id: `${prefix}:${handle}`, kind: prefix === "c" ? "carbon" : "silicon", handle } };
}

export const isAccountId = (input: string) => parseAccountId(input).ok;
