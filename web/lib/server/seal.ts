/**
 * Sealing cookie values: AES-256-GCM with a key derived from SESSION_SECRET (HKDF-SHA256), the cookie's purpose bound
 * in as additional data, so a value sealed for one cookie never opens as another. The browser only ever holds
 * ciphertext: tokens are unreadable to page scripts (the cookies are httpOnly too) and to anyone who copies them
 * without the server's secret.
 *
 *   v1.<base64url(iv ‖ ciphertext ‖ tag)>
 *
 * Adapted from the developer site (silicon-accounts/developer/lib/server/seal.ts).
 */
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { serverEnv } from "./env";

const VERSION = "v1";
const keys = new Map<string, Buffer>();

function keyFor(secret: string): Buffer {
  let key = keys.get(secret);
  if (!key) {
    key = Buffer.from(hkdfSync("sha256", secret, "silicon-web-kit", "cookie seal v1", 32));
    keys.set(secret, key);
  }
  return key;
}

/** Seals a JSON value for the cookie `purpose`. */
export function seal(value: unknown, purpose: string, secret: string = serverEnv().sessionSecret): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", keyFor(secret), iv);
  cipher.setAAD(Buffer.from(purpose));
  const body = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return `${VERSION}.${Buffer.concat([iv, body, cipher.getAuthTag()]).toString("base64url")}`;
}

/** Opens a sealed value, or null when it was not sealed by this server for `purpose` (or was tampered with). */
export function unseal<T>(sealed: string | null | undefined, purpose: string, secret: string = serverEnv().sessionSecret): T | null {
  if (!sealed || !sealed.startsWith(`${VERSION}.`)) return null;
  try {
    const raw = Buffer.from(sealed.slice(VERSION.length + 1), "base64url");
    if (raw.length < 12 + 16 + 1) return null;
    const decipher = createDecipheriv("aes-256-gcm", keyFor(secret), raw.subarray(0, 12));
    decipher.setAAD(Buffer.from(purpose));
    decipher.setAuthTag(raw.subarray(raw.length - 16));
    const text = Buffer.concat([decipher.update(raw.subarray(12, raw.length - 16)), decipher.final()]).toString("utf8");
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}
