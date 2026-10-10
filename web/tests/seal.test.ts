/** Sealing cookie values: only this server, for this purpose, can open them; any change fails. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { seal, unseal } from "../lib/server/seal";
import { SECRET, applyTestEnv } from "./env";

applyTestEnv();

test("a sealed value opens only for its purpose and secret", () => {
  const sealed = seal({ at: "eyJ.x.y", rt: "sar_x" }, "session", SECRET);
  assert.match(sealed, /^v1\.[A-Za-z0-9_-]+$/);
  assert.ok(!sealed.includes("sar_x"), "the refresh token is not readable in the cookie");
  assert.deepEqual(unseal(sealed, "session", SECRET), { at: "eyJ.x.y", rt: "sar_x" });
  assert.equal(unseal(sealed, "signin", SECRET), null, "another cookie's purpose does not open it");
  assert.equal(unseal(sealed, "session", `${SECRET}-other`), null, "another secret does not open it");
});

test("a changed byte, a truncated value or garbage never opens", () => {
  const sealed = seal({ a: 1 }, "session", SECRET);
  const flipped = `${sealed.slice(0, -2)}${sealed.at(-2) === "A" ? "B" : "A"}${sealed.slice(-1)}`;
  assert.equal(unseal(flipped, "session", SECRET), null);
  assert.equal(unseal(sealed.slice(0, 20), "session", SECRET), null);
  assert.equal(unseal("v1.", "session", SECRET), null);
  assert.equal(unseal("v2.abcdef", "session", SECRET), null);
  assert.equal(unseal("garbage", "session", SECRET), null);
  assert.equal(unseal(undefined, "session", SECRET), null);
  assert.equal(unseal(null, "session", SECRET), null);
});

test("every seal is fresh: the same value never seals the same way twice", () => {
  const a = seal({ same: true }, "session", SECRET);
  const b = seal({ same: true }, "session", SECRET);
  assert.notEqual(a, b);
  assert.deepEqual(unseal(a, "session", SECRET), unseal(b, "session", SECRET));
});

test("by default it seals with SESSION_SECRET", () => {
  const sealed = seal({ ok: 1 }, "session");
  assert.deepEqual(unseal(sealed, "session", SECRET), { ok: 1 });
});
