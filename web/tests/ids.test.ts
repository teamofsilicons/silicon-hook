/** c: and si: ids as people type them, with the reason when one is wrong (the share control relies on these words). */
import assert from "node:assert/strict";
import { test } from "node:test";
import { parseAccountId } from "../lib/ids";

test("ids are normalised to lowercase and tell Carbons from Silicons", () => {
  assert.deepEqual(parseAccountId("  C:Ada_Lovelace "), { ok: true, value: { id: "c:ada_lovelace", kind: "carbon", handle: "ada_lovelace" } });
  assert.deepEqual(parseAccountId("si:scout-2"), { ok: true, value: { id: "si:scout-2", kind: "silicon", handle: "scout-2" } });
});

test("a wrong id says exactly what is wrong", () => {
  const message = (input: string) => {
    const result = parseAccountId(input);
    assert.equal(result.ok, false, input);
    return result.ok ? "" : result.message;
  };
  assert.match(message(""), /^Type an account's id/);
  assert.equal(message("ada@example.com"), '"ada@example.com" looks like an email address. Share with an account by its id instead, such as c:ada or si:scout.');
  assert.equal(message("ada"), '"ada" has no c: or si: in front. Use c:ada for a Carbon or si:ada for a Silicon.');
  assert.equal(message("x:ada"), '"x:ada" has no c: or si: in front. Use c:ada for a Carbon or si:ada for a Silicon.');
  assert.equal(message("c:ab"), 'The handle "ab" is 2 characters; it must be 3 to 30.');
  assert.equal(message(`si:${"a".repeat(31)}`), `The handle "${"a".repeat(31)}" is 31 characters; it must be 3 to 30.`);
  assert.equal(message("c:scout!"), 'The handle "scout!" contains "!" at position 6; only a-z, 0-9, "-" and "_" are allowed.');
});
