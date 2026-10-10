import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

test("application layout tokens survive a registry foundation update", () => {
  const root = process.cwd();
  const files = ["styles", "components"].flatMap(dir => readdirSync(path.join(root, dir), { recursive: true })
    .filter(name => String(name).endsWith(".css")).map(name => path.join(root, dir, String(name))));
  const css = files.map(file => readFileSync(file, "utf8")).join("\n");
  const defined = new Set([...css.matchAll(/(--[\w-]+)\s*:/g)].map(match => match[1]));
  for (const match of css.matchAll(/var\((--(?:space-\d+|radius-(?:panel|surface|pill)|surface-secondary))\)/g)) {
    assert.ok(defined.has(match[1]), `Missing application token ${match[1]}`);
  }
});
