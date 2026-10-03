import assert from "node:assert/strict";
import test from "node:test";
import { build } from "esbuild";
import vm from "node:vm";
const bundle = await build({
  stdin: {
    contents:
      'export { createRoot } from "solid-js"; export { load } from "./src/resource.ts";',
    resolveDir: process.cwd(),
    loader: "ts",
  },
  bundle: true,
  write: false,
  format: "iife",
  globalName: "resourceApi",
  platform: "browser",
  conditions: ["browser"],
});
const context = vm.createContext({
  setTimeout,
  clearTimeout,
  queueMicrotask,
  console,
});
vm.runInContext(bundle.outputFiles[0].text, context);
const { load, createRoot } = context.resourceApi;

for (const failure of [false, true])
  test(`verified session cannot be overwritten by a delayed ${failure ? "failed" : "successful"} session read`, async () => {
    let resolve!: (data: unknown) => void, reject!: (error: Error) => void;
    const slow = new Promise((yes, no) => {
      resolve = yes;
      reject = no;
    });
    let dispose!: () => void;
    const resource = createRoot((cleanup: () => void) => {
      dispose = cleanup;
      return load(
        () => true,
        () => slow,
      );
    });
    try {
      const verified = { context_id: "new-account", kind: "silicon" };
      resource.set(verified);
      assert.equal(resource.data(), verified);
      if (failure) reject(new Error("Old session expired"));
      else resolve({ context_id: "previous-account", kind: "carbon" });
      await new Promise((done) => setImmediate(done));
      assert.equal(resource.data(), verified);
      assert.equal(resource.error(), undefined);
    } finally {
      dispose();
    }
  });

test("a later intentional session refresh can replace a verified session", async () => {
  let dispose!: () => void,
    next = { context_id: "first" };
  const resource = createRoot((cleanup: () => void) => {
    dispose = cleanup;
    return load(
      () => true,
      async () => next,
    );
  });
  try {
    await new Promise((done) => setImmediate(done));
    resource.set({ context_id: "verified" });
    next = { context_id: "refreshed" };
    await resource.refresh();
    assert.equal(resource.data(), next);
  } finally {
    dispose();
  }
});
