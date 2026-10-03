import assert from "node:assert/strict";
import test from "node:test";
import { build } from "esbuild";
import vm from "node:vm";
const bundle = await build({
  entryPoints: [new URL("../src/iam-popup.ts", import.meta.url).pathname],
  bundle: true,
  write: false,
  format: "iife",
  globalName: "popupApi",
});
const profile = "00000000-0000-4000-8000-000000000002";
function fixture(blocked = false, callback?: string) {
  let receive: ((event: any) => void) | undefined;
  const popup = {
    location: { href: "about:blank" },
    closed: false,
    close() {
      this.closed = true;
    },
  };
  const posts: unknown[] = [],
    replacements: string[] = [];
  const window = {
    location: {
      origin: "https://hook.example",
      href: callback || "https://hook.example/",
    },
    opener: {
      postMessage: (value: unknown, origin: string) =>
        posts.push({ value, origin }),
    },
    close: () => popup.close(),
    open: () => (blocked ? null : popup),
    addEventListener: (_name: string, listener: any) => {
      receive = listener;
    },
    removeEventListener: () => {
      receive = undefined;
    },
  };
  const context = vm.createContext({
    window,
    history: {
      replaceState: (_a: unknown, _b: unknown, url: string) =>
        replacements.push(url),
    },
    URL,
    crypto,
    Uint8Array,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
  });
  vm.runInContext(bundle.outputFiles[0].text, context);
  return {
    api: context.popupApi,
    popup,
    window,
    posts,
    replacements,
    send: (
      data: any,
      origin = window.location.origin,
      source: unknown = popup,
    ) => receive?.({ data, origin, source }),
    listening: () => !!receive,
  };
}
test("popup completion requires exact origin, window, nonce and opaque profile", async () => {
  const f = fixture(),
    controller = new AbortController();
  let nonce = "";
  const pending = f.api.openIamPopup((value: string) => {
    nonce = value;
    return "/auth/login";
  }, controller.signal);
  await Promise.resolve();
  await Promise.resolve();
  const data = {
    type: "silicon:hook-login-complete",
    nonce,
    context_id: profile,
  };
  f.send(data, "https://attacker.example");
  f.send(data, undefined, {});
  f.send({ ...data, nonce: "b".repeat(64) });
  f.send({ ...data, context_id: "slt_secret" });
  assert(f.listening());
  assert(!f.popup.closed);
  f.send(data);
  assert.equal(await pending, profile);
  assert(f.popup.closed);
  assert(!f.listening());
});
test("unmount cancels popup and removes completion listener", async () => {
  const f = fixture(),
    controller = new AbortController();
  const pending = f.api.openIamPopup(() => "/auth/login", controller.signal);
  controller.abort();
  await assert.rejects(pending, /cancelled/);
  assert(f.popup.closed);
  assert(!f.listening());
});
test("blocked popup directs user to typed full-page links", async () => {
  const f = fixture(true);
  await assert.rejects(
    f.api.openIamPopup(() => "/auth/login", new AbortController().signal),
    /Carbon or Silicon link/,
  );
});
test("completion removes callback metadata and sends no identity or credential", () => {
  const f = fixture(
    false,
    `https://hook.example/?iam_popup=complete&nonce=${"a".repeat(64)}&context_id=${profile}`,
  );
  assert.equal(f.api.completeIamPopup(), true);
  assert.deepEqual(JSON.parse(JSON.stringify(f.posts)), [
    {
      value: {
        type: "silicon:hook-login-complete",
        nonce: "a".repeat(64),
        context_id: profile,
      },
      origin: "https://hook.example",
    },
  ]);
  assert.deepEqual(f.replacements, ["/"]);
  assert(f.popup.closed);
});
test("same-page completion without opener proceeds to normal verified boot", () => {
  const f = fixture(
    false,
    `https://hook.example/?iam_popup=complete&nonce=${"a".repeat(64)}&context_id=${profile}`,
  );
  (f.window as any).opener = null;
  assert.equal(f.api.completeIamPopup(), false);
  assert.equal(f.posts.length, 0);
  assert.deepEqual(f.replacements, ["/"]);
});

test("popup is reserved synchronously and an aborted slow start never navigates it", async () => {
  const f = fixture(),
    controller = new AbortController();
  let opened = false,
    started = false;
  const original = f.window.open;
  f.window.open = () => {
    opened = true;
    return original();
  };
  let release!: (url: string) => void;
  const delayed = new Promise<string>((resolve) => {
    release = resolve;
  });
  const pending = f.api.openIamPopup(() => {
    started = true;
    return delayed;
  }, controller.signal);
  assert.equal(opened, true, "window reservation stays in click activation");
  assert.equal(started, false);
  await Promise.resolve();
  assert.equal(started, true);
  controller.abort();
  await assert.rejects(pending, /cancelled/);
  release("https://auth.iam.example/login");
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(f.popup.location.href, "about:blank");
  assert.equal(f.popup.closed, true);
});

test("cancelling before deferred start does not create a server login attempt", async () => {
  const f = fixture(),
    controller = new AbortController();
  let started = false;
  const pending = f.api.openIamPopup(() => {
    started = true;
    return "/start";
  }, controller.signal);
  controller.abort();
  await assert.rejects(pending, /cancelled/);
  await Promise.resolve();
  assert.equal(started, false);
});
