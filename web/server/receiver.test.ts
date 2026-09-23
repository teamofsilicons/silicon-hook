import { test } from "node:test";
import assert from "node:assert/strict";
import {
  allocate,
  closeReceiver,
  ensureReceiver,
  validateCapability,
  validateScope,
  type ReceiverScope,
  type ReceiverSlots,
  type ReceiverCapability,
} from "./receiver.ts";
import { GatewayError } from "./errors.ts";
const scope: ReceiverScope = {
  app_id: "tos>hook",
  for: "test:tos",
  kind: "silicon",
  org_id: "11111111-1111-4111-8111-111111111111",
  hook_org_id: "tos",
  environment: {
    kind: "testing",
    id: "22222222-2222-4222-8222-222222222222",
    generation: 7,
  },
};
const capability = (
  token = "a",
  expiry = Date.now() + 25000,
): ReceiverCapability => ({
  ...structuredClone(scope),
  receiver_id: "receiver_one",
  receiver_token: `ting_recv_${token.repeat(64)}`,
  expires_at: new Date(expiry).toISOString(),
});
const unavailable = () => new GatewayError(503, "unavailable", "Unavailable");

test("uncertain bootstrap survives restart, replays exact operation and explicitly renews expired receipt", async () => {
  let slots: ReceiverSlots = {};
  const id = allocate(slots, scope);
  let disk = "";
  const save = async () => {
    disk = JSON.stringify(slots);
  };
  const calls: any[] = [];
  let first = true;
  const bootstrap = async (_scope: ReceiverScope, body: any, key: string) => {
    assert.ok(JSON.parse(disk)[id].pending.inFlight);
    assert.deepEqual(JSON.parse(disk)[id].pending.body, body);
    calls.push({ body: structuredClone(body), key });
    if (first) {
      first = false;
      throw unavailable();
    }
    return body.receiver_id
      ? capability("b")
      : capability("a", Date.now() - 1000);
  };
  await assert.rejects(ensureReceiver(slots[id], save, bootstrap));
  slots = JSON.parse(disk); // A new process recovers only durable state.
  const result = await ensureReceiver(slots[id], save, bootstrap);
  assert.deepEqual(calls[1], calls[0]);
  assert.equal(calls[2].body.receiver_id, "receiver_one");
  assert.notEqual(calls[2].key, calls[1].key);
  assert.equal(result.receiver_token, capability("b").receiver_token);
  assert.equal(slots[id].pending, undefined);
});

test("closing an uncertain renewal recovers and revokes the replacement before dropping state", async () => {
  const slots: ReceiverSlots = {};
  const id = allocate(slots, scope);
  slots[id].capability = capability();
  let disk = "";
  const save = async () => {
    disk = JSON.stringify(slots);
  };
  const calls: any[] = [];
  const bootstrap = async (_scope: ReceiverScope, body: any, key: string) => {
    calls.push({ body: structuredClone(body), key });
    if (calls.length === 1) throw unavailable();
    return capability("b");
  };
  await assert.rejects(ensureReceiver(slots[id], save, bootstrap, true));
  assert.equal(
    slots[id].capability!.receiver_token,
    capability().receiver_token,
  );
  await assert.rejects(
    closeReceiver(slots, id, save, bootstrap, async (value) => {
      assert.equal(value.receiver_token, capability("b").receiver_token);
      assert.equal(
        JSON.parse(disk)[id].capability.receiver_token,
        value.receiver_token,
      );
      throw unavailable();
    }),
  );
  assert.deepEqual(calls[0], calls[1]);
  assert.equal(slots[id].closing, true);
  assert.equal(slots[id].pending, undefined);
  await closeReceiver(slots, id, save, bootstrap, async (value) => {
    assert.equal(value.receiver_token, capability("b").receiver_token);
  });
  assert.equal(slots[id], undefined);
  assert.equal(calls.length, 2);
});

test("mismatched capability stays uncertain and slot allocations remain bounded during failed cleanup", async () => {
  const slots: ReceiverSlots = {};
  const id = allocate(slots, scope);
  const save = async () => {};
  let call = 0,
    operation: any;
  const bootstrap = async (_scope: ReceiverScope, body: any, key: string) => {
    if (!operation) operation = { body: structuredClone(body), key };
    else assert.deepEqual({ body, key }, operation);
    return ++call === 1
      ? { ...capability(), for: "someone_else" }
      : capability();
  };
  await assert.rejects(ensureReceiver(slots[id], save, bootstrap));
  assert.equal(slots[id].pending?.uncertain, true);
  await assert.rejects(
    closeReceiver(slots, id, save, bootstrap, async () => {
      throw unavailable();
    }),
  );
  for (let i = 0; i < 3; i++) allocate(slots, scope);
  assert.throws(() => allocate(slots, scope), /Close another/);
  assert.equal(Object.keys(slots).length, 4);
  await closeReceiver(slots, id, save, bootstrap, async () => {});
  assert.equal(Object.keys(slots).length, 3);
  assert.equal(call, 2);
});

test("scope validation keeps lifecycle generation separate and rejects excess or foreign capability", () => {
  const expected = {
    appId: scope.app_id,
    actor: { id: scope.for, type: scope.kind },
    org: scope.hook_org_id,
    environmentId: scope.environment.id,
  };
  assert.deepEqual(validateScope(scope, expected), scope);
  for (const bad of [
    { ...scope, for: "other" },
    { ...scope, kind: "carbon" },
    { ...scope, hook_org_id: "other" },
    { ...scope, org_id: "tos" },
    { ...scope, environment: { ...scope.environment, generation: 0 } },
  ])
    assert.throws(() => validateScope(bad, expected));
  for (const bad of [
    { ...capability(), receiver_id: "another" },
    { ...capability(), environment: { ...scope.environment, generation: 8 } },
    capability("a", Date.now() + 60000),
    { ...capability(), receiver_token: "general_session" },
  ])
    assert.throws(() => validateCapability(bad, scope, "receiver_one"));
});

test("authority loss after uncertain renewal retains exact pending cleanup even after old token expiry", async () => {
  const slots: ReceiverSlots = {};
  const id = allocate(slots, scope);
  slots[id].capability = capability("a", Date.now() - 600000);
  const save = async () => {};
  await assert.rejects(
    ensureReceiver(
      slots[id],
      save,
      async () => {
        throw unavailable();
      },
      true,
    ),
  );
  const pending = structuredClone(slots[id].pending);
  for (const code of [
    "receiver_environment_changed",
    "receiver_environment_unavailable",
    "unauthenticated",
  ]) {
    await assert.rejects(
      closeReceiver(
        slots,
        id,
        save,
        async () => {
          throw new GatewayError(
            code === "unauthenticated" ? 401 : 409,
            code,
            "Authority changed",
          );
        },
        async () => {
          assert.fail("Unknown replacement must be recovered before revoking");
        },
      ),
      (error: unknown) =>
        error instanceof GatewayError &&
        error.code === "receiver_cleanup_pending",
    );
    assert.deepEqual(slots[id].pending, pending);
    assert.equal(slots[id].closing, true);
  }
  for (let i = 0; i < 3; i++) allocate(slots, scope);
  assert.throws(() => allocate(slots, scope));
});
