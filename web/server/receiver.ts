/** Private, bounded, durable scoped-receiver state. Call under the session lock. */
import { randomUUID } from "node:crypto";
import { GatewayError } from "./errors.ts";
import { identifier, PRODUCTION } from "./ting.ts";

export interface ReceiverScope {
  app_id: string;
  for: string;
  kind: "carbon" | "silicon";
  org_id: string;
  hook_org_id: string;
  environment: { kind: "testing"; id: string; generation: number };
}
export interface ReceiverCapability extends ReceiverScope {
  receiver_id: string;
  receiver_token: string;
  expires_at: string;
}
export interface ReceiverSlot {
  scope: ReceiverScope;
  closing?: boolean;
  capability?: ReceiverCapability;
  pending?: {
    key: string;
    body: { environment_id: string; generation: number; receiver_id?: string };
    uncertain?: boolean;
    inFlight?: boolean;
  };
}
export type ReceiverSlots = Record<string, ReceiverSlot>;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const failure = (code = "invalid_receiver_scope") =>
  new GatewayError(
    502,
    code,
    "The receiving authority did not match this identity and test environment. Reconnect to retry.",
  );
export function validateScope(
  value: any,
  expected: {
    appId: string;
    actor: { id: string; type: string };
    org: string;
    environmentId: string;
  },
): ReceiverScope {
  if (
    !value ||
    value.app_id !== expected.appId ||
    value.for !== expected.actor.id ||
    value.kind !== expected.actor.type ||
    !["carbon", "silicon"].includes(value.kind) ||
    value.hook_org_id !== expected.org ||
    !uuid.test(value.org_id) ||
    value.org_id === PRODUCTION ||
    value.environment?.kind !== "testing" ||
    value.environment.id !== expected.environmentId ||
    !uuid.test(value.environment.id) ||
    value.environment.id === PRODUCTION ||
    !Number.isSafeInteger(value.environment.generation) ||
    value.environment.generation <= 0
  )
    throw failure();
  return {
    app_id: value.app_id,
    for: value.for,
    kind: value.kind,
    org_id: value.org_id,
    hook_org_id: value.hook_org_id,
    environment: {
      kind: "testing",
      id: value.environment.id,
      generation: value.environment.generation,
    },
  };
}
export function sameScope(a: ReceiverScope, b: ReceiverScope): boolean {
  return (
    a.app_id === b.app_id &&
    a.for === b.for &&
    a.kind === b.kind &&
    a.org_id === b.org_id &&
    a.hook_org_id === b.hook_org_id &&
    a.environment.kind === b.environment.kind &&
    a.environment.id === b.environment.id &&
    a.environment.generation === b.environment.generation
  );
}
export function validateCapability(
  value: any,
  scope: ReceiverScope,
  receiverId?: string,
): ReceiverCapability {
  const actual = validateScope(value, {
    appId: scope.app_id,
    actor: { id: scope.for, type: scope.kind },
    org: scope.hook_org_id,
    environmentId: scope.environment.id,
  });
  if (
    !sameScope(actual, scope) ||
    !identifier(value.receiver_id) ||
    (receiverId !== undefined && value.receiver_id !== receiverId) ||
    !/^ting_recv_[a-f0-9]{64}$/.test(value.receiver_token) ||
    typeof value.expires_at !== "string" ||
    !Number.isFinite(Date.parse(value.expires_at)) ||
    Date.parse(value.expires_at) > Date.now() + 30000
  )
    throw failure("invalid_receiver_capability");
  // Expired recovery is a valid receipt, never usable receiving authority.
  return {
    ...actual,
    receiver_id: value.receiver_id,
    receiver_token: value.receiver_token,
    expires_at: value.expires_at,
  };
}
export function allocate(slots: ReceiverSlots, scope: ReceiverScope): string {
  if (Object.keys(slots).length >= 4)
    throw new GatewayError(
      409,
      "receiver_cleanup_pending",
      "Close another receiving view or retry its pending cleanup before opening a new one.",
    );
  const id = randomUUID();
  slots[id] = { scope };
  return id;
}
type Save = () => Promise<void>;
type Bootstrap = (
  scope: ReceiverScope,
  body: NonNullable<ReceiverSlot["pending"]>["body"],
  key: string,
) => Promise<any>;
async function settle(
  slot: ReceiverSlot,
  save: Save,
  bootstrap: Bootstrap,
): Promise<void> {
  const operation = slot.pending!;
  const previouslyUncertain = operation.uncertain || operation.inFlight;
  operation.inFlight = true;
  await save();
  try {
    const value = await bootstrap(slot.scope, operation.body, operation.key);
    const capability = validateCapability(
      value,
      slot.scope,
      operation.body.receiver_id,
    );
    slot.capability = capability;
    delete slot.pending;
    await save();
  } catch (error) {
    if (slot.pending) {
      delete operation.inFlight;
      if (
        previouslyUncertain ||
        !(error instanceof GatewayError) ||
        error.status >= 500 ||
        error.status === 408
      )
        operation.uncertain = true;
      else delete slot.pending;
      await save();
    }
    throw error;
  }
}
export async function ensureReceiver(
  slot: ReceiverSlot,
  save: Save,
  bootstrap: Bootstrap,
  renew = false,
): Promise<ReceiverCapability> {
  if (slot.closing)
    throw new GatewayError(
      409,
      "receiver_cleanup_pending",
      "This receiving view is closing. Retry cleanup before reconnecting.",
    );
  if (renew && slot.capability && !slot.pending) {
    slot.pending = {
      key: randomUUID(),
      body: {
        environment_id: slot.scope.environment.id,
        generation: slot.scope.environment.generation,
        receiver_id: slot.capability.receiver_id,
      },
    };
    await save();
  }
  for (let attempt = 0; attempt < 2; attempt++) {
    if (slot.pending) await settle(slot, save, bootstrap);
    if (
      slot.capability &&
      Date.parse(slot.capability.expires_at) > Date.now() + 10000
    )
      return slot.capability;
    slot.pending = {
      key: randomUUID(),
      body: {
        environment_id: slot.scope.environment.id,
        generation: slot.scope.environment.generation,
        ...(slot.capability
          ? { receiver_id: slot.capability.receiver_id }
          : {}),
      },
    };
    await save();
    await settle(slot, save, bootstrap);
    if (
      slot.capability &&
      Date.parse(slot.capability.expires_at) > Date.now() + 10000
    )
      return slot.capability;
  }
  throw new GatewayError(
    503,
    "receiver_renewal_pending",
    "The recovered receiving authority expired. Reconnect to finish renewal.",
  );
}
export async function closeReceiver(
  slots: ReceiverSlots,
  id: string,
  save: Save,
  bootstrap: Bootstrap,
  revoke: (capability: ReceiverCapability) => Promise<void>,
): Promise<void> {
  const slot = slots[id];
  if (!slot) return;
  slot.closing = true;
  await save();
  try {
    if (slot.pending) await settle(slot, save, bootstrap);
    if (slot.capability) await revoke(slot.capability);
  } catch (error) {
    // Even an expired prior token cannot prove that a timed-out renewal did
    // not commit later. Keep the bounded exact operation until recoverable.
    throw new GatewayError(
      error instanceof GatewayError && error.status >= 500 ? 503 : 409,
      "receiver_cleanup_pending",
      "The previous receiving operation still needs cleanup. Retry when its original identity and test context are available; its private authority has been retained.",
    );
  }
  delete slots[id];
  await save();
}
