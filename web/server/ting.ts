import { createHash, randomUUID } from "node:crypto";
import { WebSocket } from "ws";
import { GatewayError } from "./errors.ts";
import type { TingSession } from "./session.ts";
import type { ReceiverCapability } from "./receiver.ts";

export const PRODUCTION = "00000000-0000-0000-0000-000000000000";
export const TING_APP = "tos>ting";
export interface DeliveryContext {
  appId: string;
  org: string;
  /** IAM organization UUID used by Ting's transport; Hook retains org_id. */
  tingOrg: string;
  actor: { id: string; type: string };
  environmentId: string;
  silicons: string[];
  /** Current shared lifecycle fence; never replaces an event's Hook generation. */
  receiverGeneration?: number;
}
export interface EventReference {
  id: string;
  org_id: string;
  silicon_id: string;
  hook_id: string;
  delivery_sequence: number;
  received_at: string;
  summary: string;
  environment_id: string;
  environment_generation: number;
}
export interface Notification {
  id: string;
  created_at: string;
  type: string;
  for: string;
  key: string;
  data: unknown;
  metadata: unknown;
  read: boolean;
  silent: boolean;
}

export function secureOrigin(value: string): string {
  const url = new URL(value);
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/" ||
    !(
      url.protocol === "https:" ||
      (url.protocol === "http:" &&
        ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname))
    )
  )
    throw new Error("Origins must be HTTPS, or HTTP on loopback");
  return url.origin;
}

export class Ting {
  constructor(readonly origin: string) {}
  async call(
    path: string,
    method = "GET",
    session?: Pick<TingSession, "token">,
    body?: unknown,
    key?: string,
  ): Promise<any> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (session) headers.authorization = `Bearer ${session.token}`;
    if (body !== undefined) headers["content-type"] = "application/json";
    if (key) headers["idempotency-key"] = key;
    try {
      const response = await fetch(this.origin + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(25000),
        redirect: "error",
      });
      const chunks: Uint8Array[] = [];
      let size = 0;
      if (response.body)
        for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
          size += chunk.length;
          if (size > 2 * 1024 * 1024) throw new Error("Response limit");
          chunks.push(chunk);
        }
      const data = JSON.parse(Buffer.concat(chunks).toString());
      if (!response.ok)
        throw new GatewayError(
          response.status,
          typeof data.error?.code === "string"
            ? data.error.code
            : "ting_unavailable",
          response.status === 401
            ? "The delivery session expired. Continue with IAM again."
            : response.status === 403
              ? "Delivery access is unavailable for this identity or organization."
              : "The delivery service could not complete this request. Try again.",
          undefined,
          undefined,
          response.headers.get("retry-after") || undefined,
        );
      return data;
    } catch (error) {
      if (error instanceof GatewayError) throw error;
      throw new GatewayError(
        502,
        "ting_unavailable",
        "The delivery service could not be reached or returned an invalid response. Try again.",
      );
    }
  }
  async login(slt: string, key: string): Promise<TingSession> {
    const result = await this.call(
      "/v1/session",
      "POST",
      undefined,
      { slt },
      key,
    );
    if (
      !result.authenticated ||
      !identifier(result.id, 255) ||
      !["carbon", "silicon"].includes(result.kind) ||
      !identifier(result.session_token, 32768)
    ) {
      throw new GatewayError(
        502,
        "invalid_ting_session",
        "The delivery service returned an invalid session.",
      );
    }
    // This exchange deliberately supplies no sandbox selectors. It can only
    // create a production session; no downstream OBO credentials are repurposed.
    return {
      token: result.session_token,
      id: result.id,
      kind: result.kind,
      environmentId: PRODUCTION,
    };
  }
  async identity(session: TingSession) {
    const me = await this.call("/v1/me", "GET", session);
    if (
      me.authenticated !== true ||
      me.id !== session.id ||
      me.kind !== session.kind
    )
      throw new GatewayError(
        502,
        "delivery_identity_mismatch",
        "The delivery session does not match the signed-in identity.",
      );
    // Ting 0.1.3 attests the live environment. Missing context on older
    // servers must not become production, and this flow never accepts tests.
    if (
      session.environmentId !== PRODUCTION ||
      !exact(me.environment, ["kind"]) ||
      me.environment.kind !== "production"
    )
      throw new GatewayError(
        409,
        "delivery_environment_unverified",
        "The delivery service did not verify the production environment. Receiving is unavailable.",
      );
    return me;
  }
  async organizations(
    session: TingSession,
  ): Promise<{ id: string; name: string; handle: string }[]> {
    const data = await this.call("/v1/orgs", "GET", session);
    if (
      !Array.isArray(data.items) ||
      data.items.length > 1000 ||
      data.items.some(
        (item: any) =>
          !identifier(item.id, 255) ||
          !identifier(item.handle, 255) ||
          typeof item.name !== "string",
      )
    )
      throw new GatewayError(
        502,
        "invalid_ting_response",
        "The delivery service returned an invalid organization list.",
      );
    return data.items;
  }
  async receiverInbox(
    capability: ReceiverCapability,
  ): Promise<{ items: Notification[]; next_cursor?: string }> {
    const query = new URLSearchParams({
      type: `${capability.app_id}.webhook.received`,
      limit: "32",
    });
    const result = await this.call(`/v1/receivers/inbox?${query}`, "GET", {
      token: capability.receiver_token,
    }).catch((error: unknown) => {
      if (error instanceof GatewayError && error.status === 401)
        throw new GatewayError(
          409,
          "receiver_expired",
          "Receiving authority expired or its test context changed. Reconnect to renew it.",
        );
      throw error;
    });
    if (
      !Array.isArray(result.items) ||
      result.items.length > 32 ||
      (result.next_cursor !== undefined &&
        !identifier(result.next_cursor, 4096))
    )
      throw new GatewayError(
        502,
        "invalid_ting_response",
        "The delivery service returned an invalid inbox page.",
      );
    return result;
  }
  async revokeReceiver(capability: ReceiverCapability): Promise<void> {
    try {
      const result = await this.call("/v1/receivers/session", "DELETE", {
        token: capability.receiver_token,
      });
      if (result.revoked !== true)
        throw new GatewayError(
          502,
          "receiver_cleanup_pending",
          "Receiving cleanup could not be confirmed. Retry to finish closing this view.",
        );
    } catch (error) {
      if (!(error instanceof GatewayError) || error.status !== 401) throw error;
    }
  }

  async inbox(
    session: TingSession,
    context: DeliveryContext,
    cursor?: string,
  ): Promise<{ items: Notification[]; next_cursor?: string }> {
    const query = new URLSearchParams({
      app_id: context.appId,
      type: `${context.appId}.webhook.received`,
      limit: "32",
    });
    if (cursor) query.set("cursor", cursor);
    const result = await this.call(
      `/v1/orgs/${encodeURIComponent(context.tingOrg)}/inbox?${query}`,
      "GET",
      session,
    );
    if (
      !Array.isArray(result.items) ||
      result.items.length > 32 ||
      (result.next_cursor !== undefined &&
        !identifier(result.next_cursor, 4096))
    )
      throw new GatewayError(
        502,
        "invalid_ting_response",
        "The delivery service returned an invalid inbox page.",
      );
    return result;
  }
}

function object(value: unknown): value is Record<string, any> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
export function identifier(value: unknown, max = 255): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    Buffer.byteLength(value) <= max &&
    /^[!-~]+$/.test(value)
  );
}
function exact(value: unknown, keys: string[]): value is Record<string, any> {
  return (
    object(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const timestamp = (value: unknown): value is string =>
  typeof value === "string" &&
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)$/.test(
    value,
  ) &&
  Number.isFinite(Date.parse(value));
function invalid(): never {
  throw new GatewayError(
    502,
    "invalid_notification",
    "A delivery reference did not match the current receiving context.",
  );
}
export function reference(
  context: DeliveryContext,
  notification: Notification,
): { sender: string; metadata: EventReference } {
  if (
    !object(notification) ||
    !identifier(notification.id) ||
    !timestamp(notification.created_at) ||
    notification.type !== `${context.appId}.webhook.received` ||
    notification.for !== context.actor.id ||
    !object(notification.metadata) ||
    !exact(notification.data, ["type", "data"]) ||
    notification.data.type !== "new_event" ||
    !exact(notification.data.data, ["sender", "metadata"])
  )
    invalid();
  const data = notification.data.data,
    ref = data.metadata;
  if (
    typeof data.sender !== "string" ||
    !data.sender ||
    !exact(ref, [
      "id",
      "org_id",
      "silicon_id",
      "hook_id",
      "delivery_sequence",
      "received_at",
      "summary",
      "environment_id",
      "environment_generation",
    ]) ||
    !uuid.test(ref.id) ||
    ref.id === PRODUCTION ||
    !uuid.test(ref.hook_id) ||
    ref.hook_id === PRODUCTION ||
    ref.org_id !== context.org ||
    !identifier(ref.silicon_id) ||
    ref.environment_id !== context.environmentId ||
    !Number.isSafeInteger(ref.environment_generation) ||
    ref.environment_generation < 0 ||
    (context.environmentId === PRODUCTION &&
      ref.environment_generation !== 0) ||
    !Number.isSafeInteger(ref.delivery_sequence) ||
    ref.delivery_sequence <= 0 ||
    !timestamp(ref.received_at) ||
    typeof ref.summary !== "string" ||
    !ref.summary ||
    notification.key !==
      `hook:${ref.id}:${createHash("sha256").update(context.actor.id).digest("hex")}`
  )
    invalid();
  return data as { sender: string; metadata: EventReference };
}
export function matchesEvent(
  event: any,
  expected: EventReference,
  sender: string,
): boolean {
  return (
    object(event) &&
    [
      "id",
      "org_id",
      "silicon_id",
      "hook_id",
      "delivery_sequence",
      "received_at",
      "summary",
    ].every((key) => event[key] === expected[key as keyof EventReference]) &&
    event.provider === sender
  );
}

export function watchInbox(
  origin: string,
  session: TingSession,
  context: DeliveryContext,
  callbacks: {
    ready(): void;
    changed(): void;
    failed(error: GatewayError): void;
  },
): () => void {
  const url = new URL("/v1/ws?protocol=v1", origin);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(url, {
    maxPayload: 65536,
    handshakeTimeout: 25000,
    followRedirects: false,
  });
  let stopped = false,
    ready = false;
  const requestId = randomUUID();
  const timeout = setTimeout(
    () =>
      fail(
        new GatewayError(
          503,
          "ting_unavailable",
          "The delivery watch did not become ready. Try again.",
        ),
      ),
    25000,
  );
  const stop = () => {
    stopped = true;
    clearTimeout(timeout);
    socket.terminate();
  };
  const fail = (error: GatewayError) => {
    if (!stopped) {
      stop();
      callbacks.failed(error);
    }
  };
  socket.on("message", (raw) => {
    try {
      const message = JSON.parse(raw.toString());
      if (message.op === "ready")
        socket.send(
          JSON.stringify({
            op: "watch_inbox",
            request_id: requestId,
            org_id: context.tingOrg,
            session_token: session.token,
          }),
        );
      else if (
        message.op === "watching_inbox" &&
        message.request_id === requestId &&
        message.org_id === context.tingOrg
      ) {
        clearTimeout(timeout);
        ready = true;
        callbacks.ready();
      } else if (
        message.op === "inbox_changed" &&
        ready &&
        message.org_id === context.tingOrg
      )
        callbacks.changed();
      else if (message.op === "paused" || message.op === "error") {
        const reason = message.reason || message.error?.code;
        const denied = ["permission_changed", "permission_denied"].includes(
          reason,
        );
        const expired = ["session_expired", "authentication_required"].includes(
          reason,
        );
        fail(
          new GatewayError(
            expired ? 401 : denied ? 403 : 503,
            expired
              ? "delivery_session_expired"
              : denied
                ? "delivery_permission_changed"
                : "delivery_authorization_unavailable",
            expired
              ? "The delivery session expired. Continue with IAM again."
              : denied
                ? "Delivery access changed. Choose an allowed organization or continue with IAM again."
                : "Delivery authorization is temporarily unavailable. Reconnecting is required.",
          ),
        );
      }
    } catch {
      fail(
        new GatewayError(
          502,
          "invalid_ting_response",
          "The delivery service sent an invalid watch frame.",
        ),
      );
    }
  });
  socket.on("error", () =>
    fail(
      new GatewayError(
        503,
        "ting_unavailable",
        "The delivery watch could not connect. Try again.",
      ),
    ),
  );
  socket.on("close", () =>
    fail(
      new GatewayError(
        503,
        "ting_disconnected",
        "The delivery watch disconnected. Reconnect to resume.",
      ),
    ),
  );
  return stop;
}

/** Scoped capabilities stay between the BFF and Ting and never reach a browser. */
export function watchReceiver(
  origin: string,
  capability: ReceiverCapability,
  callbacks: {
    ready(): void;
    changed(): void;
    failed(error: GatewayError): void;
  },
): () => void {
  const url = new URL("/v1/receivers/ws?protocol=v1", origin);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(url, {
    maxPayload: 65536,
    handshakeTimeout: 5000,
    followRedirects: false,
  });
  const request = randomUUID();
  let stopped = false,
    offered = false,
    watching = false;
  const stop = () => {
    stopped = true;
    clearTimeout(timer);
    socket.terminate();
  };
  const fail = (code = "receiver_disconnected") => {
    if (stopped) return;
    stop();
    callbacks.failed(
      new GatewayError(
        503,
        code,
        "The receiving watch ended. Reconnect to renew its authority.",
      ),
    );
  };
  const timer = setTimeout(() => fail("receiver_watch_timeout"), 5000);
  const matches = (frame: any) =>
    frame.receiver_id === capability.receiver_id &&
    frame.app_id === capability.app_id &&
    frame.org_id === capability.org_id &&
    frame.environment?.kind === "testing" &&
    frame.environment.id === capability.environment.id &&
    frame.environment.generation === capability.environment.generation;
  socket.on("message", (raw) => {
    if (stopped) return;
    try {
      const frame = JSON.parse(raw.toString());
      if (
        !offered &&
        frame.op === "ready" &&
        frame.protocol === "v1" &&
        identifier(frame.receiver_id)
      ) {
        offered = true;
        socket.send(
          JSON.stringify({
            op: "watch",
            request_id: request,
            receiver_token: capability.receiver_token,
          }),
        );
      } else if (
        offered &&
        !watching &&
        frame.op === "watching_inbox" &&
        frame.request_id === request &&
        matches(frame) &&
        frame.for === capability.for &&
        frame.kind === capability.kind &&
        Date.parse(frame.expires_at) === Date.parse(capability.expires_at)
      ) {
        clearTimeout(timer);
        watching = true;
        callbacks.ready();
      } else if (watching && frame.op === "inbox_changed" && matches(frame))
        callbacks.changed();
      else fail("invalid_receiver_frame");
    } catch {
      fail("invalid_receiver_frame");
    }
  });
  socket.on("error", () => fail());
  socket.on("close", () => fail());
  return stop;
}
