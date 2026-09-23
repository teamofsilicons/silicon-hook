import type { IncomingMessage, ServerResponse, Server } from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { resolve } from "node:path";
import { WebSocket, WebSocketServer } from "ws";
import {
  SessionStore,
  type Plane,
  type Session,
  type Tokens,
  type ExchangeOutcome,
} from "./session.ts";
import { GatewayError } from "./errors.ts";
export { GatewayError } from "./errors.ts";
import {
  Ting,
  TING_APP,
  PRODUCTION,
  secureOrigin,
  identifier,
  reference,
  matchesEvent,
  watchInbox,
  watchReceiver,
  type DeliveryContext,
} from "./ting.ts";
import { callbackHtml, callbackScript } from "./callback.ts";
import {
  allocate,
  closeReceiver,
  ensureReceiver,
  sameScope,
  validateScope,
  type ReceiverCapability,
  type ReceiverScope,
} from "./receiver.ts";

export interface Config {
  origin: string;
  frontendOrigin: string;
  upstream: string;
  tingUpstream: string;
  iamUpstream: string;
  iamAuthorizeOrigin: string;
  iamBundle?: string;
  sessionDir: string;
  sessionKey: Buffer;
}
export function config(vars: Record<string, string | undefined>): Config {
  const production = vars.NODE_ENV === "production";
  if (
    production &&
    (!vars.HOOK_WEB_ORIGIN ||
      !vars.HOOK_API_UPSTREAM ||
      !vars.HOOK_SESSION_KEY ||
      !vars.HOOK_SESSION_DIR)
  )
    throw new Error(
      "Production requires HOOK_WEB_ORIGIN, HOOK_API_UPSTREAM, HOOK_SESSION_KEY and HOOK_SESSION_DIR",
    );
  const origin = new URL(vars.HOOK_WEB_ORIGIN || "http://127.0.0.1:4317");
  const upstream = new URL(vars.HOOK_API_UPSTREAM || "http://127.0.0.1:18480");
  const frontend = new URL(vars.HOOK_FRONTEND_ORIGIN || origin.origin);
  const tingUpstream = secureOrigin(
    vars.HOOK_TING_UPSTREAM || "https://backend.ting.teamofsilicons.com",
  );
  const iamUpstream = secureOrigin(
    vars.HOOK_IAM_API_UPSTREAM || "https://backend.iam.teamofsilicons.com",
  );
  const iamAuthorizeOrigin = secureOrigin(
    vars.HOOK_IAM_AUTHORIZE_ORIGIN || "https://auth.iam.teamofsilicons.com",
  );
  if (
    vars.HOOK_IAM_BUNDLE_ID &&
    !/^[^\s,>]+>[^\s,>]+$/.test(vars.HOOK_IAM_BUNDLE_ID)
  )
    throw new Error("HOOK_IAM_BUNDLE_ID must be a qualified IAM bundle ID");
  for (const url of [origin, upstream, frontend])
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
  if (
    production &&
    (origin.protocol !== "https:" || frontend.protocol !== "https:")
  )
    throw new Error("Production requires HTTPS");
  return {
    origin: origin.origin,
    frontendOrigin: frontend.origin,
    upstream: upstream.origin,
    tingUpstream,
    iamUpstream,
    iamAuthorizeOrigin,
    iamBundle: vars.HOOK_IAM_BUNDLE_ID,
    sessionDir: vars.HOOK_SESSION_DIR || resolve(".sessions"),
    sessionKey: vars.HOOK_SESSION_KEY
      ? Buffer.from(vars.HOOK_SESSION_KEY, "base64")
      : randomBytes(32),
  };
}
export function allowed(path: string, method: string): boolean {
  const p = path.split("?")[0];
  if (
    method === "GET" &&
    ["/healthz", "/readyz", "/api/version", "/api/v2/version"].includes(p)
  )
    return true;
  if (/^\/api\/v2\/testing-environments$/.test(p))
    return ["GET", "POST"].includes(method);
  if (/^\/api\/v2\/testing-environments\/[a-f0-9-]{36}$/.test(p))
    return ["GET", "DELETE"].includes(method);
  if (/^\/api\/v2\/testing-environments\/[a-f0-9-]{36}\/key$/.test(p))
    return method === "GET";
  if (
    /^\/api\/v2\/testing-environments\/[a-f0-9-]{36}\/(key\/rotate|restore)$/.test(
      p,
    )
  )
    return method === "POST";
  if (p === "/api/v2/testing-session") return method === "GET";
  if (p === "/api/v2/testing-environment") return method === "GET";
  if (p === "/api/v2/testing-environment/clean") return method === "POST";
  if (p === "/api/v2/testing-environment/iam") return method === "PUT";
  const base = "^/api/v2/silicons/[^/]+/";
  if (new RegExp(base + "hooks$").test(p))
    return ["GET", "POST", "PATCH"].includes(method);
  if (new RegExp(base + "hooks/iam$").test(p)) return method === "POST";
  if (new RegExp(base + "hooks/[a-f0-9-]{36}$").test(p))
    return ["GET", "PATCH", "DELETE"].includes(method);
  if (
    new RegExp(
      base + "hooks/[a-f0-9-]{36}/(restore|secret/rotate|endpoint/rotate)$",
    ).test(p)
  )
    return method === "POST";
  if (
    new RegExp(base + "(hooks/[a-f0-9-]{36}/)?(events|blocked-requests)$").test(
      p,
    )
  )
    return method === "GET";
  if (new RegExp(base + "events/[a-f0-9-]{36}(/publication)?$").test(p))
    return method === "GET";
  if (new RegExp(base + "delivery/subscription$").test(p))
    return ["GET", "POST", "DELETE"].includes(method);
  return p === "/api/v2/delivery/recipient" && method === "POST";
}
async function bounded(response: Response) {
  if (!response.body) return Buffer.alloc(0);
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) {
    size += chunk.length;
    if (size > 64 * 1024 * 1024)
      throw new GatewayError(
        502,
        "response_too_large",
        "The upstream response exceeded the supported size.",
      );
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
export function gateway(cfg: Config) {
  const store = new SessionStore(cfg.sessionDir, cfg.sessionKey);
  const ting = new Ting(cfg.tingUpstream);
  const contracts = new Map<string, Promise<void>>();
  const activeReceivers = new Set<string>();
  const sockets = new Map<string, Set<{ plane: string; socket: WebSocket }>>();
  const cookieName = cfg.origin.startsWith("https:")
    ? "__Host-hook-session"
    : "hook-session";
  function idOf(req: IncomingMessage) {
    const value = req.headers.cookie
      ?.split(";")
      .map((x) => x.trim())
      .find((x) => x.startsWith(cookieName + "="))
      ?.slice(cookieName.length + 1);
    return value && /^[a-f0-9]{64}$/.test(value) ? value : undefined;
  }
  function guard(req: IncomingMessage, websocket = false, callback = false) {
    if (req.headers.host !== new URL(cfg.origin).host)
      throw new GatewayError(
        403,
        "invalid_host",
        "This hostname is not configured.",
      );
    if (
      (callback || websocket || req.headers.origin) &&
      req.headers.origin !== (callback ? cfg.origin : cfg.frontendOrigin)
    )
      throw new GatewayError(
        403,
        "invalid_origin",
        "Use the configured Hook frontend origin.",
      );
    if (!websocket && req.headers["x-hook-frontend"] !== "1")
      throw new GatewayError(
        403,
        "frontend_csrf",
        "The frontend request header is required.",
      );
    if (req.headers["sec-fetch-site"] === "cross-site")
      throw new GatewayError(
        403,
        "frontend_csrf",
        "Cross-site session requests are not accepted.",
      );
  }
  function closePlane(id: string, plane: string) {
    for (const item of sockets.get(id) || [])
      if (item.plane === plane)
        item.socket.close(4001, "Session or environment changed");
  }
  async function upstream(
    path: string,
    method: string,
    plane: Plane,
    org: string,
    body?: unknown,
    key?: string,
  ) {
    if (path.startsWith("/api/v2/")) await negotiate(plane);
    const headers: Record<string, string> = {
      "silicon-hook-api-version": "v2",
      accept: "application/json",
    };
    if (plane.tokens)
      headers.authorization = "Bearer " + plane.tokens.access_token;
    if (plane.key) headers["x-hook-test-key"] = plane.key;
    if (plane.appSecret) headers["x-hook-test-app-secret"] = plane.appSecret;
    if (plane.telemetry === false) headers["x-hook-telemetry"] = "off";
    if (org) headers["x-org-id"] = org;
    if (body !== undefined) headers["content-type"] = "application/json";
    if (key) headers["idempotency-key"] = key;
    try {
      const res = await fetch(cfg.upstream + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(35000),
        redirect: "error",
      });
      const raw = res.status === 204 ? Buffer.alloc(0) : await bounded(res);
      let data: unknown;
      try {
        data = raw.length ? JSON.parse(raw.toString()) : null;
      } catch {
        throw new GatewayError(
          502,
          "invalid_upstream",
          "Hook returned an unreadable response.",
        );
      }
      if (!res.ok) {
        const e = data as {
          error?: {
            code?: string;
            message?: string;
            details?: string;
            request_id?: string;
          };
        };
        throw new GatewayError(
          res.status,
          e.error?.code || "upstream_error",
          e.error?.message || "Hook could not complete this request.",
          e.error?.details,
          e.error?.request_id,
          res.headers.get("retry-after") || undefined,
        );
      }
      return data as Record<string, any>;
    } catch (e) {
      if (e instanceof GatewayError) throw e;
      throw new GatewayError(
        502,
        "hook_unavailable",
        "The Hook backend could not be reached. Try again.",
      );
    }
  }
  async function negotiate(plane: Plane) {
    const binding = createHash("sha256")
      .update(JSON.stringify([plane.key || "", plane.appSecret || ""]))
      .digest("hex");
    let pending = contracts.get(binding);
    if (!pending) {
      pending = (async () => {
        const headers: Record<string, string> = {
          "silicon-hook-supported-api-versions": "v2",
          accept: "application/json",
        };
        // Negotiation is a public service handshake. Private selectors belong
        // only on the versioned request after this contract is verified.
        if (plane.telemetry === false) headers["x-hook-telemetry"] = "off";
        try {
          const response = await fetch(cfg.upstream + "/api/version", {
            headers,
            redirect: "error",
            signal: AbortSignal.timeout(15000),
          });
          const data = JSON.parse((await bounded(response)).toString());
          if (
            !response.ok ||
            data.service !== "silicon-hook" ||
            data.selected_api_version !== "v2"
          )
            throw new GatewayError(
              502,
              "hook_contract_unavailable",
              "This website requires the Hook v2 delivery contract. Update the configured backend before signing in.",
            );
        } catch (error) {
          if (error instanceof GatewayError) throw error;
          throw new GatewayError(
            502,
            "hook_unavailable",
            "Hook's API contract could not be verified. Try again.",
          );
        }
      })();
      if (contracts.size >= 100) contracts.clear();
      contracts.set(binding, pending);
    }
    try {
      await pending;
    } catch (error) {
      contracts.delete(binding);
      throw error;
    }
  }
  async function refresh(id: string, session: Session, plane: Plane) {
    // A recovered reply can already be expired. Persist its rotated credential
    // before one bounded renewal of the new generation.
    for (let attempt = 0; attempt < 2; attempt++) {
      if (
        !plane.tokens ||
        (!plane.refresh && (plane.expiresAt || 0) > Date.now() + 60000)
      )
        return;
      plane.refresh ??= { key: crypto.randomUUID(), started: Date.now() };
      await store.save(id, session);
      const tokens = (await upstream(
        "/api/v2/auth/refresh",
        "POST",
        plane,
        "",
        { refresh_token: plane.tokens.refresh_token },
        plane.refresh.key,
      )) as Tokens;
      if (
        !validTokens(tokens) ||
        tokens.actor.id !== plane.tokens.actor.id ||
        tokens.actor.type !== plane.tokens.actor.type
      )
        throw new GatewayError(
          502,
          "invalid_refresh",
          "Hook returned an unreadable session response. Please retry.",
        );
      plane.tokens = tokens;
      plane.expiresAt = plane.refresh.started + tokens.expires_in * 1000;
      delete plane.refresh;
      await store.save(id, session);
    }
    if ((plane.expiresAt || 0) <= Date.now())
      throw new GatewayError(
        503,
        "refresh_recovery_pending",
        "The recovered session expired. Retry to complete its renewal.",
      );
  }
  function validTokens(value: any): value is Tokens {
    return (
      identifier(value?.access_token, 32768) &&
      identifier(value?.refresh_token, 32768) &&
      Number.isFinite(value.expires_in) &&
      value.expires_in > 0 &&
      identifier(value.actor?.id) &&
      ["carbon", "silicon"].includes(value.actor?.type) &&
      Array.isArray(value.scopes)
    );
  }
  async function exchange<T>(
    id: string,
    session: Session,
    outcome: ExchangeOutcome,
    work: () => Promise<T>,
  ): Promise<T> {
    if (outcome.rejected)
      throw new GatewayError(
        401,
        "login_exchange_rejected",
        "That short-lived token was rejected. Return to the application and start a new IAM sign-in.",
      );
    const previouslyUncertain = !!(outcome.uncertain || outcome.inFlight);
    // Persist before sending: a process can die after the upstream commits but
    // before either its reply or our catch block runs.
    outcome.inFlight = true;
    await store.save(id, session);
    try {
      return await work();
    } catch (error) {
      const rejected =
        error instanceof GatewayError &&
        [400, 401, 403, 404, 406, 409, 410, 415, 422].includes(error.status);
      delete outcome.inFlight;
      if (rejected && !previouslyUncertain) outcome.rejected = true;
      else outcome.uncertain = true;
      await store.save(id, session);
      if (rejected && outcome.uncertain)
        throw new GatewayError(
          409,
          "login_cleanup_pending",
          "An interrupted sign-in could not be recovered safely. Its saved attempt has been retained; retry or contact the service operator.",
        );
      throw error;
    }
  }
  function settled(outcome: ExchangeOutcome | undefined) {
    if (outcome) {
      delete outcome.inFlight;
      delete outcome.uncertain;
    }
  }
  async function hookOrganizations(
    plane: Plane,
  ): Promise<{ id: string; name: string; iamId: string }[]> {
    const items: { id: string; name: string; iamId: string }[] = [],
      seen = new Set<string>();
    let cursor: string | undefined;
    do {
      const url = new URL("/api/v1/organizations", cfg.iamUpstream);
      url.searchParams.set("limit", "100");
      if (cursor) url.searchParams.set("cursor", cursor);
      let response: Response;
      try {
        response = await fetch(url, {
          headers: {
            authorization: `Bearer ${plane.tokens!.access_token}`,
            "silicon-iam-api-version": "v1",
            accept: "application/json",
          },
          signal: AbortSignal.timeout(15000),
          redirect: "error",
        });
      } catch {
        throw new GatewayError(
          502,
          "iam_unavailable",
          "Could not load organizations from IAM. Try again.",
        );
      }
      if (!response.ok)
        throw new GatewayError(
          response.status,
          "organizations_unavailable",
          "IAM could not load your shared organizations. Continue with IAM again.",
        );
      const page = JSON.parse((await bounded(response)).toString());
      if (
        !Array.isArray(page.items) ||
        page.items.length > 100 ||
        page.items.some(
          (org: any) =>
            !identifier(org.org_id) ||
            !identifier(org.id) ||
            typeof org.name !== "string",
        )
      )
        throw new GatewayError(
          502,
          "invalid_iam_response",
          "IAM returned an unreadable organization list.",
        );
      for (const org of page.items)
        if (!items.some((item) => item.id === org.org_id))
          items.push({ id: org.org_id, name: org.name, iamId: org.id });
      cursor = page.page?.has_more ? page.page.next_cursor : undefined;
      if (
        page.page?.has_more &&
        (!identifier(cursor, 4096) || seen.has(cursor) || seen.size >= 100)
      )
        throw new GatewayError(
          502,
          "invalid_iam_response",
          "IAM could not complete the organization list.",
        );
      if (cursor) seen.add(cursor);
    } while (cursor);
    return items;
  }
  async function completeLogin(id: string, session: Session, body: any) {
    const pending = session.login;
    if (
      !pending ||
      !identifier(body?.state, 64) ||
      pending.expires < Date.now() ||
      body.state.length !== pending.state.length ||
      !timingSafeEqual(Buffer.from(body.state), Buffer.from(pending.state))
    )
      throw new GatewayError(
        403,
        "invalid_callback",
        "This sign-in attempt expired. Return to the application and continue with IAM again.",
      );
    if (body.slts !== undefined) {
      if (
        !Array.isArray(body.slts) ||
        body.slts.length !== 2 ||
        body.slts.some(
          (item: any) =>
            !identifier(item?.slt, 8192) ||
            ![pending.hookApp, TING_APP].includes(item?.app_id),
        ) ||
        new Set(body.slts.map((item: any) => item.app_id)).size !== 2
      )
        throw new GatewayError(
          422,
          "invalid_login_pair",
          "IAM must return exactly the two requested application sessions. Continue with IAM again.",
        );
      const items = body.slts
        .map((item: any) => ({ app_id: item.app_id, slt: item.slt }))
        .sort((a: any, b: any) => a.app_id.localeCompare(b.app_id));
      const hash = createHash("sha256")
        .update(JSON.stringify(items))
        .digest("hex");
      if (pending.inputHash && hash !== pending.inputHash)
        throw new GatewayError(
          409,
          "login_attempt_mismatch",
          "This sign-in attempt already belongs to a different response. Continue with IAM again.",
        );
      if (!pending.complete) {
        pending.items = items;
        pending.inputHash = hash;
        await store.save(id, session);
      }
    }
    if (pending.complete) return;
    if (!pending.items)
      throw new GatewayError(
        422,
        "missing_login_response",
        "The IAM sign-in response is missing. Return to the application and try again.",
      );
    if (!pending.hook) {
      await negotiate({ name: "Production" });
      pending.started ??= Date.now();
      pending.hookOutcome ??= {};
      await store.save(id, session);
      const tokens = await exchange(id, session, pending.hookOutcome, () =>
        upstream(
          "/api/v2/auth/login",
          "POST",
          { name: "Production" },
          "",
          {
            slt: pending.items!.find((item) => item.app_id === pending.hookApp)!
              .slt,
          },
          pending.hookKey,
        ),
      );
      if (!validTokens(tokens))
        throw new GatewayError(
          502,
          "invalid_login",
          "Hook returned an invalid session. Retry this sign-in attempt.",
        );
      pending.hook = {
        name: "Production",
        tokens,
        expiresAt: pending.started + tokens.expires_in * 1000,
      };
      settled(pending.hookOutcome);
      await store.save(id, session);
    }
    if (!pending.ting) {
      pending.tingStarted = true;
      pending.tingOutcome ??= {};
      await store.save(id, session);
      pending.ting = await exchange(id, session, pending.tingOutcome, () =>
        ting.login(
          pending.items!.find((item) => item.app_id === TING_APP)!.slt,
          pending.tingKey,
        ),
      );
      settled(pending.tingOutcome);
      await store.save(id, session);
    }
    await refresh(id, session, pending.hook);
    const actor = pending.hook.tokens!.actor;
    if (
      actor.id !== pending.ting.id ||
      actor.type !== pending.ting.kind ||
      pending.ting.environmentId !== PRODUCTION
    )
      throw new GatewayError(
        403,
        "delivery_identity_mismatch",
        "The application and delivery sessions belong to different identities. Continue with IAM again.",
      );
    await ting.identity(pending.ting);
    const hookOrgs = await hookOrganizations(pending.hook),
      tingOrgs = await ting.organizations(pending.ting);
    const shared = hookOrgs.filter((org) =>
      tingOrgs.some(
        (other) => other.id === org.iamId && other.handle === org.id,
      ),
    );
    if ((hookOrgs.length || tingOrgs.length) && !shared.length)
      throw new GatewayError(
        403,
        "delivery_organization_mismatch",
        "Choose the same organization for both application sessions when continuing with IAM.",
      );
    if (shared.length) {
      const status = await upstream(
        "/api/v2/auth/status",
        "GET",
        pending.hook,
        shared[0].id,
      );
      if (
        status.authenticated !== true ||
        status.actor?.id !== actor.id ||
        status.actor?.type !== actor.type ||
        status.org_id !== shared[0].id
      )
        throw new GatewayError(
          403,
          "delivery_identity_mismatch",
          "The signed-in identity or organization changed. Continue with IAM again.",
        );
    }
    closePlane(id, "production");
    // Keep the new pair in the encrypted attempt until both old credentials
    // have been revoked. An unavailable logout is retried without losing either
    // session family or repeating a completed SLT exchange.
    const old = session.planes.production;
    if (old.tokens || old.ting) {
      if (
        old.tokens?.refresh_token === pending.hook.tokens?.refresh_token ||
        old.ting?.token === pending.ting.token
      )
        throw new GatewayError(
          409,
          "login_family_conflict",
          "The new login reused an existing session family. Start a new IAM sign-in attempt.",
        );
      await logoutPlane(id, session, old, `retire-${pending.hookKey}`);
    }
    await discardManual(id, session, "production");
    session.planes.production = { ...pending.hook, ting: pending.ting };
    delete pending.items;
    delete pending.hook;
    delete pending.ting;
    pending.complete = true;
    await store.save(id, session);
  }
  function bootstrapReceiver(id: string, session: Session, plane: Plane) {
    return async (
      scope: ReceiverScope,
      body: {
        environment_id: string;
        generation: number;
        receiver_id?: string;
      },
      key: string,
    ) => {
      if (!plane.appSecret || plane.key || !plane.tokens)
        throw new GatewayError(
          409,
          "receiver_cleanup_pending",
          "Restore this test application's session to finish receiving cleanup.",
        );
      await refresh(id, session, plane);
      try {
        return await upstream(
          "/api/v2/delivery/receiver",
          "POST",
          plane,
          scope.hook_org_id,
          body,
          key,
        );
      } catch (error) {
        if (!(error instanceof GatewayError) || error.status !== 401)
          throw error;
        plane.expiresAt = 0;
        await refresh(id, session, plane);
        return upstream(
          "/api/v2/delivery/receiver",
          "POST",
          plane,
          scope.hook_org_id,
          body,
          key,
        );
      }
    };
  }
  async function drainReceivers(
    id: string,
    session: Session,
    plane: Plane,
    only?: string,
    orphans = false,
  ) {
    const slots = plane.receivers;
    if (!slots) return;
    for (const slot of only ? [only] : Object.keys(slots)) {
      if (orphans && activeReceivers.has(slot)) continue;
      await closeReceiver(
        slots,
        slot,
        () => store.save(id, session),
        bootstrapReceiver(id, session, plane),
        (capability) => ting.revokeReceiver(capability),
      );
    }
    if (!Object.keys(slots).length) delete plane.receivers;
    await store.save(id, session);
  }
  async function logoutPlane(
    id: string,
    session: Session,
    plane: Plane,
    key: string,
  ) {
    plane.logout ??= { key };
    await store.save(id, session);
    await drainReceivers(id, session, plane);
    if (plane.ting) {
      try {
        await ting.call("/v1/session", "DELETE", plane.ting);
      } catch (error) {
        if (!(error instanceof GatewayError) || error.status !== 401)
          throw error;
      }
      delete plane.ting;
      await store.save(id, session);
    }
    if (plane.tokens) {
      try {
        await upstream(
          "/api/v2/auth/logout",
          "POST",
          {
            ...plane,
            tokens: {
              ...plane.tokens,
              access_token: plane.tokens.refresh_token,
            },
          },
          "",
          undefined,
          plane.logout.key,
        );
      } catch (error) {
        if (!(error instanceof GatewayError) || error.status !== 401)
          throw error;
      }
    }
    delete plane.tokens;
    delete plane.refresh;
    delete plane.expiresAt;
    delete plane.logout;
    await store.save(id, session);
  }
  async function discardBatch(id: string, session: Session) {
    const pending = session.login;
    if (!pending) return;
    if (
      pending.started &&
      !pending.hook &&
      pending.items &&
      !pending.hookOutcome?.rejected
    ) {
      pending.hookOutcome ??= {};
      const tokens = await exchange(id, session, pending.hookOutcome, () =>
        upstream(
          "/api/v2/auth/login",
          "POST",
          { name: "Production" },
          "",
          {
            slt: pending.items!.find((item) => item.app_id === pending.hookApp)!
              .slt,
          },
          pending.hookKey,
        ),
      );
      if (!validTokens(tokens))
        throw new GatewayError(
          502,
          "login_cleanup_pending",
          "The interrupted sign-in must be recovered before its session can be revoked. Retry this operation.",
        );
      pending.hook = {
        name: "Production",
        tokens,
        expiresAt: pending.started + tokens.expires_in * 1000,
      };
      settled(pending.hookOutcome);
      await store.save(id, session);
    }
    if (
      pending.tingStarted &&
      !pending.ting &&
      !pending.hook?.ting &&
      pending.items &&
      !pending.tingOutcome?.rejected
    ) {
      pending.tingOutcome ??= {};
      pending.ting = await exchange(id, session, pending.tingOutcome, () =>
        ting.login(
          pending.items!.find((item) => item.app_id === TING_APP)!.slt,
          pending.tingKey,
        ),
      );
      settled(pending.tingOutcome);
      await store.save(id, session);
    }
    if (pending.hook || pending.ting) {
      pending.hook ??= { name: "Production" };
      if (pending.ting) {
        pending.hook.ting = pending.ting;
        delete pending.ting;
        pending.tingStarted = false;
      }
      await store.save(id, session);
      await logoutPlane(id, session, pending.hook, `cancel-${pending.hookKey}`);
    }
    delete session.login;
    await store.save(id, session);
  }
  async function discardManual(id: string, session: Session, planeId: string) {
    const pending = session.manual?.[planeId];
    if (!pending) return;
    if (pending.complete) return; // A receipt contains no credential to revoke.
    if (!pending.result && !pending.outcome?.rejected) {
      const plane = session.planes[planeId];
      pending.outcome ??= {};
      const tokens = await exchange(id, session, pending.outcome, () =>
        upstream(
          "/api/v2/auth/login",
          "POST",
          { name: plane.name, key: plane.key, appSecret: plane.appSecret },
          "",
          { slt: pending.slt },
          pending.key,
        ),
      );
      if (!validTokens(tokens))
        throw new GatewayError(
          502,
          "login_cleanup_pending",
          "The interrupted sign-in must be recovered before its session can be revoked. Retry this operation.",
        );
      pending.result = {
        name: plane.name,
        key: plane.key,
        appSecret: plane.appSecret,
        tokens,
        expiresAt: pending.started + tokens.expires_in * 1000,
      };
      settled(pending.outcome);
      await store.save(id, session);
    }
    if (pending.result)
      await logoutPlane(
        id,
        session,
        pending.result,
        `cancel-${pending.key}`.slice(0, 255),
      );
    delete session.manual![planeId];
    await store.save(id, session);
  }
  async function manualLogin(
    id: string,
    session: Session,
    planeId: string,
    slt: string,
    key: string,
  ) {
    const hash = createHash("sha256").update(slt).digest("hex");
    let pending = session.manual?.[planeId];
    if (pending?.complete && pending.key === key && pending.hash === hash)
      return;
    if (pending && (pending.key !== key || pending.hash !== hash)) {
      await discardManual(id, session, planeId);
      pending = undefined;
    }
    const plane = session.planes[planeId];
    await negotiate(plane);
    if (!pending) {
      pending = { key, hash, slt, started: Date.now(), outcome: {} };
      session.manual ??= {};
      session.manual[planeId] = pending;
      await store.save(id, session);
    }
    if (!pending.result) {
      pending.outcome ??= {};
      const attempt = pending;
      const tokens = await exchange(id, session, pending.outcome, () =>
        upstream(
          "/api/v2/auth/login",
          "POST",
          { name: plane.name, key: plane.key, appSecret: plane.appSecret },
          "",
          { slt: attempt.slt },
          attempt.key,
        ),
      );
      if (!validTokens(tokens))
        throw new GatewayError(
          502,
          "invalid_login",
          "Hook returned an invalid session. Retry this sign-in attempt.",
        );
      pending.result = {
        name: plane.name,
        key: plane.key,
        appSecret: plane.appSecret,
        telemetry: plane.telemetry,
        tokens,
        expiresAt: pending.started + tokens.expires_in * 1000,
      };
      settled(pending.outcome);
      await store.save(id, session);
    }
    await refresh(id, session, pending.result);
    if (plane.tokens?.refresh_token === pending.result.tokens!.refresh_token)
      throw new GatewayError(
        409,
        "login_family_conflict",
        "This token exchange reused the current session family. Request a new IAM short-lived token.",
      );
    closePlane(id, planeId);
    await logoutPlane(
      id,
      session,
      plane,
      `retire-${pending.key}`.slice(0, 255),
    );
    if (planeId === "production") await discardBatch(id, session);
    session.planes[planeId] = pending.result;
    delete pending.result;
    delete pending.slt;
    pending.complete = true;
    await store.save(id, session);
  }
  function publicSession(session: Session) {
    return {
      planes: Object.entries(session.planes).map(([id, p]) => ({
        id,
        name: p.name,
        attached: !!(p.key || p.appSecret),
        authenticated: !!p.tokens && !p.logout,
        logout_pending: !!p.logout,
        actor: p.tokens?.actor,
        org_id: p.tokens?.org_id,
        expires_at: p.expiresAt,
      })),
      upstream: cfg.upstream,
    };
  }
  async function readBody(req: IncomingMessage) {
    let size = 0;
    const chunks: Buffer[] = [];
    for await (const c of req) {
      size += c.length;
      if (size > 2 * 1024 * 1024)
        throw new GatewayError(413, "body_too_large", "Request exceeds 2 MiB.");
      chunks.push(c);
    }
    try {
      return chunks.length
        ? JSON.parse(Buffer.concat(chunks).toString())
        : undefined;
    } catch {
      throw new GatewayError(
        400,
        "invalid_json",
        "The request must be valid JSON.",
      );
    }
  }
  async function handle(req: IncomingMessage, res: ServerResponse) {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    try {
      if (req.headers.origin === cfg.frontendOrigin) {
        res.setHeader("Access-Control-Allow-Origin", cfg.frontendOrigin);
        res.setHeader("Access-Control-Allow-Credentials", "true");
        res.setHeader("Vary", "Origin");
      }
      if (req.method === "OPTIONS") {
        if (
          req.headers.host !== new URL(cfg.origin).host ||
          req.headers.origin !== cfg.frontendOrigin
        )
          throw new GatewayError(
            403,
            "invalid_origin",
            "Use the configured Hook frontend origin.",
          );
        res.setHeader(
          "Access-Control-Allow-Methods",
          "GET, POST, PUT, PATCH, DELETE, OPTIONS",
        );
        res.setHeader(
          "Access-Control-Allow-Headers",
          "Content-Type, X-Hook-Frontend, X-Hook-Telemetry, X-Org-Id, Idempotency-Key",
        );
        res.writeHead(204);
        res.end();
        return;
      }
      const callbackPath = new URL(req.url || "/", cfg.origin).pathname;
      if (
        callbackPath === "/auth/callback" ||
        callbackPath === "/auth/callback/script.js"
      ) {
        if (
          req.method !== "GET" ||
          req.headers.host !== new URL(cfg.origin).host
        )
          throw new GatewayError(
            403,
            "invalid_callback",
            "Invalid sign-in callback.",
          );
        res.setHeader(
          "Content-Security-Policy",
          "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
        );
        res.writeHead(200, {
          "Content-Type": callbackPath.endsWith(".js")
            ? "text/javascript; charset=utf-8"
            : "text/html; charset=utf-8",
        });
        res.end(callbackPath.endsWith(".js") ? callbackScript : callbackHtml);
        return;
      }
      if (callbackPath === "/auth/callback/complete") {
        guard(req, false, true);
        if (
          req.method !== "POST" ||
          req.headers["content-type"]?.split(";")[0] !== "application/json"
        )
          throw new GatewayError(
            415,
            "invalid_callback",
            "The sign-in response must be JSON.",
          );
        const id = idOf(req);
        if (!id)
          throw new GatewayError(
            403,
            "invalid_callback",
            "This browser did not initiate the sign-in attempt.",
          );
        const body = await readBody(req);
        await store.locked(id, async () =>
          completeLogin(id, await store.read(id), body),
        );
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            redirect_url: cfg.frontendOrigin + "/#overview?iam_signed_in=1",
          }),
        );
        return;
      }
      guard(req);
      const id = idOf(req) || store.newId();
      const url = new URL(req.url || "/", cfg.origin);
      const body = req.method === "GET" ? {} : await readBody(req);
      const result = await store.locked(id, async () => {
        const session = await store.read(id);
        const planeId = url.searchParams.get("plane") || "production";
        if (planeId !== "production" && !/^[a-f0-9-]{36}$/.test(planeId))
          throw new GatewayError(
            422,
            "invalid_environment",
            "Choose a valid environment.",
          );
        const plane = Object.hasOwn(session.planes, planeId)
          ? session.planes[planeId]
          : undefined;
        for (const saved of Object.values(session.planes))
          saved.telemetry = req.headers["x-hook-telemetry"] !== "off";
        if (url.pathname === "/console/telemetry" && req.method === "POST") {
          if (plane?.telemetry !== false && plane?.tokens && !plane.logout) {
            await upstream(
              "/api/v2/telemetry",
              "POST",
              plane,
              String(req.headers["x-org-id"] || plane.tokens.org_id || ""),
              body,
            );
          }
          return { accepted: true };
        }
        if (url.pathname === "/console/session" && req.method === "GET") {
          await store.save(id, session);
          return publicSession(session);
        }
        if (url.pathname === "/console/attach" && req.method === "POST") {
          if (
            typeof body?.app_secret !== "string" ||
            !/^ask_[A-Za-z0-9_-]{43}$/.test(body.app_secret)
          )
            throw new GatewayError(
              422,
              "invalid_key",
              "Enter the IAM test application app_secret.",
            );
          const env = await upstream(
            "/api/v2/testing-session",
            "GET",
            {
              name: "Test",
              appSecret: body.app_secret,
              telemetry: req.headers["x-hook-telemetry"] !== "off",
            },
            "",
          );
          if (
            Object.keys(session.planes).length >= 20 &&
            !session.planes[env.id]
          )
            throw new GatewayError(
              422,
              "too_many_environments",
              "A browser session supports up to 19 test environments.",
            );
          closePlane(id, env.id);
          if (session.planes[env.id])
            await drainReceivers(id, session, session.planes[env.id]);
          session.planes[env.id] = {
            ...session.planes[env.id],
            name: env.name,
            key: undefined,
            appSecret: body.app_secret,
          };
          await store.save(id, session);
          return { id: env.id, ...publicSession(session) };
        }
        if (!plane)
          throw new GatewayError(
            401,
            "environment_not_attached",
            "Attach this environment before signing in or making requests.",
          );
        if (
          plane.logout &&
          ![
            "/console/login",
            "/console/login/start",
            "/console/logout",
            "/console/forget",
          ].includes(url.pathname)
        )
          throw new GatewayError(
            409,
            "logout_pending",
            "This session is signing out. Retry sign out to finish revoking its credentials.",
          );
        if (url.pathname === "/console/organizations" && req.method === "GET") {
          if (planeId !== "production") {
            const env = await upstream(
              "/api/v2/testing-session",
              "GET",
              plane,
              "",
            );
            return { items: [{ id: env.org_id, name: env.org_id }] };
          }
          if (!plane.tokens)
            throw new GatewayError(
              401,
              "unauthenticated",
              "Sign in to load your organizations.",
            );
          await refresh(id, session, plane);
          const items = await hookOrganizations(plane);
          if (!plane.ting)
            return { items: items.map(({ id, name }) => ({ id, name })) };
          const deliveryOrgs = await ting.organizations(plane.ting);
          return {
            items: items
              .filter((org) =>
                deliveryOrgs.some(
                  (other) => other.id === org.iamId && other.handle === org.id,
                ),
              )
              .map(({ id, name }) => ({ id, name })),
          };
        }
        if (url.pathname === "/console/login/start" && req.method === "POST") {
          if (planeId !== "production")
            throw new GatewayError(
              422,
              "test_token_required",
              "Use an IAM test token to sign in to this environment.",
            );
          const key = mutation(req);
          let pending = session.login;
          if (
            !pending ||
            pending.complete ||
            pending.expires < Date.now() ||
            pending.mutation !== key
          ) {
            await discardBatch(id, session);
            const info = await upstream(
              "/api/v2/auth/iam",
              "GET",
              { name: "Production" },
              "",
            );
            const deliveryInfo = await ting.call("/v1/iam");
            if (
              !identifier(info.app_id) ||
              info.testing !== false ||
              deliveryInfo.app_id !== TING_APP ||
              info.app_id === TING_APP
            )
              throw new GatewayError(
                502,
                "invalid_application_configuration",
                "The application login configuration is unavailable.",
              );
            pending = session.login = {
              state: randomBytes(32).toString("hex"),
              expires: Date.now() + 300000,
              mutation: key,
              hookApp: info.app_id,
              hookKey: crypto.randomUUID(),
              tingKey: crypto.randomUUID(),
            };
            await store.save(id, session);
          }
          const callback = new URL("/auth/callback", cfg.origin);
          callback.searchParams.set("state", pending.state);
          const authorize = new URL("/login", cfg.iamAuthorizeOrigin);
          if (cfg.iamBundle)
            authorize.searchParams.set("bundle_id", cfg.iamBundle);
          else
            authorize.searchParams.set(
              "app_ids",
              [pending.hookApp, TING_APP].join(","),
            );
          authorize.searchParams.set("redirect_uri", callback.href);
          return { authorize_url: authorize.href };
        }
        if (url.pathname === "/console/login" && req.method === "POST") {
          if (
            typeof body?.slt !== "string" ||
            body.slt.length > 8192 ||
            !body.slt.trim()
          )
            throw new GatewayError(
              422,
              "invalid_slt",
              "Enter an IAM short-lived token.",
            );
          await manualLogin(
            id,
            session,
            planeId,
            body.slt.trim(),
            mutation(req),
          );
          return publicSession(session);
        }
        if (url.pathname === "/console/logout" && req.method === "POST") {
          closePlane(id, planeId);
          await logoutPlane(id, session, plane, mutation(req));
          if (planeId === "production") await discardBatch(id, session);
          await discardManual(id, session, planeId);
          await store.save(id, session);
          return publicSession(session);
        }
        if (url.pathname === "/console/forget" && req.method === "POST") {
          closePlane(id, planeId);
          await logoutPlane(id, session, plane, mutation(req));
          if (planeId === "production") await discardBatch(id, session);
          await discardManual(id, session, planeId);
          if (planeId === "production") {
            session.planes.production = { name: "Production" };
          } else delete session.planes[planeId];
          await store.save(id, session);
          return publicSession(session);
        }
        if (url.pathname === "/console/refresh" && req.method === "POST") {
          plane.expiresAt = 0;
          await refresh(id, session, plane);
          return publicSession(session);
        }
        const path = url.pathname.replace(/^\/console\/proxy/, "");
        const query = new URLSearchParams(url.search);
        query.delete("plane");
        const full = path + (query.size ? "?" + query : "");
        if (
          !url.pathname.startsWith("/console/proxy/") ||
          !allowed(full, req.method || "GET")
        )
          throw new GatewayError(
            404,
            "not_found",
            "This operation is not available.",
          );
        if (
          path.startsWith("/api/v2/testing-environments") &&
          planeId !== "production"
        )
          throw new GatewayError(
            422,
            "production_identity_required",
            "Manage environments from your production identity.",
          );
        const root =
          path.startsWith("/api/v2/testing-environment") &&
          !path.startsWith("/api/v2/testing-environments");
        if (root && planeId === "production")
          throw new GatewayError(
            422,
            "test_environment_required",
            "Select a test environment first.",
          );
        if (
          !root &&
          path !== "/healthz" &&
          path !== "/readyz" &&
          path !== "/api/v2/testing-session" &&
          !path.endsWith("/version")
        )
          await refresh(id, session, plane);
        const requestKey = req.method === "GET" ? undefined : mutation(req);
        const send = () =>
          upstream(
            full,
            req.method || "GET",
            plane,
            String(req.headers["x-org-id"] || ""),
            ["GET", "DELETE"].includes(req.method || "GET") ? undefined : body,
            requestKey,
          );
        let data;
        try {
          data = await send();
        } catch (error) {
          if (
            !(error instanceof GatewayError) ||
            error.status !== 401 ||
            root ||
            !plane.tokens
          )
            throw error;
          plane.expiresAt = 0;
          await refresh(id, session, plane);
          data = await send();
        }
        if (
          path.startsWith("/api/v2/testing-environments") &&
          data?.key &&
          data?.id
        ) {
          // Root-key discovery must never replace an attached app selector.
          // Its authority remains pinned until explicit attach/forget cleanup.
          if (!session.planes[data.id]?.appSecret) {
            closePlane(id, data.id);
            if (session.planes[data.id])
              await drainReceivers(id, session, session.planes[data.id]);
            session.planes[data.id] = {
              ...session.planes[data.id],
              name: data.name,
              key: data.key,
            };
            await store.save(id, session);
          }
        }
        if (root && req.method !== "GET") closePlane(id, planeId);
        return data;
      });
      res.setHeader(
        "Set-Cookie",
        `${cookieName}=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${cfg.origin.startsWith("https:") ? "; Secure" : ""}`,
      );
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(result));
    } catch (error) {
      const e =
        error instanceof GatewayError
          ? error
          : new GatewayError(
              500,
              "gateway_error",
              "The frontend could not complete this request.",
            );
      res.writeHead(e.status, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: {
            code: e.code,
            message: e.message,
            details: e.details,
            request_id: e.requestId,
            retry_after: e.retryAfter,
          },
        }),
      );
    }
  }
  function attachWs(server: Server) {
    const wss = new WebSocketServer({ noServer: true, maxPayload: 8192 });
    server.on("upgrade", (req, socket, head) => {
      const url = new URL(req.url || "/", cfg.origin);
      if (url.pathname !== "/console/stream") return;
      let id: string;
      try {
        guard(req, true);
        id = idOf(req)!;
        if (!id) throw new Error("Sign in first");
      } catch {
        socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
        socket.destroy();
        return;
      }
      wss.handleUpgrade(req, socket, head, (client) => {
        const planeId = url.searchParams.get("plane") || "production";
        const org = url.searchParams.get("org") || "";
        const ids = [...new Set(url.searchParams.getAll("silicon_id"))];
        const item = { plane: planeId, socket: client };
        let set = sockets.get(id);
        if (!set) {
          set = new Set();
          sockets.set(id, set);
        }
        set.add(item);
        let stopped = false,
          stopWatch: (() => void) | undefined;
        let context!: DeliveryContext;
        let receiverSlot: string | undefined;
        let receiver: ReceiverCapability | undefined;
        let renewTimer: ReturnType<typeof setTimeout> | undefined;
        let retryTimer: ReturnType<typeof setTimeout> | undefined;
        let resumeReceiver: (() => Promise<void>) | undefined;
        let paused = false,
          everReady = false;
        let credential = "",
          authority = "";
        let polling = false,
          changed = false,
          live = false,
          pong = true;
        let catchupNotice = false;
        const seen = new Set<string>();
        let renewal: ReturnType<typeof setInterval> | undefined;
        const heartbeat = setInterval(() => {
          if (!pong) {
            client.terminate();
            return;
          }
          pong = false;
          if (client.readyState === WebSocket.OPEN) client.ping();
        }, 30000);
        const cleanup = () => {
          if (stopped) return;
          stopped = true;
          clearInterval(heartbeat);
          clearInterval(renewal);
          clearTimeout(renewTimer);
          clearTimeout(retryTimer);
          stopWatch?.();
          if (receiverSlot) {
            const closing = receiverSlot;
            activeReceivers.delete(closing);
            void store
              .locked(id, async () => {
                const session = await store.read(id),
                  plane = session.planes[planeId];
                if (plane) await drainReceivers(id, session, plane, closing);
              })
              .catch(() => {
                /* The bounded encrypted slot remains for explicit cleanup/recovery. */
              });
          }
          set!.delete(item);
          if (!set!.size) sockets.delete(id);
        };
        const send = (frame: unknown) => {
          if (stopped || client.readyState !== WebSocket.OPEN) return;
          if (client.bufferedAmount > 8 * 1024 * 1024) {
            client.close(1013, "Slow browser");
            cleanup();
            return;
          }
          client.send(JSON.stringify(frame));
        };
        const fail = (error: unknown) => {
          if (stopped) return;
          const e =
            error instanceof GatewayError
              ? error
              : new GatewayError(
                  502,
                  "delivery_unavailable",
                  "The delivery watch could not continue. Try again.",
                );
          if (e.code === "observer_paused") return;
          const retryable = e.status === 429 || e.status >= 500;
          const seconds = Number(e.retryAfter);
          const retryAfter =
            e.status === 429
              ? Math.max(
                  1,
                  Math.ceil(
                    e.retryAfter && Number.isFinite(seconds)
                      ? seconds
                      : e.retryAfter &&
                          Number.isFinite(Date.parse(e.retryAfter))
                        ? (Date.parse(e.retryAfter) - Date.now()) / 1000
                        : 30,
                  ),
                )
              : undefined;
          if (e.status === 429 && receiverSlot && everReady && resumeReceiver) {
            if (paused) return;
            // Keep the bounded private slot and already-emitted IDs while the
            // application's shared quota recovers. A capability may expire in
            // this interval; recovery always renews this same receiver first.
            paused = true;
            live = false;
            stopWatch?.();
            clearTimeout(renewTimer);
            clearInterval(renewal);
            renewal = undefined;
            send({
              type: "error",
              data: {
                code: e.code,
                message: e.message,
                retryable: true,
                fatal: false,
                retry_after: retryAfter,
              },
            });
            const retryAt = Date.now() + retryAfter! * 1000;
            const resume = () => {
              if (stopped) return;
              const remaining = retryAt - Date.now();
              if (remaining > 0) {
                retryTimer = setTimeout(
                  resume,
                  Math.min(remaining, 2147483647),
                );
                return;
              }
              retryTimer = undefined;
              paused = false;
              void resumeReceiver!().catch(fail);
            };
            retryTimer = setTimeout(
              resume,
              Math.min(retryAfter! * 1000, 2147483647),
            );
            return;
          }
          send({
            type: "error",
            data: {
              code: e.code,
              message: e.message,
              retryable,
              fatal: true,
              ...(retryAfter === undefined ? {} : { retry_after: retryAfter }),
            },
          });
          client.close(retryable ? 1013 : 4003, "Delivery watch stopped");
          cleanup();
        };
        const streamLocked = <T>(work: () => Promise<T>): Promise<T> =>
          store.locked(id, async () => {
            try {
              return await work();
            } catch (error) {
              // Set the pause before releasing the lock, so already-queued
              // reconciliation/renewal cannot spend more of the blocked quota.
              if (error instanceof GatewayError && error.status === 429)
                fail(error);
              throw error;
            }
          });
        client.on("pong", () => {
          pong = true;
        });
        client.on("close", cleanup);
        client.on("error", cleanup);
        client.on("message", () =>
          fail(
            new GatewayError(
              400,
              "unsupported_stream_operation",
              "This observer does not accept delivery acknowledgments or commands.",
            ),
          ),
        );
        const subscribe = async (plane: Plane, force = false) => {
          if (stopped)
            throw new GatewayError(
              499,
              "observer_closed",
              "The receiving view was closed.",
            );
          if (!force && authority === plane.tokens!.access_token) return;
          if (context.actor.type === "carbon") {
            for (const silicon of context.silicons) {
              if (stopped)
                throw new GatewayError(
                  499,
                  "observer_closed",
                  "The receiving view was closed.",
                );
              const result = await upstream(
                `/api/v2/silicons/${encodeURIComponent(silicon)}/delivery/subscription`,
                "POST",
                plane,
                org,
              );
              if (
                result.receiving !== true ||
                result.subscription?.recipient_id !== context.actor.id ||
                result.subscription?.org_id !== org ||
                result.subscription?.silicon_id !== silicon
              )
                throw new GatewayError(
                  502,
                  "invalid_subscription",
                  "The receiving subscription did not match the current identity.",
                );
            }
          } else {
            const result = await upstream(
              "/api/v2/delivery/recipient",
              "POST",
              plane,
              org,
            );
            if (
              result.active !== true ||
              result.for !== context.actor.id ||
              result.app_id !== context.appId
            )
              throw new GatewayError(
                502,
                "invalid_subscription",
                "The receiving registration did not match the current identity.",
              );
          }
          authority = plane.tokens!.access_token;
        };
        const current = async <T>(
          work: (plane: Plane) => Promise<T>,
          force = false,
        ): Promise<T> =>
          streamLocked(async () => {
            if (paused)
              throw new GatewayError(
                499,
                "observer_paused",
                "Receiving is waiting for the server's retry delay.",
              );
            if (stopped)
              throw new GatewayError(
                401,
                "session_changed",
                "The receiving session changed.",
              );
            const session = await store.read(id),
              plane = session.planes[planeId];
            if (stopped || paused)
              throw new GatewayError(
                499,
                "observer_paused",
                "The receiving view is closed or waiting to retry.",
              );
            if (
              !plane?.tokens ||
              plane.logout ||
              (receiverSlot
                ? !plane.appSecret ||
                  plane.appSecret !== credential ||
                  !plane.receivers?.[receiverSlot] ||
                  plane.receivers[receiverSlot].closing
                : !plane.ting ||
                  plane.ting.token !== credential ||
                  plane.ting.environmentId !== context.environmentId) ||
              plane.tokens.actor.id !== context.actor.id ||
              plane.tokens.actor.type !== context.actor.type
            )
              throw new GatewayError(
                401,
                "session_changed",
                "The receiving session changed. Continue with IAM again.",
              );
            await refresh(id, session, plane);
            // Initial bootstrap and renewal attest full receiver scope. Ting
            // fences every scoped read; Hook separately authorizes each payload
            // hydration. Repeating scope discovery here exhausts IAM quotas.
            // Only current Carbon access authority reaches Hook; its refresh family stays here.
            try {
              await subscribe(plane, force);
              return await work(plane);
            } catch (error) {
              if (!(error instanceof GatewayError) || error.status !== 401)
                throw error;
              plane.expiresAt = 0;
              await refresh(id, session, plane);
              await subscribe(plane);
              return work(plane);
            }
          });
        const scan = async () => {
          if (stopped || !live) return;
          changed = true;
          if (polling) return;
          polling = true;
          try {
            while (changed && !stopped && live) {
              changed = false;
              const page = await current((plane) =>
                receiverSlot
                  ? ting.receiverInbox(
                      plane.receivers![receiverSlot].capability!,
                    )
                  : ting.inbox(plane.ting!, context),
              );
              if (page.next_cursor && !catchupNotice) {
                catchupNotice = true;
                send({
                  type: "error",
                  data: {
                    code: "inbox_catchup_limit",
                    message:
                      "This live view shows the latest 32 retained notifications. Use History for older events; live updates remain connected.",
                    retryable: false,
                    fatal: false,
                  },
                });
              }
              for (const notification of page.items) {
                if (stopped || !live) return;
                // A fresh arrival takes priority over continuing an older
                // snapshot. This is an observer, not a durable work queue.
                if (changed) break;
                if (identifier(notification?.id) && seen.has(notification.id))
                  continue;
                let ref;
                try {
                  const data = reference(context, notification);
                  ref = data.metadata;
                  if (!context.silicons.includes(ref.silicon_id)) {
                    seen.add(notification.id);
                    continue;
                  }
                  const expected = ref;
                  const query = new URLSearchParams({
                    environment_id: expected.environment_id,
                    environment_generation: String(
                      expected.environment_generation,
                    ),
                  });
                  const event = await current((plane) =>
                    upstream(
                      `/api/v2/silicons/${encodeURIComponent(expected.silicon_id)}/events/${expected.id}?${query}`,
                      "GET",
                      plane,
                      org,
                    ),
                  );
                  if (stopped || !live) return;
                  if (!matchesEvent(event, expected, data.sender))
                    throw new GatewayError(
                      502,
                      "event_reference_mismatch",
                      "The retained event did not match its delivery reference.",
                    );
                  send({
                    type: "new_event",
                    data: { ting_id: notification.id, event },
                  });
                } catch (error) {
                  if (
                    !(error instanceof GatewayError) ||
                    (![
                      "invalid_notification",
                      "event_reference_mismatch",
                    ].includes(error.code) &&
                      error.status !== 404)
                  )
                    throw error;
                  send({
                    type: "error",
                    data: {
                      code:
                        error.status === 404 ? "event_unavailable" : error.code,
                      message:
                        error.status === 404
                          ? "A referenced event is unavailable or no longer accessible. It was not forwarded."
                          : error.message,
                      retryable: false,
                      fatal: false,
                      ...(ref ? { event_id: ref.id } : {}),
                    },
                  });
                }
                if (identifier(notification?.id)) seen.add(notification.id);
              }
              while (seen.size > 2048) seen.delete(seen.values().next().value!);
            }
          } catch (error) {
            fail(error);
          } finally {
            polling = false;
          }
        };
        void (async () => {
          if (
            (planeId !== "production" && !/^[a-f0-9-]{36}$/.test(planeId)) ||
            !identifier(org) ||
            !ids.length ||
            ids.length > 100 ||
            ids.some((id) => !identifier(id))
          )
            throw new GatewayError(
              422,
              "invalid_receiving_context",
              "Select an organization and between one and 100 Silicon identities.",
            );
          const plane = await store.locked(id, async () => {
            const session = await store.read(id),
              plane = session.planes[planeId];
            if (!plane?.tokens || plane.logout)
              throw new GatewayError(
                401,
                "unauthenticated",
                "Continue with IAM before receiving events.",
              );
            await refresh(id, session, plane);
            plane.telemetry = url.searchParams.get("telemetry") !== "off";
            const info = await upstream("/api/v2/auth/iam", "GET", plane, org);
            let status;
            try {
              status = await upstream("/api/v2/auth/status", "GET", plane, org);
            } catch (error) {
              if (!(error instanceof GatewayError) || error.status !== 401)
                throw error;
              plane.expiresAt = 0;
              await refresh(id, session, plane);
              status = await upstream("/api/v2/auth/status", "GET", plane, org);
            }
            if (
              !identifier(info.app_id) ||
              info.testing !== (planeId !== "production") ||
              status.authenticated !== true ||
              status.org_id !== org ||
              status.actor?.id !== plane.tokens!.actor.id ||
              status.actor?.type !== plane.tokens!.actor.type
            )
              throw new GatewayError(
                403,
                "delivery_identity_mismatch",
                "The receiving identity or organization did not match the current session.",
              );
            if (
              status.actor.type === "silicon" &&
              (ids.length !== 1 || ids[0] !== status.actor.id)
            )
              throw new GatewayError(
                403,
                "delivery_permission_denied",
                "A Silicon can receive its own events only.",
              );
            if (planeId !== "production") {
              if (!plane.appSecret || plane.key)
                throw new GatewayError(
                  409,
                  "test_app_selector_required",
                  "Attach this test environment using its application secret before receiving events.",
                );
              const selected = await upstream(
                "/api/v2/testing-session",
                "GET",
                plane,
                org,
              );
              if (selected.id !== planeId || selected.org_id !== org)
                throw new GatewayError(
                  403,
                  "environment_mismatch",
                  "The selected test environment changed.",
                );
              const scope = validateScope(
                await upstream("/api/v2/delivery/receiver", "GET", plane, org),
                {
                  appId: info.app_id,
                  actor: status.actor,
                  org,
                  environmentId: planeId,
                },
              );
              context = {
                appId: scope.app_id,
                org,
                tingOrg: scope.org_id,
                actor: status.actor,
                environmentId: planeId,
                receiverGeneration: scope.environment.generation,
                silicons: ids,
              };
              credential = plane.appSecret;
              await subscribe(plane);
              await drainReceivers(id, session, plane, undefined, true);
              if (stopped)
                throw new GatewayError(
                  499,
                  "observer_closed",
                  "The receiving view was closed.",
                );
              plane.receivers ??= {};
              receiverSlot = allocate(plane.receivers, scope);
              activeReceivers.add(receiverSlot);
              await store.save(id, session);
              receiver = await ensureReceiver(
                plane.receivers[receiverSlot],
                () => store.save(id, session),
                bootstrapReceiver(id, session, plane),
              );
              return structuredClone(plane);
            }
            if (!plane.ting)
              throw new GatewayError(
                409,
                "delivery_login_required",
                "Continue with IAM to connect receiving automatically. A Hook-only token provides management access.",
              );
            if (
              plane.ting.environmentId !== PRODUCTION ||
              plane.ting.id !== status.actor.id ||
              plane.ting.kind !== status.actor.type
            )
              throw new GatewayError(
                403,
                "delivery_identity_mismatch",
                "The delivery session belongs to a different identity or environment.",
              );
            if (
              status.actor.type === "silicon" &&
              (ids.length !== 1 || ids[0] !== status.actor.id)
            )
              throw new GatewayError(
                403,
                "delivery_permission_denied",
                "A Silicon can receive its own events only.",
              );
            await ting.identity(plane.ting);
            const hookOrg = (await hookOrganizations(plane)).find(
              (item) => item.id === org,
            );
            const deliveryOrg = (await ting.organizations(plane.ting)).find(
              (item) => item.id === hookOrg?.iamId && item.handle === org,
            );
            if (!hookOrg || !deliveryOrg)
              throw new GatewayError(
                403,
                "delivery_organization_mismatch",
                "This organization is not shared with the delivery session. Continue with IAM again.",
              );
            context = {
              appId: info.app_id,
              org,
              tingOrg: deliveryOrg.id,
              actor: status.actor,
              environmentId: PRODUCTION,
              silicons: ids,
            };
            credential = plane.ting.token;
            await subscribe(plane);
            return structuredClone(plane);
          });
          if (stopped) return;
          let reconciling = false;
          const ready = () => {
            if (stopped || paused) return;
            live = true;
            everReady = true;
            send({
              type: "ready",
              data: { org_id: org, silicon_ids: ids, transport: "ting_inbox" },
            });
            void scan();
            if (!renewal)
              renewal = setInterval(() => {
                if (stopped || paused || reconciling) return;
                reconciling = true;
                void current(async (plane) => {
                  const status = await upstream(
                    "/api/v2/auth/status",
                    "GET",
                    plane,
                    org,
                  );
                  if (
                    status.authenticated !== true ||
                    status.actor?.id !== context.actor.id ||
                    status.actor?.type !== context.actor.type ||
                    status.org_id !== org
                  )
                    throw new GatewayError(
                      401,
                      "session_changed",
                      "The receiving session changed. Continue with IAM again.",
                    );
                })
                  .then(() => scan())
                  .catch(fail)
                  .finally(() => {
                    reconciling = false;
                  });
              }, 10000);
          };
          const renewScoped = async () => {
            live = false;
            stopWatch?.();
            await streamLocked(async () => {
              if (stopped || paused) return;
              const session = await store.read(id),
                plane = session.planes[planeId];
              if (stopped || paused) return;
              const slot = receiverSlot && plane?.receivers?.[receiverSlot];
              if (
                !slot ||
                plane.logout ||
                slot.closing ||
                plane.appSecret !== credential ||
                plane.tokens?.actor.id !== context.actor.id ||
                plane.tokens?.actor.type !== context.actor.type
              )
                throw new GatewayError(
                  401,
                  "session_changed",
                  "The receiving session changed.",
                );
              await refresh(id, session, plane);
              const scope = validateScope(
                await upstream("/api/v2/delivery/receiver", "GET", plane, org),
                context,
              );
              if (!sameScope(scope, slot.scope))
                throw new GatewayError(
                  409,
                  "receiver_environment_changed",
                  "The test environment changed. Reconnect to receive its current generation.",
                );
              receiver = await ensureReceiver(
                slot,
                () => store.save(id, session),
                bootstrapReceiver(id, session, plane),
                true,
              );
              if (!stopped && !paused) connectScoped(receiver);
            });
          };
          const connectScoped = (capability: ReceiverCapability) => {
            if (stopped || paused) return;
            stopWatch?.();
            clearTimeout(renewTimer);
            live = false;
            stopWatch = watchReceiver(cfg.tingUpstream, capability, {
              ready,
              changed: () => {
                void scan();
              },
              failed: fail,
            });
            renewTimer = setTimeout(
              () => {
                void renewScoped().catch(fail);
              },
              Math.max(
                0,
                Date.parse(capability.expires_at) - Date.now() - 10000,
              ),
            );
          };
          resumeReceiver = renewScoped;
          if (receiver) connectScoped(receiver);
          else
            stopWatch = watchInbox(cfg.tingUpstream, plane.ting!, context, {
              ready,
              changed: () => {
                void scan();
              },
              failed: fail,
            });
        })().catch(fail);
      });
    });
  }
  return { handle, attachWs };
}
function mutation(req: IncomingMessage) {
  const key = req.headers["idempotency-key"];
  if (typeof key !== "string" || !/^[!-~]{8,255}$/.test(key))
    throw new GatewayError(
      422,
      "idempotency_required",
      "A stable mutation identifier is required.",
    );
  return key;
}
