import type { IncomingMessage, ServerResponse, Server } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { resolve } from "node:path";
import { WebSocket, WebSocketServer } from "ws";
import {
  SessionStore,
  type Plane,
  type Session,
  type Tokens,
} from "./session.ts";

export interface Config {
  origin: string;
  frontendOrigin: string;
  upstream: string;
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
    sessionDir: vars.HOOK_SESSION_DIR || resolve(".sessions"),
    sessionKey: vars.HOOK_SESSION_KEY
      ? Buffer.from(vars.HOOK_SESSION_KEY, "base64")
      : randomBytes(32),
  };
}
export class GatewayError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: string,
    public requestId?: string,
    public retryAfter?: string,
  ) {
    super(message);
  }
}
export function allowed(path: string, method: string): boolean {
  const p = path.split("?")[0];
  if (
    method === "GET" &&
    ["/healthz", "/readyz", "/api/version", "/api/v1/version"].includes(p)
  )
    return true;
  if (/^\/api\/v1\/testing-environments$/.test(p))
    return ["GET", "POST"].includes(method);
  if (/^\/api\/v1\/testing-environments\/[a-f0-9-]{36}$/.test(p))
    return ["GET", "DELETE"].includes(method);
  if (/^\/api\/v1\/testing-environments\/[a-f0-9-]{36}\/key$/.test(p))
    return method === "GET";
  if (
    /^\/api\/v1\/testing-environments\/[a-f0-9-]{36}\/(key\/rotate|restore)$/.test(
      p,
    )
  )
    return method === "POST";
  if (p === "/api/v1/testing-environment") return method === "GET";
  if (p === "/api/v1/testing-environment/clean") return method === "POST";
  if (p === "/api/v1/testing-environment/iam") return method === "PUT";
  const base = "^/api/v1/silicons/[^/]+/";
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
  if (new RegExp(base + "deliveries(/cursor)?$").test(p))
    return method === "GET";
  return new RegExp(base + "deliveries/ack$").test(p) && method === "POST";
}
async function bounded(response: Response) {
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
  function guard(req: IncomingMessage, websocket = false) {
    if (req.headers.host !== new URL(cfg.origin).host)
      throw new GatewayError(
        403,
        "invalid_host",
        "This hostname is not configured.",
      );
    if (
      (websocket || req.headers.origin) &&
      req.headers.origin !== cfg.frontendOrigin
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
    const headers: Record<string, string> = {
      "silicon-hook-api-version": "v1",
      accept: "application/json",
    };
    if (plane.tokens)
      headers.authorization = "Bearer " + plane.tokens.access_token;
    if (plane.key) headers["x-hook-test-key"] = plane.key;
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
  async function refresh(id: string, session: Session, plane: Plane) {
    if (
      !plane.tokens ||
      (!plane.refresh && (plane.expiresAt || 0) > Date.now() + 60000)
    )
      return;
    plane.refresh ??= { key: crypto.randomUUID(), started: Date.now() };
    await store.save(id, session);
    const tokens = (await upstream(
      "/api/v1/auth/refresh",
      "POST",
      plane,
      "",
      { refresh_token: plane.tokens.refresh_token },
      plane.refresh.key,
    )) as Tokens;
    plane.tokens = tokens;
    plane.expiresAt = plane.refresh.started + tokens.expires_in * 1000;
    delete plane.refresh;
    await store.save(id, session);
  }
  function publicSession(session: Session) {
    return {
      planes: Object.entries(session.planes).map(([id, p]) => ({
        id,
        name: p.name,
        attached: !!p.key,
        authenticated: !!p.tokens,
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
          "Content-Type, X-Hook-Frontend, X-Org-Id, Idempotency-Key",
        );
        res.writeHead(204);
        res.end();
        return;
      }
      if (req.url?.startsWith("/auth/callback")) {
        if (
          req.method !== "GET" ||
          req.headers.host !== new URL(cfg.origin).host
        )
          throw new GatewayError(
            403,
            "invalid_callback",
            "Invalid sign-in callback.",
          );
        const id = idOf(req),
          url = new URL(req.url, cfg.origin),
          state = url.searchParams.get("state"),
          slt = url.searchParams.get("slt");
        try {
          if (!id || !state || !slt || slt.length > 8192)
            throw new Error("Missing callback state");
          await store.locked(id, async () => {
            const session = await store.read(id);
            const pending = session.login;
            if (
              !pending ||
              pending.expires < Date.now() ||
              state.length !== pending.state.length ||
              !timingSafeEqual(Buffer.from(state), Buffer.from(pending.state))
            )
              throw new Error("Expired callback state");
            const tokens = (await upstream(
              "/api/v1/auth/login",
              "POST",
              { name: "Production" },
              "",
              { slt },
              pending.mutation,
            )) as Tokens;
            closePlane(id, "production");
            session.planes.production = {
              name: "Production",
              tokens,
              expiresAt: Date.now() + tokens.expires_in * 1000,
            };
            delete session.login;
            await store.save(id, session);
          });
          res.writeHead(303, {
            Location: cfg.frontendOrigin + "/#overview?iam_signed_in=1",
          });
          res.end();
          return;
        } catch {
          res.writeHead(303, {
            Location: cfg.frontendOrigin + "/#overview?auth_error=1",
          });
          res.end();
          return;
        }
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
        if (url.pathname === "/console/session" && req.method === "GET") {
          await store.save(id, session);
          return publicSession(session);
        }
        if (url.pathname === "/console/attach" && req.method === "POST") {
          if (
            typeof body?.key !== "string" ||
            !/^[a-zA-Z0-9]{32}$/.test(body.key)
          )
            throw new GatewayError(
              422,
              "invalid_key",
              "Enter the 32-character Hook test key.",
            );
          const env = await upstream(
            "/api/v1/testing-environment",
            "GET",
            { name: "Test", key: body.key },
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
          session.planes[env.id] = {
            ...session.planes[env.id],
            name: env.name,
            key: body.key,
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
        if (url.pathname === "/console/organizations" && req.method === "GET") {
          if (planeId !== "production") {
            const env = await upstream(
              "/api/v1/testing-environment",
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
          const items: { id: string; name: string }[] = [];
          let cursor: string | undefined;
          const seen = new Set<string>();
          do {
            const url = new URL(
              "/api/v1/organizations",
              "https://backend.iam.teamofsilicons.com",
            );
            url.searchParams.set("limit", "100");
            if (cursor) url.searchParams.set("cursor", cursor);
            let response: Response;
            try {
              response = await fetch(url, {
                headers: {
                  authorization: "Bearer " + plane.tokens!.access_token,
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
                "IAM could not load your shared organizations. Retry or continue with IAM again.",
              );
            const page = JSON.parse((await bounded(response)).toString());
            if (!Array.isArray(page.items))
              throw new GatewayError(
                502,
                "invalid_iam_response",
                "IAM returned an unreadable organization list.",
              );
            for (const org of page.items) {
              if (
                typeof org.org_id !== "string" ||
                typeof org.name !== "string"
              )
                throw new GatewayError(
                  502,
                  "invalid_iam_response",
                  "IAM returned an unreadable organization list.",
                );
              if (!items.some((item) => item.id === org.org_id))
                items.push({ id: org.org_id, name: org.name });
            }
            cursor = page.page?.has_more ? page.page.next_cursor : undefined;
            if (
              page.page?.has_more &&
              (typeof cursor !== "string" ||
                !cursor ||
                seen.has(cursor) ||
                seen.size >= 100)
            )
              throw new GatewayError(
                502,
                "invalid_iam_response",
                "IAM could not complete the organization list.",
              );
            if (cursor) seen.add(cursor);
          } while (cursor);
          return { items };
        }
        if (url.pathname === "/console/login/start" && req.method === "POST") {
          if (planeId !== "production")
            throw new GatewayError(
              422,
              "test_token_required",
              "Use an IAM test token to sign in to this environment.",
            );
          const state = randomBytes(32).toString("hex");
          session.login = {
            state,
            expires: Date.now() + 300000,
            mutation: mutation(req),
          };
          await store.save(id, session);
          const callback = new URL("/auth/callback", cfg.origin);
          callback.searchParams.set("state", state);
          const authorize = new URL(
            "/login",
            "https://auth.iam.teamofsilicons.com",
          );
          authorize.searchParams.set("app_id", "tos>hook");
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
          const tokens = (await upstream(
            "/api/v1/auth/login",
            "POST",
            { name: plane.name, key: plane.key },
            "",
            { slt: body.slt.trim() },
            mutation(req),
          )) as Tokens;
          closePlane(id, planeId);
          plane.tokens = tokens;
          plane.expiresAt = Date.now() + tokens.expires_in * 1000;
          delete plane.refresh;
          if (planeId === "production") delete session.login;
          await store.save(id, session);
          return publicSession(session);
        }
        if (url.pathname === "/console/logout" && req.method === "POST") {
          if (plane.tokens)
            await upstream(
              "/api/v1/auth/logout",
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
              mutation(req),
            );
          closePlane(id, planeId);
          delete plane.tokens;
          delete plane.refresh;
          delete plane.expiresAt;
          if (planeId === "production") delete session.login;
          await store.save(id, session);
          return publicSession(session);
        }
        if (url.pathname === "/console/forget" && req.method === "POST") {
          closePlane(id, planeId);
          if (planeId === "production") {
            session.planes.production = { name: "Production" };
            delete session.login;
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
          path.startsWith("/api/v1/testing-environments") &&
          planeId !== "production"
        )
          throw new GatewayError(
            422,
            "production_identity_required",
            "Manage environments from your production identity.",
          );
        const root =
          path.startsWith("/api/v1/testing-environment") &&
          !path.startsWith("/api/v1/testing-environments");
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
          !path.endsWith("/version")
        )
          await refresh(id, session, plane);
        const data = await upstream(
          full,
          req.method || "GET",
          plane,
          String(req.headers["x-org-id"] || ""),
          ["GET", "DELETE"].includes(req.method || "GET") ? undefined : body,
          req.method === "GET" ? undefined : mutation(req),
        );
        if (
          path.startsWith("/api/v1/testing-environments") &&
          data?.key &&
          data?.id
        ) {
          closePlane(id, data.id);
          session.planes[data.id] = {
            ...session.planes[data.id],
            name: data.name,
            key: data.key,
          };
          await store.save(id, session);
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
      if (!req.url?.startsWith("/console/stream")) return;
      void (async () => {
        guard(req, true);
        const id = idOf(req);
        if (!id) throw new Error("Sign in first");
        const url = new URL(req.url!, cfg.origin);
        const planeId = url.searchParams.get("plane") || "production";
        const plane = await store.locked(id, async () => {
          const s = await store.read(id),
            p = s.planes[planeId];
          if (!p?.tokens) throw new Error("Sign in first");
          await refresh(id, s, p);
          return structuredClone(p);
        });
        const ids = url.searchParams.getAll("silicon_id");
        if (
          !ids.length ||
          ids.length > 256 ||
          ids.some((x) => !x || x.length > 255)
        )
          throw new Error("Choose Silicons");
        const target = new URL("/api/v1/ws", cfg.upstream);
        target.protocol = target.protocol === "https:" ? "wss:" : "ws:";
        for (const sid of ids) target.searchParams.append("silicon_id", sid);
        const headers: Record<string, string> = {
          authorization: "Bearer " + plane.tokens!.access_token,
          "silicon-hook-api-version": "v1",
        };
        if (plane.key) headers["x-hook-test-key"] = plane.key;
        const org = url.searchParams.get("org");
        if (org) headers["x-org-id"] = org;
        wss.handleUpgrade(req, socket, head, (client) => {
          const upstream = new WebSocket(target, {
            headers,
            maxPayload: 4 * 1024 * 1024,
            handshakeTimeout: 30000,
            followRedirects: false,
          });
          const item = { plane: planeId, socket: client };
          let set = sockets.get(id);
          if (!set) {
            set = new Set();
            sockets.set(id, set);
          }
          set.add(item);
          const expiry = setTimeout(
            () => client.close(1012, "Renewing session"),
            Math.max(
              1000,
              (plane.expiresAt || Date.now() + 600000) - Date.now() - 60000,
            ),
          );
          client.on("message", (data) => {
            try {
              const frame = JSON.parse(data.toString());
              if (!["pong", "ack", "resume"].includes(frame.type)) return;
              if (upstream.readyState === WebSocket.OPEN)
                upstream.send(data.toString());
            } catch {
              client.close(1007, "Invalid frame");
            }
          });
          upstream.on("message", (data) => {
            if (client.readyState !== WebSocket.OPEN) return;
            if (client.bufferedAmount > 8 * 1024 * 1024) {
              client.close(1013, "Slow browser");
              return;
            }
            client.send(data.toString());
          });
          upstream.on("unexpected-response", (_req, res) =>
            client.close(
              res.statusCode === 401 || res.statusCode === 403 ? 4003 : 1013,
              "Hook rejected the connection",
            ),
          );
          upstream.on("error", () =>
            client.close(1013, "Hook stream unavailable"),
          );
          upstream.on("close", (code, reason) => {
            if (client.readyState === WebSocket.OPEN)
              client.close(
                code === 1006 ? 1013 : code,
                reason.toString().slice(0, 100),
              );
          });
          client.on("close", () => {
            clearTimeout(expiry);
            set!.delete(item);
            if (!set!.size) sockets.delete(id);
            upstream.terminate();
          });
          client.on("error", () => upstream.terminate());
        });
      })().catch(() => {
        socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
        socket.destroy();
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
