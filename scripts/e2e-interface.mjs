// Run a standalone browser against Hook. Supply a dedicated fixture token through
// stdin as JSON {access_token, silicon_uuid, refused_tokens?: string[]}.
// Uses the locked Playwright dependency in web/. Only the newly created hook
// is mutated and it is soft-deleted on exit. No credentials or payloads are logged.
import assert from "node:assert/strict";
import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { once } from "node:events";

const requireWeb = createRequire(new URL("../web/package.json", import.meta.url));
const { chromium } = requireWeb("@playwright/test");
const api = new URL(process.env.HOOK_INTERFACE_API ?? "https://api.hook.teamofsilicons.com").origin;
let input = "";
for await (const part of process.stdin) input += part;
const { access_token: token, silicon_uuid: silicon, refused_tokens: refused = [], expect_ting_acceptance: expectTing } = JSON.parse(input);
assert.ok(token && silicon, "A fixture bearer and its Silicon UUID are required");
const server = createServer((_request, response) => {
  response.setHeader("Content-Type", "text/html");
  response.end("<!doctype html><title>Standalone Hook interface test</title>");
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
let browser;
const passed = [];

try {
  browser = await chromium.launch({ executablePath: process.env.CHROMIUM_EXECUTABLE_PATH });
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  async function browserRequest(path, { method = "GET", bearer = token, body, key, handshake } = {}) {
    const headers = {};
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    if (path.startsWith("/api/v3/")) headers["Silicon-Hook-API-Version"] = "v3";
    if (handshake) headers["Silicon-Hook-Supported-API-Versions"] = "v3";
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (key) headers["Idempotency-Key"] = key;
    return page.evaluate(async ({ url, method, headers, body }) => {
      const r = await fetch(url, { method, headers, body, credentials: "omit", redirect: "error" });
      const type = r.headers.get("content-type") || "";
      return {
        status: r.status, requestId: r.headers.get("x-request-id"),
        version: r.headers.get("silicon-hook-api-version"),
        data: r.status === 204 ? null : type.includes("json") ? await r.json() : await r.text(),
      };
    }, { url: api + path, method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  }
  async function request(path, status, options) {
    const reply = await browserRequest(path, options);
    assert.equal(reply.status, status, `${options?.method ?? "GET"} ${path} returned ${reply.status} (${reply.data?.error?.code ?? "no code"}, request ${reply.requestId})`);
    assert.ok(reply.requestId, "Browser can read X-Request-Id");
    return reply.data;
  }
  const publicGet = { bearer: null };
  const handshake = await browserRequest("/api/version", { ...publicGet, handshake: true });
  assert.equal(handshake.version, "v3");
  assert.equal(handshake.data.selected_api_version, "v3");
  const metadata = await request("/api/v3/auth/accounts", 200, publicGet);
  const specUrl = new URL(metadata.openapi_url, api);
  assert.equal(specUrl.origin, api);
  assert.match(await request(specUrl.pathname, 200, publicGet), /operationId: createHook/);
  for (const path of ["/api/v3/version", "/api/contracts", "/healthz", "/readyz"]) {
    await request(path, 200, publicGet);
  }
  passed.push("public discovery, negotiation, embedded OpenAPI and diagnostics");
  for (const bearer of [null, ...refused]) await request("/api/v3/auth/status", 401, { bearer });
  const identity = await request("/api/v3/auth/status", 200);
  assert.equal(identity.authenticated, true);
  const scope = "/api/v3/silicons/" + encodeURIComponent(silicon);
  const list = await request("/api/v3/silicons", 200);
  const entry = list.items.find(item => item.silicon.uuid === silicon);
  assert.ok(["self", "custodian", "manage"].includes(entry?.access));
  const access = await request(scope + "/access", 200);
  assert.equal(access.you.access, entry.access);
  if (["self", "custodian"].includes(entry.access)) await request(scope + "/allow-list", 200);
  const delivery = await request("/api/v3/delivery", 200);
  passed.push("bearer refusals, identity, Silicon selection, access and delivery discovery");

  const collection = scope + "/hooks";
  const create = { method: "POST", key: randomUUID(), body: { name: `Interface QA ${randomUUID().slice(0, 8)}` } };
  const made = await request(collection, 201, create);
  const hook = collection + "/" + encodeURIComponent(made.id);
  try {
    assert.equal((await request(collection, 201, create)).id, made.id);
    await request(collection, 409, { ...create, body: { name: "Conflicting request" } });
    assert.ok(made.signing_secret);
    assert.equal(new URL(made.endpoint_url).origin, api);
    const details = await request(hook, 200);
    assert.equal(details.signature.has_secret, true);
    assert.equal(details.signing_secret, undefined);
    await request(hook, 200, { method: "PATCH", body: { description: "Standalone interface check", time_zone: "UTC" } });
    for (const enabled of [false, true]) {
      await request(collection, 200, { method: "PATCH", body: { hook_ids: [made.id], enabled } });
      assert.equal((await request(hook, 200)).status, enabled ? "active" : "disabled");
    }
    const rotate = { method: "POST", key: randomUUID() };
    const rotated = await request(hook + "/secret/rotate", 200, rotate);
    assert.ok(rotated.signing_secret && rotated.signing_secret !== made.signing_secret);
    const endpoint = await request(hook + "/endpoint/rotate", 200, { method: "POST", key: randomUUID() });
    assert.notEqual(endpoint.endpoint_url, made.endpoint_url);
    assert.equal(new URL(endpoint.endpoint_url).origin, api);
    assert.equal((await fetch(made.endpoint_url, { method: "POST", redirect: "error" })).status, 410);
    passed.push("creation and idempotent retry, metadata, activation and both rotations");

    const secret = randomBytes(32).toString("hex");
    await request(hook, 200, { method: "PATCH", body: { signature: { secret } } });
    // Ingress is a separate provider request. The Hook access token stays on management calls.
    for (const n of [1, 2, 3]) {
      const body = JSON.stringify({ interfaceTest: n });
      const eventId = randomUUID(), stamp = String(Math.floor(Date.now() / 1000));
      const headers = { "Content-Type": "application/json", "webhook-id": eventId, "webhook-timestamp": stamp };
      if (n !== 3) headers["webhook-signature"] = createHmac("sha256", secret)
        .update(`${eventId}.${stamp}.${body}`).digest("base64");
      const reply = await fetch(endpoint.endpoint_url, { method: "POST", headers, body, redirect: "error" });
      assert.equal(reply.status, 200);
      assert.equal((await reply.json()).status, "webhook.ok");
    }
    const events = await request(hook + "/events?limit=1", 200);
    assert.equal(events.items.length, 1);
    assert.ok(events.next_cursor);
    const older = await request(hook + "/events?" + new URLSearchParams({ limit: "1", cursor: events.next_cursor }), 200);
    assert.notEqual(events.items[0].id, older.items[0].id);
    const eventPath = scope + "/events/" + events.items[0].id;
    const event = await request(eventPath, 200);
    assert.equal(JSON.parse(event.request.body).interfaceTest, 2);
    assert.equal((await request(scope + "/events?hook_id=" + made.id, 200)).items.length, 2);
    assert.equal((await request(hook + "/blocked-requests", 200)).items.length, 1);
    assert.equal((await request(scope + "/blocked-requests?hook_id=" + made.id, 200)).items.length, 1);
    let publication = await request(eventPath + "/publication", 200);
    if (expectTing) {
      const accepted = () => ["accepted_by_ting", "accepted_silently"].includes(publication.state) && publication.recipient_receipt;
      for (let attempt = 0; !accepted() && attempt < 20; attempt++) {
        await new Promise(resolve => setTimeout(resolve, 1500));
        publication = await request(eventPath + "/publication", 200);
      }
      assert.ok(accepted(), `Ting publication: ${publication.state} (${publication.last_error_code ?? publication.recipient_status_error ?? "no receipt"})`);
      passed.push("Ting accepted the event and returned its recipient receipt");
    }
    assert.equal(publication.event_id, event.id);
    assert.equal(typeof publication.state, "string");
    passed.push("signed provider requests, withheld request, cursor pagination, event hydration and publication");
    await request(hook, 204, { method: "DELETE" });
    assert.ok((await request(collection + "?include_deleted=true", 200)).items.some(item => item.id === made.id && item.status === "deleted"));
    assert.equal((await request(hook + "/restore", 200, { method: "POST", key: randomUUID() })).id, made.id);
    passed.push("delete, deleted listing and restore");
  } finally {
    await request(hook, 204, { method: "DELETE" });
    assert.ok(!(await request(collection, 200)).items.some(item => item.id === made.id));
  }
  console.log(JSON.stringify({ passed, fixtureSoftDeleted: true, delivery: delivery.transport ?? "disabled" }, null, 2));
} finally {
  await browser?.close();
  server.close();
}
