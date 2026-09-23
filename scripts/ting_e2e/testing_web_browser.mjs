// Real browser integration driver; receives one private fixture configuration.
// No SLTs, cookies, credentials, or provider payloads are printed.
import fs from "node:fs/promises";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { createHash, createHmac, createDecipheriv, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";

const cfg = JSON.parse(await fs.readFile(process.argv[2], "utf8"));
const require = createRequire(import.meta.url);
const { chromium } = require(cfg.playwright);
const run = promisify(execFile);
const output = cfg.output;
await fs.mkdir(output, { recursive: true, mode: 0o700 });
const privateJson = (path, value) => fs.writeFile(path, JSON.stringify(value, null, 2), { mode: 0o600 });
let browser, page, cleanup;
try {
  const executable = chromium.executablePath();
  browser = await chromium.launch({ headless: true,
    executablePath: existsSync(executable) ? executable : "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, locale: "en-US" });
  await context.addInitScript(() => localStorage.setItem("hook.telemetry", "off"));
  page = await context.newPage();
  const pageErrors = [];
  const eventFrames = [];
  page.on("pageerror", error => pageErrors.push(error.name));
  page.on("websocket", socket => socket.on("framereceived", ({ payload }) => {
    try {
      const frame = JSON.parse(String(payload));
      if (frame.type === "new_event") eventFrames.push(frame);
    } catch {}
  }));
  const scoped = path => path + (path.includes("?") ? "&" : "?") + new URLSearchParams({ plane: cfg.plane });
  async function request(path, method = "GET", data) {
    const response = await context.request.fetch(cfg.origin + scoped(path), { method, data,
      headers: { "Origin": cfg.origin, "X-Hook-Frontend": "1", "X-Org-Id": cfg.org,
        "Idempotency-Key": randomUUID(), "Content-Type": "application/json" } });
    if (!response.ok()) {
      await privateJson(join(output, "http-error.private.json"), { path, status: response.status(), body: await response.text() });
      throw new Error("Browser fixture request failed; inspect private diagnostic");
    }
    return response.json();
  }
  await page.goto(cfg.origin);
  await page.getByRole("button", { name: "Sign in", exact: true }).waitFor();
  cleanup = () => request("/console/logout", "POST", {});
  await page.getByRole("link", { name: "Connections & setup", exact: false }).click();
  await page.getByRole("button", { name: "Select test environment", exact: true }).click();
  const fixture = JSON.parse(await fs.readFile(join(cfg.directory, "fixture.private.json"), "utf8"));
  await page.getByLabel(/^IAM test app_secret/).fill(fixture.imports["hook"].app_secret);
  await page.getByRole("button", { name: "Attach environment", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" });
  const tokensFile = join(output, "hook-slt.private.json");
  const tokenScript = ["import sys", "from pathlib import Path", "sys.path.insert(0,sys.argv[1])",
    "import fixture,testing", "state=fixture.load(Path(sys.argv[2]))",
    "value=testing.cli(state,'test-admin',['login','--app-id','hook','--grant-org','tos','--approve-scopes'])",
    "fixture.private(Path(sys.argv[3]),value)"].join("\n");
  await run(cfg.python, ["-c", tokenScript, cfg.scripts, cfg.directory, tokensFile], { timeout: 60000 });
  const slt = JSON.parse(await fs.readFile(tokensFile, "utf8")).slt;
  await fs.unlink(tokensFile);
  await page.getByRole("banner").getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByLabel("Short-lived token", { exact: true }).fill(slt);
  await page.getByRole("dialog").getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden", timeout: 45000 });
  const session = await request("/console/session");
  const identity = session.planes.find(item => item.id === cfg.plane);
  if (!identity?.authenticated || identity.actor?.type !== "carbon") throw new Error("Actual UI Hook-only test login failed");
  if (page.url().includes(slt) || page.url().includes(fixture.imports["hook"].app_secret)) throw new Error("Browser URL exposed credentials");
  console.log("SCOPED_BROWSER_STAGE actual UI attached Hook selector and consumed Hook-only SLT");
  async function capability() {
    const id = (await context.cookies()).find(cookie => /^[a-f0-9]{64}$/.test(cookie.value))?.value;
    if (!id) throw new Error("Owned browser session cookie missing");
    const sealed = await fs.readFile(join(cfg.session_folder, id));
    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(cfg.session_key, "base64"), sealed.subarray(0, 12));
    decipher.setAAD(Buffer.from(id)); decipher.setAuthTag(sealed.subarray(12, 28));
    const plane = JSON.parse(Buffer.concat([decipher.update(sealed.subarray(28)), decipher.final()])).planes[cfg.plane];
    if (plane.ting) throw new Error("Testing browser acquired a general Ting session");
    const slots = Object.values(plane.receivers || {});
    if (slots.length !== 1 || !slots[0].capability) throw new Error("Testing browser capability missing");
    return slots[0].capability;
  }
  await page.getByLabel("Organization", { exact: true }).selectOption(cfg.org);
  await page.getByLabel("Silicon", { exact: true }).fill(cfg.actor);
  await page.getByLabel("Silicon", { exact: true }).press("Tab");
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Overview", exact: true }).click();
  await page.getByRole("heading", { name: "Your webhooks, in one place.", exact: true }).waitFor();
  await page.screenshot({ path: join(output, "overview-desktop.png"), fullPage: true });
  const provider = await request(`/console/proxy/api/v2/silicons/${encodeURIComponent(cfg.actor)}/hooks`, "POST",
    { name: "real-ting-browser-" + randomUUID().slice(0, 8) });
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Live stream", exact: true }).click();
  await page.getByRole("heading", { name: "Live stream", exact: true }).waitFor();
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await page.getByText("Connected", { exact: true }).waitFor({ timeout: 120000 });
  const firstReceiver = await capability();
  await new Promise(resolve => setTimeout(resolve, 35000));
  const renewedReceiver = await capability();
  if (firstReceiver.receiver_id !== renewedReceiver.receiver_id || firstReceiver.receiver_token === renewedReceiver.receiver_token)
    throw new Error("Actual browser did not renew its scoped receiver");
  console.log("SCOPED_BROWSER_STAGE actual Live connection survived 35 seconds and renewed its capability");
  const body = Buffer.from(JSON.stringify({ message: "real Hook to Ting delivery", source: "actual browser",
    run: randomUUID(), padding: "b".repeat(300000) }));
  const identifier = randomUUID(), timestamp = String(Math.floor(Date.now() / 1000));
  const signature = createHmac("sha256", provider.signing_secret).update(`${identifier}.${timestamp}.`).update(body).digest("base64");
  const ingress = await fetch(cfg.hook + new URL(provider.endpoint_url).pathname, {
    method: "POST", body, headers: { "webhook-id": identifier, "webhook-timestamp": timestamp, "webhook-signature": `v1,${signature}` },
  });
  if (!ingress.ok) throw new Error("Browser fixture signed provider ingress failed");
  const { receipt_id: eventId } = await ingress.json();
  const row = page.locator("tbody tr").filter({ hasText: provider.name });
  await row.first().waitFor({ timeout: 45000 });
  const frame = eventFrames.find(item => item.data?.event?.id === eventId);
  if (!frame || frame.data.event.request.body !== body.toString()) throw new Error("Browser live stream did not receive the exact provider payload");
  const currentReceiver = await capability();
  const receiptResponse = await fetch(cfg.ting + "/v1/receivers/inbox/" + frame.data.ting_id,
    { headers: { Authorization: "Bearer " + currentReceiver.receiver_token } });
  if (!receiptResponse.ok) throw new Error("Scoped browser receipt unavailable");
  const receipt = await receiptResponse.json();
  if (!receipt.silent || receipt.read) throw new Error("Browser did not catch up silent unread event");
  console.log("SCOPED_BROWSER_STAGE actual Live UI received exact large silent event without ACK");
  await page.screenshot({ path: join(output, "live-desktop.png"), fullPage: true });
  await row.getByRole("button", { name: provider.name, exact: true }).click();
  await page.getByRole("dialog").waitFor();
  if (await page.getByRole("dialog").locator("pre.payload").textContent() !== body.toString()) throw new Error("Browser payload inspector changed the original body");
  await page.screenshot({ path: join(output, "payload-desktop.png"), fullPage: true });
  await page.getByRole("button", { name: "Close dialog", exact: true }).click();
  await page.getByRole("link", { name: "Deliveries", exact: false }).click();
  await page.getByRole("heading", { name: "Deliveries", exact: true }).waitFor();
  await page.locator("tbody tr").filter({ hasText: provider.name }).getByRole("button", { name: provider.name, exact: true }).click();
  await page.getByRole("region", { name: "Event delivery status" }).getByText("Accepted for delivery", { exact: true }).first().waitFor({ timeout: 30000 });
  const status = await request(`/console/proxy/api/v2/silicons/${encodeURIComponent(cfg.actor)}/events/${eventId}/publication`);
  if (status.state !== "accepted_by_ting" || status.recipient_id !== cfg.actor) throw new Error("Browser delivery view did not inspect the primary Silicon publication");
  if (await page.getByRole("button", { name: /acknowledge|read ack|resume/i }).count()) throw new Error("Browser exposed transport acknowledgment controls");
  await page.screenshot({ path: join(output, "deliveries-desktop.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: join(output, "deliveries-mobile.png"), fullPage: true });
  const geometry = await page.evaluate(() => ({ width: innerWidth, scrollWidth: document.documentElement.scrollWidth,
    offenders: [...document.querySelectorAll("*")].filter(element => {
      const style = getComputedStyle(element), rect = element.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && rect.right > innerWidth + 1;
    }).slice(0, 30).map(element => { const rect = element.getBoundingClientRect(), style = getComputedStyle(element);
      return { tag: element.tagName, class: element.className, left: rect.left, right: rect.right, width: rect.width,
        clientWidth: element.clientWidth, scrollWidth: element.scrollWidth, overflow: style.overflowX, minWidth: style.minWidth,
        offsetParent: element.offsetParent ? { tag: element.offsetParent.tagName, class: element.offsetParent.className } : null }; }) }));
  if (geometry.scrollWidth > geometry.width + 1) {
    geometry.relativeContainerProbe = await page.evaluate(() => {
      const nodes = [...document.querySelectorAll(".table-wrap")], before = nodes.map(node => node.style.position);
      nodes.forEach(node => { node.style.position = "relative"; });
      const width = document.documentElement.scrollWidth;
      nodes.forEach((node, index) => { node.style.position = before[index]; });
      return width;
    });
    await privateJson(join(output, "overflow.json"), geometry);
    throw new Error("Mobile website has horizontal page overflow");
  }
  const tableScroll = await page.locator(".table-wrap").first().evaluate(element => {
    const initial = element.scrollLeft;
    element.scrollLeft = element.scrollWidth;
    const measured = { clientWidth: element.clientWidth, scrollWidth: element.scrollWidth,
      scrollLeft: element.scrollLeft, position: getComputedStyle(element).position };
    element.scrollLeft = initial;
    return measured;
  });
  if (tableScroll.scrollWidth <= tableScroll.clientWidth || tableScroll.scrollLeft <= 0) {
    throw new Error("Mobile event table cannot scroll horizontally within its container");
  }
  await page.getByRole("button", { name: "Toggle navigation", exact: true }).click();
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Live stream", exact: true }).click();
  await page.getByRole("heading", { name: "Live stream", exact: true }).waitFor();
  await page.screenshot({ path: join(output, "live-mobile.png"), fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole("link", { name: "Connections & setup", exact: false }).click();
  const logoutReceiver = currentReceiver;
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Confirm", exact: true }).click();
  await page.getByRole("button", { name: "Sign in", exact: true }).first().waitFor();
  const signedOut = await request("/console/session");
  if (signedOut.planes.some(item => item.authenticated)) throw new Error("Browser sign-out left an authenticated session");
  const revoked = await fetch(cfg.ting + "/v1/receivers/me", { headers: { Authorization: "Bearer " + logoutReceiver.receiver_token } });
  if (revoked.status !== 401) throw new Error("Browser sign-out did not revoke its scoped capability");
  await page.setViewportSize({ width: 390, height: 844 });
  const exitTesting = page.getByRole("button", { name: "Exit testing mode", exact: true });
  if (await exitTesting.count()) await exitTesting.click();
  else await page.getByLabel("Environment", { exact: true }).selectOption("production");
  const productionWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  if (productionWidth > 391) throw new Error("Production header overflows after exiting testing mode");
  await page.screenshot({ path: join(output, "production-header-mobile.png"), fullPage: true });
  if (pageErrors.length) throw new Error("Browser raised JavaScript exceptions");
  const report = { complete: true,
    server_sha256: cfg.server_sha256 || createHash("sha256").update(await fs.readFile(join(cfg.scripts, "../../web/dist/server.js"))).digest("hex"),
    hook_binary_sha256: cfg.hook_binary_sha256 || createHash("sha256").update(await fs.readFile(join(cfg.scripts, "../../target/debug/hook-api"))).digest("hex"), environment_id: cfg.plane, shared_generation: cfg.generation, automatic_renewal_wait_seconds: 35, event_id: eventId, ting_id: frame.data.ting_id,
    payload_bytes: body.length, payload_sha256: createHash("sha256").update(body).digest("hex"),
    viewport_desktop: "1440x1000", viewport_mobile: "390x844", mobile_document_width: geometry.scrollWidth, production_header_mobile_width: productionWidth,
    mobile_table_scroll: tableScroll, screenshots: ["overview-desktop.png", "live-desktop.png",
      "payload-desktop.png", "deliveries-desktop.png", "deliveries-mobile.png", "live-mobile.png", "production-header-mobile.png"].map(name => join(output, name)),
    checks: ["actual UI attaches only Hook selector and signs in with real Hook SLT",
      "automatic scoped receiver renewal survives beyond 30 seconds without another app credential",
      "silent ordinary Carbon event appears through periodic inbox reconciliation without read ACK",
      "authenticated overview and organization/Silicon controls", "actual Live connect uses BFF Ting receiving",
      "large signed provider payload matches browser WebSocket and payload inspector exactly",
      "Deliveries displays primary Silicon publication without acknowledgment controls",
      "desktop and mobile pages render without horizontal page overflow; mobile table scroll remains available", "UI sign-out clears the browser session; the observed scoped capability is revoked by completion",
      "production header fits390px after logout and Exit testing mode", "no browser JavaScript exceptions"],
    limitations: ["official IAM CLI performs real testing consent/SLT issuance; IAM consent webpage is not exercised",
      "local participant lifecycle only; full Honeycomb coordinator and production approvals unverified"] };
  await privateJson(join(cfg.directory, "testing-web-browser-verification.json"), report);
  console.log(JSON.stringify(report, null, 2));
} catch (error) {
  await privateJson(join(output, "failure.private.json"), { name: error.name, message: error.message });
  await page?.screenshot({ path: join(output, "failure.png"), fullPage: true }).catch(() => {});
  console.error("Browser fixture failed; inspect its private diagnostic.");
  process.exitCode = 1;
} finally {
  await cleanup?.().catch(() => {});
  await browser?.close();
}
