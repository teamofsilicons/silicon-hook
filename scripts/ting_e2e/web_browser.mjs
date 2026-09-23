// Real browser integration driver; receives one private fixture configuration.
// No SLTs, cookies, credentials, or provider payloads are printed.
import fs from "node:fs/promises";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { createHash, createHmac, randomUUID } from "node:crypto";
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
let browser, page;
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
  async function request(path, method = "GET", data) {
    const response = await context.request.fetch(cfg.origin + path, { method, data,
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
  const started = await request("/console/login/start", "POST", {});
  const authorize = new URL(started.authorize_url);
  if (authorize.searchParams.get("app_ids") !== "tos>hook,tos>ting") throw new Error("Browser login did not request the expected IAM batch");
  const callback = new URL(authorize.searchParams.get("redirect_uri"));
  const tokensFile = join(output, "batch.private.json");
  const tokenScript = [
    "import sys", "from pathlib import Path", "sys.path.insert(0,sys.argv[1])", "import fixture",
    "state=fixture.load(Path(sys.argv[2]))",
    "result=fixture.cli(state,'admin',['batch-login','--app-id','tos>hook,tos>ting','--grant-org',state['org_id'],'--approve-scopes'])",
    "fixture.private(Path(sys.argv[3]),result)",
  ].join("\n");
  await run(cfg.python, ["-c", tokenScript, cfg.scripts, cfg.directory, tokensFile], { timeout: 60000 });
  const batch = JSON.parse(await fs.readFile(tokensFile, "utf8"));
  await fs.unlink(tokensFile);
  callback.hash = new URLSearchParams({ slts: JSON.stringify(batch.items) }).toString();
  await page.goto(callback.href);
  await page.waitForURL(url => url.origin === cfg.origin && url.pathname === "/", { timeout: 45000 });
  if (/slts?=/.test(page.url())) throw new Error("Browser callback retained the credential fragment");
  await page.getByRole("heading", { name: "Your webhooks, in one place.", exact: true }).waitFor();
  const session = await request("/console/session");
  const identity = session.planes.find(item => item.id === "production");
  if (!identity?.authenticated || identity.actor?.type !== "carbon") throw new Error("Browser did not finish real Carbon batch login");
  console.log("BROWSER_STAGE actual callback fragment consumed and URL cleared");
  await page.getByLabel("Organization", { exact: true }).selectOption(cfg.org);
  await page.getByLabel("Silicon", { exact: true }).fill(cfg.actor);
  await page.getByLabel("Silicon", { exact: true }).press("Tab");
  await page.screenshot({ path: join(output, "overview-desktop.png"), fullPage: true });
  const provider = await request(`/console/proxy/api/v2/silicons/${encodeURIComponent(cfg.actor)}/hooks`, "POST",
    { name: "real-ting-browser-" + randomUUID().slice(0, 8) });
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Live stream", exact: true }).click();
  await page.getByRole("heading", { name: "Live stream", exact: true }).waitFor();
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await page.getByText("Connected", { exact: true }).waitFor({ timeout: 45000 });
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
  console.log("BROWSER_STAGE actual Live UI received the exact large provider payload");
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
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Confirm", exact: true }).click();
  await page.getByRole("button", { name: "Sign in", exact: true }).first().waitFor();
  const signedOut = await request("/console/session");
  if (signedOut.planes.some(item => item.authenticated)) throw new Error("Browser sign-out left an authenticated session");
  if (pageErrors.length) throw new Error("Browser raised JavaScript exceptions");
  const report = { complete: true, event_id: eventId, ting_id: frame.data.ting_id,
    payload_bytes: body.length, payload_sha256: createHash("sha256").update(body).digest("hex"),
    viewport_desktop: "1440x1000", viewport_mobile: "390x844", mobile_document_width: geometry.scrollWidth,
    mobile_table_scroll: tableScroll, screenshots: ["overview-desktop.png", "live-desktop.png",
      "payload-desktop.png", "deliveries-desktop.png", "deliveries-mobile.png", "live-mobile.png"].map(name => join(output, name)),
    checks: ["real callback JavaScript consumes IAM batch fragment and clears credentials from the URL",
      "authenticated overview and organization/Silicon controls", "actual Live connect uses BFF Ting receiving",
      "large signed provider payload matches browser WebSocket and payload inspector exactly",
      "Deliveries displays primary Silicon publication without acknowledgment controls",
      "desktop and mobile pages render without horizontal page overflow; mobile table scroll remains available", "UI sign-out clears the browser session",
      "no browser JavaScript exceptions"],
    limitations: ["official IAM CLI performs real batch consent/issuance; IAM consent webpage is not exercised",
      "fixture uses production protocol on isolated loopback services; sandbox bootstrap is not covered"] };
  await privateJson(join(cfg.directory, "web-browser-verification.json"), report);
  console.log(JSON.stringify(report, null, 2));
} catch (error) {
  await privateJson(join(output, "failure.private.json"), { name: error.name, message: error.message });
  await page?.screenshot({ path: join(output, "failure.png"), fullPage: true }).catch(() => {});
  console.error("Browser fixture failed; inspect its private diagnostic.");
  process.exitCode = 1;
} finally {
  await browser?.close();
}
