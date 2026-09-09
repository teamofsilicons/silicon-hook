import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve, extname } from "node:path";
import { config, gateway } from "./gateway";
const cfg = config(process.env);
const app = gateway(cfg);
const root = resolve("dist/client");
const mime: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
  ".json": "application/json",
};
const server = createServer(async (req, res) => {
  if (req.headers.host !== new URL(cfg.origin).host) {
    res.writeHead(403);
    res.end();
    return;
  }
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  );
  if (cfg.origin.startsWith("https:"))
    res.setHeader("Strict-Transport-Security", "max-age=31536000");
  if (
    req.url?.startsWith("/console/") ||
    req.url?.startsWith("/auth/callback")
  ) {
    await app.handle(req, res);
    return;
  }
  if (!["GET", "HEAD"].includes(req.method || "")) {
    res.writeHead(405);
    res.end();
    return;
  }
  try {
    const path = decodeURIComponent(
      new URL(req.url || "/", cfg.origin).pathname,
    );
    const relative = extname(path) ? path : "/index.html";
    const file = resolve(root, "." + relative);
    if (!file.startsWith(root + "/")) {
      res.writeHead(404);
      res.end();
      return;
    }
    const bytes = await readFile(file);
    res.writeHead(200, {
      "Content-Type": mime[extname(file)] || "application/octet-stream",
      "Cache-Control":
        extname(file) === ".html" ? "no-store" : "public, max-age=3600",
    });
    res.end(req.method === "HEAD" ? undefined : bytes);
  } catch {
    res.writeHead(404);
    res.end("Not found");
  }
});
app.attachWs(server);
server.listen(
  Number(process.env.PORT || 4317),
  process.env.HOST || "127.0.0.1",
  () => console.log(`Silicon Hook frontend: ${cfg.origin}`),
);
