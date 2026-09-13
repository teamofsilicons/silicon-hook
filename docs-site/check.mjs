import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "dist");
async function walk(dir) {
  const files = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const f = path.join(dir, e.name);
    if (e.isDirectory()) files.push(...(await walk(f)));
    else files.push(f);
  }
  return files;
}
const pages = (await walk(root)).filter((f) => f.endsWith(".html") && !f.endsWith("/404.html"));
let checks = 0;
for (const page of pages) {
  const html = await readFile(page, "utf8");
  if (!html.includes("https://docs.hook.teamofsilicons.com"))
    throw new Error("Missing canonical host: " + page);
  for (const match of html.matchAll(/(?:href|src)="([^\"]+)"/g)) {
    const href = match[1].replaceAll("&amp;", "&");
    if (!href.startsWith("/") && !href.startsWith("#")) continue;
    const url = new URL(
      href,
      "https://docs.hook.teamofsilicons.com/" +
        path.relative(root, page).replace(/index.html$/, ""),
    );
    let target = path.join(root, decodeURIComponent(url.pathname));
    if ((await stat(target)).isDirectory()) target = path.join(target, "index.html");
    if (url.hash && target.endsWith(".html")) {
      const text = await readFile(target, "utf8");
      if (!text.includes(`id="${decodeURIComponent(url.hash.slice(1))}"`))
        throw new Error(`Broken anchor ${href} in ${page}`);
    }
    checks++;
  }
}
console.log(`Verified ${pages.length} pages and ${checks} local links/assets.`);
