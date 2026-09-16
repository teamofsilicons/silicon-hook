import { readFile, writeFile, mkdir, readdir, cp, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { marked } from "marked";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = path.join(root, "docs"),
  output = path.join(root, "docs-site/dist");
const origin = "https://docs.hook.teamofsilicons.com";
const escape = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
const route = (file) => "/" + file.replace(/README\.md$/, "").replace(/\.md$/, "/");
const slug = (text) =>
  text
    .replace(/<[^>]+>/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-");
async function inventory(dir, prefix = "") {
  const entries = await readdir(dir, { withFileTypes: true });
  const result = [];
  for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const relative = path.posix.join(prefix, e.name);
    if (e.isDirectory()) result.push(...(await inventory(path.join(dir, e.name), relative)));
    else result.push(relative);
  }
  return result;
}
const files = await inventory(source),
  documents = files.filter((f) => f.endsWith(".md"));
const titles = new Map(
  await Promise.all(
    documents.map(async (file) => [
      file,
      (await readFile(path.join(source, file), "utf8")).match(/^# (.+)$/m)?.[1] || file,
    ]),
  ),
);
const navigation = ["README.md", "cli/README.md", "testing/README.md", "testing/cli.md", "client/README.md", "client/relay.md", "testing/client.md", "api/README.md", "testing/api.md", "iam/README.md", "contracts.md", "configuration.md", "releases.md", "testing/honeycomb.md", "telemetry.md", "deployment.md", "verification/current.md"];
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
const search = [];
for (const file of documents) {
  const markdown = await readFile(path.join(source, file), "utf8");
  const headings = [];
  const slugs = new Map();
  const renderer = new marked.Renderer();
  renderer.heading = ({ tokens, depth }) => {
    const text = renderer.parser.parseInline(tokens),
      base = slug(text),
      n = slugs.get(base) || 0,
      id = base + (n ? "-" + n : "");
    slugs.set(base, n + 1);
    if (depth === 2) headings.push({ text: text.replace(/<[^>]+>/g, ""), id });
    return `<h${depth} id="${id}">${text}<a class="anchor" href="#${id}" aria-label="Link to ${escape(text.replace(/<[^>]+>/g, ""))}">#</a></h${depth}>`;
  };
  renderer.link = ({ href, title, tokens }) => {
    let destination = href;
    if (!/^(?:[a-z]+:|\/|#)/i.test(href)) {
      const [relative, fragment] = href.split("#");
      const absolute = path.resolve(source, path.dirname(file), relative);
      const inDocs = path.relative(source, absolute).replaceAll(path.sep, "/");
      if (documents.includes(inDocs))
        destination = route(inDocs) + (fragment ? "#" + fragment : "");
      else if (absolute === path.join(root, "openapi.yaml")) destination = "/openapi.yaml";
      else if (files.includes(inDocs)) destination = "/source/" + inDocs;
      else
        destination =
          "https://github.com/teamofsilicons/silicon-hook/blob/main/" +
          path.relative(root, absolute).split(path.sep).map(encodeURIComponent).join("/") +
          (fragment ? "#" + fragment : "");
    }
    return `<a href="${escape(destination)}"${title ? ` title="${escape(title)}"` : ""}>${renderer.parser.parseInline(tokens)}</a>`;
  };
  const body = marked.parse(markdown, { renderer, gfm: true });
  const title = titles.get(file);
  const url = origin + route(file);
  const nav = navigation
    .map(
      (f) =>
        `<a href="${route(f)}"${f === file ? ' aria-current="page"' : ""}>${escape(titles.get(f))}</a>`,
    )
    .join("");
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)} · Hook Docs</title><meta name="description" content="Silicon Hook 0.6 documentation: ${escape(title)}"><link rel="canonical" href="${url}"><meta property="og:title" content="${escape(title)} · Hook Docs"><meta property="og:url" content="${url}"><link rel="icon" href="/favicon.svg"><link rel="stylesheet" href="/styles.css"><script src="/search.js" defer></script></head><body><a class="skip" href="#main">Skip to content</a><header><a class="brand" href="/"><span>▣</span> Hook <small>Docs</small></a><label class="search-label" for="search">Search docs<input id="search" type="search" placeholder="Search the documentation" autocomplete="off" aria-controls="search-results"></label><a class="app-link" href="https://hook.teamofsilicons.com">Open Hook ↗</a></header><div id="search-results" hidden role="region" aria-label="Search results"></div><div class="layout"><aside><span class="version">VERSION · 0.6.0</span><nav aria-label="Documentation">${nav}</nav><a class="source" href="https://github.com/teamofsilicons/silicon-hook">Source on GitHub ↗</a></aside><main id="main"><div class="eyebrow">SILICON HOOK / DOCUMENTATION</div><article>${body}</article><footer>Silicon Hook · Client 0.6.0 · API v1 · <a href="/contracts/">Version policy</a></footer></main><nav class="toc" aria-label="On this page"><strong>On this page</strong>${headings.map((h) => `<a href="#${h.id}">${escape(h.text)}</a>`).join("")}</nav></div></body></html>`;
  const directory = path.join(output, route(file));
  await mkdir(directory, { recursive: true });
  await writeFile(path.join(directory, "index.html"), html);
  search.push({
    title,
    url: route(file),
    text: markdown
      .replace(/```[\s\S]*?```/g, "")
      .replace(/[#*`\[\]]/g, "")
      .slice(0, 30000),
  });
}
for (const file of files.filter((f) => !f.endsWith(".md"))) {
  const dest = path.join(output, "source", file);
  await mkdir(path.dirname(dest), { recursive: true });
  await cp(path.join(source, file), dest);
}
for (const file of ["styles.css", "search.js"])
  await cp(path.join(root, "docs-site", file), path.join(output, file));
await cp(path.join(source, "install.sh"), path.join(output, "install.sh"));
await cp(path.join(root, "openapi.yaml"), path.join(output, "openapi.yaml"));
await cp(path.join(root, "web/public/brand/mark.svg"), path.join(output, "favicon.svg"));
await writeFile(path.join(output, "search-index.json"), JSON.stringify(search));
await writeFile(
  path.join(output, "robots.txt"),
  `User-agent: *\nAllow: /\nSitemap: ${origin}/sitemap.xml\n`,
);
await writeFile(
  path.join(output, "sitemap.xml"),
  `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${search.map((p) => `<url><loc>${origin + p.url}</loc></url>`).join("")}</urlset>`,
);
await writeFile(
  path.join(output, "404.html"),
  '<!doctype html><html lang="en"><meta charset="utf-8"><title>Page not found · Hook Docs</title><link rel="stylesheet" href="/styles.css"><main><h1>Page not found</h1><a href="/">Return to Hook documentation</a></main></html>',
);
console.log(`Built ${documents.length} documentation pages for ${origin}`);


