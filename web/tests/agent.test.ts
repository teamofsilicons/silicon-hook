/** The public files built from lib/app.config.ts: robots.txt, the sitemap and the llms.txt stub. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { llmsTxt, robotsTxt, sitemapXml } from "../lib/agent/files";
import { appConfig } from "../lib/app.config";
import { markSvg } from "../lib/brand-svg";

const ORIGIN = "https://webkit.example";

test("robots.txt opens the public pages and keeps the workspace, sign-in and the proxy out", () => {
  const text = robotsTxt(ORIGIN);
  assert.match(text, /^# https:\/\/webkit\.example: Hook\./);
  for (const line of ["User-agent: ClaudeBot", "User-agent: *", "Allow: /", "Allow: /llms.txt", "Disallow: /api/", "Disallow: /auth/", "Disallow: /sign-in", "Disallow: /hooks", "Disallow: /settings", `Sitemap: ${ORIGIN}/sitemap.xml`]) {
    assert.ok(text.split("\n").includes(line), line);
  }
});

test("the sitemap lists the public pages with their date", () => {
  const xml = sitemapXml(ORIGIN, "2026-10-10");
  assert.match(xml, /^<\?xml version="1\.0" encoding="UTF-8"\?>/);
  assert.ok(xml.includes(`<url><loc>${ORIGIN}/</loc><lastmod>2026-10-10</lastmod></url>`));
  assert.ok(xml.includes(`<loc>${ORIGIN}/llms.txt</loc>`));
});

test("llms.txt says what the app is, how a Silicon installs it and signs in, and where the docs are", () => {
  const text = llmsTxt(ORIGIN);
  assert.ok(text.startsWith(`# ${appConfig.name}\n\n> ${appConfig.tagline}\n`));
  assert.ok(text.includes("`silicon-apps install hook`"));
  assert.ok(text.includes("`silicon-accounts login --app hook -q | hook login --slt-stdin`"));
  assert.ok(text.includes(`- [Docs](${appConfig.links.docs})`));
  for (const word of ["AI agent", "human", "user account", "organization", " org ", "Honeycomb", "IAM"]) assert.ok(!text.includes(word), `never "${word}"`);
});

test("the mark is the configured glyph, white on a squircle of the app's colour", () => {
  const svg = markSvg();
  assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 64 64"><path fill="#1F5FB8" d="M32 0c19\.6/);
  assert.ok(svg.includes('stroke="#FFFFFF"'));
  assert.ok(svg.includes(`<path d="${appConfig.mark.paths[0]}"/>`));
  assert.match(markSvg({ shape: "square" }), /<rect width="64" height="64" fill="#1F5FB8"\/>/);
});
