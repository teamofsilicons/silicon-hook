/**
 * The public files every app serves, built from lib/app.config.ts and PUBLIC_URL at request time:
 *
 *   robots.txt   the landing page is open to every crawler, answer engines named and welcome; the workspace, the
 *                sign-in routes and the API proxy are kept out
 *   sitemap.xml  the public pages (the landing page and llms.txt)
 *   llms.txt     a stub in the llmstxt.org shape: what the app is, how a Silicon installs it and signs in, where the
 *                docs are. Replace it with the Carbon's own words when they write them (ADOPTING.md).
 */
import { appConfig } from "../app.config";

/** Crawlers that read for answer engines and Silicons. They are welcome to everything public here. */
export const ANSWER_CRAWLERS = [
  "GPTBot", "OAI-SearchBot", "ChatGPT-User",
  "ClaudeBot", "Claude-User", "Claude-SearchBot",
  "PerplexityBot", "Perplexity-User",
  "Google-Extended", "Applebot-Extended", "Meta-ExternalAgent", "Amazonbot", "DuckAssistBot",
  "CCBot", "MistralAI-User",
];

export function robotsTxt(origin: string): string {
  const workspace = [...new Set(appConfig.nav.map(item => item.href))];
  return [
    `# ${origin}: ${appConfig.name}. ${appConfig.tagline}`,
    "# The landing page and llms.txt are meant to be read and quoted by Carbons and Silicons alike.",
    "",
    ...ANSWER_CRAWLERS.map(agent => `User-agent: ${agent}`),
    "User-agent: *",
    "Allow: /",
    "Allow: /llms.txt",
    ...["/api/", "/auth/", "/sign-in", ...workspace].map(path => `Disallow: ${path}`),
    "",
    `Sitemap: ${origin}/sitemap.xml`,
    "",
  ].join("\n");
}

export function sitemapXml(origin: string, modified: string): string {
  const urls = [`${origin}/`, `${origin}/llms.txt`];
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ...urls.map(url => `  <url><loc>${url}</loc><lastmod>${modified}</lastmod></url>`),
    "</urlset>",
    "",
  ].join("\n");
}

export function llmsTxt(origin: string): string {
  const { name, appId, description, tagline, links, cli, landing } = appConfig;
  const features = [...landing.forCarbons, ...landing.forSilicons].map(feature => `- ${feature.title}: ${feature.text}`);
  return [
    `# ${name}`,
    "",
    `> ${tagline}`,
    "",
    description,
    "",
    "## Install and sign in",
    "",
    `- Install: \`silicon-apps install ${appId}\` (Silicon Apps keeps it up to date).`,
    ...(cli
      ? [`- A Silicon signs in with a short-lived token: \`silicon-accounts login --app ${appId} -q | ${cli.command} login --slt-stdin\`.`, `- A Carbon signs in on the command line with \`${cli.command} login\`, or in the browser at ${origin}/sign-in.`]
      : [`- Carbons sign in in the browser at ${origin}/sign-in.`]),
    "",
    "## What it does",
    "",
    ...features,
    "",
    "## Links",
    "",
    `- [Docs](${links.docs})`,
    `- [${name} in the Silicon Apps store](${links.store})`,
    `- [Home page](${origin}/)`,
    "",
  ].join("\n");
}
