/** GET /sitemap.xml: the public pages (lib/agent/files.ts). */
import { sitemapXml } from "@/lib/agent/files";
import { publicResponse } from "@/lib/server/public-response";
import { publicOrigin } from "@/lib/server/site";

export const dynamic = "force-dynamic";

/** When the public pages last changed: the deployment's start (they come from lib/app.config.ts). */
const STARTED = new Date().toISOString().slice(0, 10);

export function GET(request: Request) {
  return publicResponse(request, sitemapXml(publicOrigin(), STARTED), { type: "application/xml; charset=utf-8", maxAge: 3600 });
}
