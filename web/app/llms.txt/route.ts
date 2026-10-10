/**
 * GET /llms.txt (llmstxt.org): the app for language models and Silicons. A stub built from lib/app.config.ts
 * (lib/agent/files.ts); replace it with the Carbon's own text once written (ADOPTING.md, "Public pages").
 */
import { llmsTxt } from "@/lib/agent/files";
import { preflight, publicResponse } from "@/lib/server/public-response";
import { publicOrigin } from "@/lib/server/site";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return publicResponse(request, llmsTxt(publicOrigin()), { type: "text/plain; charset=utf-8", maxAge: 3600 });
}

export const HEAD = GET;
export const OPTIONS = () => preflight();
