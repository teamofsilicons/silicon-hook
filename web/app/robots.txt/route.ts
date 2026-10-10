/** GET /robots.txt (lib/agent/files.ts). */
import { robotsTxt } from "@/lib/agent/files";
import { publicResponse } from "@/lib/server/public-response";
import { publicOrigin } from "@/lib/server/site";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return publicResponse(request, robotsTxt(publicOrigin()), { type: "text/plain; charset=utf-8", maxAge: 86400 });
}
