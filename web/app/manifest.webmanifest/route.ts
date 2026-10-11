/** GET /manifest.webmanifest: the web app manifest (name, colours, icons from app/icon.tsx and app/apple-icon.tsx). */
import { appConfig } from "@/lib/app.config";
import { publicResponse } from "@/lib/server/public-response";

export function GET(request: Request) {
  const manifest = {
    name: appConfig.name,
    short_name: appConfig.name,
    description: appConfig.tagline,
    start_url: appConfig.home,
    scope: "/",
    display: "standalone",
    background_color: "#FFFDF9",
    theme_color: "#FFFDF9",
    lang: "en",
    icons: [
      { src: "/icon", type: "image/png", sizes: "512x512" },
      { src: "/apple-icon", type: "image/png", sizes: "180x180" },
    ],
    shortcuts: appConfig.nav.map(item => ({ name: item.label, url: item.href })),
  };
  return publicResponse(request, `${JSON.stringify(manifest, null, 2)}\n`, { type: "application/manifest+json; charset=utf-8", maxAge: 86400 });
}
