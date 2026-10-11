/**
 * GET /og.png: the app's Open Graph image (1200 by 630), in the look of Silicon Writings and the store's images: the
 * mark on its cream square and the name in the pixel face, the landing page's headline in the blue serif, and its
 * tagline, on warm paper. Everything comes from lib/app.config.ts, so it is drawn once at build time. The faces are
 * read from assets/og (TrueType: next/og cannot read the site's WOFF2 files; SIL OFL 1.1).
 */
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ImageResponse } from "next/og";
import { appConfig } from "@/lib/app.config";
import { markSvg, svgDataUri } from "@/lib/brand-svg";

export const dynamic = "force-static";

const PAPER = "#FFFDF9";
const INK = "#1E1E1C";
const SECONDARY = "#57544D";
const BLUE = "#1F5CB1";

const fonts = (async () => {
  const dir = join(process.cwd(), "assets", "og");
  const [regular, serif, pixel] = await Promise.all(["BDOGrotesk-Regular.ttf", "HedvigLettersSerif-Regular.ttf", "GeistPixel-Square.ttf"].map(name => readFile(join(dir, name))));
  return [
    { name: "BDO Grotesk", data: regular, weight: 400 as const, style: "normal" as const },
    { name: "Hedvig", data: serif, weight: 400 as const, style: "normal" as const },
    { name: "Pixel", data: pixel, weight: 400 as const, style: "normal" as const },
  ];
})();

const clip = (text: string, max: number) => (text.length <= max ? text : `${text.slice(0, max - 1).trimEnd()}…`);
const name = appConfig.brandPrefix ? `${appConfig.brandPrefix} ${appConfig.name}` : appConfig.name;

export async function GET() {
  const headline = clip(appConfig.landing.headline.replace(/\s*\n\s*/g, " "), 64);
  return new ImageResponse(
    (
      <div style={{ width: "100%", height: "100%", display: "flex", flexDirection: "column", justifyContent: "space-between", padding: "84px 96px", backgroundColor: PAPER, color: INK, fontFamily: "BDO Grotesk" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 18, fontFamily: "Pixel", fontSize: 34 }}>
          {/* eslint-disable-next-line @next/next/no-img-element -- next/og draws plain elements */}
          <img src={svgDataUri(markSvg())} width={56} height={56} alt="" style={{ borderRadius: 12 }} />
          <span>{name}</span>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 28, maxWidth: 1000 }}>
          <div style={{ fontFamily: "Hedvig", fontSize: 84, lineHeight: 1.08, letterSpacing: -1, color: BLUE }}>{headline}</div>
          <div style={{ fontSize: 30, color: SECONDARY, lineHeight: 1.35 }}>{clip(appConfig.tagline, 110)}</div>
        </div>
        <div style={{ display: "flex" }} />
      </div>
    ),
    { width: 1200, height: 630, fonts: await fonts, headers: { "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400" } },
  );
}
