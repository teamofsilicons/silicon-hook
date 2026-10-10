/**
 * GET /og.png: the app's Open Graph image (1200 by 630), in the look of the store's app images: BDO Grotesk on the
 * light page colour, the dot grid and a wash of the app's colour, the mark and name, the landing page's headline, and
 * the command that installs it. Everything comes from lib/app.config.ts, so it is drawn once at build time.
 * BDO Grotesk is read from assets/og (TrueType: next/og cannot read the site's WOFF2 files; SIL OFL 1.1).
 */
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ImageResponse } from "next/og";
import { appConfig } from "@/lib/app.config";
import { markFill, markSvg, svgDataUri } from "@/lib/brand-svg";

export const dynamic = "force-static";

const PAGE = "#F7F8FA";
const INK = "#292929";
const SECONDARY = "#4C5260";
const BORDER = "#E2E5EB";
const BLUE = "#1F5FB8";

const fonts = (async () => {
  const dir = join(process.cwd(), "assets", "og");
  const [regular, medium, demi] = await Promise.all(["BDOGrotesk-Regular.ttf", "BDOGrotesk-Medium.ttf", "BDOGrotesk-DemiBold.ttf"].map(name => readFile(join(dir, name))));
  return [
    { name: "BDO Grotesk", data: regular, weight: 400 as const, style: "normal" as const },
    { name: "BDO Grotesk", data: medium, weight: 500 as const, style: "normal" as const },
    { name: "BDO Grotesk", data: demi, weight: 600 as const, style: "normal" as const },
  ];
})();

/** Hex colour to "r,g,b" for the wash. */
function rgb(hex: string): string {
  const value = hex.replace("#", "");
  const full = value.length === 3 ? value.split("").map(c => c + c).join("") : value;
  const n = parseInt(full.slice(0, 6), 16);
  return Number.isFinite(n) ? `${(n >> 16) & 255},${(n >> 8) & 255},${n & 255}` : "31,95,184";
}

const clip = (text: string, max: number) => (text.length <= max ? text : `${text.slice(0, max - 1).trimEnd()}…`);

export async function GET() {
  const wash = rgb(markFill());
  return new ImageResponse(
    (
      <div style={{ width: "100%", height: "100%", display: "flex", flexDirection: "column", padding: "64px 76px", backgroundColor: PAGE, backgroundImage: `radial-gradient(circle at 86% 18%, rgba(${wash},0.18), rgba(247,248,250,0) 55%)`, color: INK, fontFamily: "BDO Grotesk" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 18, fontSize: 34, fontWeight: 600, letterSpacing: -0.7 }}>
          {/* eslint-disable-next-line @next/next/no-img-element -- next/og draws plain elements */}
          <img src={svgDataUri(markSvg())} width={60} height={60} alt="" />
          {appConfig.brandPrefix ? <span>{appConfig.brandPrefix}</span> : null}
          <span style={appConfig.brandPrefix ? { color: SECONDARY, fontWeight: 500, marginLeft: -6 } : undefined}>{appConfig.name}</span>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 22, marginTop: 70, maxWidth: 940 }}>
          <div style={{ fontSize: 72, fontWeight: 600, letterSpacing: -2.6, lineHeight: 1.02 }}>{clip(appConfig.landing.headline, 70)}</div>
          <div style={{ fontSize: 30, color: SECONDARY, lineHeight: 1.35 }}>{clip(appConfig.tagline, 110)}</div>
        </div>
        <div style={{ display: "flex", marginTop: "auto", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14, padding: "14px 22px", border: `1.5px solid ${BORDER}`, borderRadius: 20, backgroundColor: "#FFFFFF", fontSize: 26, fontWeight: 500 }}>
            <span style={{ color: BLUE, fontWeight: 600 }}>$</span>
            <span>{`silicon-apps install ${appConfig.appId}`}</span>
          </div>
          <div style={{ display: "flex", fontSize: 24, color: SECONDARY }}>For Carbons and Silicons</div>
        </div>
      </div>
    ),
    { width: 1200, height: 630, fonts: await fonts, headers: { "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400" } },
  );
}
