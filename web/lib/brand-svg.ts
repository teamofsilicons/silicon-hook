/**
 * The app's mark as an SVG document, for the places that need a file rather than a component: the browser icon
 * (app/icon.tsx), the home-screen icon (app/apple-icon.tsx) and the Open Graph image (app/og.png). The glyph is
 * lib/app.config.ts `mark` (lucide-style strokes on a 24 by 24 grid) in #181818 on a cream square, the way the family's
 * icons are drawn (Silicon Apps, Silicon Accounts, Silicon Developer). The system rounds a home-screen icon itself.
 */
import { appConfig } from "./app.config";

export const ICON_PAPER = "#EDE8E0";
export const ICON_INK = "#181818";

const escape = (value: string) => value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");

/** The mark on its cream square. `glyph` is the share of the side the glyph spans. `shape` is kept for callers. */
export function markSvg({ glyph = 0.56 }: { shape?: "squircle" | "square"; glyph?: number } = {}): string {
  const scale = (64 * glyph) / 24;
  const offset = (64 - 24 * scale) / 2;
  const paths = appConfig.mark.paths.map(d => `<path d="${escape(d)}"/>`).join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" fill="${ICON_PAPER}"/><g transform="translate(${offset.toFixed(2)} ${offset.toFixed(2)}) scale(${scale.toFixed(4)})" fill="none" stroke="${ICON_INK}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${paths}</g></svg>`;
}

export const svgDataUri = (svg: string) => `data:image/svg+xml;base64,${Buffer.from(svg, "utf8").toString("base64")}`;
