/**
 * The app's mark as an SVG document, for the places that need a file rather than a component: the browser icon
 * (app/icon.tsx), the home-screen icon (app/apple-icon.tsx) and the Open Graph image (app/og.png). The glyph is
 * lib/app.config.ts `mark` (lucide-style strokes on a 24 by 24 grid), white on the app's colour or brand blue.
 */
import { appConfig } from "./app.config";

/** The squircle the Silicon marks sit on (the developer site's and the store's icon outline), on a 64 by 64 grid. */
export const SQUIRCLE_64 = "M32 0c19.6 0 25.4 1.4 28.6 3.4C62.6 6.6 64 12.4 64 32s-1.4 25.4-3.4 28.6C57.4 62.6 51.6 64 32 64S6.6 62.6 3.4 60.6C1.4 57.4 0 51.6 0 32S1.4 6.6 3.4 3.4C6.6 1.4 12.4 0 32 0Z";

export const BRAND_BLUE = "#1F5FB8";
export const markFill = () => appConfig.accent?.light ?? BRAND_BLUE;

const escape = (value: string) => value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");

/**
 * The mark: `shape` "squircle" (icons, the social image) or "square" (a home-screen icon the system rounds itself).
 * `glyph` is the share of the side the glyph spans.
 */
export function markSvg({ shape = "squircle", glyph = 0.6, fill = markFill() }: { shape?: "squircle" | "square"; glyph?: number; fill?: string } = {}): string {
  const scale = (64 * glyph) / 24;
  const offset = (64 - 24 * scale) / 2;
  const base = shape === "square" ? `<rect width="64" height="64" fill="${escape(fill)}"/>` : `<path fill="${escape(fill)}" d="${SQUIRCLE_64}"/>`;
  const paths = appConfig.mark.paths.map(d => `<path d="${escape(d)}"/>`).join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">${base}<g transform="translate(${offset.toFixed(2)} ${offset.toFixed(2)}) scale(${scale.toFixed(4)})" fill="none" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${paths}</g></svg>`;
}

export const svgDataUri = (svg: string) => `data:image/svg+xml;base64,${Buffer.from(svg, "utf8").toString("base64")}`;
