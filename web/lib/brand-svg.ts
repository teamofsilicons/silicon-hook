/**
 * The app's logo as an SVG document, for the places that need a file rather than a component: the browser icon
 * (app/icon.tsx, on a rounded tile), the home-screen icon (app/apple-icon.tsx, on a full square the system rounds itself)
 * and the Open Graph image (app/og.png). The logo is lib/app-logo.ts `LOGO`: the mark in #181818 on a cream square, the way
 * the family's icons are drawn (Silicon Apps, Silicon Accounts, Silicon Developer).
 */
import { LOGO } from "./app-logo";

export const ICON_PAPER = "#EDE8E0";
export const ICON_INK = "#181818";

/** The logo. `rounded` rounds its square for the browser tab; `shape` and `glyph` are kept for callers. */
export function markSvg({ rounded = false }: { rounded?: boolean; shape?: "squircle" | "square"; glyph?: number } = {}): string {
  return rounded ? LOGO.replace(/<rect width="200" height="200"/g, '<rect width="200" height="200" rx="44"') : LOGO;
}

export const svgDataUri = (svg: string) => `data:image/svg+xml;base64,${Buffer.from(svg, "utf8").toString("base64")}`;
