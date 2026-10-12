/**
 * Silicon Hook's logo, as the Carbon drew it. `LOGO` is the whole icon, the mark in #181818 on a cream (#EDE8E0) square,
 * as a 200 by 200 SVG document: the browser and home-screen icons, the Open Graph image and the Silicon Apps listing use
 * it (lib/brand-svg.ts). `LOGO_MARK` is the mark alone, drawn in the text colour (currentColor), as the header shows it
 * beside the name (components/foundation/brand/app-mark.tsx).
 */
export const LOGO = `<svg width="200" height="200" viewBox="0 0 200 200" fill="none" xmlns="http://www.w3.org/2000/svg"><rect width="200" height="200" fill="#EDE8E0"/><path d="M94.9631 36.4931L105.981 36.7805L106.077 107.776L130.988 82.8652L138.461 90.3384L101.095 127.704L62.7708 89.3803L70.4357 81.7155L95.5379 106.818L94.9631 36.4931Z" fill="#181818"/><circle cx="100.5" cy="144.5" r="12.5" fill="#181818"/></svg>`;

export const LOGO_MARK = {
  viewBox: "38.6 34.8 124 124",
  body: `<path d="M94.9631 36.4931L105.981 36.7805L106.077 107.776L130.988 82.8652L138.461 90.3384L101.095 127.704L62.7708 89.3803L70.4357 81.7155L95.5379 106.818L94.9631 36.4931Z" fill="currentColor"/><circle cx="100.5" cy="144.5" r="12.5" fill="currentColor"/>`,
};
