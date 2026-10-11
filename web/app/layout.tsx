/**
 * The root layout: <html> and <body>, the Silicon look (Arc's foundation, BDO Grotesk, the tokens, squircles, the base),
 * the light-only boot script (inline, with the request's CSP nonce from proxy.ts), the app's colour and the
 * metadata every page shares. It ships no client code of its own: the public pages stay server-rendered HTML with a
 * few small islands, and the signed-in workspace mounts its providers in app/(workspace)/layout.tsx. Every page renders
 * per request (the nonce changes each time).
 */
import "@/components/silicon-ui/foundation.css";
import "@/styles/fonts.css";
import "@/styles/tokens.css";
import "@/styles/squircle.css";
import "@/styles/base.css";
import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import type { CSSProperties, ReactNode } from "react";
import { appConfig } from "@/lib/app.config";
import { publicOrigin } from "@/lib/server/site";
import { THEME_BOOT_SCRIPT } from "@/lib/theme";

export async function generateMetadata(): Promise<Metadata> {
  const origin = publicOrigin();
  return {
    metadataBase: new URL(origin),
    title: { default: appConfig.name, template: `%s · ${appConfig.name}` },
    description: appConfig.description,
    applicationName: appConfig.name,
    referrer: "strict-origin-when-cross-origin",
    // The signed-in workspace is private; the landing page opens itself to search engines (app/page.tsx).
    robots: { index: false, follow: false },
    manifest: "/manifest.webmanifest",
    openGraph: { type: "website", siteName: appConfig.name, locale: "en_US", images: [{ url: `${origin}/og.png`, width: 1200, height: 630, alt: `${appConfig.name}: ${appConfig.tagline}` }] },
    twitter: { card: "summary_large_image" },
  };
}

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
  themeColor: "#FFFDF9",
  colorScheme: "light",
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  const accent = appConfig.accent ? ({ "--app-accent-light": appConfig.accent.light, "--app-accent-dark": appConfig.accent.dark } as CSSProperties) : undefined;
  return (
    <html lang="en" style={accent} suppressHydrationWarning>
      <head>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
        {/* Every face the first paint uses, fetched with the page so text never paints in a fallback first (styles/fonts.css). */}
        <link rel="preload" href="/fonts/bdo-grotesk/BDOGrotesk-Regular.woff2" as="font" type="font/woff2" crossOrigin="anonymous" />
        <link rel="preload" href="/fonts/bdo-grotesk/BDOGrotesk-Medium.woff2" as="font" type="font/woff2" crossOrigin="anonymous" />
        <link rel="preload" href="/fonts/hedvig-letters-serif/HedvigLettersSerif-Regular.woff2" as="font" type="font/woff2" crossOrigin="anonymous" />
        <link rel="preload" href="/fonts/geist-pixel/GeistPixel-Square.woff2" as="font" type="font/woff2" crossOrigin="anonymous" />
      </head>
      <body>{children}</body>
    </html>
  );
}
