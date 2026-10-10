/**
 * The root layout: <html> and <body>, the Silicon look (Arc's foundation, BDO Grotesk, the tokens, squircles, the base),
 * the no-flash theme boot script (inline, with the request's CSP nonce from proxy.ts), the app's colour and the
 * metadata every page shares. It ships no client code of its own: the public pages stay server-rendered HTML with a
 * few small islands, and the signed-in workspace mounts its providers in app/(workspace)/layout.tsx. Every page renders
 * per request (the nonce changes each time).
 */
import "@/components/arc/foundation.css";
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
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#F7F8FA" },
    { media: "(prefers-color-scheme: dark)", color: "#02040A" },
  ],
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  const nonce = (await headers()).get("x-nonce") ?? undefined;
  const accent = appConfig.accent ? ({ "--app-accent-light": appConfig.accent.light, "--app-accent-dark": appConfig.accent.dark } as CSSProperties) : undefined;
  return (
    <html lang="en" style={accent} suppressHydrationWarning>
      <head>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
        {/* Page titles are set in DemiBold: the one weight worth fetching before first paint. */}
        <link rel="preload" href="/fonts/bdo-grotesk/BDOGrotesk-DemiBold.woff2" as="font" type="font/woff2" crossOrigin="anonymous" />
      </head>
      <body>{children}</body>
    </html>
  );
}
