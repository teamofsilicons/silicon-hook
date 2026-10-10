/**
 * /: the app's public landing page (components/landing). A signed-in browser never sees it: proxy.ts sends it on to the
 * workspace (appConfig.home). Server-rendered; its only script is the theme switch and the copy buttons.
 */
import type { Metadata } from "next";
import { headers } from "next/headers";
import { LandingPage } from "@/components/landing/landing-page";
import { Enhancer } from "@/components/site/enhancer";
import { SiteFooter } from "@/components/site/site-footer";
import { SiteHeader } from "@/components/site/site-header";
import { appConfig } from "@/lib/app.config";
import { getSession } from "@/lib/server/rsc";
import { publicOrigin } from "@/lib/server/site";

export async function generateMetadata(): Promise<Metadata> {
  const origin = publicOrigin();
  const title = `${appConfig.name}: ${appConfig.tagline.replace(/\.$/, "")}`;
  return {
    title: { absolute: title },
    description: appConfig.description,
    alternates: { canonical: `${origin}/` },
    robots: { index: true, follow: true },
    openGraph: { type: "website", url: `${origin}/`, title, description: appConfig.description, siteName: appConfig.name, images: [{ url: `${origin}/og.png`, width: 1200, height: 630, alt: title }] },
    twitter: { card: "summary_large_image", title, description: appConfig.description, images: [`${origin}/og.png`] },
  };
}

export default async function Page() {
  const [session, requestHeaders] = await Promise.all([getSession(), headers()]);
  const origin = publicOrigin();
  const graph = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: appConfig.name,
    description: appConfig.description,
    url: `${origin}/`,
    applicationCategory: "BusinessApplication",
    operatingSystem: "Web, Linux, Windows, macOS",
    installUrl: appConfig.links.store,
    softwareHelp: appConfig.links.docs,
  };
  return (
    <>
      <SiteHeader path="/" signedIn={session !== null} />
      <main id="main" tabIndex={-1}>
        <LandingPage signedIn={session !== null} />
      </main>
      <SiteFooter />
      <Enhancer />
      <script type="application/ld+json" nonce={requestHeaders.get("x-nonce") ?? undefined} dangerouslySetInnerHTML={{ __html: JSON.stringify(graph).replace(/</g, "\\u003c") }} />
    </>
  );
}
