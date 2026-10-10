/** Any address the site does not know: a public page, server-rendered, in the landing page's frame. */
import type { Metadata } from "next";
import { Compass } from "lucide-react";
import { Problem } from "@/components/foundation/feedback/problem";
import { Action } from "@/components/site/action";
import { SiteFooter } from "@/components/site/site-footer";
import { SiteHeader } from "@/components/site/site-header";
import { appConfig } from "@/lib/app.config";
import { getSession } from "@/lib/server/rsc";

export const metadata: Metadata = { title: { absolute: `Not found · ${appConfig.name}` }, robots: { index: false, follow: true } };

export default async function NotFound() {
  const signedIn = (await getSession()) !== null;
  return (
    <>
      <SiteHeader path="/404" signedIn={signedIn} />
      <main id="main" tabIndex={-1}>
        <Problem
          icon={<Compass strokeWidth={1.5} />}
          title="Nothing lives at this address"
          actions={
            <>
              <Action href={signedIn ? appConfig.home : "/"}>{signedIn ? `Open ${appConfig.name}` : "Go to the home page"}</Action>
              <Action href={appConfig.links.docs} variant="secondary" rel="noopener">Read the docs</Action>
            </>
          }
        >
          <p>This is not a page of {appConfig.name}. Check the link, or start again from the home page.</p>
        </Problem>
      </main>
      <SiteFooter />
    </>
  );
}
