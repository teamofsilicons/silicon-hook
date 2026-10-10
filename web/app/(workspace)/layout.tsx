/**
 * The signed-in workspace around every page under it: the session is checked here on the server (no session: the
 * hosted sign-in, coming back to this page), then the providers (query client, toasts, squircles, the session keeper)
 * and the app shell (sidebar, top bar, ⌘K, account menu). One instance stays mounted while you move between pages.
 */
import { HookScope } from "@/components/hook/context";
import "@/components/hook/hook.css";
import type { ReactNode } from "react";
import { Providers } from "@/components/foundation/providers";
import { AppShell } from "@/components/foundation/shell/app-shell";
import { requireSession } from "@/lib/server/rsc";
import { accountsOrigin } from "@/lib/server/site";

export default async function WorkspaceLayout({ children }: { children: ReactNode }) {
  const session = await requireSession();
  return (
    <Providers session={{ signedIn: true, account: session.account, expiresAt: session.expiresAt }}>
      <AppShell account={session.account} accountsUrl={accountsOrigin()}>
        <HookScope>{children}</HookScope>
      </AppShell>
    </Providers>
  );
}
