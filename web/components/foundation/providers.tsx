"use client";

/**
 * Everything the signed-in workspace shares, mounted once by its layout: the TanStack Query client (errors toast with
 * message and hint; a 401 ends the session), the Arc toast stack, the squircle runtime for browsers without
 * corner-shape, Motion's reduced-motion setting, and the session keeper started with what the server rendered.
 * The public pages (the landing page, sign-in) mount none of this.
 */
import { useEffect, useState, type ReactNode } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { MotionConfig } from "motion/react";
import { ToastStack, ToastStackProvider, useToastStack } from "@/components/silicon-ui/toast-stack/toast-stack";
import { SquircleRuntime } from "@/components/foundation/squircle/squircle";
import type { SessionView } from "@/lib/account";
import { createQueryClient } from "@/lib/client/query";
import { startSessionKeeper } from "@/lib/client/session";
import { connectToasts } from "@/lib/notify";
import { applyTheme } from "@/lib/theme";
import styles from "./providers.module.css";

/** Hands the mounted toast stack to lib/notify, so toasts can be raised from anywhere. */
function ToastBridge() {
  const { toast, update, dismiss } = useToastStack();
  useEffect(() => connectToasts({ toast, update, dismiss }), [toast, update, dismiss]);
  return null;
}

export function Providers({ session, children }: { session: SessionView; children: ReactNode }) {
  const [client] = useState(createQueryClient);

  // The boot script painted the stored theme; from here the theme store keeps <html> in sync.
  useEffect(() => {
    applyTheme();
  }, []);

  // The keeper refreshes the sign-in ahead of expiry (lib/client/session.ts). A later render can hand it a newer expiry.
  useEffect(() => {
    startSessionKeeper(session);
  }, [session]);

  return (
    <MotionConfig reducedMotion="user">
      <QueryClientProvider client={client}>
        <ToastStackProvider>
          <SquircleRuntime />
          {children}
          <ToastBridge />
          <ToastStack label="Notifications" className={styles.toasts} />
        </ToastStackProvider>
      </QueryClientProvider>
    </MotionConfig>
  );
}
