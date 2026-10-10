"use client";

/**
 * A workspace page crashed: the shell stays, the page says what happened and offers to try again. Production hides a
 * Server Component's own message (only its digest reaches here), so pages show the service's words inline with
 * tryApiFetch() and <ErrorAlert>, and this boundary is for the unexpected.
 */
import { useEffect } from "react";
import { RotateCcw } from "lucide-react";
import { Button } from "@/components/arc/button/button";
import { ButtonLink } from "@/components/foundation/button-link";
import { Problem } from "@/components/foundation/feedback/problem";
import { appConfig } from "@/lib/app.config";

export default function WorkspaceError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error(error);
  }, [error]);
  return (
    <Problem
      layout="inset"
      icon={<RotateCcw strokeWidth={1.5} />}
      title="This page stopped working"
      reference={error.digest}
      actions={
        <>
          <Button variant="secondary" onClick={reset}>Try again</Button>
          <ButtonLink href={appConfig.home} variant="ghost">Back to {appConfig.nav[0]?.label ?? appConfig.name}</ButtonLink>
        </>
      }
    >
      <p>Something in the page failed{error.digest ? "" : `: ${error.message || "an unexpected error"}`}. Try again; if it keeps happening, quote the reference when you report it.</p>
    </Problem>
  );
}
