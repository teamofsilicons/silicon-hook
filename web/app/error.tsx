"use client";

/**
 * A page crashed while rendering: say so plainly, keep the digest for a report, and offer to try again. Plain elements
 * in Arc's button styles (no motion library): this boundary is part of every page's script, the public pages included.
 */
import { useEffect } from "react";
import { RotateCcw } from "lucide-react";
import buttonStyles from "@/components/silicon-ui/button/button.module.css";
import { Problem } from "@/components/foundation/feedback/problem";
import linkStyles from "@/components/foundation/button-link.module.css";

export default function ErrorPage({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error(error);
  }, [error]);
  return (
    <main id="main">
      <Problem
        icon={<RotateCcw strokeWidth={1.5} />}
        title="This page stopped working"
        reference={error.digest}
        actions={
          <>
            <button type="button" data-sq="surface" className={`${buttonStyles.button} ${buttonStyles.secondary} ${buttonStyles.md}`} onClick={reset}>Try again</button>
            <a href="/" data-sq="surface" className={`${buttonStyles.button} ${buttonStyles.ghost} ${buttonStyles.md} ${linkStyles.link}`}>Go to the home page</a>
          </>
        }
      >
        <p>Something in the page failed{error.digest ? "" : `: ${error.message || "an unexpected error"}`}. Try again; if it keeps happening, quote the reference below when you report it.</p>
      </Problem>
    </main>
  );
}
