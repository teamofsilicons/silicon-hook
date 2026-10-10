"use client";

/**
 * The last resort: the root layout itself failed, so this renders its own <html> with the tokens inline (the
 * stylesheets may be what failed). Plain words and one way back.
 */
export default function GlobalError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, minHeight: "100vh", display: "grid", placeItems: "center", background: "#F7F8FA", color: "#292929", font: "16px/1.5 -apple-system, BlinkMacSystemFont, system-ui, sans-serif" }}>
        <main style={{ maxWidth: 460, padding: 24, textAlign: "center" }}>
          <h1 style={{ margin: "0 0 12px", fontSize: 28, letterSpacing: "-0.02em" }}>This site stopped working</h1>
          <p style={{ margin: "0 0 20px", color: "#4C5260" }}>Something failed before the page could load. Try again in a moment.{error.digest ? ` Reference ${error.digest}.` : ""}</p>
          <button type="button" onClick={reset} style={{ font: "inherit", padding: "10px 18px", borderRadius: 14, border: 0, background: "#1F5FB8", color: "#FFFFFF", cursor: "pointer" }}>Try again</button>
        </main>
      </body>
    </html>
  );
}
