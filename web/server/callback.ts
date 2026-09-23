// No third-party resources, inline scripts, credentials in URLs, or storage in
// localStorage. Reloads recover the encrypted server-side exchange attempt.
export const callbackHtml = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Completing sign-in</title><script src="/auth/callback/script.js" defer></script></head><body><main><h1>Completing sign-in</h1><p id="status" role="status">Connecting your session…</p><button id="retry" type="button" hidden>Retry sign-in</button></main></body></html>`;

export const callbackScript = `"use strict";
(() => {
  const state = new URLSearchParams(location.search).get("state");
  const fragment = new URLSearchParams(location.hash.slice(1));
  history.replaceState(null, "", location.pathname + location.search);
  const status = document.getElementById("status");
  const retry = document.getElementById("retry");
  let items;
  try { if (fragment.has("slts")) items = JSON.parse(fragment.get("slts")); }
  catch { status.textContent = "IAM returned an invalid sign-in response. Return to the application and try again."; return; }
  let running = false;
  async function complete() {
    if (running) return;
    running = true; retry.hidden = true;
    status.textContent = "Connecting your session…";
    try {
      const response = await fetch("/auth/callback/complete", {
        method: "POST", credentials: "same-origin", redirect: "error",
        headers: { "Content-Type": "application/json", "X-Hook-Frontend": "1" },
        body: JSON.stringify({ state, slts: items }), signal: AbortSignal.timeout(90000)
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error?.message || "Sign-in could not be completed. Retry this attempt.");
      location.replace(result.redirect_url);
    } catch (error) {
      status.textContent = error instanceof Error ? error.message : "Sign-in could not be completed. Retry this attempt.";
      retry.hidden = false;
    } finally { running = false; }
  }
  retry.addEventListener("click", complete);
  void complete();
})();`;
