export type IdentityKind = "carbon" | "silicon";
const messageType = "silicon:hook-login-complete";
const profilePattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Only a nonce and opaque local context ID cross the window boundary.
export function completeIamPopup(): boolean {
  const url = new URL(window.location.href);
  if (url.searchParams.get("iam_popup") !== "complete") return false;
  const nonce = url.searchParams.get("nonce"),
    profile = url.searchParams.get("context_id");
  history.replaceState(null, "", url.pathname + url.hash);
  if (
    nonce &&
    /^[a-f0-9]{64}$/.test(nonce) &&
    profile &&
    profilePattern.test(profile) &&
    window.opener
  ) {
    window.opener.postMessage(
      { type: messageType, nonce, context_id: profile },
      window.location.origin,
    );
    window.close();
    return true;
  }
  return false;
}

export function openIamPopup(
  start: (nonce: string) => string | Promise<string>,
  signal: AbortSignal,
): Promise<string> {
  if (signal.aborted)
    return Promise.reject(new Error("Sign-in was cancelled."));
  const nonce = Array.from(
    crypto.getRandomValues(new Uint8Array(32)),
    (value) => value.toString(16).padStart(2, "0"),
  ).join("");
  const popup = window.open(
    "about:blank",
    "iam-" + nonce,
    "popup,width=520,height=760",
  );
  if (!popup)
    return Promise.reject(
      new Error(
        "Popups are unavailable. Continue in this tab using the Carbon or Silicon link below.",
      ),
    );
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error, profile?: string) => {
      if (settled) return;
      settled = true;
      window.removeEventListener("message", receive);
      signal.removeEventListener("abort", abort);
      clearInterval(closed);
      clearTimeout(timeout);
      popup.close();
      if (error) reject(error);
      else resolve(profile!);
    };
    const receive = (event: MessageEvent) => {
      if (
        event.origin !== window.location.origin ||
        event.source !== popup ||
        event.data?.type !== messageType ||
        event.data?.nonce !== nonce ||
        typeof event.data?.context_id !== "string" ||
        !profilePattern.test(event.data.context_id)
      )
        return;
      finish(undefined, event.data.context_id);
    };
    const abort = () => finish(new Error("Sign-in was cancelled."));
    const closed = setInterval(() => {
      if (popup.closed)
        finish(
          new Error(
            "Sign-in was closed. Choose your account type to try again.",
          ),
        );
    }, 500);
    const timeout = setTimeout(
      () =>
        finish(
          new Error("Sign-in expired. Choose your account type to try again."),
        ),
      600_000,
    );
    window.addEventListener("message", receive);
    signal.addEventListener("abort", abort, { once: true });
    Promise.resolve()
      .then(() => (settled ? undefined : start(nonce)))
      .then((url) => {
        if (!settled && url) popup.location.href = url;
      })
      .catch((error) =>
        finish(
          error instanceof Error
            ? error
            : new Error("Unable to start sign-in."),
        ),
      );
  });
}
