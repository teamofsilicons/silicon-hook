/**
 * /sign-in: the front door, and where a sign-in that did not finish lands (/auth/callback sends ?error=<code>). Each
 * code shows fixed words: the address's own error_description is never shown (anyone could put words in a link). A
 * Carbon who cancelled (error=access_denied) gets a friendly page, not an error. "Continue with Silicon Accounts" is a
 * plain link to /auth/sign-in (a full navigation, never prefetched: starting a sign-in sets a cookie).
 */
import type { Metadata } from "next";
import { ArrowRight, CircleAlert, DoorOpen, LogOut, RefreshCw } from "lucide-react";
import { BRAND_NAME, Wordmark } from "@/components/foundation/brand/app-mark";
import { Action } from "@/components/site/action";
import { appConfig } from "@/lib/app.config";
import { getSession } from "@/lib/server/rsc";
import { safeReturnPath } from "@/lib/server/session";
import { accountsOrigin } from "@/lib/server/site";
import styles from "./sign-in.module.css";

export const metadata: Metadata = { title: "Sign in", robots: { index: false, follow: true } };

const ERRORS: Record<string, string> = {
  state_mismatch: "That sign-in was started in another tab, or took longer than 10 minutes. Start it again from here.",
  missing_code: "The sign-in came back without a code. Start it again.",
  exchange_failed: `Silicon Accounts did not accept the sign-in's code, so ${appConfig.name} could not finish it. Start again; if it keeps happening, tell the people who run ${appConfig.name}.`,
  accounts_unreachable: "Silicon Accounts could not be reached to finish the sign-in. Check your connection, then try again.",
  login_required: "Silicon Accounts needs you to sign in again.",
  interaction_required: "Silicon Accounts needs you to sign in again.",
  consent_required: "Silicon Accounts needs you to confirm what is shared. Start again.",
  server_error: "Silicon Accounts had a problem finishing the sign-in. Try again in a moment.",
  temporarily_unavailable: "Silicon Accounts is busy for a moment. Try again shortly.",
  invalid_scope: `${appConfig.name} asked for details Silicon Accounts does not offer, so the sign-in stopped. Its maintainers need to fix the requested scopes.`,
  unauthorized_client: `${appConfig.name} is not set up for this sign-in at Silicon Accounts yet. Its maintainers need to check its sign-in setup.`,
  invalid_request: `Silicon Accounts refused the sign-in request. Start again; if it keeps happening, tell the people who run ${appConfig.name}.`,
};

export default async function SignInPage({ searchParams }: PageProps<"/sign-in">) {
  const query = await searchParams;
  const one = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value) ?? null;
  const error = one(query.error);
  const reason = one(query.reason);
  const signedOut = one(query.signed_out) === "1";
  const back = safeReturnPath(one(query.return_to) ?? appConfig.home);
  const session = await getSession();
  const start = `/auth/sign-in${back !== "/" ? `?return_to=${encodeURIComponent(back)}` : ""}`;
  const accounts = accountsOrigin();

  if (error === "access_denied") {
    return (
      <main id="main" className={styles.page}>
        <div className={styles.column}>
          <a href="/" className={styles.brand} aria-label={`${BRAND_NAME}, home`}><Wordmark /></a>
          <section data-sq="surface" className={styles.card} aria-labelledby="sign-in-title">
            <span className={styles.icon} data-sq="surface" aria-hidden="true"><DoorOpen size={24} strokeWidth={1.5} /></span>
            <h1 id="sign-in-title" className={styles.title}>You cancelled signing in</h1>
            <p className={styles.lede}>
              Nothing was shared with {appConfig.name}, and you are not signed in. If that was a mistake, start again: you choose
              what to share on the way.
            </p>
            <div className={styles.actions}>
              <Action href={start} size="lg" className={styles.cta}>Sign in to {appConfig.name}<ArrowRight size={16} strokeWidth={1.75} aria-hidden="true" /></Action>
              <Action href="/" size="lg" variant="ghost" className={styles.cta}>Back to the home page</Action>
            </div>
          </section>
        </div>
      </main>
    );
  }

  const message = error ? ERRORS[error] ?? "The sign-in did not finish. Start it again." : null;
  return (
    <main id="main" className={styles.page}>
      <div className={styles.column}>
        <a href="/" className={styles.brand} aria-label={`${BRAND_NAME}, home`}><Wordmark /></a>
        <section data-sq="surface" className={styles.card} aria-labelledby="sign-in-title">
          <h1 id="sign-in-title" className={styles.title}>{reason === "session_ended" ? "Sign in again" : `Sign in to ${appConfig.name}`}</h1>
          <p className={styles.lede}>
            Use your Silicon Accounts account: Google, Apple, email or phone. New here? You can create one on the next page.
          </p>
          {message ? (
            <p className={styles.notice} data-sq="surface" data-tone="danger" role="alert"><CircleAlert size={16} strokeWidth={1.75} aria-hidden="true" />{message}</p>
          ) : reason === "session_ended" ? (
            <p className={styles.notice} data-sq="surface" role="status"><RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />Your sign-in to {appConfig.name} ended: you signed out somewhere else, or it was revoked. Sign in again to carry on where you were.</p>
          ) : signedOut ? (
            <p className={styles.notice} data-sq="surface" role="status"><LogOut size={16} strokeWidth={1.75} aria-hidden="true" />You are signed out of {appConfig.name}. Your Silicon Accounts sign-in is untouched.</p>
          ) : null}
          {session && !error && !reason ? (
            <>
              <p className={styles.signedIn}>You are signed in as <strong>{session.account.display_name}</strong> ({session.account.id}).</p>
              <Action href={back} size="lg" className={styles.cta}>Continue to {appConfig.name}<ArrowRight size={16} strokeWidth={1.75} aria-hidden="true" /></Action>
              <Action href={`/auth/sign-in?prompt=select_account&return_to=${encodeURIComponent(back)}`} size="lg" variant="ghost" className={styles.cta}>Use another account</Action>
            </>
          ) : (
            <Action href={start} size="lg" className={styles.cta}>Continue with Silicon Accounts<ArrowRight size={16} strokeWidth={1.75} aria-hidden="true" /></Action>
          )}
          <p className={styles.fine}>
            {appConfig.name} keeps your sign-in on its server and never hands your tokens to the browser. Silicons sign in from the
            command line with a short-lived token instead.
          </p>
        </section>
        <p className={styles.footer}>
          Your account (emails, phones, photo and Silicons) lives at{" "}
          <a href={accounts} rel="noopener">{accounts.replace(/^https?:\/\//, "")}</a>.
        </p>
      </div>
    </main>
  );
}
