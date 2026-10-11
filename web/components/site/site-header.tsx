/**
 * The public pages' header (server-rendered), as on Silicon Writings, Silicon Apps and Silicon Accounts: the wordmark
 * on the left; on the right the docs (another site, a quiet link) and Sign in (or "Open <app>" once signed in).
 * Nothing else: the page itself says what to do next. Links are plain links: every public page is a full document.
 */
import { ArrowUpRight } from "lucide-react";
import { BRAND_NAME, Wordmark } from "@/components/foundation/brand/app-mark";
import { appConfig } from "@/lib/app.config";
import { Action } from "./action";
import styles from "./site.module.css";

export interface SiteHeaderProps {
  /** This page's path (kept for callers). */
  path: string;
  signedIn: boolean;
}

export function SiteHeader({ signedIn }: SiteHeaderProps) {
  const account = signedIn ? { href: appConfig.home, label: `Open ${appConfig.name}` } : { href: "/auth/sign-in", label: "Sign in" };
  return (
    <header className={styles.header}>
      <a className="skip-link" data-sq="surface" href="#main">Skip to content</a>
      <div className={styles.bar}>
        <a href="/" className={styles.brand} data-sq="surface" aria-label={`${BRAND_NAME}, home`}>
          <Wordmark />
        </a>
        <div className={styles.actions}>
          <a href={appConfig.links.docs} className={styles.navLink} data-sq="surface" rel="noopener">
            Docs
            <ArrowUpRight size={14} strokeWidth={1.75} aria-hidden="true" className={styles.navExternal} />
          </a>
          <Action href={account.href} size="sm" variant="secondary" className={styles.account}>{account.label}</Action>
        </div>
      </div>
    </header>
  );
}
