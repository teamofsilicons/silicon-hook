/**
 * The public pages' header (server-rendered): the app's mark and name, the landing page's sections and docs, the theme
 * switch, and Sign in (or Open {App} once signed in). Below 900 px the links move into a menu: a native popover, so it
 * opens, closes on Escape or an outside tap, and keeps focus without any script of ours (its close button carries
 * autofocus, so opening it moves focus in, and closing it gives focus back to the menu button). Links are plain links:
 * every public page is a full HTML document. Adapted from the developer site's components/site/site-header.tsx.
 */
import { Menu, X } from "lucide-react";
import { BRAND_NAME, Wordmark } from "@/components/foundation/brand/app-mark";
import { appConfig } from "@/lib/app.config";
import { Action } from "./action";
import { ThemeToggle } from "./theme-controls";
import styles from "./site.module.css";

const NAV: Array<{ href: string; label: string; external?: boolean }> = [
  { href: "/#what-it-does", label: "What it does" },
  { href: "/#for-silicons", label: "For Silicons" },
  { href: "/#get-started", label: "Get started" },
  { href: appConfig.links.docs, label: "Docs", external: true },
];

export interface SiteHeaderProps {
  /** This page's path, to mark the link that leads to it. */
  path: string;
  signedIn: boolean;
}

export function SiteHeader({ path, signedIn }: SiteHeaderProps) {
  const account = signedIn ? { href: appConfig.home, label: `Open ${appConfig.name}` } : { href: `/auth/sign-in`, label: "Sign in" };
  return (
    <header className={styles.header}>
      <a className="skip-link" data-sq="surface" href="#main">Skip to content</a>
      <div className={styles.bar}>
        <a href="/" className={styles.brand} data-sq="surface" aria-label={`${BRAND_NAME}, home`}>
          <Wordmark />
        </a>
        <nav className={styles.nav} aria-label="Main">
          <ul role="list" className={styles.navList}>
            {NAV.map(item => (
              <li key={item.href}>
                <a href={item.href} className={styles.navLink} data-sq="surface" aria-current={item.href === path ? "page" : undefined} rel={item.external ? "noopener" : undefined}>{item.label}</a>
              </li>
            ))}
          </ul>
        </nav>
        <div className={styles.actions}>
          <ThemeToggle />
          <Action href={account.href} size="sm" className={styles.account}>{account.label}</Action>
          <button type="button" className={`${styles.iconButton} ${styles.menuButton}`} data-sq="surface" popoverTarget="site-menu" aria-label="Open the menu">
            <Menu size={18} strokeWidth={1.75} aria-hidden="true" />
          </button>
        </div>
      </div>
      <div id="site-menu" popover="auto" className={styles.menu} data-sq="surface" role="dialog" aria-label="Menu">
        <div className={styles.menuHead}>
          <span className={styles.menuTitle}>Menu</span>
          <button type="button" className={styles.iconButton} data-sq="surface" popoverTarget="site-menu" popoverTargetAction="hide" aria-label="Close the menu" autoFocus>
            <X size={18} strokeWidth={1.75} aria-hidden="true" />
          </button>
        </div>
        <nav aria-label="Main menu" className={styles.menuNav}>
          <ul role="list">
            <li><a href="/" className={styles.menuLink} data-sq="surface" aria-current={path === "/" ? "page" : undefined}>Home</a></li>
            {NAV.map(item => (
              <li key={item.href}><a href={item.href} className={styles.menuLink} data-sq="surface" rel={item.external ? "noopener" : undefined}>{item.label}</a></li>
            ))}
          </ul>
        </nav>
        <div className={styles.menuFoot}>
          <Action href={account.href} size="md" className={styles.menuAction}>{account.label}</Action>
        </div>
      </div>
    </header>
  );
}
