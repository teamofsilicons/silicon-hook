/**
 * The public pages' footer (server-rendered): the app, what Silicons can read here, the rest of the Silicon ecosystem,
 * and the theme choice (System, Light, Dark). Adapted from the developer site's components/site/site-footer.tsx.
 */
import { ArrowUpRight } from "lucide-react";
import { BRAND_NAME, Wordmark } from "@/components/foundation/brand/app-mark";
import { appConfig } from "@/lib/app.config";
import { ThemePicker } from "./theme-controls";
import styles from "./site.module.css";

const COLUMNS: Array<{ title: string; links: Array<{ href: string; label: string; external?: boolean }> }> = [
  {
    title: appConfig.name,
    links: [
      { href: "/auth/sign-in", label: "Sign in" },
      { href: appConfig.links.docs, label: "Docs", external: true },
      { href: appConfig.links.store, label: "In the Silicon Apps store", external: true },
      ...(appConfig.links.source ? [{ href: appConfig.links.source, label: "Source code", external: true }] : []),
    ],
  },
  {
    title: "For Silicons",
    links: [
      { href: "/llms.txt", label: "llms.txt" },
      { href: "/#for-silicons", label: "Install and sign in" },
    ],
  },
  {
    title: "Silicon",
    links: [
      { href: "https://apps.teamofsilicons.com", label: "Silicon Apps", external: true },
      { href: "https://accounts.teamofsilicons.com", label: "Silicon Accounts", external: true },
      { href: "https://developers.teamofsilicons.com", label: "Silicon Developer", external: true },
    ],
  },
];

export function SiteFooter() {
  return (
    <footer className={styles.footer}>
      <div className={styles.footerInner}>
        <div className={styles.footerTop}>
          <div className={styles.footerIntro}>
            <a href="/" className={styles.footerBrand} aria-label={`${BRAND_NAME}, home`}>
              <Wordmark />
            </a>
            <p className={styles.tagline}>{appConfig.tagline}</p>
          </div>
          <nav className={styles.columns} aria-label="Footer">
            {COLUMNS.map((column, index) => (
              <section key={column.title} className={styles.column} aria-labelledby={`footer-column-${index}`}>
                <h2 id={`footer-column-${index}`}>{column.title}</h2>
                <ul role="list">
                  {column.links.map(link => (
                    <li key={link.href}>
                      <a href={link.href} className={styles.footerLink} rel={link.external ? "noopener" : undefined}>
                        {link.label}
                        {link.external ? <ArrowUpRight size={13} strokeWidth={1.75} aria-hidden="true" className={styles.externalIcon} /> : null}
                      </a>
                    </li>
                  ))}
                </ul>
              </section>
            ))}
          </nav>
        </div>
        <div className={styles.footerBottom}>
          <p className={styles.copyright}>© {new Date().getFullYear()} Team of Silicons. Sign-in by Silicon Accounts; distribution by Silicon Apps.</p>
          <ThemePicker />
        </div>
      </div>
    </footer>
  );
}
