/**
 * The public pages' footer (server-rendered), one quiet line as on Silicon Writings and the Silicon Apps store: the
 * copyright in the pixel face and a few links (the docs, the app's page in the store, what a Silicon can read here,
 * the source when the app names one).
 */
import { appConfig } from "@/lib/app.config";
import styles from "./site.module.css";

const LINKS: Array<{ href: string; label: string; external?: boolean }> = [
  { href: appConfig.links.docs, label: "Docs", external: true },
  { href: appConfig.links.store, label: "Silicon Apps", external: true },
  { href: "https://accounts.teamofsilicons.com", label: "Silicon Accounts", external: true },
  { href: "/llms.txt", label: "llms.txt" },
  ...(appConfig.links.source ? [{ href: appConfig.links.source, label: "Source", external: true }] : []),
];

export function SiteFooter() {
  return (
    <footer className={styles.footer}>
      <div className={styles.footerInner}>
        <p className={styles.copyright}>© {new Date().getFullYear()} Team of Silicons</p>
        <nav aria-label="Footer">
          <ul role="list" className={styles.footerLinks}>
            {LINKS.map(link => (
              <li key={link.label}>
                <a href={link.href} className={styles.footerLink} rel={link.external ? "noopener" : undefined}>{link.label}</a>
              </li>
            ))}
          </ul>
        </nav>
      </div>
    </footer>
  );
}
