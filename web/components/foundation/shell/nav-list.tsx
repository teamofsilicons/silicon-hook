"use client";

/**
 * The workspace's sections (lib/app.config.ts `nav`) and the app's outside links, as the sidebar and the phone menu
 * sheet both show them. The current section's surface glides between items on Arc's morph spring (Motion layoutId);
 * page changes slide in the direction of travel down or up the list (lib/navigation.ts).
 */
import Link from "next/link";
import { usePathname } from "next/navigation";
import { LayoutGroup, motion } from "motion/react";
import { ArrowUpRight, BookOpen, Store } from "lucide-react";
import { motionTokens } from "@/components/arc/lib/motion-tokens";
import { appConfig } from "@/lib/app.config";
import { navigationType, navItemFor } from "@/lib/navigation";
import styles from "./shell.module.css";

export function NavList({ id, onNavigate }: { id: string; onNavigate?: () => void }) {
  const pathname = usePathname();
  const current = navItemFor(pathname);
  return (
    <LayoutGroup id={id}>
      <ul role="list" className={styles.navList}>
        {appConfig.nav.map(item => {
          const active = current?.href === item.href;
          const Icon = item.icon;
          return (
            <li key={item.href}>
              <Link
                href={item.href}
                data-sq="surface"
                className={styles.navLink}
                aria-current={active ? (pathname === item.href ? "page" : "true") : undefined}
                transitionTypes={[navigationType(pathname, item.href)]}
                onClick={onNavigate}
              >
                {active ? <motion.span layoutId="nav-highlight" data-sq="surface" className={styles.navHighlight} transition={motionTokens.spring.morph} aria-hidden="true" /> : null}
                <Icon size={18} strokeWidth={1.75} aria-hidden="true" />
                <span className={styles.navLabel}>{item.label}</span>
              </Link>
            </li>
          );
        })}
      </ul>
    </LayoutGroup>
  );
}

/** The app's documentation and its page in the Silicon Apps store (they open in a new tab). */
export function OutsideLinks() {
  return (
    <div>
      <p className={styles.groupLabel}>Resources</p>
      <ul role="list" className={styles.navList}>
        <li>
          <a href={appConfig.links.docs} target="_blank" rel="noopener" data-sq="surface" className={styles.navLink}>
            <BookOpen size={18} strokeWidth={1.75} aria-hidden="true" />
            <span className={styles.navLabel}>Docs</span>
            <ArrowUpRight size={14} strokeWidth={1.75} aria-hidden="true" className={styles.external} />
            <span className="sr-only">(opens in a new tab)</span>
          </a>
        </li>
        <li>
          <a href={appConfig.links.store} target="_blank" rel="noopener" data-sq="surface" className={styles.navLink}>
            <Store size={18} strokeWidth={1.75} aria-hidden="true" />
            <span className={styles.navLabel}>In the Silicon Apps store</span>
            <ArrowUpRight size={14} strokeWidth={1.75} aria-hidden="true" className={styles.external} />
            <span className="sr-only">(opens in a new tab)</span>
          </a>
        </li>
      </ul>
    </div>
  );
}
