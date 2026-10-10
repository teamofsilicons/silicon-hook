"use client";

/**
 * The signed-in workspace's frame: the sidebar (the app's mark and name, its sections, its docs and store page), a
 * sticky top bar (the current section, ⌘K search, the theme switch and the account menu), the page, and the ⌘K palette.
 * Below 900 px the sidebar folds into a menu sheet opened from the top bar. Page changes slide along the sections.
 *
 * The workspace layout (a Server Component) has already checked the session, so the shell renders signed in from its
 * first frame: no loading flash, no client-side "who am I" request.
 */
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ViewTransition, useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import { BookOpen, CircleUserRound, LogOut, Menu, Monitor, Moon, Search, Sun } from "lucide-react";
import { Drawer, DrawerContent } from "@/components/arc/drawer/drawer";
import { ThemeSwitch } from "@/components/arc/theme-switch/theme-switch";
import { BRAND_NAME, Wordmark } from "@/components/foundation/brand/app-mark";
import { useTheme } from "@/components/foundation/theme/use-theme";
import type { SessionAccount } from "@/lib/account";
import { appConfig } from "@/lib/app.config";
import { useSignOut } from "@/lib/client/session";
import { openCommandPalette, toggleCommandPalette, useRegisterCommands } from "@/lib/commands";
import { navigationType, navItemFor } from "@/lib/navigation";
import { notifyError } from "@/lib/notify";
import { changeTheme } from "@/lib/theme";
import { AccountMenu } from "./account-menu";
import { CommandMenu } from "./command-menu";
import { NavList, OutsideLinks } from "./nav-list";
import styles from "./shell.module.css";

const subscribeNothing = () => () => undefined;

function detectApple(): boolean {
  const nav = navigator as Navigator & { userAgentData?: { platform?: string } };
  return /mac|iphone|ipad|ipod/i.test(nav.userAgentData?.platform ?? nav.platform ?? "");
}

const PAGE_CLASSES = { "nav-forward": "page-forward", "nav-back": "page-back", "nav-fade": "page-fade", default: "page-fade" };

export interface AppShellProps {
  account: SessionAccount;
  /** Silicon Accounts' public origin: "Your account" opens it. */
  accountsUrl: string;
  children: ReactNode;
}

export function AppShell({ account, accountsUrl, children }: AppShellProps) {
  const pathname = usePathname();
  const router = useRouter();
  const { theme, change } = useTheme();
  const { signOut } = useSignOut();
  const isApple = useSyncExternalStore(subscribeNothing, detectApple, () => false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const section = navItemFor(pathname);
  const SectionIcon = section?.icon;

  // The top bar shows a hairline once the page scrolls under it.
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 4);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // ⌘K (Ctrl K) toggles the palette.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && !event.altKey && !event.shiftKey && event.key.toLowerCase() === "k") {
        event.preventDefault();
        toggleCommandPalette();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  useRegisterCommands(() => [
    ...appConfig.nav.map(item => {
      const Icon = item.icon;
      return { id: `go.${item.href}`, label: item.label, group: "Go to", icon: <Icon size={16} strokeWidth={1.75} />, keywords: item.keywords, run: () => router.push(item.href, { transitionTypes: [navigationType(window.location.pathname, item.href)] }) };
    }),
    { id: "go.docs", label: `${appConfig.name} docs`, description: "Opens in a new tab", group: "Go to", icon: <BookOpen size={16} strokeWidth={1.75} />, keywords: ["docs", "help", "guide"], run: () => void window.open(appConfig.links.docs, "_blank", "noopener") },
    { id: "go.account", label: "Your account", description: "Silicon Accounts, in a new tab", group: "Go to", icon: <CircleUserRound size={16} strokeWidth={1.75} />, keywords: ["account", "profile", "photo"], run: () => void window.open(accountsUrl, "_blank", "noopener") },
    { id: "theme.light", label: "Use the light theme", group: "Appearance", icon: <Sun size={16} strokeWidth={1.75} />, keywords: ["theme", "light"], run: () => changeTheme("light", null) },
    { id: "theme.dark", label: "Use the dark theme", group: "Appearance", icon: <Moon size={16} strokeWidth={1.75} />, keywords: ["theme", "dark", "night"], run: () => changeTheme("dark", null) },
    { id: "theme.system", label: "Match the device theme", group: "Appearance", icon: <Monitor size={16} strokeWidth={1.75} />, keywords: ["theme", "system", "auto"], run: () => changeTheme("system", null) },
    { id: "account.signout", label: "Sign out", description: `Sign this browser out of ${appConfig.name}`, group: "Account", icon: <LogOut size={16} strokeWidth={1.75} />, keywords: ["logout", "log out", "sign out"], run: () => void signOut().catch(failure => notifyError(failure, "Could not sign out")) },
  ], [router, accountsUrl, signOut]);

  return (
    <div className={styles.shell}>
      <a className="skip-link" data-sq="surface" href="#main">Skip to content</a>
      <div className={styles.rail} data-vt="sidebar">
        <aside className={styles.sidebar} aria-label={`${appConfig.name} navigation`}>
          <div className={styles.sidebarHead}>
            <Link href={appConfig.home} data-sq="surface" className={styles.brand} aria-label={`${BRAND_NAME}, home`}>
              <Wordmark />
            </Link>
          </div>
          <nav className={styles.nav} aria-label={appConfig.name}>
            <NavList id="sidebar" />
            <OutsideLinks />
          </nav>
          <div className={styles.sidebarFoot}>
            Signed in with <a href={accountsUrl} target="_blank" rel="noopener">Silicon Accounts</a>
          </div>
        </aside>
      </div>

      <div className={styles.column}>
        <header className={styles.top} data-vt="topbar" data-scrolled={scrolled ? "" : undefined}>
          <div className={styles.topStart}>
            <button type="button" data-sq="surface" className={`${styles.iconButton} ${styles.menuButton}`} onClick={() => setMenuOpen(true)} aria-label="Open the menu" aria-expanded={menuOpen}>
              <Menu size={20} strokeWidth={1.75} aria-hidden="true" />
            </button>
            <Link href={appConfig.home} data-sq="surface" className={`${styles.brand} ${styles.mobileBrand}`} aria-label={`${BRAND_NAME}, home`}>
              <Wordmark />
            </Link>
            {section && SectionIcon ? (
              <span className={styles.section}>
                <SectionIcon size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>{section.label}</span>
              </span>
            ) : null}
          </div>
          <div className={styles.topEnd}>
            <button data-sq="surface" type="button" className={styles.search} onClick={openCommandPalette} aria-keyshortcuts={isApple ? "Meta+K" : "Control+K"}>
              <Search size={16} strokeWidth={1.75} aria-hidden="true" />
              <span className={styles.searchLabel}>Search and jump</span>
              <kbd data-sq="surface">{isApple ? "⌘ K" : "Ctrl K"}</kbd>
            </button>
            <span className={styles.tool}>
              <ThemeSwitch theme={theme} variant="eclipse" iconOnly onThemeChange={(next, _variant, trigger) => change(next, trigger)} />
            </span>
            <AccountMenu account={account} accountsUrl={accountsUrl} isApple={isApple} />
          </div>
        </header>

        <main id="main" className={styles.main} tabIndex={-1}>
          <ViewTransition key={section?.href ?? pathname} enter={PAGE_CLASSES} exit={PAGE_CLASSES} default="none">
            <div className={styles.page}>{children}</div>
          </ViewTransition>
        </main>
      </div>

      <Drawer open={menuOpen} onOpenChange={setMenuOpen}>
        <DrawerContent side="left" title={appConfig.name} description={appConfig.tagline} className={styles.sheet}>
          <nav className={styles.sheetNav} aria-label={`${appConfig.name} menu`}>
            <NavList id="sheet" onNavigate={() => setMenuOpen(false)} />
            <OutsideLinks />
          </nav>
          <p className={styles.sheetFoot}>Signed in as {account.id} with Silicon Accounts.</p>
        </DrawerContent>
      </Drawer>
      <CommandMenu />
    </div>
  );
}
