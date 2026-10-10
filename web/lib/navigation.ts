/**
 * Where the workspace's sections are, from lib/app.config.ts `nav`: which one an address belongs to, and which way a
 * page transition goes between two of them (forward down the sidebar, back up it, a fade inside one section).
 */
import { appConfig, type NavItem } from "./app.config";

/** The nav item an address belongs to (the longest matching href wins), or null. */
export function navItemFor(pathname: string): NavItem | null {
  let best: NavItem | null = null;
  for (const item of appConfig.nav) {
    const match = pathname === item.href || ((item.prefix ?? true) && pathname.startsWith(`${item.href}/`));
    if (match && (!best || item.href.length > best.href.length)) best = item;
  }
  return best;
}

const indexOf = (pathname: string) => {
  const item = navItemFor(pathname);
  return item ? appConfig.nav.indexOf(item) : -1;
};

/** The view-transition type for moving between two addresses. */
export function navigationType(from: string, to: string): "nav-forward" | "nav-back" | "nav-fade" {
  const a = indexOf(from);
  const b = indexOf(to);
  if (a < 0 || b < 0 || a === b) return "nav-fade";
  return b > a ? "nav-forward" : "nav-back";
}
