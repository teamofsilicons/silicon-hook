/**
 * Theme manager: light, dark or system, persisted per browser. The inline boot script (THEME_BOOT_SCRIPT, rendered with
 * the CSP nonce in the root layout's <head>) applies the stored choice before the first paint; this module takes over
 * in the browser and keeps <html data-theme> in sync with the preference and the system setting.
 *
 * React reads it through `useTheme()` (components/foundation/theme/use-theme.ts), a useSyncExternalStore over this
 * store, so the server snapshot ("light", "system") renders first and the client value follows after hydration.
 */
import { motionTokens } from "@/components/silicon-ui/lib/motion-tokens";
import { appConfig } from "@/lib/app.config";

export type Theme = "light" | "dark";
export type ThemePreference = Theme | "system";

export const THEME_STORAGE_KEY = `${appConfig.appId}.theme`;

/**
 * Runs in <head> before the body paints. Kept tiny and dependency-free. It also marks <html data-js>, so controls that
 * only work with script (copy buttons) stay hidden in a browser without it.
 */
export const THEME_BOOT_SCRIPT = `(function(){var r=document.documentElement;r.setAttribute("data-js","");var p="system";try{var s=localStorage.getItem(${JSON.stringify(THEME_STORAGE_KEY)});if(s==="light"||s==="dark"||s==="system")p=s}catch(e){}var d=p==="dark"||(p==="system"&&!!window.matchMedia&&matchMedia("(prefers-color-scheme: dark)").matches);r.setAttribute("data-theme",d?"dark":"light");r.setAttribute("data-theme-preference",p);r.style.colorScheme=d?"dark":"light"})();`;

const isBrowser = typeof window !== "undefined";
const listeners = new Set<() => void>();

function readStored(): ThemePreference {
  try {
    const value = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (value === "light" || value === "dark" || value === "system") return value;
  } catch {
    // Blocked storage (private mode, disabled site data): fall back to the system theme.
  }
  return "system";
}

function writeStored(value: ThemePreference) {
  try {
    if (value === "system") window.localStorage.removeItem(THEME_STORAGE_KEY);
    else window.localStorage.setItem(THEME_STORAGE_KEY, value);
  } catch {
    // Not persisted, but still applied for this page.
  }
}

const media = isBrowser && typeof window.matchMedia === "function" ? window.matchMedia("(prefers-color-scheme: dark)") : undefined;

let preference: ThemePreference = isBrowser ? readStored() : "system";
let systemDark = media?.matches ?? false;

function resolved(): Theme {
  return preference === "system" ? (systemDark ? "dark" : "light") : preference;
}

/** Writes the resolved theme onto <html>. */
export function applyTheme(value: Theme = resolved(), pref: ThemePreference = preference): void {
  if (!isBrowser) return;
  const root = document.documentElement;
  root.setAttribute("data-theme", value);
  root.setAttribute("data-theme-preference", pref);
  root.style.colorScheme = value;
}

function emit() {
  for (const listener of listeners) listener();
}

/** The resolved theme in use right now. */
export function currentTheme(): Theme {
  return resolved();
}

/** The stored preference (light, dark or system). */
export function themePreference(): ThemePreference {
  return preference;
}

/** Resolves what `setThemePreference(value)` would show, without applying it. */
export function resolveTheme(value: ThemePreference): Theme {
  return value === "system" ? (systemDark ? "dark" : "light") : value;
}

/** Sets, persists and applies the theme preference (no animation; see changeTheme for the eclipse). */
export function setThemePreference(value: ThemePreference): void {
  preference = value;
  writeStored(value);
  applyTheme();
  emit();
}

export function subscribeTheme(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

if (isBrowser) {
  media?.addEventListener("change", event => {
    systemDark = event.matches;
    applyTheme();
    emit();
  });
  // Another tab changed the preference: follow it.
  window.addEventListener("storage", event => {
    if (event.key !== THEME_STORAGE_KEY) return;
    preference = readStored();
    applyTheme();
    emit();
  });
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* The eclipse (Arc theme-switch-eclipse)                                                                              */
/* ------------------------------------------------------------------------------------------------------------------ */

type ViewTransitionDocument = Document & {
  startViewTransition?: (update: () => void | Promise<void>) => { finished: Promise<void>; ready: Promise<void> };
};

let running = false;

function prefersReducedMotion(): boolean {
  return isBrowser && typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Changes the theme with Arc's eclipse: the next appearance crosses the page as a disc travelling from the switch,
 * like a moon passing. Runs inside a View Transition; browsers without view transitions, and anyone who prefers
 * reduced motion, get an instant change. `trigger` is the switch the person pressed (null: from the page's corner).
 */
export function changeTheme(next: ThemePreference, trigger?: HTMLElement | null): void {
  const doc = document as ViewTransitionDocument;
  const target = resolveTheme(next);
  const current = document.documentElement.getAttribute("data-theme");
  if (!doc.startViewTransition || prefersReducedMotion() || running || target === current) {
    setThemePreference(next);
    return;
  }
  const root = document.documentElement;
  const width = window.innerWidth;
  const height = window.innerHeight;
  const rect = trigger?.getBoundingClientRect();
  const cx = rect ? rect.left + rect.width / 2 : width;
  const cy = rect ? rect.top + rect.height / 2 : 0;
  // A disc as large as the viewport diagonal covers the page from any centre inside it. It starts just behind the
  // switch (its leading edge on the switch) and travels to the page centre.
  const radius = Math.hypot(width, height);
  const dx = width / 2 - cx;
  const dy = height / 2 - cy;
  const length = Math.hypot(dx, dy) || 1;
  root.style.setProperty("--eclipse-r", `${radius}px`);
  root.style.setProperty("--eclipse-x0", `${cx - (dx / length) * radius}px`);
  root.style.setProperty("--eclipse-y0", `${cy - (dy / length) * radius}px`);
  root.style.setProperty("--eclipse-x1", `${width / 2}px`);
  root.style.setProperty("--eclipse-y1", `${height / 2}px`);
  root.style.setProperty("--eclipse-duration", `${Math.round(motionTokens.duration.considered * 1500)}ms`);
  root.setAttribute("data-transition", "eclipse");
  running = true;
  const transition = doc.startViewTransition(() => setThemePreference(next));
  transition.finished.finally(() => {
    running = false;
    if (root.getAttribute("data-transition") === "eclipse") root.removeAttribute("data-transition");
    for (const name of ["--eclipse-r", "--eclipse-x0", "--eclipse-y0", "--eclipse-x1", "--eclipse-y1", "--eclipse-duration"]) root.style.removeProperty(name);
  });
}
