/**
 * The site is light only, as Silicon Writings, the Silicon Apps store and Silicon Accounts are. The inline boot script
 * (THEME_BOOT_SCRIPT, rendered with the CSP nonce in the root layout's <head>) pins <html data-theme="light"> before
 * the first paint and marks <html data-js>, so controls that only work with script stay hidden in a browser without it.
 *
 * The functions below keep the shape the site's code reads (useTheme in components/foundation/theme/use-theme.ts): the
 * theme is always "light", and changing it does nothing but make sure light is applied.
 */
import { appConfig } from "@/lib/app.config";

export type Theme = "light" | "dark";
export type ThemePreference = Theme | "system";

/** Where the theme choice used to be stored; the boot script clears it so nothing reads a stale choice. */
export const THEME_STORAGE_KEY = `${appConfig.appId}.theme`;

export const THEME_BOOT_SCRIPT = `(function(){var r=document.documentElement;r.setAttribute("data-js","");r.setAttribute("data-theme","light");r.setAttribute("data-theme-preference","light");r.style.colorScheme="light";try{localStorage.removeItem(${JSON.stringify(THEME_STORAGE_KEY)})}catch(e){}})();`;

/** Writes the light theme onto <html>. */
export const applyTheme: (value?: Theme, pref?: ThemePreference) => void = () => {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  root.setAttribute("data-theme", "light");
  root.setAttribute("data-theme-preference", "light");
  root.style.colorScheme = "light";
};

/** The theme in use: always light. */
export const currentTheme = (): Theme => "light";

/** The preference: always light. */
export const themePreference = (): ThemePreference => "light";

/** What a preference would show: always light on this site. */
export const resolveTheme: (value: ThemePreference) => Theme = () => "light";

/** Kept for callers; the site has one theme. */
export const setThemePreference: (value: ThemePreference) => void = () => applyTheme();

/** The theme never changes, so there is nothing to subscribe to. */
export const subscribeTheme: (listener: () => void) => () => void = () => () => {};

/** Kept for callers; the site has one theme. */
export const changeTheme: (next: ThemePreference, trigger?: HTMLElement | null) => void = () => applyTheme();
