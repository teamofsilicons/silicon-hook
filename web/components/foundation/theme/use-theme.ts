"use client";

import { useSyncExternalStore } from "react";
import { changeTheme, currentTheme, setThemePreference, subscribeTheme, themePreference, type Theme, type ThemePreference } from "@/lib/theme";

export type { Theme, ThemePreference } from "@/lib/theme";

const serverTheme = (): Theme => "light";
const serverPreference = (): ThemePreference => "system";

/**
 * The current theme and preference, and ways to change them. The first render (server and hydration) reads "light" /
 * "system"; the stored value follows right after hydration (the boot script already painted the right one).
 *
 *   const { theme, preference, change } = useTheme();
 *   <ThemeSwitch theme={theme} variant="eclipse" onThemeChange={(next, _variant, trigger) => change(next, trigger)} />
 */
export function useTheme(): {
  theme: Theme;
  preference: ThemePreference;
  /** Animated (the eclipse from `trigger`), or instant with reduced motion. */
  change: (next: ThemePreference, trigger?: HTMLElement | null) => void;
  /** Instant, no animation. */
  set: (next: ThemePreference) => void;
} {
  const theme = useSyncExternalStore(subscribeTheme, currentTheme, serverTheme);
  const preference = useSyncExternalStore(subscribeTheme, themePreference, serverPreference);
  return { theme, preference, change: changeTheme, set: setThemePreference };
}
