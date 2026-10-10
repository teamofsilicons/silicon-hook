"use client";

/**
 * The public pages' two theme islands, the only script their header and footer carry. Both read and change the one
 * theme store (lib/theme.ts): light, dark or the system's.
 *
 * - ThemeToggle: the header's icon button (Arc's icon-only theme switch, without its motion library). It flips between
 *   light and dark with Arc's eclipse; the icon shown follows <html data-theme> in CSS, so the right one paints
 *   before hydration.
 * - ThemePicker: the footer's three-way choice (System, Light, Dark), a group of pressed buttons.
 */
import { useSyncExternalStore } from "react";
import { Monitor, Moon, Sun } from "lucide-react";
import { changeTheme, currentTheme, subscribeTheme, themePreference, type ThemePreference } from "@/lib/theme";
import styles from "./site.module.css";

const serverTheme = () => "light" as const;
const serverPreference = () => "system" as const;

export function ThemeToggle() {
  const theme = useSyncExternalStore(subscribeTheme, currentTheme, serverTheme);
  const next = theme === "light" ? "dark" : "light";
  return (
    <button
      type="button"
      className={styles.iconButton}
      data-sq="surface"
      data-theme-toggle=""
      aria-label={`Switch to ${next} mode`}
      aria-pressed={theme === "dark"}
      onClick={event => changeTheme(next, event.currentTarget)}
    >
      <Sun size={17} strokeWidth={1.75} aria-hidden="true" className={styles.sun} />
      <Moon size={17} strokeWidth={1.75} aria-hidden="true" className={styles.moon} />
    </button>
  );
}

const CHOICES: Array<{ value: ThemePreference; label: string; icon: typeof Sun }> = [
  { value: "system", label: "System", icon: Monitor },
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
];

export function ThemePicker() {
  const preference = useSyncExternalStore(subscribeTheme, themePreference, serverPreference);
  return (
    <div className={styles.picker} role="group" aria-label="Theme" data-sq="surface">
      {CHOICES.map(({ value, label, icon: Icon }) => (
        <button
          key={value}
          type="button"
          aria-pressed={preference === value}
          className={styles.pickerOption}
          data-sq="surface"
          onClick={event => changeTheme(value, event.currentTarget)}
        >
          <Icon size={14} strokeWidth={1.75} aria-hidden="true" />
          <span>{label}</span>
        </button>
      ))}
    </div>
  );
}
