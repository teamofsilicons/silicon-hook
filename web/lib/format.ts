/**
 * Formatting helpers shared by every page: dates, relative times, counts, ids and spans. A fixed locale (en-US), so
 * every visitor reads the same digits; time zones are explicit. Adapted from the developer site's lib/format.ts.
 */
export type AccountKind = "carbon" | "silicon";

const LOCALE = "en-US";

function toDate(value: string | number | Date | null | undefined): Date | null {
  if (value === null || value === undefined || value === "") return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value)) {
    const [y, m, d] = value.split("-").map(Number) as [number, number, number];
    return new Date(Date.UTC(y, m - 1, d, 12));
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** "Oct 6, 2026" (date-only strings are calendar dates, never shifted by the time zone); "Not set" for none. */
export function formatDate(value: string | number | Date | null | undefined, timeZone?: string): string {
  const date = toDate(value);
  if (!date) return "Not set";
  const dateOnly = typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value);
  return new Intl.DateTimeFormat(LOCALE, { month: "short", day: "numeric", year: "numeric", timeZone: dateOnly ? "UTC" : timeZone }).format(date);
}

/** "Oct 6, 2026, 14:05" in the given time zone (the visitor's by default); "Not set" for none. */
export function formatDateTime(value: string | number | Date | null | undefined, timeZone?: string): string {
  const date = toDate(value);
  if (!date) return "Not set";
  return new Intl.DateTimeFormat(LOCALE, { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone }).format(date);
}

/** "14:05" in a time zone; "Not set" for none. */
export function formatTime(value: string | number | Date | null | undefined, timeZone?: string, seconds = false): string {
  const date = toDate(value);
  if (!date) return "Not set";
  return new Intl.DateTimeFormat(LOCALE, { hour: "2-digit", minute: "2-digit", second: seconds ? "2-digit" : undefined, hourCycle: "h23", timeZone }).format(date);
}

const UNITS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["week", 7 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
  ["second", 1],
];
const relative = new Intl.RelativeTimeFormat(LOCALE, { numeric: "auto" });

/** "2 hours ago", "in 5 minutes", "just now"; "Never" for no time at all. */
export function formatRelative(value: string | number | Date | null | undefined, now: number = Date.now()): string {
  const date = toDate(value);
  if (!date) return "Never";
  const seconds = Math.round((date.getTime() - now) / 1000);
  if (Math.abs(seconds) < 45) return "just now";
  for (const [unit, size] of UNITS) {
    if (Math.abs(seconds) >= size || unit === "second") return relative.format(Math.round(seconds / size), unit);
  }
  return relative.format(seconds, "second");
}

/** 12480 → "12,480". */
export function formatCount(value: number): string {
  return new Intl.NumberFormat(LOCALE).format(value);
}

/** "1 item", "3 items". */
export function plural(count: number, one: string, other = `${one}s`): string {
  return `${formatCount(count)} ${count === 1 ? one : other}`;
}

/** The noun for an account kind, capitalized: "Carbon" / "Silicon". */
export function kindNoun(kind: AccountKind): string {
  return kind === "carbon" ? "Carbon" : "Silicon";
}

/** Splits `c:saket` into prefix and handle for typography. */
export function splitId(id: string | null | undefined): { prefix: string; handle: string } {
  if (!id) return { prefix: "", handle: "" };
  const at = id.indexOf(":");
  return at < 0 ? { prefix: "", handle: id } : { prefix: id.slice(0, at + 1), handle: id.slice(at + 1) };
}

/** Initials for an avatar without a photo: "Ada Lovelace" → "AL", "si:scout" → "S". */
export function initialsOf(name: string): string {
  const words = name.replace(/^(c|si):/, "").split(/[\s_.-]+/).filter(Boolean);
  return words.slice(0, 2).map(word => word[0]?.toUpperCase() ?? "").join("") || "?";
}

/**
 * A wait in seconds as people say it, to the minute once it is long: "40 seconds", "5 minutes", "23 hours 37 minutes",
 * "3 days 4 hours".
 */
export function durationText(totalSeconds: number): string {
  const seconds = Math.max(0, Math.round(totalSeconds));
  const unit = (value: number, name: string) => `${value} ${name}${value === 1 ? "" : "s"}`;
  if (seconds < 90) return unit(seconds, "second");
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return unit(minutes, "minute");
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return minutes % 60 ? `${unit(hours, "hour")} ${unit(minutes % 60, "minute")}` : unit(hours, "hour");
  const days = Math.floor(hours / 24);
  return hours % 24 ? `${unit(days, "day")} ${unit(hours % 24, "hour")}` : unit(days, "day");
}

const TIMESTAMP = /\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\b/g;
const SECONDS_FROM_NOW = /\((\d+) seconds? from now\)/g;
const HOUR_MS = 3_600_000;

/**
 * Services write times into some sentences as RFC 3339 ("try again at 2026-10-16T11:01:06Z") and waits in seconds;
 * people read clock times and spans. A time within the hour reads as a time of day with seconds, one within two days
 * as a date and time, anything further as a date.
 */
export function readableTimes(message: string, options: { timeZone?: string; now?: number } = {}): string {
  const now = options.now ?? Date.now();
  return message
    .replace(TIMESTAMP, value => {
      const away = Math.abs(Date.parse(value) - now);
      if (!Number.isFinite(away)) return value;
      if (away < HOUR_MS) return formatTime(value, options.timeZone, true);
      if (away < 48 * HOUR_MS) return formatDateTime(value, options.timeZone);
      return formatDate(value, options.timeZone);
    })
    .replace(SECONDS_FROM_NOW, (_, seconds: string) => `(in ${durationText(Number(seconds))})`);
}
