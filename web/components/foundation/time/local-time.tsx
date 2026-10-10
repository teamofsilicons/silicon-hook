"use client";

/**
 * A time as the person reading it would say it: "3 hours ago" or "Oct 10, 2026, 14:05" in their own time zone. The
 * server cannot know either (its clock and zone are not the reader's), so the page first shows the date in UTC, the
 * same on the server and in the browser, and the browser puts its own words in right after hydrating. No hydration
 * mismatch, no wrong time zone. The full time is always in the title and in <time dateTime>.
 *
 *   <LocalTime value={item.updated_at} />                   "3 hours ago"
 *   <LocalTime value={item.created_at} format="datetime" />  "Oct 10, 2026, 14:05"
 */
import { useEffect, useState, useSyncExternalStore } from "react";
import { formatDate, formatDateTime, formatRelative } from "@/lib/format";

const subscribeNothing = () => () => undefined;

/** False while rendering on the server and hydrating, true from the browser's first own render on. */
function useHydrated(): boolean {
  return useSyncExternalStore(subscribeNothing, () => true, () => false);
}

export interface LocalTimeProps {
  value: string | number | Date;
  format?: "relative" | "datetime" | "date";
  /** Words before the time ("Updated "), part of the same text. */
  prefix?: string;
  className?: string;
}

export function LocalTime({ value, format = "relative", prefix = "", className }: LocalTimeProps) {
  const hydrated = useHydrated();
  const date = new Date(value);
  // Relative words go stale: refresh them every minute while on screen.
  const [, tick] = useState(0);
  useEffect(() => {
    if (!hydrated || format !== "relative") return;
    const timer = window.setInterval(() => tick(count => count + 1), 60_000);
    return () => window.clearInterval(timer);
  }, [hydrated, format]);
  if (Number.isNaN(date.getTime())) return <span className={className}>{prefix}Not set</span>;
  const text = !hydrated ? formatDate(date, "UTC") : format === "relative" ? formatRelative(date) : format === "date" ? formatDate(date) : formatDateTime(date);
  return (
    <time dateTime={date.toISOString()} title={hydrated ? formatDateTime(date) : undefined} className={className}>
      {prefix}{text}
    </time>
  );
}
