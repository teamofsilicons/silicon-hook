"use client";

/**
 * The public pages' one behaviour island, as on the store and the developer site (their components/site/enhancer.tsx,
 * cut to what the kit's public pages use). The pages are server-rendered HTML that works without script; this adds,
 * by delegation over the markup, so no part of the page has to hydrate:
 *
 * - copy buttons ([data-copy]): copy the block's code (or data-copy-value) and confirm for a moment;
 * - the menu (#site-menu): close it when one of its links only moves within this page.
 *
 * It renders one visually hidden status line, so a copy is announced to screen readers.
 */
import { useEffect, useState } from "react";

const COPIED_MS = 1600;

function copyText(button: HTMLElement): string {
  const value = button.getAttribute("data-copy-value");
  if (value !== null) return value;
  return button.closest("[data-docs-code]")?.querySelector("pre")?.textContent ?? "";
}

async function writeClipboard(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(text);
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.append(area);
  area.select();
  document.execCommand("copy");
  area.remove();
}

export function Enhancer() {
  const [status, setStatus] = useState("");

  useEffect(() => {
    const timers = new Map<HTMLElement, number>();
    const onClick = (event: MouseEvent) => {
      const target = event.target instanceof Element ? event.target : null;
      if (!target) return;

      const copy = target.closest<HTMLElement>("[data-copy]");
      if (copy) {
        const label = copy.getAttribute("data-label") ?? "Copy";
        writeClipboard(copyText(copy)).then(
          () => {
            copy.setAttribute("data-state", "copied");
            copy.setAttribute("aria-label", "Copied");
            setStatus("Copied to the clipboard");
          },
          () => setStatus("Could not copy: the browser refused access to the clipboard. Select the text and copy it yourself."),
        );
        window.clearTimeout(timers.get(copy));
        timers.set(copy, window.setTimeout(() => {
          copy.setAttribute("data-state", "idle");
          copy.setAttribute("aria-label", label);
          setStatus("");
        }, COPIED_MS));
        return;
      }

      // A menu link that only moves within this page leaves the page under the open menu: close it.
      const link = target.closest<HTMLAnchorElement>("#site-menu a[href]");
      if (link && link.pathname === window.location.pathname && link.hash) {
        const menu = document.getElementById("site-menu") as (HTMLElement & { hidePopover?: () => void }) | null;
        menu?.hidePopover?.();
      }
    };
    document.addEventListener("click", onClick);
    return () => {
      document.removeEventListener("click", onClick);
      for (const timer of timers.values()) window.clearTimeout(timer);
    };
  }, []);

  return <span className="sr-only" role="status" aria-live="polite">{status}</span>;
}
