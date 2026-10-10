"use client";

/**
 * Where focus goes when a layer (Dialog, Drawer, the command palette) closes: back to what opened it (WCAG 2.4.3).
 *
 * Radix returns focus to its own <Dialog.Trigger>. Our layers are mostly opened from plain state (a button that sets
 * `open`, a keyboard shortcut, a command), so there is no Trigger, and Radix then cancels its focus scope's own return
 * and focuses nothing: focus fell to <body> after every Escape. `useLayerOpener` remembers the element that had focus
 * when `open` turned true (read while rendering that change, before the layer mounts and a field inside it takes focus),
 * and `returnFocusTo` gives Radix an `onCloseAutoFocus` that puts focus back there.
 */
import { useState } from "react";

/** The element that has focus now, or null when nothing (the page itself) has it. */
function focusedElement(): HTMLElement | null {
  if (typeof document === "undefined") return null;
  const element = document.activeElement;
  return element instanceof HTMLElement && element !== document.body ? element : null;
}

/** The element that had focus when `open` last turned true (null until then, or when nothing had focus). */
export function useLayerOpener(open: boolean): HTMLElement | null {
  const [seen, setSeen] = useState<{ open: boolean; opener: HTMLElement | null }>({ open, opener: null });
  if (seen.open !== open) setSeen({ open, opener: open ? focusedElement() : seen.opener });
  return seen.opener;
}

/**
 * The `onCloseAutoFocus` an application layer gives Radix: the page's own handler first (it may send focus somewhere else with
 * `event.preventDefault()`), then focus goes back to the opener while it is still on the page. Focus that already
 * moved elsewhere on purpose (a page that focused its new content) stays there. Without an opener, Radix's own rule
 * applies (its Trigger).
 */
export function returnFocusTo(opener: HTMLElement | null, own?: (event: Event) => void): (event: Event) => void {
  return event => {
    own?.(event);
    if (event.defaultPrevented || !opener?.isConnected) return;
    event.preventDefault();
    const active = document.activeElement;
    const layer = event.currentTarget instanceof Node ? event.currentTarget : null;
    const lost = !active || active === document.body || (!!layer && layer.contains(active));
    if (lost && !opener.closest("[inert]")) opener.focus({ preventScroll: true });
  };
}
