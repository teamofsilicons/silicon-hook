/**
 * Escape inside a layer (Dialog, Drawer, BottomSheet, Popover) belongs to the control that has focus when that control
 * has something of its own to close: an open Combobox list, an open DatePicker calendar, an InlineEdit being edited, a
 * ConfirmMorph asking its question. Only the next Escape closes the layer.
 *
 * Radix closes its layers from a capture listener on the document, before the control's own key handler runs, so every
 * Arc layer passes its `onEscapeKeyDown` through `layerEscape` (and marks its own panel with `data-escape-layer`, where
 * the search for an inner popup stops). Pages need nothing for this; their own `onEscapeKeyDown` still runs first and
 * can keep the layer open for reasons of its own with `event.preventDefault()`.
 */

/** Marks a layer's own panel (so it is never mistaken for a popup of a control inside it). */
export const ESCAPE_LAYER_ATTRIBUTE = "data-escape-layer";

/** Controls that close something of their own on Escape while focus is in them. */
const OWN_ESCAPE = [
  // Combobox with its list open (focus stays in its input).
  '[role="combobox"][aria-expanded="true"]',
  // DatePicker's trigger (or any popup button) while its panel is open.
  '[aria-haspopup="dialog"][aria-expanded="true"]',
  '[aria-haspopup="listbox"][aria-expanded="true"]',
  // InlineEdit while editing: Escape puts the saved text back.
  "[data-editing]",
].join(", ");

/** ConfirmMorph asking its question or showing a result (Escape returns it to rest). */
const MORPH_STATES = '[data-state="confirming"], [data-state="done"], [data-state="error"]';

/** True when Escape at `target` is handled by a control inside the layer, which closes its own part first. */
export function escapeBelongsInside(target: EventTarget | null): boolean {
  if (!(target instanceof Element)) return false;
  if (target.closest(OWN_ESCAPE)) return true;
  // A ConfirmMorph's root (focused while it works or shows a result) or one of its faces. A HoldToConfirm button also
  // says data-state="done", but it has no faces and no Escape of its own.
  const morph = target.closest(MORPH_STATES);
  if (morph?.querySelector("[data-face]")) return true;
  // A popup of a control (DatePicker's calendar is a dialog inside the layer); the layer's own panel is not one.
  const dialog = target.closest('[role="dialog"]');
  return !!dialog && !dialog.hasAttribute(ESCAPE_LAYER_ATTRIBUTE);
}

/**
 * The `onEscapeKeyDown` an Arc layer gives Radix: the page's own handler first, then the layer stays open when the
 * Escape belongs to a control inside it.
 */
export function layerEscape<E extends KeyboardEvent>(own?: (event: E) => void): (event: E) => void {
  return event => {
    own?.(event);
    if (!event.defaultPrevented && escapeBelongsInside(event.target)) event.preventDefault();
  };
}
