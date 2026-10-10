/**
 * Squircles (superellipse corners) for every rounded surface. Framework-free: the React hook and component
 * (components/foundation/squircle) and the auto-attaching runtime build on it.
 *
 * Two paths, chosen once per page:
 *  1. Native: browsers with `corner-shape` (Chromium 139+, current Safari) get `corner-shape: squircle` with the radius
 *     scaled by --sq-k (1.6, which matches Figma's 60 % corner smoothing). Backgrounds, borders, shadows and overflow
 *     clipping all follow the curve, and no script runs: styles/squircle.css does everything from [data-sq].
 *  2. Fallback (Firefox, older Safari): a Figma-style smoothed corner path is computed for the element's size (one
 *     shared ResizeObserver, recomputed only when the size changes) and painted with two pseudo-elements: ::before
 *     fills the curve with --sq-fill, ::after draws the border ring (outer path minus inner path, evenodd) with
 *     --sq-stroke. The element's own background and border colour go transparent and an outer box-shadow becomes a
 *     drop-shadow filter, so fill, border and shadow all follow the curve. Media (mode "clip") is clipped with
 *     clip-path instead. Nothing here changes layout, so there is no shift.
 *
 * Styling contract for a squircled element (see web/README.md):
 *   data-sq="surface" | "clip"   marks the element (server-rendered, so the native path paints on first frame)
 *   --sq-r       base radius (e.g. var(--radius-control), 30 %). Do not set border-radius yourself.
 *   --sq-fill    background colour. Use `background: var(--sq-fill)` and change the variable per state.
 *   --sq-stroke  border colour. Use `border: 1px solid var(--sq-stroke)` and change the variable per state.
 * Do not use ::before/::after on a squircled element, and keep `overflow: visible` on "surface" elements when the
 * border must sit exactly on the edge (an element that clips overflow draws its ring 1px inside the edge instead).
 */

export type SquircleMode = "surface" | "clip";

export interface SquircleOptions {
  /** "surface" (default): fill + border follow the curve. "clip": clip the element and its content (avatars, logos). */
  mode?: SquircleMode;
  /** Corner smoothing for the fallback path, 0 to 1. Defaults to 0.6 (Figma's iOS-like smoothing). */
  smoothing?: number;
}

const isBrowser = typeof window !== "undefined" && typeof document !== "undefined";

/**
 * Debug switch: `?squircle=fallback` forces the SVG-path fallback in browsers that support corner-shape, so the
 * Firefox path can be reviewed in Chromium (the attribute also turns off the native CSS rule).
 */
function readForcedFallback(): boolean {
  if (!isBrowser) return false;
  try {
    if (new URLSearchParams(window.location.search).get("squircle") !== "fallback") return false;
  } catch {
    return false;
  }
  document.documentElement.setAttribute("data-squircle-fallback", "");
  return true;
}

let nativeCache: boolean | undefined;

/** True when the browser draws squircles natively with `corner-shape` (false on the server). */
export function nativeSquircles(): boolean {
  if (nativeCache !== undefined) return nativeCache;
  if (!isBrowser) return false;
  const forced = readForcedFallback();
  nativeCache = !forced && typeof CSS !== "undefined" && typeof CSS.supports === "function" && CSS.supports("corner-shape", "squircle");
  return nativeCache;
}

/**
 * How much the native path scales --sq-r (--sq-k, 1.6) so a native squircle matches the fallback's size; 1 in the
 * fallback and on the server. For script that animates a squircled element's border-radius in pixels (Arc Card's
 * morph): multiply token radii by this so the corners land where the CSS puts them.
 */
export function squircleRadiusScale(el?: Element | null): number {
  if (!nativeSquircles()) return 1;
  const raw = el ? getComputedStyle(el).getPropertyValue("--sq-k").trim() : "";
  const k = parseFloat(raw);
  return Number.isFinite(k) && k > 0 ? k : 1.6;
}

/**
 * Replaced and void elements (inputs, textareas, images…) cannot host the ::before/::after layers the fallback paints
 * with, and making their own paint transparent would erase them. In the fallback they keep plain rounded corners.
 */
const REPLACED = new Set(["INPUT", "TEXTAREA", "SELECT", "IMG", "VIDEO", "CANVAS", "IFRAME", "OBJECT", "EMBED"]);

const round = (value: number) => Math.round(value * 100) / 100;
const rad = (degrees: number) => (degrees * Math.PI) / 180;

interface CornerParams {
  a: number;
  b: number;
  c: number;
  d: number;
  p: number;
  arc: number;
  radius: number;
}

/** Corner geometry from Figma's "Desperately seeking squircles" construction (as in the figma-squircle package). */
function cornerParams(radius: number, smoothing: number, budget: number): CornerParams {
  let p = (1 + smoothing) * radius;
  // Not enough room for the full smoothing: reduce the smoothing first, the way Figma does without "preserve smoothing".
  if (p > budget) {
    const maxSmoothing = budget / radius - 1;
    smoothing = Math.max(0, Math.min(smoothing, maxSmoothing));
    p = Math.min(p, budget);
  }
  const arcMeasure = 90 * (1 - smoothing);
  const arc = Math.sin(rad(arcMeasure / 2)) * radius * Math.SQRT2;
  const alpha = (90 - arcMeasure) / 2;
  const p3ToP4 = radius * Math.tan(rad(alpha / 2));
  const beta = 45 * smoothing;
  const c = p3ToP4 * Math.cos(rad(beta));
  const d = c * Math.tan(rad(beta));
  const b = (p - arc - c - d) / 3;
  const a = 2 * b;
  return { a, b, c, d, p, arc, radius };
}

export type Radii = readonly [number, number, number, number];

export interface SquirclePathInput {
  width: number;
  height: number;
  /** One radius, or per corner: [top-left, top-right, bottom-right, bottom-left]. */
  radius: number | Radii;
  smoothing?: number;
  x?: number;
  y?: number;
}

/** An SVG path for a smoothed rounded rectangle. Coordinates are absolute, so paths can be combined (rings). */
export function squirclePath({ width, height, radius, smoothing = 0.6, x = 0, y = 0 }: SquirclePathInput): string {
  if (width <= 0 || height <= 0) return "";
  const budget = Math.min(width, height) / 2;
  const radii = (typeof radius === "number" ? [radius, radius, radius, radius] : radius).map(r => Math.max(0, Math.min(r, budget)));
  const [tl, tr, br, bl] = radii.map(r => (r > 0 ? cornerParams(r, smoothing, budget) : null)) as [CornerParams | null, CornerParams | null, CornerParams | null, CornerParams | null];
  const n = round;
  const right = x + width;
  const bottom = y + height;
  const out: string[] = [];
  out.push(`M${n(right - (tr?.p ?? 0))} ${n(y)}`);
  if (tr) out.push(
    `c${n(tr.a)} 0 ${n(tr.a + tr.b)} 0 ${n(tr.a + tr.b + tr.c)} ${n(tr.d)}`,
    `a${n(tr.radius)} ${n(tr.radius)} 0 0 1 ${n(tr.arc)} ${n(tr.arc)}`,
    `c${n(tr.d)} ${n(tr.c)} ${n(tr.d)} ${n(tr.b + tr.c)} ${n(tr.d)} ${n(tr.a + tr.b + tr.c)}`,
  );
  out.push(`L${n(right)} ${n(bottom - (br?.p ?? 0))}`);
  if (br) out.push(
    `c0 ${n(br.a)} 0 ${n(br.a + br.b)} ${n(-br.d)} ${n(br.a + br.b + br.c)}`,
    `a${n(br.radius)} ${n(br.radius)} 0 0 1 ${n(-br.arc)} ${n(br.arc)}`,
    `c${n(-br.c)} ${n(br.d)} ${n(-(br.b + br.c))} ${n(br.d)} ${n(-(br.a + br.b + br.c))} ${n(br.d)}`,
  );
  out.push(`L${n(x + (bl?.p ?? 0))} ${n(bottom)}`);
  if (bl) out.push(
    `c${n(-bl.a)} 0 ${n(-(bl.a + bl.b))} 0 ${n(-(bl.a + bl.b + bl.c))} ${n(-bl.d)}`,
    `a${n(bl.radius)} ${n(bl.radius)} 0 0 1 ${n(-bl.arc)} ${n(-bl.arc)}`,
    `c${n(-bl.d)} ${n(-bl.c)} ${n(-bl.d)} ${n(-(bl.b + bl.c))} ${n(-bl.d)} ${n(-(bl.a + bl.b + bl.c))}`,
  );
  out.push(`L${n(x)} ${n(y + (tl?.p ?? 0))}`);
  if (tl) out.push(
    `c0 ${n(-tl.a)} 0 ${n(-(tl.a + tl.b))} ${n(tl.d)} ${n(-(tl.a + tl.b + tl.c))}`,
    `a${n(tl.radius)} ${n(tl.radius)} 0 0 1 ${n(tl.arc)} ${n(-tl.arc)}`,
    `c${n(tl.c)} ${n(-tl.d)} ${n(tl.b + tl.c)} ${n(-tl.d)} ${n(tl.a + tl.b + tl.c)} ${n(-tl.d)}`,
  );
  out.push("Z");
  return out.join("");
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* Fallback painter                                                                                                    */
/* ------------------------------------------------------------------------------------------------------------------ */

interface Entry {
  el: HTMLElement;
  mode: SquircleMode;
  smoothing: number;
  captured: boolean;
  width: number;
  height: number;
  key: string;
}

const entries = new Map<Element, Entry>();
let observer: ResizeObserver | undefined;

function parseRadius(value: string, width: number, height: number): number {
  const first = value.trim().split(/\s+/)[0] ?? "0";
  const amount = parseFloat(first);
  if (!Number.isFinite(amount)) return 0;
  return first.endsWith("%") ? (amount / 100) * Math.min(width, height) : amount;
}

const TRANSPARENT = /^(transparent|rgba\(0,\s*0,\s*0,\s*0\))$/;

let resolvedCache: boolean | undefined;
/** True when the browser resolves the registered --sq-fill-c / --sq-stroke-c colours (CSS @property support). */
function resolvedVariables(): boolean {
  if (resolvedCache === undefined) resolvedCache = typeof CSS !== "undefined" && typeof (CSS as { registerProperty?: unknown }).registerProperty === "function";
  return resolvedCache;
}

/**
 * An outer box-shadow as the equivalent drop-shadow() chain (a drop-shadow blur is a standard deviation, half a
 * box-shadow blur radius). Null when there is no shadow or it cannot be expressed (inset layers).
 */
export function dropShadowFrom(boxShadow: string): string | null {
  if (!boxShadow || boxShadow === "none") return null;
  // Split on commas outside parentheses.
  const layers: string[] = [];
  let depth = 0;
  let start = 0;
  for (let index = 0; index < boxShadow.length; index++) {
    const char = boxShadow[index];
    if (char === "(") depth++;
    else if (char === ")") depth--;
    else if (char === "," && depth === 0) {
      layers.push(boxShadow.slice(start, index));
      start = index + 1;
    }
  }
  layers.push(boxShadow.slice(start));
  const out: string[] = [];
  for (const raw of layers) {
    const layer = raw.trim();
    if (!layer) continue;
    if (/\binset\b/.test(layer)) return null;
    const color = /(rgba?\([^)]*\)|oklch\([^)]*\)|oklab\([^)]*\)|color-mix\(.*\)|#[0-9a-f]{3,8}\b)/i.exec(layer)?.[1];
    const lengths = layer.replace(color ?? "", "").trim().split(/\s+/).map(token => parseFloat(token)).filter(Number.isFinite);
    const [x = 0, y = 0, blur = 0] = lengths;
    if (!color) continue;
    out.push(`drop-shadow(${round(x)}px ${round(y)}px ${round(blur / 2)}px ${color})`);
  }
  return out.length ? out.join(" ") : null;
}

/** A planned paint: everything read from the DOM first, so a batch of elements causes one style pass, not one each. */
type Plan =
  | { kind: "skip" }
  | { kind: "clear" }
  | { kind: "paint"; mode: SquircleMode; vars: Record<string, string>; makeRelative: boolean; shadow: string | null };

/**
 * Reads what one element's fallback needs and computes its paths. Read-only: writes happen in `apply`, after every
 * element of the batch has been read, so the browser never has to lay the page out between elements.
 * Elements styled the plain way (background / border-color instead of the --sq-* variables) still render: their
 * computed colours are copied into the variables once (state changes then do not follow; use the variables).
 */
function plan(entry: Entry): Plan {
  const { el, width, height } = entry;
  if (!el.isConnected || width <= 0 || height <= 0) return { kind: "skip" };
  const corner = el.closest("[data-corner]")?.getAttribute("data-corner");
  if (corner === "rounded" || corner === "sharp") {
    entry.key = "";
    return { kind: "clear" };
  }
  const style = getComputedStyle(el);
  const vars: Record<string, string> = {};
  if (!entry.captured) {
    entry.captured = true;
    const fill = style.backgroundColor;
    const stroke = parseFloat(style.borderTopWidth) > 0 ? style.borderTopColor : "";
    if (resolvedVariables()) {
      // --sq-fill and --sq-stroke inherit (the pseudo-elements read them), so an element can carry its ancestor's
      // values (a plain-styled chip inside a card). styles/squircle.css resolves both into registered <color>
      // properties; whenever what the element paints differs from them, the painted colour wins.
      if (fill && fill !== style.getPropertyValue("--sq-fill-c").trim()) vars["--sq-fill"] = fill;
      if (stroke && stroke !== style.getPropertyValue("--sq-stroke-c").trim()) vars["--sq-stroke"] = stroke;
    } else {
      if (!style.getPropertyValue("--sq-fill").trim() && fill && !TRANSPARENT.test(fill)) vars["--sq-fill"] = fill;
      if (!style.getPropertyValue("--sq-stroke").trim() && stroke && !TRANSPARENT.test(stroke)) vars["--sq-stroke"] = stroke;
    }
  }
  const border = parseFloat(style.borderTopWidth) || 0;
  const radii = [style.borderTopLeftRadius, style.borderTopRightRadius, style.borderBottomRightRadius, style.borderBottomLeftRadius]
    .map(value => parseRadius(value, width, height)) as unknown as [number, number, number, number];
  const uniform = radii.every(r => r === radii[0]);
  const radius = radii[0];
  const clips = style.overflowX !== "visible" || style.overflowY !== "visible";
  const shadow = entry.mode === "surface" ? dropShadowFrom(style.boxShadow) : null;
  const key = `${width}x${height}:${radii.join(",")}:${border}:${clips}:${entry.mode}:${shadow ?? ""}`;
  if (key === entry.key && !Object.keys(vars).length) return { kind: "skip" };
  entry.key = key;
  const makeRelative = style.position === "static";
  const s = entry.smoothing;
  const less = (by: number): number | Radii => (uniform ? Math.max(0, radius - by) : (radii.map(r => Math.max(0, r - by)) as unknown as Radii));
  if (entry.mode === "clip") {
    // clip-path uses the border box; the ring sits inside the padding box so overflow clipping can never hide it.
    const outer = squirclePath({ width, height, radius: uniform ? radius : radii, smoothing: s });
    const pw = width - 2 * border;
    const ph = height - 2 * border;
    const ringOuter = squirclePath({ width: pw, height: ph, radius: less(border), smoothing: s });
    const ringInner = squirclePath({ x: border, y: border, width: pw - 2 * border, height: ph - 2 * border, radius: less(2 * border), smoothing: s });
    vars["--sq-path"] = `path("${outer}")`;
    vars["--sq-ring"] = border > 0 ? `path(evenodd, "${ringOuter} ${ringInner}")` : "inset(50%)";
    vars["--sq-inset"] = "0px";
    return { kind: "paint", mode: "clip", vars, makeRelative, shadow: null };
  }
  // Surface: paint the border box when nothing clips; otherwise the padding box (overflow would cut the border area).
  const inset = clips ? 0 : -border;
  const w = clips ? width - 2 * border : width;
  const h = clips ? height - 2 * border : height;
  const r = clips ? less(border) : uniform ? radius : radii;
  const outer = squirclePath({ width: w, height: h, radius: r, smoothing: s });
  const inner = squirclePath({ x: border, y: border, width: w - 2 * border, height: h - 2 * border, radius: clips ? less(2 * border) : less(border), smoothing: s });
  vars["--sq-inset"] = `${inset}px`;
  vars["--sq-path"] = `path("${outer}")`;
  vars["--sq-ring"] = border > 0 ? `path(evenodd, "${outer} ${inner}")` : "inset(50%)";
  if (shadow) vars["--sq-drop"] = shadow;
  return { kind: "paint", mode: "surface", vars, makeRelative, shadow };
}

function clearFallback(el: HTMLElement) {
  el.removeAttribute("data-sq-fb");
  el.removeAttribute("data-sq-shadow");
  for (const name of ["--sq-path", "--sq-ring", "--sq-inset", "--sq-drop"]) el.style.removeProperty(name);
}

function apply(entry: Entry, planned: Plan) {
  const el = entry.el;
  if (planned.kind === "skip") return;
  if (planned.kind === "clear") return clearFallback(el);
  if (planned.makeRelative) el.style.position = "relative";
  for (const [name, value] of Object.entries(planned.vars)) el.style.setProperty(name, value);
  if (planned.shadow) el.setAttribute("data-sq-shadow", "");
  else el.removeAttribute("data-sq-shadow");
  el.setAttribute("data-sq-fb", planned.mode);
}

/** Reads every entry, then writes every entry. */
function paintAll(batch: Entry[]) {
  const plans = batch.map(entry => [entry, plan(entry)] as const);
  for (const [entry, planned] of plans) apply(entry, planned);
}

function ensureObserver(): ResizeObserver | undefined {
  if (observer || typeof ResizeObserver === "undefined") return observer;
  observer = new ResizeObserver(records => {
    const batch: Entry[] = [];
    for (const record of records) {
      const entry = entries.get(record.target);
      if (!entry) continue;
      const box = record.borderBoxSize?.[0];
      entry.width = round(box ? box.inlineSize : (record.target as HTMLElement).offsetWidth);
      entry.height = round(box ? box.blockSize : (record.target as HTMLElement).offsetHeight);
      batch.push(entry);
    }
    paintAll(batch);
  });
  return observer;
}

function modeOf(el: Element, fallback: SquircleMode = "surface"): SquircleMode {
  const value = el.getAttribute("data-sq");
  return value === "clip" ? "clip" : value === "surface" ? "surface" : fallback;
}

/**
 * Makes `el` a squircle and returns a disposer. Safe to call before the element is measured: the attribute applies at
 * once (the native path needs nothing else), and the fallback path is computed when the element is first measured.
 * Calling it twice for the same element keeps one registration.
 */
export function attachSquircle(el: HTMLElement, options: SquircleOptions = {}): () => void {
  const mode = options.mode ?? modeOf(el);
  if (el.getAttribute("data-sq") !== mode) el.setAttribute("data-sq", mode);
  if (nativeSquircles() || (mode === "surface" && REPLACED.has(el.tagName))) return () => undefined;
  const ro = ensureObserver();
  if (!ro) return () => undefined;
  const existing = entries.get(el);
  if (existing) {
    existing.mode = mode;
    existing.key = "";
    return () => detachSquircle(el);
  }
  const entry: Entry = { el, mode, smoothing: options.smoothing ?? 0.6, captured: false, width: 0, height: 0, key: "" };
  entries.set(el, entry);
  ro.observe(el, { box: "border-box" });
  return () => detachSquircle(el);
}

/** Stops painting `el`'s fallback (the data-sq attribute stays, so the native rule and the CSS radius still apply). */
export function detachSquircle(el: HTMLElement): void {
  if (!entries.has(el)) return;
  observer?.unobserve(el);
  entries.delete(el);
  clearFallback(el);
}

/** Recomputes fallback squircles inside `root` (for example after branding switches corner style). No-op natively. */
export function refreshSquircles(root: Element | Document = document): void {
  if (nativeSquircles()) return;
  const batch: Entry[] = [];
  for (const entry of entries.values()) {
    if (root === document || (root as Element).contains(entry.el)) {
      entry.key = "";
      batch.push(entry);
    }
  }
  paintAll(batch);
}

/* ------------------------------------------------------------------------------------------------------------------ */
/* Runtime: every [data-sq] element in the document gets the fallback, including portals, without refs               */
/* ------------------------------------------------------------------------------------------------------------------ */

let runtime: MutationObserver | null = null;
let runtimeUsers = 0;

function scan(node: Node, attach: boolean) {
  if (!(node instanceof HTMLElement)) return;
  const found: HTMLElement[] = node.matches("[data-sq]") ? [node] : [];
  for (const el of node.querySelectorAll<HTMLElement>("[data-sq]")) found.push(el);
  for (const el of found) {
    if (attach) attachSquircle(el, { mode: modeOf(el) });
    else if (!el.isConnected) detachSquircle(el);
  }
}

/**
 * Starts the document-wide runtime (fallback browsers only): every element with [data-sq] that is or becomes part of
 * the document is painted, and removed elements are released. Returns a stop function; nested starts share one
 * observer. Arc components only need the attribute, never a ref.
 */
export function startSquircleRuntime(): () => void {
  if (!isBrowser || nativeSquircles() || typeof MutationObserver === "undefined") return () => undefined;
  runtimeUsers += 1;
  if (!runtime) {
    scan(document.documentElement, true);
    runtime = new MutationObserver(records => {
      for (const record of records) {
        if (record.type === "attributes") {
          const target = record.target as HTMLElement;
          if (target.hasAttribute("data-sq")) attachSquircle(target, { mode: modeOf(target) });
          else detachSquircle(target);
          continue;
        }
        for (const node of record.addedNodes) scan(node, true);
        for (const node of record.removedNodes) scan(node, false);
      }
    });
    runtime.observe(document.documentElement, { subtree: true, childList: true, attributes: true, attributeFilter: ["data-sq"] });
  }
  return () => {
    runtimeUsers = Math.max(0, runtimeUsers - 1);
    if (runtimeUsers === 0 && runtime) {
      runtime.disconnect();
      runtime = null;
    }
  };
}
