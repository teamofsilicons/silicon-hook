"use client";

/**
 * Squircles for React. Three ways in, all built on lib/squircle/core.ts:
 *
 *   1. The attribute: `<div data-sq="surface" className={styles.card}>` (or "clip" for media). This is what the Arc
 *      components use. Native browsers need nothing else; in fallback browsers <SquircleRuntime /> (mounted once in the
 *      root providers) finds every [data-sq] element, portals included, and paints it.
 *   2. The hook: `const ref = useSquircle<HTMLDivElement>({ mode: "clip" })` for elements you create yourself, or
 *      when you need to attach before the runtime would (it is idempotent with the runtime).
 *   3. The component: `<Squircle radius="var(--radius-surface)" fill="var(--surface)" stroke="var(--border)">`.
 *
 * Style a squircled element through --sq-r / --sq-fill / --sq-stroke, never border-radius (see web/README.md).
 */
import { createElement, useCallback, useEffect, useRef, type CSSProperties, type ElementType, type HTMLAttributes, type ReactNode, type Ref } from "react";
import { attachSquircle, startSquircleRuntime, type SquircleMode, type SquircleOptions } from "@/lib/squircle/core";

export { refreshSquircles, nativeSquircles, squirclePath, type SquircleMode, type SquircleOptions } from "@/lib/squircle/core";

/** Mount once (the root providers do): paints every [data-sq] element in browsers without corner-shape. */
export function SquircleRuntime(): null {
  useEffect(() => startSquircleRuntime(), []);
  return null;
}

/**
 * A ref callback that makes its element a squircle for as long as it is mounted.
 *
 *   const ref = useSquircle<HTMLSpanElement>({ mode: "clip" });
 *   return <span ref={ref} className={styles.logo}>…</span>;
 */
export function useSquircle<T extends HTMLElement = HTMLElement>(options: SquircleOptions = {}): (el: T | null) => void {
  const mode = options.mode;
  const smoothing = options.smoothing;
  const dispose = useRef<(() => void) | null>(null);
  return useCallback((el: T | null) => {
    dispose.current?.();
    dispose.current = el ? attachSquircle(el, { mode, smoothing }) : null;
  }, [mode, smoothing]);
}

/** Props that mark an element as a squircle: spread them onto any element (`<li {...squircleProps("clip")}>`). */
export function squircleProps(mode: SquircleMode = "surface"): { "data-sq": SquircleMode } {
  return { "data-sq": mode };
}

export type SquircleProps = Omit<HTMLAttributes<HTMLElement>, "style"> & {
  /** Element to render. Defaults to a div. */
  as?: ElementType;
  /** "surface" (default) or "clip" for media. */
  mode?: SquircleMode;
  /** Base radius, any CSS length or token, for example "var(--radius-surface)" or "30%". */
  radius?: string;
  /** Background colour (sets --sq-fill). */
  fill?: string;
  /** Border colour (sets --sq-stroke). A 1px border is drawn when set. */
  stroke?: string;
  style?: CSSProperties;
  ref?: Ref<HTMLElement>;
  children?: ReactNode;
};

/**
 * A squircle surface without writing CSS:
 * `<Squircle radius="var(--radius-surface)" fill="var(--surface)" stroke="var(--border)">…</Squircle>`.
 * For state-driven colours, style a class with the --sq-* variables instead.
 */
export function Squircle({ as = "div", mode = "surface", radius, fill, stroke, style, children, ...rest }: SquircleProps) {
  const merged = {
    ...(radius ? { "--sq-r": radius } : {}),
    ...(fill ? { "--sq-fill": fill, background: "var(--sq-fill)" } : {}),
    ...(stroke ? { "--sq-stroke": stroke, border: "1px solid var(--sq-stroke)" } : {}),
    ...style,
  } as CSSProperties;
  return createElement(as, { ...rest, "data-sq": mode, style: merged }, children);
}
