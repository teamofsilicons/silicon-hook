/**
 * A placeholder block in the final layout's size (Arc: skeletons in the final layout, never a page spinner). Arc's
 * own <Skeleton> draws text lines; this draws any box: a card, a heading, a tile.
 *
 *   <SkeletonBlock width="min(320px, 70%)" height="44px" radius="12px" />
 */
import type { CSSProperties } from "react";
import styles from "./skeleton-block.module.css";

export interface SkeletonBlockProps {
  width?: string;
  height?: string;
  /** Base radius (a squircle). Defaults to the control radius. */
  radius?: string;
  /** Position in a group: each block pulses a beat after the previous one. */
  index?: number;
  className?: string;
}

export function SkeletonBlock({ width = "100%", height = "16px", radius, index = 0, className }: SkeletonBlockProps) {
  const style = { width, height, "--sq-r": radius ?? "var(--radius-control)", "--index": index } as CSSProperties;
  return <span data-sq="surface" className={[styles.block, className].filter(Boolean).join(" ")} style={style} aria-hidden="true" />;
}
