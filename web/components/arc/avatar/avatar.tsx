"use client";

import Image from "next/image";
import { useLayoutEffect, useRef, useState, type HTMLAttributes } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { motionTokens } from "../lib/motion-tokens";
import styles from "./avatar.module.css";
export interface AvatarProps extends HTMLAttributes<HTMLSpanElement> { name: string; src?: string; size?: "sm" | "md" | "lg" | "xl"; status?: "online" | "offline" }
export function Avatar({ name, src, size = "md", status, className, ...props }: AvatarProps) {
  const initials = name.trim().split(/\s+/).slice(0, 2).map(part => part[0]?.toUpperCase()).join("");
  const reduceMotion = !!useReducedMotion();
  const image = useRef<HTMLImageElement>(null);
  const [failedSrc, setFailedSrc] = useState<string>();
  // A photo that is already decoded shows at once. One that is still loading waits, then fades in from a soft blur.
  useLayoutEffect(() => { const node = image.current; if (node && !node.complete) node.dataset.loading = ""; }, [src]);
  const showImage = src && failedSrc !== src;
  // Silicon Accounts: the initials are drawn (::before, from data-initials), not written into the page. They stand in
  // for a photo or logo inside role="img", whose name is the whole name; as text they also counted as words a control
  // shows, so a named link or button holding an avatar without a photo (an app tile with no logo, a member who shares
  // no photo) failed WCAG 2.5.3's name check on two letters that are part of a picture.
  return <span {...props} className={[styles.avatar, styles[size], className].filter(Boolean).join(" ")} data-sq="clip" role="img" aria-label={`${name}${status ? `, ${status}` : ""}`}>
    {showImage ? <Image key={src} ref={image} src={src} alt="" fill sizes={size === "xl" ? "88px" : size === "lg" ? "48px" : size === "md" ? "36px" : "28px"} onLoad={event => { delete event.currentTarget.dataset.loading; }} onError={() => setFailedSrc(src)} /> : <span className={[styles.initials, src ? styles.fallback : undefined].filter(Boolean).join(" ")} data-initials={initials} aria-hidden="true" />}
    <AnimatePresence initial={false}>{status && <motion.i key={status} className={[styles.status, styles[status]].join(" ")} aria-hidden="true" initial={{ opacity: 0, scale: .6 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: .6, transition: { duration: reduceMotion ? 0 : motionTokens.duration.fast } }} transition={reduceMotion ? { duration: 0 } : motionTokens.spring.snappy} />}</AnimatePresence>
  </span>;
}
