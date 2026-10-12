/**
 * The app's mark: the mark of its logo (lib/app-logo.ts `LOGO_MARK`) in ink, beside the name in the pixel face, as
 * Silicon Writings, Silicon Apps and Silicon Accounts draw theirs. The icons (app/icon.tsx, app/apple-icon.tsx) and the
 * Open Graph image draw the whole logo, the mark in #181818 on a cream square (lib/brand-svg.ts).
 * Plain SVG, server-rendered, shared by the landing page, the sign-in page and the signed-in shell.
 *
 *   <AppMark />                 the bare glyph at 22 px
 *   <AppMark size={40} />       larger
 *   <Wordmark />                the glyph and the app's name
 */
import type { CSSProperties } from "react";
import { appConfig } from "@/lib/app.config";
import { LOGO_MARK } from "@/lib/app-logo";
import styles from "./app-mark.module.css";

/** The mark alone, in the text colour. `strokeWidth` is kept for callers; the logo's own weights are drawn as they are. */
export function AppGlyph({ size = 18 }: { size?: number; strokeWidth?: number }) {
  return (
    <svg viewBox={LOGO_MARK.viewBox} width={size} height={size} aria-hidden="true" focusable="false" dangerouslySetInnerHTML={{ __html: LOGO_MARK.body }} />
  );
}

export function AppMark({ size = 22, className }: { size?: number; className?: string }) {
  const style = { "--mark-size": `${size}px` } as CSSProperties;
  return (
    <span className={[styles.mark, className].filter(Boolean).join(" ")} style={style} aria-hidden="true">
      <AppGlyph size={size} strokeWidth={size >= 36 ? 1.75 : 2} />
    </span>
  );
}

/** The wordmark's words ("Silicon Remind"): a link that shows the wordmark is named with them first (WCAG 2.5.3). */
export const BRAND_NAME = appConfig.brandPrefix ? `${appConfig.brandPrefix} ${appConfig.name}` : appConfig.name;

/** The glyph and the app's name in the pixel face ("Silicon Remind"), as the bars show it. */
export function Wordmark({ size = 22, className }: { size?: number; className?: string }) {
  return (
    <span className={[styles.wordmark, className].filter(Boolean).join(" ")}>
      <AppMark size={size} />
      <span className={styles.name}>{BRAND_NAME}</span>
    </span>
  );
}
