/**
 * The loading stand-in for a workspace page: a header and two regions where the real ones will be, pulsing a beat
 * apart. Announced once as "Loading" (aria-busy), never as a list of shapes.
 */
import { Page } from "@/components/foundation/layout/layout";
import { SkeletonBlock } from "./skeleton-block";
import styles from "./page-skeleton.module.css";

export function PageSkeleton({ rows = 2 }: { rows?: number }) {
  return (
    <Page>
      <div className={styles.loading} aria-busy="true" aria-label="Loading">
        <div className={styles.header}>
          <SkeletonBlock width="min(280px, 70%)" height="40px" radius="12px" />
          <SkeletonBlock width="min(460px, 90%)" height="18px" radius="8px" index={1} />
        </div>
        <SkeletonBlock width="100%" height="52px" radius="var(--radius-panel)" index={2} />
        {Array.from({ length: rows }, (_, index) => (
          <SkeletonBlock key={index} width="100%" height={index === 0 ? "260px" : "140px"} radius="var(--radius-surface)" index={index + 3} />
        ))}
      </div>
    </Page>
  );
}
