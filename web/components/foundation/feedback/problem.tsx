/**
 * One calm message in the middle of the page, for "nothing lives here", "this page stopped working" and "you cancelled
 * signing in": an icon on a squircle, a title that says what happened, a sentence that says why and what to do, and at
 * most two actions. Server-safe.
 *
 *   <Problem icon={<Compass />} title="Nothing lives at this address" actions={<ButtonLink href="/">Go home</ButtonLink>}>
 *     Check the link, or start again from the home page.
 *   </Problem>
 */
import type { ReactNode } from "react";
import styles from "./problem.module.css";

export interface ProblemProps {
  icon: ReactNode;
  title: string;
  children: ReactNode;
  actions?: ReactNode;
  /** A reference to quote in a report (an error digest or request id). */
  reference?: string | null;
  /** "page" fills the window (public pages); "inset" sits inside the workspace. */
  layout?: "page" | "inset";
  /** The heading level: h1 when this is the page's only heading. */
  as?: "h1" | "h2";
}

export function Problem({ icon, title, children, actions, reference, layout = "page", as: Heading = "h1" }: ProblemProps) {
  return (
    <div className={styles.problem} data-layout={layout}>
      <div className={styles.box}>
        <span className={styles.icon} data-sq="surface" aria-hidden="true">{icon}</span>
        <Heading className={styles.title}>{title}</Heading>
        <div className={styles.text}>{children}</div>
        {actions ? <div className={styles.actions}>{actions}</div> : null}
        {reference ? <p className={styles.reference}>Reference {reference}</p> : null}
      </div>
    </div>
  );
}
