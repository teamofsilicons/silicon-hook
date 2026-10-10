/**
 * A code block on the public pages, as on the store and the developer site (silicon-apps/store/components/site and
 * developer/components/docs/code-block.tsx): Arc's code-block anatomy (a squircle panel, a header with its title and a
 * copy button, the source in the monospace face), highlighted on the server (lib/highlight.ts) so the page ships plain
 * spans. The copy button is wired by the one script island (components/site/enhancer.tsx) through its data attributes;
 * without script it stays hidden ([data-js-only]) and the command is plain, selectable text.
 */
import { Check, Copy } from "lucide-react";
import copyStyles from "@/components/silicon-ui/copy-button/copy-button.module.css";
import { highlight, languageLabel } from "@/lib/highlight";
import styles from "./code-block.module.css";

/** Arc's icon-only copy button, as markup: the island swaps data-state between idle and copied. */
export function CopyCode({ label, value }: { label: string; value?: string }) {
  return (
    <button type="button" className={`${copyStyles.button} ${copyStyles.iconOnly} ${copyStyles.plain} ${styles.copy}`} data-sq="surface" data-copy="" data-copy-value={value} data-js-only="" data-state="idle" aria-label={label} data-label={label}>
      <span className={styles.copyIcon} aria-hidden="true">
        <Copy size={16} strokeWidth={1.75} data-icon="idle" />
        <Check size={16} strokeWidth={1.75} data-icon="copied" />
      </span>
    </button>
  );
}

export function CodeBlock({ code, lang = "sh", title }: { code: string; lang?: string; title?: string }) {
  const tokens = highlight(code, lang);
  const label = languageLabel(lang);
  return (
    <figure className={styles.block} data-sq="clip" data-docs-code="">
      <figcaption className={styles.header}>
        <span className={styles.label}>
          {title ? <span className={styles.title}>{title}</span> : null}
          <span className={title ? styles.language : styles.languageOnly}>{label}</span>
        </span>
        <CopyCode label={title ? `Copy ${title}` : `Copy ${label} code`} />
      </figcaption>
      <pre className={styles.pre} tabIndex={0} aria-label={title ?? `${label} code`} data-lang={lang || undefined}>
        <code>
          {tokens.map((token, index) => (token.k ? <span key={index} className={styles[token.k]}>{token.v}</span> : token.v))}
        </code>
      </pre>
    </figure>
  );
}
