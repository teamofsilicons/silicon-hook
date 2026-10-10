/**
 * A link that looks like an Arc button: navigation goes through a link, never a button with a router push (Arc
 * components.md). Same variants and sizes as <Button>, the same squircle, and the hosted pages' button styles
 * (data-variant) apply.
 *
 *   <ButtonLink href={paths.signIn} size="lg">Sign in</ButtonLink>
 *   <ButtonLink href="https://apps.teamofsilicons.com" variant="secondary" external>Make an app</ButtonLink>
 */
import Link from "next/link";
import type { AnchorHTMLAttributes, ReactNode } from "react";
import buttonStyles from "@/components/arc/button/button.module.css";
import type { ButtonSize, ButtonVariant } from "@/components/arc/button/button";
import styles from "./button-link.module.css";

export interface ButtonLinkProps extends Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href"> {
  href: string;
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** A plain <a> for other sites (no client-side navigation, no prefetch). */
  external?: boolean;
  children: ReactNode;
}

export function ButtonLink({ href, variant = "primary", size = "md", external, className, children, ...rest }: ButtonLinkProps) {
  const classes = [buttonStyles.button, buttonStyles[variant], buttonStyles[size], styles.link, className].filter(Boolean).join(" ");
  const content = <span className={styles.content}>{children}</span>;
  if (external) {
    return <a {...rest} href={href} data-sq="surface" data-variant={variant} className={classes}>{content}</a>;
  }
  return <Link {...rest} href={href} data-sq="surface" data-variant={variant} className={classes}>{content}</Link>;
}
