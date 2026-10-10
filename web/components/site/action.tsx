/**
 * A plain link that looks like an Arc button, for the public pages (server-rendered, no client router): the same
 * variants and sizes as <Button>, the same squircle.
 *
 *   <Action href="/docs">Read the docs</Action>
 *   <Action href="/docs/apps/start/publish" variant="secondary">Publish an app</Action>
 */
import type { AnchorHTMLAttributes, ReactNode } from "react";
import buttonStyles from "@/components/silicon-ui/button/button.module.css";
import linkStyles from "@/components/foundation/button-link.module.css";

export interface ActionProps extends AnchorHTMLAttributes<HTMLAnchorElement> {
  href: string;
  variant?: "primary" | "secondary" | "ghost";
  size?: "sm" | "md" | "lg";
  children: ReactNode;
}

export function Action({ href, variant = "primary", size = "md", className, children, ...rest }: ActionProps) {
  const classes = [buttonStyles.button, buttonStyles[variant], buttonStyles[size], linkStyles.link, className].filter(Boolean).join(" ");
  return (
    <a {...rest} href={href} data-sq="surface" data-variant={variant} className={classes}>
      <span className={linkStyles.content}>{children}</span>
    </a>
  );
}
