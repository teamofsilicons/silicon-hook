"use client";

import * as PopoverPrimitive from "@radix-ui/react-popover";
import { forwardRef } from "react";
import type { ComponentPropsWithoutRef } from "react";
import { ESCAPE_LAYER_ATTRIBUTE, layerEscape } from "../lib/escape";
import styles from "./popover.module.css";

export const Popover = PopoverPrimitive.Root;
export const PopoverClose = PopoverPrimitive.Close;

/** The trigger anchors the panel, so it opts out of press-scale: a scaled rect measured on open would shift the panel as the trigger springs back. */
export const PopoverTrigger = forwardRef<
  HTMLButtonElement,
  ComponentPropsWithoutRef<typeof PopoverPrimitive.Trigger>
>(function PopoverTrigger({ className, ...props }, ref) {
  return <PopoverPrimitive.Trigger {...props} ref={ref} className={[styles.anchor, className].filter(Boolean).join(" ")}/>;
});

PopoverTrigger.displayName = "PopoverTrigger";

export const PopoverContent = forwardRef<
  HTMLDivElement,
  ComponentPropsWithoutRef<typeof PopoverPrimitive.Content>
>(function PopoverContent({ className, align = "start", sideOffset = 6, collisionPadding = 10, onEscapeKeyDown, ...props }, ref) {
  return <PopoverPrimitive.Portal>
    <PopoverPrimitive.Content
      {...props}
      {...{ [ESCAPE_LAYER_ATTRIBUTE]: "" }}
      // Escape inside belongs to an open list, calendar or question first (lib/escape.ts).
      onEscapeKeyDown={layerEscape(onEscapeKeyDown)}
      ref={ref}
      align={align}
      sideOffset={sideOffset}
      collisionPadding={collisionPadding}
      className={[styles.content, className].filter(Boolean).join(" ")}
      data-sq="surface"
    />
  </PopoverPrimitive.Portal>;
});

PopoverContent.displayName = "PopoverContent";
