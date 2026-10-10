"use client";

import * as DialogPrimitive from "@radix-ui/react-dialog";
import { createContext, useCallback, useContext, useLayoutEffect, useRef, useState } from "react";
import type { ComponentPropsWithoutRef, ReactNode } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import type { Transition } from "motion/react";
import { X } from "lucide-react";
import { ESCAPE_LAYER_ATTRIBUTE, layerEscape } from "../lib/escape";
import { motionTokens } from "../lib/motion-tokens";
import { returnFocusTo, useLayerOpener } from "../lib/return-focus";
import styles from "./dialog.module.css";

/** Mirrors the open state so the content can stay mounted while it animates out, and retarget mid-flight if it is reopened or closed early. */
const OpenContext = createContext<boolean | null>(null);
/** What had focus when the dialog opened: focus returns there when it closes (lib/return-focus.ts). */
const OpenerContext = createContext<HTMLElement | null>(null);

export function Dialog({ open: openProp, defaultOpen = false, onOpenChange, ...props }: ComponentPropsWithoutRef<typeof DialogPrimitive.Root>) {
  const [uncontrolled, setUncontrolled] = useState(defaultOpen);
  const open = openProp ?? uncontrolled;
  const opener = useLayerOpener(open);
  const setOpen = useCallback((next: boolean) => { if (openProp === undefined) setUncontrolled(next); onOpenChange?.(next); }, [openProp, onOpenChange]);
  return <OpenContext.Provider value={open}><OpenerContext.Provider value={opener}><DialogPrimitive.Root {...props} open={open} onOpenChange={setOpen}/></OpenerContext.Provider></OpenContext.Provider>;
}

export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogClose = DialogPrimitive.Close;

export interface DialogContentProps extends ComponentPropsWithoutRef<typeof DialogPrimitive.Content> {
  title: string;
  description?: string;
  children: ReactNode;
}

const fade: Transition = { duration: motionTokens.duration.instant };
const leave: Transition = { duration: motionTokens.duration.fast, ease: [...motionTokens.ease.standard] };

/** When the title or description changes while open, the new copy rises in and the old copy leaves upward. */
function SwapText({ text }: { text: string }) {
  const reduced = useReducedMotion();
  return <AnimatePresence mode="popLayout" initial={false}>
    <motion.span key={text} className={styles.swap} initial={reduced ? false : { opacity: 0, y: "0.3em", filter: `blur(${motionTokens.blur.soft}px)` }} animate={{ opacity: 1, y: 0, filter: "blur(0px)" }} exit={reduced ? { opacity: 0, transition: { duration: 0 } } : { opacity: 0, y: "-0.3em", filter: `blur(${motionTokens.blur.subtle}px)`, transition: { duration: motionTokens.duration.fast, ease: [...motionTokens.ease.standard] } }} transition={{ duration: motionTokens.duration.standard, ease: [...motionTokens.ease.enter] }}>{text}</motion.span>
  </AnimatePresence>;
}

export function DialogContent({ title, description, children, className, onPointerDownOutside, onEscapeKeyDown, onCloseAutoFocus, ...props }: DialogContentProps) {
  const open = useContext(OpenContext);
  const opener = useContext(OpenerContext);
  const reduced = useReducedMotion();
  // When the open state last changed. Radix waits for the click before treating a press as outside, and a press on the trigger
  // while the dialog leaves reopens it first, so that press must not close it again.
  const change = useRef({ open, at: 0 });
  useLayoutEffect(() => { change.current = { open, at: performance.now() }; }, [open]);
  const pressOutside: DialogContentProps["onPointerDownOutside"] = event => {
    onPointerDownOutside?.(event);
    if (open !== null && (!change.current.open || event.detail.originalEvent.timeStamp < change.current.at)) event.preventDefault();
  };
  const classes = [styles.content, className].filter(Boolean).join(" ");
  // Escape inside belongs to an open list, calendar or question first (lib/escape.ts); the next one closes the dialog.
  const escape = { [ESCAPE_LAYER_ATTRIBUTE]: "", onEscapeKeyDown: layerEscape(onEscapeKeyDown) };
  // Opened from plain state (no Trigger), Radix would leave focus on <body>: it goes back to what opened the dialog.
  const closeFocus = returnFocusTo(opener, onCloseAutoFocus);
  const inner = <>
    <div className={styles.header}><div><DialogPrimitive.Title className={styles.title}><SwapText text={title}/></DialogPrimitive.Title>{description ? <DialogPrimitive.Description className={styles.description}><SwapText text={description}/></DialogPrimitive.Description> : null}</div><DialogPrimitive.Close className={styles.close} data-sq="surface" aria-label="Close dialog"><X size={16} strokeWidth={1.75} aria-hidden="true"/></DialogPrimitive.Close></div>
    <div className={styles.body}>{children}</div>
  </>;
  // Under a bare Radix root the open state is unknown here, so CSS keyframes keyed off data-state animate the layers instead.
  if (open === null) return <DialogPrimitive.Portal>
    <DialogPrimitive.Overlay className={`${styles.overlay} ${styles.keyframes}`}/>
    <DialogPrimitive.Content {...props} {...escape} onPointerDownOutside={pressOutside} onCloseAutoFocus={closeFocus} className={`${classes} ${styles.keyframes}`}>{inner}</DialogPrimitive.Content>
  </DialogPrimitive.Portal>;
  // The overlay fades while the dialog rises 8px and scales up on a spring. Closing is shorter and quieter, and starts from wherever the entrance is.
  return <AnimatePresence>
    {open && <DialogPrimitive.Portal key="dialog" forceMount>
      <DialogPrimitive.Overlay asChild forceMount><motion.div className={styles.overlay} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0, transition: reduced ? fade : leave }} transition={reduced ? fade : { duration: motionTokens.duration.standard, ease: [...motionTokens.ease.enter] }}/></DialogPrimitive.Overlay>
      <DialogPrimitive.Content {...props} {...escape} onPointerDownOutside={pressOutside} onCloseAutoFocus={closeFocus} asChild forceMount>
        <motion.div className={classes} data-sq="surface" initial={reduced ? { opacity: 0 } : { opacity: 0, y: 8, scale: .96 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={reduced ? { opacity: 0, transition: fade } : { opacity: 0, y: 4, scale: .98, transition: leave }} transition={reduced ? fade : { default: motionTokens.spring.smooth, opacity: { duration: motionTokens.duration.fast, ease: [...motionTokens.ease.enter] } }}>{inner}</motion.div>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>}
  </AnimatePresence>;
}
