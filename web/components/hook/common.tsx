"use client";
import { Button } from "@/components/silicon-ui/button/button";
import { Badge } from "@/components/silicon-ui/badge/badge";
import { Dialog, DialogContent } from "@/components/silicon-ui/dialog/dialog";
import type { ReactNode } from "react";
export function Blank({ title, children }: { title: string; children?: ReactNode }) { return <div className="hook-empty" data-sq="surface"><h2>{title}</h2><p>{children}</p></div>; }
export function Status({ value }: { value: string }) { return <Badge tone={value === "active" ? "success" : value === "deleted" ? "danger" : "neutral"}>{value.replaceAll("_", " ")}</Badge>; }
export function Modal({ title, description, children, close }: { title: string; description?: string; children: ReactNode; close: () => void }) { return <Dialog open onOpenChange={open => { if (!open) close(); }}><DialogContent title={title} description={description}>{children}</DialogContent></Dialog>; }
export function Pager({ next, previous, onNext, onPrevious, count }: { next?: string | null; previous: boolean; onNext: () => void; onPrevious: () => void; count: number }) { return <div className="hook-toolbar"><span>{count} on this page</span><div className="hook-actions"><Button variant="secondary" size="sm" disabled={!previous} onClick={onPrevious}>Previous</Button><Button variant="secondary" size="sm" disabled={!next} onClick={onNext}>Next</Button></div></div>; }
export function Copy({ value }: { value: string }) { return <div className="hook-copy"><code>{value}</code><Button size="sm" variant="secondary" onClick={async () => { await navigator.clipboard.writeText(value); }}>Copy</Button></div>; }
