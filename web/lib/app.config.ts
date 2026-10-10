import { Activity, Bot, BookOpen, History, Radio, Settings2, ShieldCheck, TerminalSquare, Webhook } from "lucide-react";
import type { AppConfig } from "./app-config.types";
export const appConfig: AppConfig = {
  appId: "hook", name: "Hook", brandPrefix: "Silicon",
  tagline: "Every webhook, understood.",
  description: "Give your Silicons verified webhook endpoints. Inspect requests, understand blocked signatures, and follow every delivery from one calm workspace.",
  mark: { paths: ["M6 12a4 4 0 1 1 4-4", "M10 8h4", "M18 12a4 4 0 1 1-4 4", "M14 16H6", "M6 12v4", "M18 8v4"] },
  cli: { command: "hook" }, home: "/hooks",
  nav: [
    { href: "/hooks", label: "Hooks", icon: Webhook },
    { href: "/history", label: "History", icon: History },
    { href: "/blocked", label: "Blocked requests", icon: ShieldCheck },
    { href: "/deliveries", label: "Deliveries", icon: Activity },
    { href: "/live", label: "Live stream", icon: Radio },
    { href: "/access", label: "Access", icon: Bot },
    { href: "/settings", label: "Settings", icon: Settings2 },
  ],
  links: { docs: "https://github.com/teamofsilicons/silicon-hook/tree/main/docs", store: "https://apps.teamofsilicons.com/apps/hook" },
  signIn: { scopes: [] },
  api: { forwardHeaders: ["x-hook-telemetry"], exposeHeaders: ["x-hook-api-version"] },
  landing: {
    headline: "The outside world.\nDelivered to your Silicon.",
    lede: "One endpoint for every signal. Hook checks signatures, keeps the full request, and makes it easy to see exactly what arrived.",
    forCarbons: [
      { icon: Webhook, title: "A home for every webhook", text: "Create and manage endpoints for the Silicons you look after, with a signing policy that fits each provider." },
      { icon: History, title: "See the whole request", text: "Inspect bodies, headers and delivery status. Find the reason a signature was blocked without losing the original request." },
      { icon: ShieldCheck, title: "Choose who has access", text: "Give a Carbon or Silicon view or manage access, and revoke it when the work is done." },
    ],
    forSilicons: [
      { icon: TerminalSquare, title: "Ready at the command line", text: "Install Hook through Silicon Apps, sign in with Silicon Accounts, and create your first endpoint." },
      { icon: Radio, title: "Signals that stay inspectable", text: "Read verified history, query deliveries, and receive updates when delivery is enabled." },
      { icon: BookOpen, title: "Built for exact requests", text: "A documented API and Rust client give every action a precise result and a clear error." },
    ],
  },
};
export type { AppConfig, NavItem } from "./app-config.types";
