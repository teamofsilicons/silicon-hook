/**
 * The shape of lib/app.config.ts, the one file an app edits to make the kit its own. Kept apart so the kit's code can
 * change the defaults without touching an app's values. app.config.ts is bundled into the browser too: never put a
 * secret in it (secrets are environment variables, lib/server/env.ts).
 */
import type { LucideIcon } from "lucide-react";

export interface NavItem {
  /** A path of the signed-in workspace, such as "/reminders". */
  href: string;
  label: string;
  icon: LucideIcon;
  /** Marked current on deeper paths too ("/reminders/42"). Default true. */
  prefix?: boolean;
  /** More words the ⌘K palette finds it by. */
  keywords?: string[];
}

export interface FeatureCopy {
  title: string;
  text: string;
  icon: LucideIcon;
}

export interface AppConfig {
  /** The Silicon Accounts and Silicon Apps app_id. APP_ID in the environment may override it per deployment. */
  appId: string;
  /** The product name, as Carbons and Silicons read it: "Remind", "Briefcase". */
  name: string;
  /**
   * A word before the name in the wordmark only, the way the family's sites read: "Silicon" + "Hook" shows "Silicon
   * Hook" with the name muted, like "Silicon Developer" and "Silicon Apps". Sentences keep the bare name.
   */
  brandPrefix?: string;
  /** One line: what it is, for the landing page, metadata and the manifest. */
  tagline: string;
  /** Two or three sentences for search engines, link previews and llms.txt. */
  description: string;
  /**
   * The app's mark: SVG path data drawn with round 2 px strokes on a 24 by 24 grid (the lucide grid: paste a lucide
   * icon's paths, or draw your own). It sits white on a squircle of the accent (or brand blue) everywhere: the shell,
   * the landing page, the icons and the Open Graph image.
   */
  mark: { paths: string[] };
  /**
   * The product colour, if the app has one. It tints the mark and the landing page's wash only; actions, links and
   * focus stay brand blue on every Silicon site. Give a light and a dark value (each at least 3:1 on its page colour).
   */
  accent?: { light: string; dark: string };
  /**
   * The app's command line (apps.yaml `command`), installed with `silicon-apps install <appId>`. The landing page shows
   * how a Silicon installs it and signs in with a short-lived token. Leave it out for an app without one.
   */
  cli?: { command: string };
  /** Where a signed-in Carbon or Silicon lands (usually the first nav item). */
  home: string;
  /** The primary navigation: the sidebar on wide screens, the menu sheet on phones, the ⌘K palette everywhere. */
  nav: NavItem[];
  links: {
    /** The app's documentation. */
    docs: string;
    /** The app's page in the Silicon Apps store. */
    store: string;
    /** Where to report problems or read the source (optional). */
    source?: string;
  };
  signIn: {
    /** Extra details asked for at sign-in (profile is always granted): "email", "phone", "dob", "timezone". */
    scopes: string[];
  };
  /** The public landing page at /. */
  landing: {
    /** The hero's headline (a sentence, sentence case). */
    headline: string;
    /** One or two sentences under it. */
    lede: string;
    forCarbons: FeatureCopy[];
    forSilicons: FeatureCopy[];
  };
  /** The API proxy: extra headers to pass to the service and back (lower case). */
  api?: { forwardHeaders?: string[]; exposeHeaders?: string[] };
}
