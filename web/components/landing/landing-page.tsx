/**
 * The public landing page of the app (server-rendered, no client code of its own but the copy buttons): what it is,
 * what it does for Carbons and for Silicons, how to install it and sign in, and where the docs are. Every word comes
 * from lib/app.config.ts, so an app changes its landing page there. Semantic HTML: one h1, a section per subject, lists
 * for lists; plain links, so the page is a full document that crawlers and Silicons read as text.
 */
import type { ReactNode } from "react";
import { ArrowRight, ArrowUpRight } from "lucide-react";
import { AppMark } from "@/components/foundation/brand/app-mark";
import { Action } from "@/components/site/action";
import { CodeBlock } from "@/components/site/code-block";
import { appConfig, type AppConfig } from "@/lib/app.config";
import styles from "./landing.module.css";

type Feature = AppConfig["landing"]["forCarbons"][number];

function SectionHead({ id, eyebrow, title, children }: { id: string; eyebrow: string; title: string; children?: ReactNode }) {
  return (
    <div className={styles.sectionHead}>
      <p className={styles.eyebrow}>{eyebrow}</p>
      <h2 id={id} className={styles.sectionTitle}>{title}</h2>
      {children ? <p className={styles.sectionLede}>{children}</p> : null}
    </div>
  );
}

function FeatureList({ features }: { features: Feature[] }) {
  return (
    <ul className={styles.features} role="list">
      {features.map(feature => {
        const Icon = feature.icon;
        return (
          <li key={feature.title} className={styles.feature}>
            <span className={styles.featureIcon} data-sq="surface" aria-hidden="true"><Icon size={18} strokeWidth={1.75} /></span>
            <span className={styles.featureText}>
              <strong>{feature.title}</strong>
              <span>{feature.text}</span>
            </span>
          </li>
        );
      })}
    </ul>
  );
}

export function LandingPage({ signedIn }: { signedIn: boolean }) {
  const { name, appId, landing, links, cli } = appConfig;
  const install = `silicon-apps install ${appId}`;
  const heroCode = [
    `# Install ${name} (Silicon Apps keeps it up to date)`,
    install,
    ...(cli ? ["", "# Sign in with a short-lived token: no browser", `silicon-accounts login --app ${appId} -q \\`, `  | ${cli.command} login --slt-stdin`, `${cli.command} --help`] : []),
  ].join("\n");
  const primary = signedIn ? { href: appConfig.home, label: `Open ${name}` } : { href: "/auth/sign-in", label: `Sign in to ${name}` };
  return (
    <>
      <section className={styles.hero} aria-labelledby="hero-title">
        <div className={styles.heroInner}>
          <div className={styles.heroCopy}>
            <p className={styles.heroBadge} data-sq="surface"><span className={styles.dot} data-sq-native="" aria-hidden="true" />For Carbons and Silicons</p>
            <h1 id="hero-title" className={styles.heroTitle}>{landing.headline}</h1>
            <p className={styles.heroLede}>{landing.lede}</p>
            <div className={styles.heroActions}>
              <Action href={primary.href} size="lg">{primary.label}<ArrowRight size={16} strokeWidth={1.75} aria-hidden="true" /></Action>
              <Action href={links.docs} size="lg" variant="secondary" rel="noopener">Read the docs</Action>
            </div>
            <p className={styles.heroNote}>Sign in with your Silicon Accounts account: Google, Apple, email or phone.</p>
          </div>
          <div className={styles.heroArt}>
            <CodeBlock code={heroCode} lang="sh" title="As a Silicon" />
          </div>
        </div>
      </section>

      <section className={styles.section} id="what-it-does" aria-labelledby="what-title">
        <div className={styles.inner}>
          <SectionHead id="what-title" eyebrow="What it does" title={`${name} works the same for Carbons and Silicons`}>
            {appConfig.description}
          </SectionHead>
          <div className={styles.split}>
            <article className={styles.panel} data-sq="surface" aria-labelledby="for-carbons">
              <h3 id="for-carbons" className={styles.panelTitle}>For Carbons</h3>
              <p className={styles.panelLede}>In the browser, signed in with Silicon Accounts.</p>
              <FeatureList features={landing.forCarbons} />
            </article>
            <article className={styles.panel} data-sq="surface" id="for-silicons" aria-labelledby="for-silicons-title">
              <h3 id="for-silicons-title" className={styles.panelTitle}>For Silicons</h3>
              <p className={styles.panelLede}>From the command line, without a page.</p>
              <FeatureList features={landing.forSilicons} />
            </article>
          </div>
        </div>
      </section>

      <section className={`${styles.section} ${styles.band}`} id="get-started" aria-labelledby="start-title">
        <div className={styles.inner}>
          <SectionHead id="start-title" eyebrow="Get started" title="Three steps, whoever you are" />
          <ol className={styles.steps} role="list">
            <li className={styles.step}>
              <span className={styles.stepNumber} data-sq="surface" aria-hidden="true">1</span>
              <h3>Install it</h3>
              <p>Silicons and their custodians install {name} with Silicon Apps: <code data-sq-native="">{install}</code>. Updates arrive on their own.</p>
            </li>
            <li className={styles.step}>
              <span className={styles.stepNumber} data-sq="surface" aria-hidden="true">2</span>
              <h3>Sign in</h3>
              <p>Carbons sign in here with Silicon Accounts. Silicons hand {cli ? <code data-sq-native="">{cli.command} login</code> : name} a short-lived token instead of opening a page.</p>
            </li>
            <li className={styles.step}>
              <span className={styles.stepNumber} data-sq="surface" aria-hidden="true">3</span>
              <h3>Share what you choose</h3>
              <p>Everything you make is yours. Share it with exact accounts by their c: or si: id; a Carbon also sees what its Silicons keep.</p>
            </li>
          </ol>
        </div>
      </section>

      <section className={styles.closing} aria-labelledby="closing-title">
        <div className={styles.closingCard} data-sq="surface">
          <AppMark size={48} />
          <h2 id="closing-title" className={styles.closingTitle}>{signedIn ? `Back to ${name}` : `Start using ${name}`}</h2>
          <p className={styles.closingText}>{appConfig.tagline}</p>
          <div className={styles.closingActions}>
            <Action href={primary.href} size="lg">{primary.label}<ArrowRight size={16} strokeWidth={1.75} aria-hidden="true" /></Action>
            <Action href={links.store} size="lg" variant="ghost" rel="noopener">See it in the Silicon Apps store<ArrowUpRight size={16} strokeWidth={1.75} aria-hidden="true" /></Action>
          </div>
        </div>
      </section>
    </>
  );
}
