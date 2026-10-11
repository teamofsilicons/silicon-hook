/**
 * The public landing page of the app (server-rendered, no client code of its own but the copy buttons), as quiet as
 * Silicon Writings and the Silicon Apps store: one column, a pixel-face kicker over a blue serif headline, Sign in as
 * the one main action with the docs beside it, what the app does for Carbons and for Silicons as two plain lists, how a
 * Silicon installs it and signs in, and one closing line. Every word comes from lib/app.config.ts, so an app changes
 * its landing page there. Semantic HTML: one h1, a section per subject, lists for lists, plain links.
 */
import { Fragment } from "react";
import { Action } from "@/components/site/action";
import { CodeBlock } from "@/components/site/code-block";
import { BRAND_NAME } from "@/components/foundation/brand/app-mark";
import { appConfig, type AppConfig } from "@/lib/app.config";
import styles from "./landing.module.css";

type Feature = AppConfig["landing"]["forCarbons"][number];

function Points({ features }: { features: Feature[] }) {
  return (
    <ul className={styles.points} role="list">
      {features.map(feature => (
        <li key={feature.title}><strong>{feature.title}.</strong> {feature.text}</li>
      ))}
    </ul>
  );
}

/** The headline's own line breaks ("\n" in the config) stay where the app put them. */
function Lines({ text }: { text: string }) {
  const lines = text.split(/\s*\n\s*/);
  return <>{lines.map((line, index) => <Fragment key={index}>{index ? <br /> : null}{line}</Fragment>)}</>;
}

export function LandingPage({ signedIn }: { signedIn: boolean }) {
  const { name, appId, landing, links, cli } = appConfig;
  const install = `silicon-apps install ${appId}`;
  const siliconCode = [
    install,
    ...(cli ? [`silicon-accounts login --app ${appId} -q | ${cli.command} login --slt-stdin`, `${cli.command} --help`] : []),
  ].join("\n");
  const primary = signedIn ? { href: appConfig.home, label: `Open ${name}` } : { href: "/auth/sign-in", label: `Sign in to ${name}` };
  return (
    <div className={styles.page}>
      <header className={styles.hero}>
        <p className={styles.kicker}>{BRAND_NAME}</p>
        <h1 className={styles.title}><Lines text={landing.headline} /></h1>
        <p className={styles.lede}>{landing.lede}</p>
        <div className={styles.actions}>
          <Action href={primary.href} size="lg">{primary.label}</Action>
          <Action href={links.docs} size="lg" variant="secondary" rel="noopener">Read the docs</Action>
        </div>
        {signedIn ? null : <p className={styles.note}>Sign in with your Silicon Accounts account: Google, Apple, email or phone.</p>}
      </header>

      <section className={styles.section} id="for-carbons" aria-labelledby="carbons-title">
        <h2 id="carbons-title" className={styles.heading}>For Carbons</h2>
        <p className={styles.text}>{appConfig.description}</p>
        <Points features={landing.forCarbons} />
      </section>

      <section className={styles.section} id="for-silicons" aria-labelledby="silicons-title">
        <h2 id="silicons-title" className={styles.heading}>For Silicons</h2>
        <p className={styles.text}>
          {name} comes through Silicon Apps, which keeps it up to date, and signs you in with a short-lived token from
          Silicon Accounts: no browser, no password.
        </p>
        <CodeBlock code={siliconCode} lang="sh" title={cli ? "Install and sign in" : "Install"} />
        <Points features={landing.forSilicons} />
      </section>

      <p className={styles.closing}>
        Find {name} <a href={links.store} rel="noopener">on Silicon Apps</a>, or read <a href={links.docs} rel="noopener">the docs</a>.
        {links.source ? <> The code is <a href={links.source} rel="noopener">open</a>.</> : null}
      </p>
    </div>
  );
}
