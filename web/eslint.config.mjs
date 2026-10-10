import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

export default defineConfig([
  ...nextVitals,
  ...nextTs,
  globalIgnores([".next/**", ".next-*/**", "out/**", "build/**", "next-env.d.ts", "public/**", "test-results/**", "playwright-report/**", "screens/**", ".mig/**"]),
  {
    // The public pages (the landing page, sign-in, not-found) are plain HTML documents: their links are plain <a>
    // elements on purpose, so a visit loads no client router state and nothing is prefetched (components/site).
    files: ["components/site/**", "components/landing/**", "app/page.tsx", "app/sign-in/**", "app/not-found.tsx", "app/error.tsx", "app/global-error.tsx"],
    rules: { "@next/next/no-html-link-for-pages": "off" },
  },
]);
