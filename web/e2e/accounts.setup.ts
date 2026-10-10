/**
 * Once per run: two Carbons sign in to the kit through the hosted pages with an email code (new accounts each run), and
 * their browser state is kept in test-results/.auth/. Specs start from their Silicon Accounts sign-in and continue as
 * them ("Continue as …"), so the run spends two codes of the shared stack's budget, not one per spec.
 */
import { seedSilicon } from "./seed";
import { mkdirSync, writeFileSync } from "node:fs";
import { test as setup } from "@playwright/test";
import { accountsFile, BASE, sameOrigin, sessionOf, signIn, statePath, uniqueEmail, type Who } from "./support";

setup("sign two Carbons in once for the whole run", async ({ browser }) => {
  mkdirSync("test-results/.auth", { recursive: true });
  const accounts: Record<string, { email: string; id: string }> = {};
  for (const who of ["carbon", "friend"] as Who[]) {
    const context = await browser.newContext({ baseURL: BASE });
    const page = await context.newPage();
    const email = uniqueEmail(who);
    await signIn(page, email);
    accounts[who] = { email, id: (await sessionOf(context)).account!.id };
    await context.storageState({ path: statePath(who) });
    // The kit's own sign-in ends here (revoked); the Silicon Accounts sign-in stays for "Continue as".
    await context.request.post("/auth/sign-out", { headers: sameOrigin() });
    await context.close();
  }
  const silicon = await seedSilicon(accounts.carbon!.email);
  writeFileSync("test-results/.auth/silicon.json", JSON.stringify(silicon));
  writeFileSync(accountsFile, `${JSON.stringify(accounts, null, 2)}\n`);
});
