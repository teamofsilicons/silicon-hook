# Test Hook in a shared sandbox

## Select a sandbox

Create a shared test environment in Honeycomb and import `tos>hook`. Wait for shared readiness. Copy that application's **test app_secret** into a private file. Hook validates it with IAM and automatically finds the correct sandbox; there is no manual pairing or IAM root-key input.

```sh
hook env use --app-secret-file ./iam-test-app-secret
hook login '<test-SLT-or-existing-Carbon-or-Silicon-ID>'
hook login status --json
hook env current
```

Only an existing active sandbox identity can use the public-ID login shortcut. IAM rejects unknown, inactive, production and foreign-environment identities. Production always requires an IAM-issued SLT.

## Use the website

Choose **Use test app_secret** on the sign-in screen, or **Select test environment** from Connections/settings. Enter the secret and then a test SLT or identity ID. The top banner shows the sandbox name and current identity. **Exit testing mode** returns to the separate production session, or asks you to sign in.

## Understand permissions and isolation

The app secret selects storage; it grants no actor authority. Every normal action uses the signed-in user's actual IAM permissions. Root administration remains a separately named legacy control surface and is not part of ordinary sandbox testing.

New storage starts empty. Hooks, signing keys, history, blocked requests, delivery cursors, idempotency, audit data, background jobs and contract counters stay inside the sandbox. The new app-selected sandbox uses production hook capacity. A retired legacy root-key sandbox retains its documented ten-hook limit until selected through IAM's application flow.

Invalid, revoked or unavailable selectors return errors. Neither the CLI nor the backend falls back to production. Production tokens and tokens for another sandbox are rejected by IAM. Application selectors are carried on every scoped IAM call, including actor authorization and refresh. Cached database pools do not bypass selector validation.

Honeycomb sends authenticated lifecycle operations directly to Hook. Cleaning completes before Hook reports success, retains the shared binding, and fences old requests, queued deliveries and retries. Disable blocks access; restore waits for IAM readiness and leaves cleaned data empty. Hook reports activity to Honeycomb instead of retiring environments itself. See [the participant contract](honeycomb.md).

## Deliver safely

Public provider URLs retain `/test/silicon/{silicon_id}/{endpoint_key}`. Never put app secrets or root keys in URLs. Receivers default to loopback. A remote sandbox receiver must be explicitly marked with `hook webhook <https-url> --test-destination`; choose a destination that simulates external effects. Hook does not itself send email, SMS or payments.

Test IAM application webhooks verify the complete raw body with the imported application signing key. The authenticated sandbox key digest selects the matching environment. Duplicate or old events only invalidate authorization: current IAM state is fetched again rather than replaying stale permissions. The root-bearing wrapper is not logged or stored. Other captured test JSON requests redact known credential fields after signature verification.

## Leave testing

```sh
hook env exit
hook login status --json
# Or use production for one command without changing the selected sandbox:
hook --production login status --json
```

CLI test context is printed to stderr, including failed commands and help, so JSON stdout stays valid. Each profile has independent production and sandbox sessions.

Continue with [CLI examples](cli.md), [Rust examples](client.md), [HTTP contract](api.md), or [Honeycomb's environment guide](https://docs.honeycomb.teamofsilicons.com/).
