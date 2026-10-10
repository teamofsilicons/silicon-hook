# Proposed changes to Hook's UNDERSTANDING.md

`understanding/UNDERSTANDING.md` is Carbon-edited only, so this stage did not touch it. These are the edits
that would make it match Hook after the move to Silicon Accounts and Silicon Apps. Each item names the section,
says what changes and gives text the Carbon can paste or reword. Everything else in the file stays as it is.

## Glossary
Remove `Org`. Add:
- `Custodian` - the Carbon who looks after a Silicon.
- `uuid` - an account's permanent Silicon Accounts identifier. Ids (`si:cos`, `c:saket`) can change; the uuid never does.

## Login
Replace the section with:

> Signing in is handled entirely by Silicon Accounts. Hook has an app id (`hook`) and an app secret in its
> environment. Every API call carries a Silicon Accounts access token issued to Hook; Hook verifies it itself and
> confirms with Silicon Accounts that it is still active before revealing a secret, changing who has access, or
> deleting and restoring a hook. Use the official, latest `silicon-accounts-client` crate everywhere.
>
> Hook's webhook endpoint (backend.hook.teamofsilicons.com/webhook) tells Hook when an account signs out, removes
> Hook's access, changes its id, changes custodian, is updated or is deleted.

## Who can see and manage a Silicon's hooks (replaces the last two paragraphs of Login and "How it works")
> Webhooks belong to the Silicon they were made for. The Silicon and its custodian can do everything with them; the
> custodian acts as itself, never as the Silicon. They can grant another Carbon or Silicon `view` (hooks, history,
> logs) or `manage` (also create and change hooks) access, and a grantee can leave. A Silicon looked after by a
> different custodian only receives access after it (or its custodian) has allowed the owning Silicon or its
> custodian. Nobody else sees a Silicon's hooks, including its sibling Silicons.

## How it works, first paragraph
> For any Silicon that signs in to Hook, its Silicon Accounts uuid is the key its webhooks are stored under.

## Url
Add:
> `{silicon_id}` is the Silicon's current id or its uuid. A URL keeps working after the Silicon changes its id: the
> uuid, the current id and every earlier id route to the same webhooks, and the 8-character key decides which one.

## Rotate
"not already registered for that silicon id" becomes "not already used by any webhook". Keys are unique across Hook.

## Delete Webhook
> A webhook can be deleted by the Silicon, its custodian, or an account with `manage` access. When a Silicon's
> account is deleted, all its webhooks are deleted at once (they answer 410) and removed after the 45 days.

## Delivery
Replace the second paragraph with:
> The app handles recipient registration and authorization with Silicon Accounts and Ting internally. Delivery
> through Ting is optional: when Hook is not configured with Ting it still receives, verifies and stores every event,
> queues nothing, and says so.

## Backend Versioning
Add: "The current API is v3. v1 and v2 are retired and answer 410."

## Testing Environment
Remove the whole section, including Environment Lifecycle, Using a Test Environment, Website and CLI, Isolation, and
Webhooks and External Actions. Silicon Apps has no test environments or lifecycle instructions, and testing in
the CLI (`hook --test <test_id>`) goes with it.

## Rust Package & CLI
- "Testing in the test enviorment should also be possible via both cli, and the package" and the `--test`
  paragraph: remove.
- Logging in: Carbons run `hook login` (prints a code and a URL, then waits); Silicons keep
  `hook login <slt>`, with the short-lived token from `silicon-accounts login --app hook -q`.
- "`iam --json`" becomes "`accounts --json`" (returns `app_id` alongside other information), here and in Cli experience.
- "carbons, silicons, org, access keys, api keys" becomes "Carbons and Silicons".

## Cli experience
"short lived tokens that the user can generate from the official iam cli" becomes "from the official
silicon-accounts CLI". "On the docs page, show `honeycomb install 'hook'`" becomes "show `silicon-apps install hook`".
"`app iam --json` gives {app_id: "...", ...}" becomes "`hook accounts --json` gives {app_id: "hook", ...}".

## Docs and Telemetry
"all IAM apps" becomes "all apps" (two places).

## Updates
Replace with (added by the release stage: Silicon Apps uploads and validates one target per package, so a
release is one archive per target rather than one archive for all of them):
> For each Hook release, build the hook CLI for Linux, Windows and macOS on x86_64 and aarch64, and package each
> build as its own .tar.gz with `apps.yaml` at the archive root naming that target and the executable. Check every
> package with `silicon-apps validate` and make it with `silicon-apps pack`; each executable must answer
> `hook --help`, `hook accounts --json` and `hook login status --json` signed out. Silicon Apps installs and
> updates the CLI (`silicon-apps install hook`); Hook never replaces its own executable. Silicon Apps validates
> Linux packages today; the macOS and Windows ones are kept until it validates those systems.

## Identifier schema
Replace the last sentence of the first paragraph with "Accounts are stored by their Silicon Accounts uuid and shown
by their current id." and drop the mention of `org_id`.

## Rust Package & CLI (added by the client and CLI stage)
- "if you need a local store for auth or something else, use `{home_dir}/.{appname}/dir`": Hook has always used
  `.silicon-hook` (not `.hook`), and keeps it so existing installations keep their settings. Suggested wording:
  "Hook keeps its local state in `{home_dir}/.silicon-hook/`."
- "For logging in via the cli or the package for any carbon/silicon you don't ask for their credentials or redirect
  them anywhere, instead you just request for their short lived token": Carbons now sign in with a device code they
  approve in the browser (no credentials are typed into the CLI). Suggested wording: "The CLI never asks for
  credentials. A Carbon runs `hook login` and approves the printed code at Silicon Accounts; a Silicon (or anyone
  holding one) passes a short-lived token: `hook login <slt>`, or
  `silicon-accounts login --app hook -q | hook login --slt-stdin`."
- "`login status --json` ... reports `authenticated: true`, alongside which carbon or silicon": add "with its uuid,
  id and kind; `{"authenticated": false}` when signed out".

## Route inventory (`understanding/api.yaml`, added by the release stage)
`api.yaml` is the Carbon's route inventory and was not edited. It still lists the routes Hook 1.0 removed:
`/api/v1/auth/iam`, `/api/v1/iam/events`, the testing-environment routes (including
`/api/v1/testing-environment/iam`), the lifecycle route under `/internal/…/testing-environments/…`,
`/api/v1/silicons/{silicon_id}/hooks/iam`, and examples with `org_id: tos`. Suggested: replace the inventory with
the v3 routes in `openapi.yaml` (or regenerate `api.yaml` from it): no sign-in routes (Silicon Accounts signs
everyone in), `/api/v3/silicons/{silicon}/hooks/accounts` instead of `hooks/iam`, the access and allow-list routes,
and examples that show accounts as `{uuid, id}` instead of `org_id`.
