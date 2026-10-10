# Hook 1.0 cutover to Silicon Accounts and Silicon Apps (runbook)

Hook 1.0 signs everyone in with Silicon Accounts, gives every hook to its Silicon, serves API v3, ships its CLI
through Silicon Apps and retires the browser gateway. The switch is one coordinated change on the production host
plus the web, the CLI release and the Silicon runtime. **Nothing here has been run against production.** Every
command that touches production is marked *run at cutover* and needs a Carbon's go-ahead; everything else was
rehearsed locally (see "Rehearsed" at the end).

## What changes and what does not

- **Provider URLs keep working.** `https://backend.hook.teamofsilicons.com/silicon/si:<id>/<KEY>` (and the older
  `/api/v1/silicon/…`, `/api/v2/silicon/…` forms) route by the key. Ingress never calls Silicon Accounts and is not
  interrupted except for the minute the API restarts. Unlinked hooks keep receiving; they just cannot be managed
  until their owner is linked.
- **Data is kept.** Migration 0019 only adds columns and tables; history, secrets (bound to hook ids) and retired
  keys are untouched. Unaccepted Ting sends from the old sign-in are parked as `legacy_identity`.
- **API v1 and v2 answer `410 api_version_sunset`.** CLIs and clients before 1.0, the old web console and its
  gateway stop being able to manage hooks at the switch.
- **Sign-ins start over.** Old CLI sessions (`~/.silicon-hook/state.json`) and gateway sessions are never read.
- **Delivery through Ting is off** until Ting accepts Silicon Accounts proofs (`HOOK_TING_URL` stays unset). Hook
  keeps receiving and storing events; Silicons read them with `hook events` and the web console instead of
  receiving them in real time.

## Order relative to the other apps and the fleet

No other app in this migration calls Hook on someone's behalf, and Hook calls none of them; the Silicon Interface
does not call Hook either. Hook can switch on its own day, but in step with:

1. **Silicon Accounts and Silicon Apps in production** (both already live). Hook's app `hook` exists at Silicon
   Accounts; its sign-in setup and webhook are prerequisites below.
2. **The Silicon runtime** (stemcell `silicon connect`, outside this migration). Today it installs `hook` through the
   previous distribution and runs `hook login <SLT>` with a token from the previous identity service, then
   `hook iam --json`. Hook 1.0 keeps both command shapes (`hook login <SLT>` positional, a hidden `hook iam --json`
   that prints `hook accounts --json`), so the runtime only has to change where the token and the binary come from:
   `silicon-apps install hook` and `silicon-accounts login --app hook -q`. Release that runtime change in the same
   window; until it ships, Silicons connected afterwards cannot sign in to Hook (their old tokens are refused as
   `unknown` or `not_an_slt`), while their provider URLs keep receiving.
3. **Ting** (stays on the previous identity service, D4). Nothing to do at cutover; see "Turning Ting delivery on".
4. **The web console.** Deploy the Next.js web in the same window as the backend; the old console cannot sign in to
   Hook 1.0.

## Before the window

All *run at cutover (prerequisite)*, by a Carbon who owns Hook's app (with Hook's app secret in a private file,
never on a command line or in shell history). If the secret is lost, an author rotates it first
(`silicon-apps authors hook rotate-secret`, shown once).

### 1. Check where production is

```sh
# run at cutover — on the host, through SSM, as root
docker exec hook-postgres psql -U postgres -d hook_prod -Atc \
  "SELECT max(version) FROM _sqlx_migrations"            # expect 17 (0.9) or 18 (0.10)
systemctl is-active silicon-hook-api silicon-hook-worker
readlink /opt/silicon-hook/current
```

`hook-migrate` applies whatever is pending (0018 if missing, then 0019).

### 2. Hook's sign-in setup at Silicon Accounts

The web needs its callback, the CLI needs the device flow and public-client exchange (Silicons sign in with an SLT,
Carbons with a device code; the CLI never holds the app secret):

```sh
# run at cutover — as Hook's app (arrays replace; note config_version and the current redirect_uris first)
export ACCOUNTS_APP_ID=hook
silicon-accounts --url https://accounts.teamofsilicons.com app config get --app-secret-stdin < ~/.silicon-hook/app-secret
cat > /tmp/hook-signin.json <<'JSON'
{"redirect_uris": ["https://hook.teamofsilicons.com/auth/callback"],
 "device_flow": true, "public_client": true}
JSON
silicon-accounts --url https://accounts.teamofsilicons.com app config set /tmp/hook-signin.json \
  --expected-version <config_version> --app-secret-stdin < ~/.silicon-hook/app-secret
```

Keep any redirect URIs already listed that are still in use (the patch replaces the array). Hook needs no required
details (no email, phone or date of birth).

### 3. The webhook signing secret

Make the secret before the URL, so Hook 1.0 can verify the very first delivery:

```sh
# run at cutover — prints {"secret": "whsec_…"} once; it goes straight into accounts.env, nowhere else
curl -s -X POST -u "hook:$(cat ~/.silicon-hook/app-secret)" -H 'Idempotency-Key: hook-1.0-webhook-secret' \
  https://accounts.teamofsilicons.com/v1/apps/hook/webhook/generate-secret
```

### 4. The private settings file for the host

`/opt/silicon-hook/accounts.env` on the host, root-owned, mode 0600, one `KEY=value` per line without quotes:

```text
HOOK_APP_SECRET=sa_app_…
HOOK_ACCOUNTS_WEBHOOK_SECRET=whsec_…
```

(`ACCOUNTS_URL` defaults to `https://accounts.teamofsilicons.com`; `HOOK_TING_URL` stays out.) Copy it with SSM
(`aws ssm start-session`, then write the file with `umask 077`), never through the release bucket.

### 5. The CLI release and Silicon Apps

```sh
# run at cutover — a maintainer: tag the release commit; the workflow builds and packs, it publishes nothing
git tag v1.0.0 && git push origin v1.0.0
gh run watch --exit-status "$(gh run list --workflow release.yml --limit 1 --json databaseId -q '.[0].databaseId')"
gh run download --name hook-silicon-apps-release --dir dist/apps
(cd dist/apps && sha256sum --check SHA256SUMS)
```

Then an author of the Silicon Apps app `hook` (create it first if `silicon-apps show hook` finds none:
`silicon-apps create hook --name "Silicon Hook"`, then `setup hook details` and `setup hook access --visibility public`):

```sh
# run at cutover — Linux only today; macOS and Windows uploads are refused until their workers are live
silicon-apps upload hook --target linux-x86_64 dist/apps/hook-1.0.0-linux-x86_64.tar.gz
silicon-apps upload hook --target linux-aarch64 dist/apps/hook-1.0.0-linux-aarch64.tar.gz
silicon-apps packages hook                                  # both validated: the three commands passed
silicon-apps release hook --version 1.0.0 --package <linux-x86_64 id> --package <linux-aarch64 id>
silicon-apps readiness hook && silicon-apps publish hook    # first publication only
```

That makes a development release (`silicon-apps install 'hook>dev'`). Promote it after the window's checks pass.

### 6. The backend archive

```sh
# run at cutover — builds silicon-hook-backend-<rev>-linux-aarch64.tar.gz from the tag; publishes nothing
gh workflow run deployment-builds.yml -f source_ref=v1.0.0
gh run download --name hook-deployment-backend --dir dist/backend
aws s3 cp dist/backend/ s3://silicon-hook-standalone-artifacts-lxpfsbc0jpuk/releases/1.0.0/ --recursive \
  --sse AES256 --profile silicon-production
```

### 7. Rehearse the identity mapping on a copy

The mapping links every id Hook stored before 1.0 (`si:cos`, `c:saket`) to a Silicon Accounts uuid. Rehearse it on
last night's backup so the review happens before the window:

```sh
# run at cutover (rehearsal) — on the host as root, in the private staging folder where the 1.0 bundle is
# extracted; restores into a scratch database, never into hook_prod
aws s3 cp s3://silicon-hook-standalone-artifacts-lxpfsbc0jpuk/backups/<latest>/hook_prod.dump /root/
docker exec hook-postgres psql -U postgres -c 'CREATE DATABASE hook_rehearsal'
docker exec -i hook-postgres pg_restore -U postgres -d hook_rehearsal --no-owner < /root/hook_prod.dump
set -a; . /etc/silicon-hook/migration.env; set +a
export HOOK_MIGRATOR_DATABASE_URL="${HOOK_MIGRATOR_DATABASE_URL/\/hook_prod\?/\/hook_rehearsal?}"
./bin/hook-migrate
HOOK_APP_SECRET="$(grep ^HOOK_APP_SECRET= /opt/silicon-hook/accounts.env | cut -d= -f2-)" \
  python3 draft-identity-mapping.py --out /root/hook-mapping.csv
```

`draft-identity-mapping.py` (in the bundle; `deploy/native/` in the repository) reads the stored ids and looks
each one up at Silicon Accounts by its current id with Hook's app credentials, writing `hook-mapping.csv` and
`hook-mapping.csv.report.json`. **Review it; it is a proposal.** The same id at Silicon Accounts is not proof of the
same account: check that each Silicon's custodian in the report is the Carbon who ran it before, add a row for every
account whose id changed, and remove any row that is wrong. Ids left out stay unlinked (their hooks keep receiving
and can be linked later by running `link-identities` again). Then:

```sh
# run at cutover (rehearsal)
./bin/hook-migrate link-identities --file /root/hook-mapping.csv --dry-run
docker exec hook-postgres psql -U postgres -c 'DROP DATABASE hook_rehearsal'
```

## The window

All *run at cutover*, on the host through SSM as root unless a step says otherwise. Expect a few minutes in which
management answers 503 and provider requests are refused while the API restarts (providers retry).

1. **Stage the bundle.** Copy the backend archive from `releases/1.0.0/`, verify it against its `.sha256`, extract it
   to a private folder (`umask 077`), and make sure `/opt/silicon-hook/accounts.env` is in place (step 4 above).
2. **Preview.** `python3 install.py` (no `--apply`) verifies the bundle and prints the configuration change by name:
   `api` gains `ACCOUNTS_URL`, `HOOK_APP_SECRET`, `HOOK_ACCOUNTS_WEBHOOK_SECRET`; every process loses the settings
   of the previous sign-in, the test environments and `HOOK_TING_BASE_URL`; `missing` must be `[]`.
3. **Install.**

   ```sh
   # run at cutover
   python3 install.py --apply --backup-bucket silicon-hook-standalone-artifacts-lxpfsbc0jpuk
   ```

   It backs up both databases and the configuration (online, then again with both services stopped), applies
   0018/0019 to `hook_prod`, reapplies the runtime grants, switches `current`, starts both units and waits for
   `/readyz`. Keep the printed `backup` path: it is the rollback point. `hook_test` is backed up and left alone.
4. **Point Silicon Accounts' webhook at Hook, with every update** (from the Carbon's machine; the secret made in
   step 3 is kept). Send `"events": null` explicitly: setting the URL keeps any update picks made earlier, and
   Silicon Apps' recommended picks leave out `custodian_change`, without which custodian changes reach Hook only
   through its 5-minute re-checks. The CLI's `app webhook set` cannot choose updates, so use the API:

   ```sh
   # run at cutover
   curl -s -X PUT -u "hook:$(cat ~/.silicon-hook/app-secret)" -H 'Idempotency-Key: hook-1.0-webhook-url' \
     -H 'Content-Type: application/json' \
     -d '{"url": "https://backend.hook.teamofsilicons.com/webhook", "events": null}' \
     https://accounts.teamofsilicons.com/v1/apps/hook/webhook
   # expect {"url": "https://backend.hook.teamofsilicons.com/webhook", "secret": null, "events": null}
   curl -s -u "hook:$(cat ~/.silicon-hook/app-secret)" https://accounts.teamofsilicons.com/v1/apps/hook/webhook
   # expect "secret_set": true, "events": null, "status": "active"
   silicon-accounts --url https://accounts.teamofsilicons.com app webhook test --app-id hook \
     --app-secret-stdin < ~/.silicon-hook/app-secret
   ```

   On the host, `journalctl -u silicon-hook-api --since -5min | grep 'event_type=ping'` shows the ping arrived and
   verified. hook-api also checks the webhook settings once at startup: restart it after this step (or read the
   log of its next start) and look for `Silicon Accounts delivers every account event Hook acts on to this Hook`;
   any other line names what is missing (an update, the secret, a paused subscription, another URL).
5. **Link the stored identities.** Draft again against production (step 7 above, with
   `HOOK_MIGRATOR_DATABASE_URL` from `/etc/silicon-hook/migration.env` unchanged), compare it with the reviewed
   rehearsal file, then:

   ```sh
   # run at cutover
   ./bin/hook-migrate link-identities --file /root/hook-mapping.csv --dry-run   # read linked, unlinked, hooks_without_owner
   ./bin/hook-migrate link-identities --file /root/hook-mapping.csv
   ```

   It runs in one transaction, writes only the new uuid columns and `hook_private.identity_links`, and can be run
   again with a corrected file at any time.
6. **Retire the gateway.** The new web needs no process on the host; Caddy proxies only the API:

   ```sh
   # run at cutover
   cp /opt/silicon-hook/Caddyfile /opt/silicon-hook/Caddyfile.before-1.0
   cat > /opt/silicon-hook/Caddyfile <<'CADDY'
   backend.hook.teamofsilicons.com {
       header Strict-Transport-Security "max-age=31536000"
       reverse_proxy 127.0.0.1:8080
   }
   CADDY
   docker exec hook-https caddy reload --config /etc/caddy/Caddyfile
   docker update --restart=no hook-gateway && docker stop -t 30 hook-gateway
   ```

7. **Deploy the web** to the Vercel project `silicon-hook-frontend` (production, `https://hook.teamofsilicons.com`)
   with the server-only settings in the web's `.env.example` (Silicon Accounts URL, `HOOK_APP_ID=hook`, Hook's app
   secret, the session key, and the Hook API URL `https://backend.hook.teamofsilicons.com`), set in Vercel's
   environment, never committed.
8. **Verify** (below), then **promote** the CLI and publish the crates:

   ```sh
   # run at cutover — an author, and a crates.io owner
   silicon-apps releases hook --channel development             # the 1.0.0 development release id
   silicon-apps promote hook <development release id> --version 1.0.0
   cargo publish -p silicon-hook-client && cargo publish -p silicon-hook-cli
   ```

9. **Docs.** `python3 scripts/deploy-docs.py` publishes docs.hook.teamofsilicons.com (Vercel project
   `silicon-hook-docs`).

## Verify

```sh
# run at cutover
curl -fsS https://backend.hook.teamofsilicons.com/healthz
curl -fsS https://backend.hook.teamofsilicons.com/readyz                  # delivery: off, the reason given
curl -fsS -H 'Silicon-Hook-Supported-API-Versions: v3' https://backend.hook.teamofsilicons.com/api/version
curl -s -o /dev/null -w '%{http_code}\n' https://backend.hook.teamofsilicons.com/api/v2/hooks   # 410
```

- **Ingress on an existing URL**: send a provider's test delivery (GitHub "Redeliver", Stripe "Send test webhook")
  to a hook created before the cutover; it answers `webhook.ok` and appears in the history.
- **A Silicon**: `silicon-apps install 'hook>dev'` (or the promoted release), then
  `silicon-accounts login --app hook -q | hook login --slt-stdin`, `hook login status --json` (verified),
  `hook list` (its hooks, linked by the mapping), `hook events`, `hook system delivery` (off, with the reason).
- **A Carbon**: `hook login` (approve the code), `hook silicons` (the Silicons it looks after),
  `hook --silicon si:<id> list`; the same in the web console after signing in.
- **Webhooks from Silicon Accounts**: `silicon-accounts app webhook deliveries --status failed` is empty.
- **The fleet**: one Silicon connected with the new runtime signs in and lists its hooks.

## Rollback

- **The installer failed**: it already restored the previous release, settings and units and restarted them (or the
  retained containers). Nothing else to do; read the printed error and the backup's `migration.log`.
- **After 1.0 started serving**: the previous binary refuses the 1.0 schema, so roll back database and binary
  together. Events received since the switch are lost with this; provider URLs are unaffected.

  ```sh
  # run at cutover (only on a rollback decision) — BACKUP is the path install.py printed
  systemctl stop silicon-hook-api silicon-hook-worker
  set -a; . "$BACKUP/native-config/migration.env"; set +a      # the previous settings
  docker exec hook-postgres psql -U postgres -c 'DROP DATABASE hook_prod WITH (FORCE)' \
    -c 'CREATE DATABASE hook_prod'
  docker exec -i hook-postgres pg_restore -U postgres -d hook_prod < "$BACKUP/quiesced-hook_prod.dump"
  ln -sfn "$(python3 -c "import json;print(json.load(open('$BACKUP/rollback.json'))['previous_release'])")" /opt/silicon-hook/current
  cp "$BACKUP"/native-config/*.env /etc/silicon-hook/
  psql -v ON_ERROR_STOP=1 -v api_role=silicon_hook_api -v worker_role=silicon_hook_worker \
    -f /opt/silicon-hook/current/grant-runtime.sql "$HOOK_MIGRATOR_DATABASE_URL"
  systemctl start silicon-hook-api silicon-hook-worker
  cp /opt/silicon-hook/Caddyfile.before-1.0 /opt/silicon-hook/Caddyfile
  docker exec hook-https caddy reload --config /etc/caddy/Caddyfile
  docker update --restart=unless-stopped hook-gateway && docker start hook-gateway
  ```

  Then remove the Silicon Accounts webhook URL (`silicon-accounts app webhook remove`), roll the web back in Vercel to
  the previous deployment, and withdraw the CLI release (`silicon-apps withdraw hook <release id> --reason "…"`).
  Silicons keep the 0.10 CLI they had.

## After the window

- **The old CLI on Silicons.** Copies installed through the previous distribution stay at 0.10: every management
  call answers `410 api_version_sunset` naming v3, and their old sign-in is refused. They move to 1.0 when the
  Silicon runtime installs `hook` from Silicon Apps; from then on Silicon Apps' updater keeps them current. Their
  provider URLs keep receiving the whole time.
- **Gateway sessions.** After the rollback window (a week), delete the stopped gateway and its session files, which
  hold encrypted tokens of the previous sign-in: `docker rm hook-gateway && rm -rf /opt/silicon-hook/sessions`, and
  delete `/opt/silicon-hook/iam.json`. *(run at cutover + 7 days)*
- **The shared test database.** `hook_test` is unused from 1.0 on and stays in the daily backup until someone
  decides to drop it (`DROP DATABASE hook_test`, after a restore of its last backup has been tested). Not part of
  this cutover: no data is deleted by it.
- **Re-linking.** Ids left unlinked can be linked later with another `link-identities` run; nothing else changes.

## Turning Ting delivery on

When Ting accepts Silicon Accounts proofs (enrolment with a User verification proof for receiving app `ting`, scope
`tings.subscribe`; sends and receipts with App verification proofs, scopes `tings.send` and `sent.query`). If Ting's
app at Silicon Accounts is not called `ting`, also set `HOOK_TING_APP_ID` to its id:

```sh
# run when Ting is ready — on the host
echo 'HOOK_TING_URL=https://backend.ting.teamofsilicons.com/' >> /etc/silicon-hook/api.env
# only if Ting's app id is not `ting`:  echo 'HOOK_TING_APP_ID=<its app id>' >> /etc/silicon-hook/api.env
systemctl restart silicon-hook-api
```

If Silicon Accounts refuses Hook's proofs (for example `unknown_receiving_app` because the id is wrong), the log
says so once with a pause before the next request, and queued sends stay `pending` with
`last_error_code: proof_unavailable` until it is fixed; nothing is lost.

Hook then queues references for new events only (nothing was queued while delivery was off). Recipients enrol again
(`POST /api/v3/delivery/recipient`); Carbon observers subscribe again.

## Blocked on

- **Ting** must accept Silicon Accounts proofs before `HOOK_TING_URL` is set (D4).
- **The Silicon runtime** (stemcell) must install from Silicon Apps and mint its token with
  `silicon-accounts login --app hook -q`.
- **The Next.js web** is built by the web stages of this migration; step 7 deploys what they produce.

## Rehearsed

Locally, against the shared Silicon Accounts test stack and PostgreSQL 16 (2026-10-10): packaging the macOS build
(the three commands from the extracted archive in an empty home); the native installer's preview and settings plan
(unit tests with the real file layout); the daily backup script with stubbed `docker`/`aws`; the mapping draft
against a migrated database with a real Carbon and Silicon (two linked, two unknown ids left out), followed by
`link-identities --dry-run` and a real run accepting the drafted file. The production commands above were not run.

End to end (2026-10-10, stage 4): `scripts/e2e-accounts.sh` ran Hook 1.0 against the same stack with real tokens:
137 checks, 0 failures, in 80 s. It covers the step 4 webhook with every update (all six events delivered by the
stack and applied, a replay and a reused `event_id` ignored, forged and stale deliveries refused), sign-in for the
web (code + PKCE), the CLI (short-lived token, device flow, refresh, logout) and a server (SLT exchange), the
custodian circle and sharing, restart safety, Silicon Accounts cut off mid-run, Hook's proofs to a Ting stand-in
(including renewal and the Silicon's receiving host hydrating the event), and the packaged CLI's discovery
commands. Run it again before the cutover: `HOOK_DEV_STACK_FILE=… HOOK_E2E_MINT=… HOOK_E2E_TSX=…
HOOK_E2E_ACCOUNTS_CLI=… scripts/e2e-accounts.sh` (see the root README).
