# Real IAM + Ting fixture

This starts a fresh Docker PostgreSQL database, real IAM, and the published Ting
server on loopback ports. It uses synthetic identities, isolated CLI profiles,
and a dedicated Docker network. It never reads existing login credentials or
writes to existing IAM or production. Telemetry destinations point to local
port 1. The Docker bridge is separate but does not block outbound networking.

Prerequisites: Docker, the official `iam` CLI, Python 3.12+, a CA bundle, and the
local IAM image pinned in `fixture.py` (ARM64). Current required-delivery and
scoped-receiver checks require the [Ting 0.1.4 upgrade](#ting-release-compatibility-verification).
The initial Ting 0.1.2 fixture is downloaded from its
public release at commit `a86971a08089bd212810b2df49f3f13bd41e83ac` and checked
against the release SHA-256. That server source matches the server source at
the reviewed main commit `1999c7b02762077da77153b23de4bf5c8d6f9498`.

```sh
python3 -m venv /tmp/hook-ting-e2e-tools
/tmp/hook-ting-e2e-tools/bin/pip install websocket-client
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/fixture.py setup
```

On Linux pass `--ca-bundle /etc/ssl/certs/ca-certificates.crt`. The default is
the macOS CA bundle. The fixture directory and final `READY` path are safe to
print; the credential files are not. The directory is mode 0700 and private
files are mode 0600. Failed runs retain their owned container list and private
diagnostics for cleanup. Run cleanup on a failed fixture before starting again.

The setup exercises real official IAM SLT issuance and application login,
recipient OBO registration, request-bound OBO send, fresh-proof idempotent retry,
websocket receipt of the exact event, delivery ACK (still unread), and read ACK.
`verification.json` contains the non-secret result and limitations. Re-run with:

```sh
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/fixture.py verify FIXTURE_DIRECTORY
```

For Hook, read `fixture.private.json` inside a script without printing it:

- `iam_url`, `ting_url`: the local service origins.
- `app_secrets["hook"]`: `HOOK_IAM_APP_SECRET`; use `hook` for the app ID.
- `hook_admin.access_token`: synthetic org-owner application token for setup.
- `hook_recipient.access_token`: recipient application token for Hook login.
- `actor_id`, `org_id`: recipient and organization.
- `ting_session`: recipient's real Ting session for a websocket test receiver.

Issue a fresh one-use SLT for the separate publisher Silicon, then let Hook
exchange it and retain its own refreshable service session:

```sh
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/fixture.py slt FIXTURE_DIRECTORY \
  --actor publisher --app 'hook' --output /tmp/hook-publisher.private.json
```

The same command supports `--actor admin` or `--actor recipient` and app
`ting`. Read the output's `slt` field privately; do not paste it into logs.

Identity/contact rows and application catalogue rows are fixture seeded. The
Hook notification type `hook.webhook.received` is seeded while Ting is
stopped; Honeycomb type-management bootstrap is therefore untested. This uses
the normal data plane of a disposable IAM instance, so IAM testing-plane
isolation is untested. The receiver is a real websocket harness; native Ting
daemon and local callback behavior are covered by the additional native fixture below.

## Native receiving fixture

`native.py` downloads the checksum-pinned published Linux ARM64 Ting 0.1.2 CLI
and daemon, then runs them inside an owned Ubuntu 24.04 container sharing only
the isolated IAM network namespace. Ubuntu 24.04 is required by that release's
glibc 2.39 dependency. No host Ting installation, home directory, socket, or
service manager is touched. `SILICON_HOME` alone cannot isolate a daemon:
Ting uses a fixed OS socket and the operating-system user's real home for its
queue, while `SILICON_HOME` changes only the CLI profile.

After building and starting the Hook fixture:

```sh
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/native.py setup FIXTURE_DIRECTORY
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/native.py verify FIXTURE_DIRECTORY
```

Setup uses an independent real Ting-bound SLT and the official CLI to establish
the private recipient profile. Verify registers a random-port callback with a
secret bearer, ingests a signed provider event into Hook, and hydrates the native
Ting batch through authenticated Hook HTTP. It holds the callback response until
Hook confirms the event is still unread, then returns exactly HTTP 204 and waits
for Hook's publication status to confirm the native daemon's read ACK. The
callback binds all local interfaces so the Docker guest can reach it, is secret
protected, and is removed along with its destination at the end of verification.
`native-verification.json` contains the non-secret evidence and explicit limits.
This fixture tests the published daemon; a synthetic callback still does not
prove the Hook SDK consumer or an enclosing application's integration.

An enclosing runtime that already owns a logged-in Ting profile does not need
another SLT to attach a destination. The official client exposes `ipc` with a
newline-delimited request containing `op: "webhook"`, `api_url`, `org_id`, the
canonical private `profile` path, its saved `session_token`, callback `url`, and
an optional local bearer `secret` and `health_url`. Passing an existing `id`
reattaches that stable destination. The daemon checks the socket peer UID,
profile ownership/private permissions, token equality, and remote authority.
Keep this orchestration inside the host runtime; Hook's consumer SDK can remain
stateless and need not own another daemon or login profile.

The local callback body contains only `tings`; each item contains `id`,
`created_at`, `type`, `key`, `data`, and `metadata`. Unlike the WebSocket item,
it does **not** contain `for`. Bind receiving to the configured destination and
current Hook identity, authenticate the bearer and `Ting-Webhook-Id`, validate
every compact reference, then hydrate it through Hook. Persist acceptance and
deduplicate stable Ting IDs or Hook event IDs before returning HTTP 204 for the
whole batch. A lost response may repeat an already accepted item; Ting does not
provide exactly-once application effects.

The daemon container stays available for later tests. `fixture.py cleanup`
includes it, or `native.py cleanup` removes just that owned container.

## Rust SDK and restart verification

Build the controlled receiving example after the client tests pass, then run:

```sh
cargo build --locked -p silicon-hook-client --example ting_receiver_e2e
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/sdk.py FIXTURE_DIRECTORY
```

The example accepts one private JSON configuration path. It runs the real Hook
SDK's `Receiver::decode` and `Receiver::resolve`, writes each accepted event to
an atomic private file, syncs both file and directory, and deduplicates by event
ID. No token, signing secret, callback bearer, or provider body is printed.

The driver sends a provider body larger than 256 KiB, verifies exact hydration
through a compact native Ting callback, and deliberately returns HTTP 503 after
the first durable acceptance. It checks that Ting has delivery ACK but no read
ACK, restarts both the owned native daemon and SDK listener, then enables HTTP
204. The daemon's automatic retry must preserve the notification identity and
the SDK host must deduplicate the original event from disk before acknowledgment.
This takes about one minute because the real daemon retains its retry schedule.
`sdk-verification.json` records the binary checksum, event identities, payload
checksum, attempts, deduplication counts, and explicit coverage limitations.

## CLI verification

After the backend and SDK checks pass, build the management CLI and run:

```sh
cargo build --locked -p silicon-hook-cli --bin hook
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/cli.py FIXTURE_DIRECTORY
```

This creates a private CLI home and an independent IAM token family. It checks
SLT-file login, online status, recipient registration, signed provider creation,
and an actual provider request delivered through the native Ting daemon and the
Rust SDK. The CLI must return the exact hydrated event and history entry, then
report both delivery and read acknowledgements for that destination. It also
checks that removed relay commands fail clearly, no Hook relay process or state
is created, and logout invalidates both access and refresh credentials.
`cli-verification.json` records the binary checksums and non-secret evidence.
The fixture uses the normal IAM plane; this does not prove sandbox bootstrap.

## Unavailable payload recovery

```sh
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/unavailable.py FIXTURE_DIRECTORY
```

This queues a signed event in the real native daemon while its callback is
offline, then deletes exactly that event from the isolated Hook fixture. This
models retention or clean after Ting has accepted the reference. A later valid
event is published before the SDK receiver starts. The daemon's automatic retry
must resolve the missing payload to a durable `unavailable` result, acknowledge
it, and continue to the later event with its exact original body. Unavailable
results are stored separately from accepted application work. A controlled local
callback repeats the terminal result and checks durable deduplication.
`unavailable-verification.json` records the evidence and distinguishes the
modeled deletion and local replay from the actual native delivery path.

The driver also restarts the SDK host before checking terminal-result dedupe.
It then removes the later event after successful acceptance and replays its
callback: the original durable application work must remain unchanged.

## Publisher CLI bootstrap verification

After building the management CLI, verify publisher setup independently:

```sh
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/publisher.py FIXTURE_DIRECTORY
```

This creates a separate Hook database/process and fresh synthetic publisher and
recipient Silicons inside the existing disposable IAM fixture. It exercises the
real `publisher provision` command without a Silicon target, file and stdin SLT
input, same-key replay, refusal to replace a healthy publisher, signed ingress,
publication into the new recipient's real Ting inbox, and exact CLI hydration.
The original fixture publisher and recipient remain untouched.
`publisher-verification.json` records evidence. The secondary backend/database,
Hook management sessions, Ting session and local IAM profiles are cleaned up.
IAM does not support Silicon logout-all: those synthetic direct sessions and the
backend-owned publisher family remain confined to IAM until full fixture cleanup.

## Website and browser verification

After the website tests and production build pass:

```sh
npm --prefix web run build
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/web.py FIXTURE_DIRECTORY
```

The driver starts the actual built website server on a random loopback port with
an isolated encrypted session directory. Official IAM `batch-login` issues both
application SLTs atomically. The driver exercises the state-bound callback,
Carbon receiving subscription, real Ting inbox watch, exact hydration of a
signed provider body above 256 KiB, event history, and logout. An independent
same-identity Ting session confirms that browser observation leaves the event
unread. `web-verification.json` contains non-secret evidence.

Pass `--browser --playwright /absolute/path/to/playwright` to also exercise the
actual callback JavaScript, credential-fragment removal, overview, Live connect,
payload inspector, delivery status, mobile navigation and UI sign-out in a new
headless Chromium context. The browser driver uses Playwright's Chromium when
installed, or the existing macOS Google Chrome binary with an isolated profile.
It saves desktop and 390-pixel mobile screenshots and
`web-browser-verification.json`. Neither driver exercises IAM's consent webpage:
the official IAM CLI performs real consent and batch issuance for the synthetic
fixture identity. Existing browser profiles and production logins are untouched.

Keep the fixture recipient free of unrelated unread test messages before this
focused test. If a prior attempt failed after publication, `native.py verify`
validates and accepts retained controlled-fixture messages before its new event.

When Hook binaries change, preserve IAM/Ting state and ports with:

```sh
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/hook.py refresh FIXTURE_DIRECTORY
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/hook.py verify FIXTURE_DIRECTORY
```

Refresh verifies the saved process identity, stops only that Hook process,
applies pending migrations using the fixture owner, reapplies runtime grants,
and starts the rebuilt backend with the same stored environment and origin.

```sh
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/fixture.py cleanup FIXTURE_DIRECTORY
```

Cleanup removes only this fixture's recorded containers and network. It retains
the private directory and evidence; delete that directory separately when no
longer needed. Never open the Linux server's SQLite file with a host SQLite
process while Ting is running: Docker file sharing does not provide safe
cross-kernel WAL coordination.

## Ting release compatibility verification

The original fixture above retains its 0.1.2 release pins. Upgrade only that
owned fixture to the published 0.1.3 server and native daemon with:

```sh
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/upgrade.py FIXTURE_DIRECTORY
```

To test the pinned 0.1.4 release after 0.1.3, use the current upgrade directory:

```sh
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/upgrade.py UPGRADE_013_DIRECTORY --version 0.1.4
```

The script verifies both release checksums, stops the owned Ting services, copies
their SQLite data and private native profile/queue, then starts new containers
from those copies. The old containers remain stopped with their data unchanged.
They are historical snapshots; do not restart them beside the upgraded services
or treat them as containing events accepted after the upgrade.
Transient Unix sockets are excluded from file backups. The parent cleanup list
includes the new containers. No host daemon or external account is changed.

Each upgrade creates another private directory and distinct versioned containers;
cleanup ownership is recorded through the original fixture's ancestor chain.
Use the returned `UPGRADE_READY` directory for subsequent backend, native, SDK,
CLI, unavailable-reference and website tests. Reports and credentials are written
there, preserving the historical 0.1.2 evidence. `upgrade-verification.json`
records source revision, archive and binary hashes, the real health response,
and `/v1/me` production environment attestation. Build the latest website before
running its tests: normal receiving requires explicit production attestation
(introduced in 0.1.3), while current required delivery and scoped receiving need
0.1.4. Earlier version reports are historical compatibility evidence.

To reproduce the late login operation replay boundary on that upgraded fixture:

```sh
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/login_recovery.py UPGRADE_READY_DIRECTORY
```

This creates a fresh synthetic identity/session, proves immediate replay returns
the identical response, waits 125 real seconds without altering clocks, and
retries the exact operation. Version 0.1.3 must reproduce the expired-operation
error; version 0.1.4 must recover the identical original response. The test then
deletes only that new Ting session and verifies that exact operation replay
cannot resurrect it. `--expect expired` or `--expect recovered` makes the desired
assertion explicit. `login-recovery-verification.json` contains sanitized evidence. The
successful first response is retained privately for the oracle and cleanup;
this does not simulate an actual lost packet or production outage.

These compatibility runs exercise Hook's existing delivery integration. They do
not prove adoption of Ting's new receiver-bootstrap or required-delivery adapters.

For the current required-delivery backend, use these normal-plane regressions
with the owned 0.1.4 directory:

```sh
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/required_delivery.py UPGRADE_014_DIRECTORY
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/required_sdk.py UPGRADE_014_DIRECTORY
```

They make the synthetic recipient's explicit opt-in through its own Ting session,
verify required muted delivery and actual acceptance, and restore its prior
preference/consent. The delivery regression first proves missing consent leaves
the original body/key pending until its scheduled retry. The SDK wrapper verifies
durable acceptance across restart. The older raw Hook/native/SDK/CLI helpers
assume this fixture recipient has already opted in when used with current Hook.

## Real testing-plane prerequisite

Create a separate IAM/Ting testing fixture from the pinned 0.1.4 release already
available in the owned upgrade directory:

```sh
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/testing.py UPGRADE_014_DIRECTORY
```

This starts a separate Docker network, IAM control and testing databases, and
Ting server. IAM creates the test identities through signup, login and Silicon
APIs. Authenticated lifecycle participant APIs prepare the environment, import
the applications and activate private test configuration. Receiving uses only a
Hook test login and fresh IAM OBO proofs with Ting's audience testing context.
The direct protocol check covers Carbon and Silicon capability replay, scope,
generation mismatch and revocation. Its sanitized report is
`testing-prerequisite-verification.json` in the returned private directory.

This fixture drives the participant protocol; it does not run the Honeycomb
coordinator or establish production approval. Normal control identities remain
synthetic local fixtures, without external scopes or OBO endpoints. Clean fencing
and actual Hook adapter checks are separate gates. The existing normal fixture
is untouched. Clean up this fixture using `fixture.py cleanup` with its own
returned directory, and preserve the reports as needed.

Once the current Hook API/migrator and CLI binaries have been built, exercise
the adapter using that new testing directory:

```sh
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/hook.py setup TESTING_DIRECTORY
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/testing_hook.py TESTING_DIRECTORY
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/testing_hook.py TESTING_DIRECTORY --events
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/testing_hook.py TESTING_DIRECTORY --clean
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/testing.py TESTING_DIRECTORY --rebuild
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/testing_hook.py TESTING_DIRECTORY
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/testing_cli.py TESTING_DIRECTORY
```

The Hook fixture has separate normal and test databases. Capability checks cover
both Carbon and Silicon, exact retry and explicit renewal. The event stage uses
real signed ingress, scoped watch/inbox, exact payload hydration, and no read ACK.
Only the synthetic Ting type is seeded; the owned server is stopped and the
host SQLite connection is explicitly closed before restarting it. Required
delivery is separately opted into by the synthetic recipient's own Ting session
and restored after the check. Sandbox polling uses two seconds to avoid the
older normal fixture's aggressive polling exhausting IAM's real rate limit.

Clean advances the real IAM generation, then applies the resulting generation
to Hook and Ting, checking rejection before the fresh capabilities expire.
Rebuild archives the prior reports under `generation-N-evidence` before actual
signup/import/configuration in the next generation. The CLI gate uses a fresh
profile and proves private output files, same-operation replay, explicit renewal,
stale-generation rejection and revocation without printing/persisting a receiver
token in its profile. It exercises the SDK through the CLI. Stop the owned Hook
process/database with `hook.py cleanup TESTING_DIRECTORY` before the upstream
`fixture.py cleanup` command.

After the website build gate, verify scoped website receiving in the rebuilt
owned generation:

```sh
/tmp/hook-ting-e2e-tools/bin/python scripts/ting_e2e/testing_web.py TESTING_DIRECTORY \
  --node /absolute/path/to/node --browser --playwright /absolute/path/to/playwright
```

The HTTP stage attaches only Hook's test app secret and signs in with an actual
Hook SLT. It waits beyond the thirty-second receiver lifetime, checks automatic
same-ID token replacement, and verifies exact large signed events through both
ordinary notifications and silent inbox reconciliation. A separate test actor's
own Ting session changes notification preferences for the test; it is never
provided to the BFF. Primary required-delivery consent and Carbon preferences
are restored afterward. Both observer and primary receipts remain unread.

The optional fresh browser context uses the actual attach and sign-in forms,
Live connection, payload inspector, delivery status, and sign-out. It also waits
beyond thirty seconds and receives a muted event. Reports are saved separately
as `testing-web-verification.json` and `testing-web-browser-verification.json`,
with screenshots under the new private `testing-web-*` directory. IAM consent
is performed by the real CLI, not its browser page. Local participant lifecycle
coverage does not prove production scope approval or the Honeycomb coordinator.

`testing_idle.py TESTING_DIRECTORY --seconds 30` samples the real IAM application
rate buckets while no outbox work is due. It changes no service settings, limits,
clock, or bucket state. Use the default 1,000ms worker interval after the idle
publisher fix to prove that an idle sandbox makes no IAM application requests;
the report records the actual configured interval and observed quota units.

`testing_catchup.py TESTING_DIRECTORY --node /absolute/path/to/node` is a separate
32-small-event stress check. It submits actual signed provider requests and waits
for the real outbox to publish all primary and Carbon copies. A private setup
journal permits retry without recreating accepted events. After a natural rate
window reset, it verifies that the default latest-32 live view survives a real
IAM 429 on the same socket, renews the same receiver, and forwards every event
once. It does not increase quota, alter clocks, or insert accepted notifications.

After successful HTTP evidence, `testing_browser.py TESTING_DIRECTORY --node
/absolute/path/to/node --playwright /absolute/path/to/playwright` repeats only the
actual browser phase. Its report records the HTTP and browser BFF hashes
separately and includes the production header after exiting testing mode.

Once the reports have been copied and inspected, `testing_finish.py
TESTING_DIRECTORY` archives that generation's evidence and performs the real
shared IAM/Hook/Ting clean. `testing_finish.py TESTING_DIRECTORY --stop` then
stops only the verified owned Hook process and four fixture containers, retaining
all volumes, private files and logs. Neither command touches the original normal
fixture or unrelated services. Do not run final clean while another test still
needs the selected generation.
