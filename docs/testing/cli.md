# Test with the CLI

```sh
hook env use --app-secret-file ./iam-test-app-secret
hook env current
hook login 'cos:tos'
hook login status --json
hook create Demo --unsigned
hook list
hook events
hook event <event-id>
hook publication <event-id>
hook env exit
```

Use a public identity ID only in the selected sandbox; an IAM test SLT also
works. `--test <UUID>` selects a saved sandbox for one command. `--production`
uses production for one invocation. `env use` remembers the sandbox;
`env exit` clears that choice without logging out production.

`--app-secret-file -` reads stdin. JSON output stays on stdout; the active test
context is always printed on stderr, including help and errors. Missing or
revoked selectors fail without changing the saved selection.

The CLI manages and inspects testing through API v2. The test application's
internal Ting receiver owns delivery; login starts no Hook daemon or local
gateway. Operators can register a test actor with `hook receiving register`.
An authorized Carbon may use `hook --silicon cos:tos receiving subscribe`,
`receiving status`, or `receiving unsubscribe` in the selected sandbox. These
commands configure only registration or interest, not a receiver or Ting login.
For native receiving, the application uses its paired Ting test credentials and
destination internally. A scoped inbox/watch observer can instead use only the
selected Hook app secret and signed-in test actor:

```sh
hook receiving register
hook receiving scope > receiver-scope.json
hook --idempotency-key receiver-create-001 receiving bootstrap \
  --scope-file receiver-scope.json --output receiver.private.json
# Renewal uses the original returned receiver_id and a new operation key:
hook --idempotency-key receiver-renew-001 receiving bootstrap \
  --scope-file receiver-scope.json --receiver-id <receiver-id> \
  --output receiver-renewed.private.json
```

The output file must be new and is created privately (0600 on Unix; a verified
owner-only ACL on Windows). Windows failures may leave an empty reservation;
retry with a new output path and the original scope/key. Stdout contains only safe
metadata; the capability is not saved in the CLI profile. Keep scope/key/body
unchanged when retrying an uncertain operation. Exact replay can return an
expired historical result; it does not extend authority. The host must check
expiry and renew/reconnect within 30 seconds. This is scoped inbox/watch
authority, not a running listener, native destination, preference control or ACK
permission. No production fallback occurs. Hook's backend and Ting require the
approved `receivers.bootstrap` scope and current recipient consent.

`env create`, `env attach`, `env key`, `env rotate-key`, `env clean`, and
`env configure-iam` remain available for existing root-key integrations. They
require their existing administrative authority and are not needed to select
an IAM application sandbox. A clean erases Hook data and observer subscriptions;
old notification references then fail hydration. Rotation and restore preserve
retained data. See `hook env <command> --help`.

Bug-report submission creates a real GitHub issue and notification. Testing
refuses it; use `hook --production report "description"` to submit explicitly
outside the sandbox.
