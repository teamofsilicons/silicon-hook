# Test with the CLI

```sh
hook env use --app-secret-file ./iam-test-app-secret
hook env current
hook login 'cos:tos'
hook login status --json
hook webhook http://127.0.0.1:9000/test-events
hook create Demo --unsigned
hook list
hook events
hook deliveries cursor
hook env exit
```

Use a public identity ID only in the selected sandbox; an IAM test SLT also works. `--test <UUID>` selects a previously saved sandbox for one command. `--production` uses the production session for one command. `env use` remembers the choice; `env exit` clears it without logging out production.

`--app-secret-file -` reads the secret from stdin. Files, JSON output and pipes are never mixed with the test-context footer, which always goes to stderr. Missing or revoked selectors fail without changing the selection.

Local delivery can optionally use `--secret-file ./receiver-secret` for HMAC signing, `--isi <id>` for internal Silicon metadata and `--test-destination` to explicitly mark a remote test receiver. No ISI is required.

Legacy `env create`, `env attach`, `env key`, `env rotate-key`, `env clean` and `env configure-iam` remain available for existing root-key integrations. These are administrative commands, require their existing owner/root authority, and are not needed to select or use an IAM application sandbox. See `hook env <command> --help`.

Bug-report submission creates a real GitHub issue and email notification. While testing it is refused; use `hook --production report "description"` to submit explicitly outside the sandbox.
