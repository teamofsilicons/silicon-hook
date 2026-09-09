# Testing through the CLI

Create an IAM test world first and save its root key in a private file. Create
or import `tos>hook` in that IAM world, saving the returned app secret and its
webhook signing configuration as the JSON shown in the testing API guide.

```sh
hook --profile work --org tos env create provider-test \
  --iam-key-file /private/iam-test-key \
  --iam-config /private/iam-test-application.json
hook --profile work env list --status all
```

Creation prints a Hook environment UUID and root key and saves the key in the
selected local profile. Save the UUID as your context selector; never place the
root key in `--test`.

```sh
hook --profile work --test <uuid> env current
hook --profile work --test <uuid> env configure-iam \
  --file /private/iam-test-application.json
hook --profile work --test <uuid> iam --json
hook --profile work --test <uuid> --org tos --silicon cos:tos login \
  --slt-file /private/test-slt
hook --profile work --test <uuid> login status --json
hook --profile work --test <uuid> webhook http://127.0.0.1:9000/events
hook --profile work --test <uuid> --silicon cos:tos create Provider
hook --profile work --test <uuid> --silicon cos:tos events
```

`configure-iam` is needed only if omitted during creation or deliberately
changing that configuration. Obtain the SLT by signing in through IAM in the
linked test world. Production and test sessions occupy different local slots.

To use an existing environment from another profile/machine, obtain its key
through an authorized route and run:

```sh
hook --profile another env attach <uuid> --key-file /private/hook-test-key
```

Attach checks that the key belongs to the specified UUID. It does not sign an
actor in. Set the correct service origin for a new profile before attaching.

## Administrative actions

These use the production session, so omit `--test`:

```sh
hook --profile work env show <uuid>
hook --profile work env key <uuid>
hook --profile work --idempotency-key rotate-example-001 env rotate-key <uuid>
hook --profile work env delete <uuid>
hook --profile work env restore <uuid>
```

Key retrieval/rotation updates the local profile's stored key. Other profiles
must retrieve/attach the replacement. Their old streams close. Delete keeps
data recoverable for 30 days; restore re-enables the retained key.

Root operations use `--test`:

```sh
hook --profile work --test <uuid> --idempotency-key reset-example-001 env clean
```

This clears all Hook data in that environment. Repeating the exact mutation key
returns the first result rather than clearing again. The environment, IAM
binding and URL tombstones remain. There is no production `clean` equivalent.

The same `create`, `list`, `update`, rotations, history, deliveries and daemon
commands work under `--test`. The ten-hook ceiling is for the whole environment,
including soft-deleted hooks, and is not a production quota. For lifecycle and
isolation details see the [testing model](README.md).

For environment listing, use `env list --limit 100 --after <last-uuid>` to
continue a previous page. The default is 100; the maximum is 1000.

`webhook` and `unhook` only change delivery for the selected test session.
Omitting `--test` selects the production session; it does not detach test
recipients. Status never borrows production credentials for a missing test login.
