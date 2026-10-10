# Native Hook backend releases

The API and worker run as native Linux ARM64 executables under systemd. The
backend archive contains `hook-api`, `hook-worker`, `hook-migrate`,
`hook-contract`, systemd units, runtime grants, an installer and a SHA-256 file
manifest. It contains no credentials. It is separate from the CLI's Silicon Apps
archives ([releases](../../docs/releases.md)).

Build it with the `Build deployment artifacts` workflow, or locally with Rust
1.98, cargo-zigbuild and Zig on PATH:

```sh
cargo zigbuild --locked --release -p silicon-hook --bins \
  --target aarch64-unknown-linux-gnu.2.28 --target-dir target/hook-backend-native
python3 scripts/package-backend.py \
  --artifacts target/hook-backend-native/aarch64-unknown-linux-gnu/release
```

## Install a release

On the Amazon Linux 2023 ARM64 host, the PostgreSQL 16 client utilities must be
installed (`dnf install postgresql16`). Upload the archive to the private release
bucket, verify its checksum, and extract it to a private staging folder. Run the
bundled `install.py` without `--apply` first, as root. It validates the file
inventory, every hash, the executables' libraries and the host prerequisites, and
previews the configuration change by variable name (never by value), including
any setting that is still `missing`. Then:

```sh
python3 install.py --apply \
  --backup-bucket silicon-hook-standalone-artifacts-lxpfsbc0jpuk
```

Hook 1.0 signs in with Silicon Accounts, so `hook-api` needs `HOOK_APP_SECRET` and
`HOOK_ACCOUNTS_WEBHOOK_SECRET`. The first 1.0 install reads them from
`/opt/silicon-hook/accounts.env` (or `--accounts-env FILE`): owner-only, one
`KEY=value` per line without quotes, and only Silicon Accounts settings
(`ACCOUNTS_URL`, `ACCOUNTS_API_URL`, `HOOK_APP_ID`, `HOOK_APP_SECRET`,
`HOOK_ACCOUNTS_WEBHOOK_SECRET`, `HOOK_ACCOUNTS_WEBHOOK_PREVIOUS_SECRET`,
`HOOK_ACCOUNTS_TIMEOUT_SECONDS`, `HOOK_TING_URL`). They go into the API's settings
only; later installs carry them over. Without them the installer refuses before
it changes anything. Settings of earlier versions are removed from every
process, and the API keeps delivery through Ting off unless `HOOK_TING_URL` is
set ([delivery](../../docs/ting-delivery.md)).

The installer reads the existing private configuration, backs up the databases
and configuration to the encrypted private bucket, creates the unprivileged
`silicon-hook` account and installs an immutable release under
`/opt/silicon-hook/releases/<revision>`; `/opt/silicon-hook/current` selects the
active one. Root-owned environment files live under `/etc/silicon-hook`. Only the
worker can write the telemetry spool. Both services have systemd filesystem,
privilege and capability restrictions and restart on failure.

With both writers stopped it takes a second, quiesced backup, applies the
embedded migrations to `hook_prod` and reapplies the exact runtime grants, then
starts `silicon-hook-api.service` and `silicon-hook-worker.service` and checks API
readiness and both process states. The shared test database of Hook before 1.0 is
backed up while its URL is still configured, but never migrated. Use
`systemctl status` and `journalctl -u` for operations, and check public
`/healthz`, `/readyz` and `/api/version` afterwards.

## Roll back

A failed switch restores the previous release, settings and units (or restarts
the retained containers). Database migrations are not reversed: an older
executable refuses a schema it does not know, so after a schema-changing release
recovery means stopping both services, restoring the quiesced dumps from the
backup, and then restoring the previous release. The installer records the
previous release and container restart policies in the backup's
`rollback.json`. Never restore over a database that is accepting writes. The
exact 1.0 steps are in [the cutover runbook](../../docs/migration/cutover.md).

Daily backups include `/etc/silicon-hook`, both service units and the active
release symlink, alongside the database and configuration backups. Records of
earlier deployments are in [docs/history](../../docs/history/README.md).
