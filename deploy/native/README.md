# Native Hook backend releases

The API and worker run as native Linux ARM64 executables under systemd. The
backend archive contains `hook-api`, `hook-worker`, `hook-migrate`,
`hook-contract`, systemd units, runtime grants, an installer and a SHA-256 file
manifest. It contains no credentials. This is separate from the Honeycomb CLI
archive.

Build with Rust 1.98, cargo-zigbuild and Zig on PATH:

```sh
cargo zigbuild --locked --release -p silicon-hook --bins \
  --target aarch64-unknown-linux-gnu.2.28 --target-dir target/hook-backend-native
python3 scripts/package-backend.py \
  --artifacts target/hook-backend-native/aarch64-unknown-linux-gnu/release
```

On the existing Amazon Linux 2023 ARM64 host, install the PostgreSQL 16 client
utilities (`dnf install postgresql16`). Upload the archive to the private release
bucket, verify its archive checksum, and extract it to a private staging folder.
Run the bundled `install.py` without `--apply` first. It validates the complete
file inventory, all hashes, native executable dependencies and host prerequisites.
Then run as root:

```sh
python3 install.py --apply \
  --backup-bucket silicon-hook-standalone-artifacts-lxpfsbc0jpuk
```

The installer reads existing private configuration, backs up both databases and
configuration to the encrypted private bucket, creates an unprivileged
`silicon-hook` account, and installs an immutable release under
`/opt/silicon-hook/releases/<revision>`. `/opt/silicon-hook/current` selects the
active bundle. Root-owned environment files live under `/etc/silicon-hook`.
Only the worker can write the existing telemetry spool. Both services have
systemd filesystem, privilege and capability restrictions and restart on failure.

The API and worker containers are stopped and their automatic restart is disabled.
They are retained for recovery; PostgreSQL, Caddy, the browser gateway and their
volumes are untouched by this migration. New deployments use the native bundle,
not `deploy/aws/install.py` or Docker image loading.

The installer applies embedded migrations and exact runtime grants before starting
`silicon-hook-api.service` and `silicon-hook-worker.service`. It checks API
readiness and both process states. Use `systemctl status` and `journalctl -u` for
operations. Verify public `/healthz`, `/readyz`, `/api/version` and authenticated
status after deployment.

A failed service switch restores the previous release/configuration or restarts
the retained containers. Database migrations are not reversed automatically. An
older executable can reject a newer schema; when schema changes were applied,
recovery may require restoring both database dumps while services are stopped.
The installer records the previous release and container restart policies in the
private backup's `rollback.json`. Never restore over a database that is accepting
writes.

## Verified deployment

On September 17, 2026, release `2c3a41118ad4` replaced the API and worker
containers on the standalone host. Both native units are enabled and healthy;
production and shared-test databases have migrations 1–9. See the
[deployment evidence](../../docs/verification/native-backend-2026-09-17.json).
Daily backups include `/etc/silicon-hook`, both service units and the active
release symlink, alongside the existing database and configuration backups.
