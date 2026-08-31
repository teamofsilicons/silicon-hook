# PostgreSQL runtime privileges

`hook-migrate` owns schema changes. The API and worker must use distinct
non-owner login roles. Create those logins through the platform secret manager,
run the migration, and then apply the reviewed grant manifest as the schema
owner:

```bash
psql "$HOOK_MIGRATOR_DATABASE_URL" \
  --set=api_role=silicon_hook_api \
  --set=worker_role=silicon_hook_worker \
  --file=deploy/postgres/grant-runtime.sql
```

The script fails when either role is absent or the role names are equal. It
first removes existing table privileges, then grants only the current process
requirements:

| Object | API | Worker |
|---|---|---|
| `_sqlx_migrations` | `SELECT` for readiness | `SELECT` for startup readiness |
| `hook.hooks` | `SELECT, INSERT, UPDATE` | `SELECT, DELETE` for retention |
| `hook.events` | `SELECT, INSERT` | `SELECT, DELETE` for retention |
| event-retention state | trigger-owned only | `SELECT, UPDATE` for fair scheduling |
| ingress key bindings | `SELECT, INSERT` | cascade only |
| authenticated replay guards | `SELECT, INSERT, DELETE` | cascade only |
| IAM default-hook lifetime ledger | `INSERT` | none |
| `hook_private.dm_outbox` | `SELECT, INSERT` | `SELECT, UPDATE, DELETE` |
| management idempotency | `SELECT, INSERT, UPDATE, DELETE` | `SELECT, DELETE` |
| audit log | `INSERT` | none |

Reapply this manifest after every migration. New tables receive no runtime
access by default, forcing each migration review to update this matrix
deliberately. Docker Compose executes the same manifest with development-only
roles and passwords; those values are not suitable for any shared environment.
`/readyz` and worker startup separately probe this matrix, so a missing grant
fails before the process advertises readiness or starts consuming work.
