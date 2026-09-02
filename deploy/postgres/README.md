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
| `hook.hooks` | `SELECT, INSERT, UPDATE` | `SELECT, DELETE` for expired-recovery purge |
| `hook.events` | `SELECT, INSERT` | `SELECT, DELETE` for 14-day retention |
| `hook.blocked_requests` | `SELECT, INSERT` | `SELECT, DELETE` for 14-day retention |
| retired endpoint keys | `SELECT, INSERT` | none |
| delivery sequences | `SELECT, INSERT, UPDATE` | none |
| delivery cursors | `SELECT, INSERT, UPDATE` | none |
| address blocks | `SELECT, INSERT, UPDATE` | `SELECT, DELETE` for stale-block cleanup |
| management idempotency | `SELECT, INSERT, UPDATE, DELETE` | `SELECT, DELETE` |
| audit log | `INSERT` | none |

The API also issues `LISTEN`/`NOTIFY` on the `hook_delivery` channel, which
needs no table privilege.

Reapply this manifest after every migration. New tables receive no runtime
access by default, forcing each migration review to update this matrix
deliberately. Docker Compose executes the same manifest with development-only
roles and passwords; those values are not suitable for any shared environment.
`/readyz` and worker startup separately probe this matrix, so a missing grant
fails before the process advertises readiness or starts consuming work.
