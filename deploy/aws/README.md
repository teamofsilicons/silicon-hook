# Hook standalone hosting

The API and worker run as [native systemd releases](../native/README.md); use that
procedure for every backend release. This folder describes the host itself and how
to rebuild it.

One dedicated ARM64 EC2 `t4g.small` runs Caddy, the Hook API, the retention worker
and PostgreSQL 16. No load balancer is attached. Only TCP 80 and 443 are public;
administration uses Systems Manager. The database and API listen on loopback. The
web console is a Next.js app on Vercel (`https://hook.teamofsilicons.com`) that
signs Carbons in with Silicon Accounts and calls the API from its server; nothing
of it runs on this host.

- AWS profile: `silicon-production`, account `234951665042`, region `us-east-1`.
- Stack: `silicon-hook-standalone` ([template](standalone.yaml)).
- Server: `i-04398b332e0a3c1b7`, public address `44.201.25.46`.
- API and provider ingress: `https://backend.hook.teamofsilicons.com`.
- Web console: `https://hook.teamofsilicons.com`, Vercel project `silicon-hook-frontend`.
- Private artifacts and backups: `silicon-hook-standalone-artifacts-lxpfsbc0jpuk`.

The account's regional Elastic IP allocation is full; all allocations were in
use and a quota-increase request already existed. The instance uses its
automatically assigned public IPv4. Reboots preserve it; stop/start or
replacement can change it. Update only Namecheap's `backend.hook` A record after
such a change. Add a dedicated Elastic IP when quota is available.

## Runtime and data

Runtime files are private under `/opt/silicon-hook` and `/etc/silicon-hook`.
Production encryption, cursor and database keys are generated on the host and
kept across releases. Hook's Silicon Accounts app secret and webhook signing
secret live only in the API's settings (`/etc/silicon-hook/api.env`); the worker
and the migrator never receive them. No development database, test token or
local secret is copied into the deployment.

PostgreSQL holds `hook_prod`, with private API and worker roles and the
repository's explicit [runtime grants](../postgres/README.md). The shared test
database of Hook before 1.0 (`hook_test`) is no longer migrated or used; it is
kept, and backed up, until it is dropped (see
[the 1.0 cutover](../../docs/migration/cutover.md)). Connections verify the local
TLS certificate. Migrations run as the database administrator before the
services start; the API and worker have no administrator credentials. Caddy
obtains and renews the public certificate and proxies everything to the API.

Data volumes live on encrypted 40 GiB gp3 EBS kept on instance termination.
`hook-backup.timer` runs daily at 03:15 UTC and uploads PostgreSQL custom-format
dumps, the private configuration and the native release settings to an encrypted
private S3 prefix. The host role can read release objects and write backup
objects only. A restore needs the database dumps and the matching encryption
keys; test restoration separately before relying on backups for disaster
recovery. This small deployment has no replica or failover and is down while
the host fails or is replaced.

## Rebuild the host

1. Create the stack from [standalone.yaml](standalone.yaml).
2. Build the `silicon-hook:production` image from the repository root
   (`docker build --platform linux/arm64 -t silicon-hook:production .`).
3. Put Hook's Silicon Accounts settings in `~/.silicon-hook/accounts.env`
   (owner-only, one `KEY=value` per line): `HOOK_APP_SECRET` and
   `HOOK_ACCOUNTS_WEBHOOK_SECRET`, optionally `ACCOUNTS_URL` and `HOOK_TING_URL`.
   Run [prepare.py](prepare.py); it prints only the private archive path.
4. Upload the archive and [install.py](install.py) under the bucket's
   `releases/` prefix and run [install-command.json](install-command.json)
   through SSM. The script creates PostgreSQL, the database roles, TLS, the API
   and worker containers, Caddy and the daily backup.
5. Install the current [native release](../native/README.md); it moves the API
   and worker from the containers to systemd.
6. Check public `/healthz`, `/readyz`, `/api/version`, provider ingress on an
   existing hook URL, and signing in to the web console.

Use `docker ps`, container logs, `systemctl status silicon-hook-api` and
`systemctl status hook-backup.timer` through SSM for diagnosis. Logs must not
include credential files or tokens. Back up before schema upgrades; rolling back
a release does not reverse migrations.

Earlier host records (the September 2026 cutovers and verifications) are kept in
[docs/history](../../docs/history/README.md).
