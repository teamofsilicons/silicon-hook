# Hook standalone hosting

The frontend is a static SolidJS build on Vercel. One dedicated ARM64 EC2
`t4g.small` runs Caddy, Hook API, retention worker, Node browser gateway, and
PostgreSQL 16. No load balancer is attached. Only TCP 80 and 443 are public;
administration uses Systems Manager. Database/API/gateway listeners use loopback.

- AWS profile: `silicon-production`, account `234951665042`, region `us-east-1`.
- Stack: `silicon-hook-standalone` ([template](standalone.yaml)).
- Server: `i-04398b332e0a3c1b7`, public address `44.201.25.46`.
- API/gateway: `https://backend.hook.teamofsilicons.com`.
- Frontend: `https://hook.teamofsilicons.com`, Vercel project `silicon-hook-frontend`.
- Private artifacts/backups: `silicon-hook-standalone-artifacts-lxpfsbc0jpuk`.

The account's regional Elastic IP allocation is full; all allocations were in
use and a quota-increase request already existed. The instance currently uses
its automatically assigned public IPv4. Reboots preserve it; stop/start or
replacement can change it. Update only Namecheap's `backend.hook` A record after
such a change. Add a dedicated Elastic IP when quota is available.

## Runtime and data

Runtime files are private under `/opt/silicon-hook`. Fresh production encryption,
cursor, database and browser-session keys are generated on the host and retained
across releases. The supplied IAM app credentials select `tos>hook`. No development
database, actor token, or testing root key is copied into the deployment.

PostgreSQL has separate `hook_prod` and `hook_test` databases, private API and
worker roles, and the repository's explicit runtime grants. Connections verify
the local TLS certificate. Migrations run as the database administrator before
runtime startup; runtime containers have no administrator credentials. Caddy
obtains/renews the public certificate. Sessions use encrypted files with a stable
key; the gateway must remain a single process with private persistent storage.

Data volumes reside on encrypted 40 GiB gp3 EBS retained on instance termination.
`hook-backup.timer` runs daily at 03:15 UTC. It uploads PostgreSQL custom-format
dumps and the encryption/configuration files to an encrypted private S3 prefix.
The host role can read release objects and write backup objects only. Restore
requires database dumps and matching encryption keys; test restoration separately
before relying on backups as a disaster-recovery procedure. This small deployment
has no replica/failover and incurs downtime during host failure/replacement.

## Release procedure

1. Build the ARM64 backend and gateway Docker images from the intended source.
2. Run `prepare.py` locally to stage a private release using the existing IAM
   credential file. It prints only the private archive path.
3. Upload the archive under the stack bucket's `releases/` prefix. Use SSM to
   unpack/load it and run `install.py`. The script preserves database data and
   credentials, applies migrations/grants, and replaces only Hook containers.
4. Deploy `web/` with Vercel, setting `VITE_HOOK_GATEWAY_ORIGIN` to the backend
   origin. The `.vercel/output` build contains static files and no session data.
5. Check public `/healthz`, `/readyz`, `/api/version`, frontend sign-in, and a
   paired IAM/Hook testing environment with live delivery and acknowledgment.

Use `docker ps`, container logs and `systemctl status hook-backup.timer` through
SSM for diagnosis. Logs must not include credential environment files or IAM
callback query strings. Back up before schema upgrades; a container rollback
does not reverse migrations. No source commit or public CLI/client release is
implied by deploying this working-tree build.
