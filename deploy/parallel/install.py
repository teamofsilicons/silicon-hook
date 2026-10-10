#!/usr/bin/env python3
"""Install only the independent Accounts Hook; never replace the IAM deployment.

Run on the existing Hook host after its fresh hook_accounts database and scoped
Secrets Manager permission have been prepared. Public proxy stays in maintenance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import tarfile
import time
import urllib.parse
import urllib.request

ROOT = Path('/opt/silicon-accounts-apps/hook')
USER = 'silicon-hook-accounts'
SECRET = 'silicon-hook/accounts-production/runtime'
SERVICES = ('silicon-hook-accounts-api', 'silicon-hook-accounts-worker')


def run(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed with exit {result.returncode}')
    return result.stdout


def envfile(path, values):
    if any('\n' in str(v) or '\r' in str(v) for v in values.values()):
        raise ValueError('Environment values must be single line')
    path.write_text(''.join(f'{k}={v}\n' for k, v in values.items()))
    path.chmod(0o600)


def install(archive, expected):
    if os.geteuid() != 0:
        raise ValueError('Run as root on the target host')
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise ValueError('Backend archive checksum mismatch')
    secret = json.loads(json.loads(run(['aws', '--region', 'us-east-1', 'secretsmanager',
        'get-secret-value', '--secret-id', SECRET]))['SecretString'])
    if secret['database'] != 'hook_accounts' or set(secret['role_passwords']) != {
            'hook_accounts_migrator', 'hook_accounts_api', 'hook_accounts_worker'}:
        raise ValueError('Only the isolated Accounts database and roles are allowed')
    try:
        pwd.getpwnam(USER)
    except KeyError:
        run(['useradd', '--system', '--no-create-home', '--shell', '/sbin/nologin', USER])
    identity = pwd.getpwnam(USER)
    ROOT.mkdir(parents=True, exist_ok=True)
    ROOT.chmod(0o750)
    os.chown(ROOT, 0, identity.pw_gid)
    # Parent is traversal-only; each application's private directory enforces isolation.
    ROOT.parent.chmod(0o755)
    releases = ROOT / 'releases'
    releases.mkdir(exist_ok=True)
    releases.chmod(0o755)
    with tarfile.open(archive) as bundle:
        manifest = json.load(bundle.extractfile('manifest.json'))
        revision = manifest['source_revision']
        if manifest['target'] != 'linux-aarch64' or not re.fullmatch(r'[0-9a-f]{40}', revision):
            raise ValueError('Invalid backend target or source revision')
        destination = releases / revision
        if destination.exists():
            raise ValueError('Release already installed; inspect it instead of overwriting')
        for member in bundle.getmembers():
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError('Unsafe archive member')
        destination.mkdir(mode=0o755)
        destination.chmod(0o755)
        bundle.extractall(destination)
    for name, digest in manifest['files'].items():
        path = destination / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Extracted file checksum mismatch')
    ca = ROOT / 'db-ca.crt'
    shutil.copyfile('/opt/silicon-hook/db-tls/ca.crt', ca)
    ca.chmod(0o644)

    def url(role):
        password = urllib.parse.quote(secret['role_passwords'][role], safe='')
        return f'postgres://{role}:{password}@127.0.0.1:5432/hook_accounts?sslmode=verify-full&sslrootcert={ca}'

    common = {'HOOK_ENVIRONMENT': 'production', 'HOOK_DATABASE_MAX_CONNECTIONS': '4',
              'HOOK_LOG_FILTER': 'silicon_hook=info'}
    migration = {**common, 'HOOK_MIGRATOR_DATABASE_URL': url('hook_accounts_migrator')}
    api = {**common, 'HOOK_DATABASE_URL': url('hook_accounts_api'),
           'HOOK_BIND_ADDR': '127.0.0.1:8081', 'HOOK_PUBLIC_BASE_URL': 'https://api.hook.teamofsilicons.com',
           'HOOK_TRUSTED_PROXY_HOPS': '1', 'HOOK_ENCRYPTION_KEYS': '1:' + secret['data_key'],
           'HOOK_ENCRYPTION_CURRENT_VERSION': '1', 'HOOK_CURSOR_SIGNING_KEY': secret['cursor_key'],
           'ACCOUNTS_URL': 'https://accounts.teamofsilicons.com', 'HOOK_APP_SECRET': secret['app_secret'],
           'HOOK_ACCOUNTS_WEBHOOK_SECRET': secret['webhook_secret']}
    worker = {**common, 'HOOK_DATABASE_URL': url('hook_accounts_worker')}
    config = ROOT / 'config'
    config.mkdir(mode=0o700, exist_ok=True)
    for role, values in [('migration', migration), ('api', api), ('worker', worker)]:
        envfile(config / (role + '.env'), values)
    output = run([str(destination / 'bin/hook-migrate')], env={**os.environ, **migration})
    (ROOT / 'migration.log').write_text(output)
    (ROOT / 'migration.log').chmod(0o600)
    # Run grants as the new owner, through the existing PostgreSQL client only.
    env = {**os.environ, 'PGPASSWORD': secret['role_passwords']['hook_accounts_migrator']}
    run(['docker', 'exec', '-i', '-e', 'PGPASSWORD', 'hook-postgres', 'psql', '-X',
         '-h', '127.0.0.1', '-U', 'hook_accounts_migrator', '-d', 'hook_accounts',
         '-v', 'ON_ERROR_STOP=1', '-v', 'api_role=hook_accounts_api', '-v', 'worker_role=hook_accounts_worker'],
        input=(destination / 'grant-runtime.sql').read_text(), env=env)
    for role, service in [('api', SERVICES[0]), ('worker', SERVICES[1])]:
        unit = f'''[Unit]
Description=Silicon Hook Accounts {role} (independent deployment)
After=network-online.target docker.service
Wants=network-online.target
[Service]
Type=simple
User={USER}
Group={USER}
WorkingDirectory={destination}
EnvironmentFile={config / (role + '.env')}
ExecStart={destination / ('bin/hook-' + role)}
Restart=on-failure
RestartSec=3
TimeoutStopSec=120
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
MemoryMax=384M
[Install]
WantedBy=multi-user.target
'''
        unitpath = Path('/etc/systemd/system') / (service + '.service')
        if unitpath.exists():
            raise ValueError('New service already exists; inspect before replacing')
        unitpath.write_text(unit)
        unitpath.chmod(0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', *SERVICES])
    ready = False
    for _ in range(20):
        try:
            with urllib.request.urlopen('http://127.0.0.1:8081/readyz', timeout=2) as response:
                ready = response.status == 200
            if ready:
                break
        except Exception:
            pass
        time.sleep(1)
    receipt = {'source_revision': revision, 'archive_sha256': expected, 'database': 'hook_accounts',
               'services': list(SERVICES), 'local_ready': ready, 'public_proxy': 'maintenance',
               'iam_units': run(['systemctl', 'is-active', 'silicon-hook-api', 'silicon-hook-worker']).splitlines()}
    (ROOT / 'install-receipt.json').write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt))
    if not ready:
        raise RuntimeError('New local API readiness failed; IAM deployment remains running')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    install(args.archive, args.sha256)
