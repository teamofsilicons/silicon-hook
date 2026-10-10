#!/usr/bin/env python3
"""Set up a new dedicated Hook host (PostgreSQL, Caddy, API and worker containers); never prints secrets.

This is the original host setup, kept for rebuilding the host. Releases on an
existing host use the native bundle (deploy/native/install.py). accounts.json
holds Hook's Silicon Accounts settings: HOOK_APP_SECRET and
HOOK_ACCOUNTS_WEBHOOK_SECRET are required. The web console runs on Vercel, so
Caddy sends everything to the API.
"""
import base64
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import time

os.umask(0o077)
root = Path('/opt/silicon-hook')
root.mkdir(exist_ok=True)
os.chdir(root)

def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def envfile(name, values):
    (root / name).write_text(''.join(f'{k}={v}\n' for k, v in values.items()))

credentials = root / 'credentials.json'
if credentials.exists():
    creds = json.loads(credentials.read_text())
else:
    creds = {k: secrets.token_hex(32) for k in ['postgres', 'api', 'worker']}
    creds.update({k: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=') for k in ['encryption', 'cursor']})
    credentials.write_text(json.dumps(creds))
ACCOUNTS_KEYS = {'ACCOUNTS_URL', 'ACCOUNTS_API_URL', 'HOOK_APP_ID', 'HOOK_APP_SECRET', 'HOOK_ACCOUNTS_WEBHOOK_SECRET',
                 'HOOK_ACCOUNTS_WEBHOOK_PREVIOUS_SECRET', 'HOOK_ACCOUNTS_TIMEOUT_SECONDS', 'HOOK_TING_URL'}
accounts = json.loads((root / 'accounts.json').read_text())
if set(accounts) - ACCOUNTS_KEYS:
    raise RuntimeError('accounts.json may hold only Silicon Accounts settings: ' + ', '.join(sorted(ACCOUNTS_KEYS)))
for key in ('HOOK_APP_SECRET', 'HOOK_ACCOUNTS_WEBHOOK_SECRET'):
    if not accounts.get(key):
        raise RuntimeError(f'accounts.json is missing {key}')
tls = root / 'db-tls'
tls.mkdir(exist_ok=True)
tls.chmod(0o755)
renewed = not (tls / 'ca.crt').exists()
if renewed:
    run('openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '3650',
        '-keyout', str(tls / 'ca.key'), '-out', str(tls / 'ca.crt'),
        '-subj', '/CN=Hook local database CA', '-addext', 'basicConstraints=critical,CA:TRUE',
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run('openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes',
        '-keyout', str(tls / 'server.key'), '-out', str(tls / 'server.csr'), '-subj', '/CN=localhost',
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (tls / 'extensions.cnf').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
    run('openssl', 'x509', '-req', '-in', str(tls / 'server.csr'), '-CA', str(tls / 'ca.crt'),
        '-CAkey', str(tls / 'ca.key'), '-CAcreateserial', '-days', '3650',
        '-out', str(tls / 'server.crt'), '-extfile', str(tls / 'extensions.cnf'),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (tls / 'server.crt').chmod(0o644)
    (tls / 'ca.crt').chmod(0o644)
    os.chown(tls / 'server.key', 999, 999)
    (tls / 'server.key').chmod(0o600)
envfile('postgres.env', {'POSTGRES_PASSWORD': creds['postgres']})
existing = run('docker', 'ps', '-a', '--format', '{{.Names}}', capture_output=True, text=True).stdout.splitlines()
if renewed and 'hook-postgres' in existing:
    run('docker', 'restart', 'hook-postgres')
if 'hook-postgres' not in existing:
    run('docker', 'run', '-d', '--name', 'hook-postgres', '--restart', 'unless-stopped',
        '--network', 'host', '--env-file', str(root / 'postgres.env'),
        '-v', 'hook-postgres:/var/lib/postgresql/data', '-v', f'{tls}:/run/hook-db:ro',
        '--log-opt', 'max-size=10m', '--log-opt', 'max-file=3',
        'postgres:16-bookworm', '-c', 'listen_addresses=127.0.0.1', '-c', 'ssl=on',
        '-c', 'ssl_cert_file=/run/hook-db/server.crt', '-c', 'ssl_key_file=/run/hook-db/server.key')
for _ in range(60):
    if subprocess.run(['docker', 'exec', 'hook-postgres', 'pg_isready', '-U', 'postgres'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        break
    time.sleep(1)
else:
    raise RuntimeError('PostgreSQL did not become ready')

sql = fr"""
SELECT 'CREATE DATABASE hook_prod' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='hook_prod')\gexec
SELECT 'CREATE ROLE silicon_hook_api LOGIN PASSWORD ''{creds['api']}'' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='silicon_hook_api')\gexec
SELECT 'CREATE ROLE silicon_hook_worker LOGIN PASSWORD ''{creds['worker']}'' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='silicon_hook_worker')\gexec
"""
run('docker', 'exec', '-i', 'hook-postgres', 'psql', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', input=sql, text=True, stdout=subprocess.DEVNULL)

def db(role, database):
    username = 'postgres' if role == 'postgres' else 'silicon_hook_' + role
    return f'postgres://{username}:{creds[role]}@127.0.0.1:5432/{database}?sslmode=verify-full&sslrootcert=/run/hook-db/ca.crt'

common = {
    'HOOK_ENVIRONMENT': 'production', 'HOOK_PUBLIC_BASE_URL': 'https://backend.hook.teamofsilicons.com',
    'HOOK_BIND_ADDR': '127.0.0.1:8080', 'HOOK_TRUSTED_PROXY_HOPS': '1',
    'HOOK_DATABASE_MAX_CONNECTIONS': '6', 'HOOK_DATABASE_MIN_CONNECTIONS': '1',
    'HOOK_ENCRYPTION_KEYS': '1:' + creds['encryption'], 'HOOK_ENCRYPTION_CURRENT_VERSION': '1',
    'HOOK_CURSOR_SIGNING_KEY': creds['cursor'],
}
# Only hook-api talks to Silicon Accounts; the worker and the migrator never get its secrets.
api_accounts = {'ACCOUNTS_URL': 'https://accounts.teamofsilicons.com', 'HOOK_APP_ID': 'hook', **accounts}
telemetry = {}
for line in (root/'telemetry.env').read_text().splitlines():
    if line.strip() and not line.lstrip().startswith('#'):
        key, value = line.split('=', 1)
        if key == 'HOOK_TELEMETRY_TABLE_KEY':
            telemetry[key] = shlex.split(value)[0]
if not telemetry.get('HOOK_TELEMETRY_TABLE_KEY'):
    raise RuntimeError('Missing dedicated Hook telemetry table credential')
spool = root/'telemetry-spool'
spool.mkdir(exist_ok=True)
os.chown(spool, 10001, 10001)
spool.chmod(0o700)
for role in ['api', 'worker']:
    export = {**telemetry, 'HOOK_TELEMETRY_SPOOL_DIR': '/var/lib/hook-telemetry'} if role == 'worker' else api_accounts
    envfile(role + '.env', {**common, **export, 'HOOK_DATABASE_URL': db(role, 'hook_prod')})
envfile('migration.env', {**common, 'HOOK_MIGRATOR_DATABASE_URL': db('postgres', 'hook_prod')})
run('docker', 'run', '--rm', '--network', 'host', '--env-file', str(root/'migration.env'),
    '-v', f'{tls}:/run/hook-db:ro', '--entrypoint', '/usr/local/bin/hook-migrate', 'silicon-hook:production')
run('docker', 'exec', '-i', 'hook-postgres', 'psql', '-U', 'postgres', '-d', 'hook_prod',
    '-v', 'ON_ERROR_STOP=1', '-v', 'api_role=silicon_hook_api', '-v', 'worker_role=silicon_hook_worker',
    input=(root/'grant-runtime.sql').read_text(), text=True, stdout=subprocess.DEVNULL)

for role in ['api', 'worker']:
    name = 'hook-' + role
    if name in existing:
        run('docker', 'stop', '-t', '120', name)
        run('docker', 'rm', name)
    run('docker', 'run', '-d', '--name', name, '--restart', 'unless-stopped', '--network', 'host',
        '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--log-opt', 'max-size=10m', '--log-opt', 'max-file=3',
        '--env-file', str(root/(role+'.env')), '-v', f'{tls}:/run/hook-db:ro',
        *(['-v', f'{spool}:/var/lib/hook-telemetry'] if role == 'worker' else []),
        '--entrypoint', '/usr/local/bin/hook-'+role, 'silicon-hook:production')

# The browser gateway of Hook before 1.0 is retired: the web console is a
# Next.js app on Vercel. A gateway left from an earlier setup is stopped with
# its restart disabled (kept for rollback), and Caddy proxies only the API.
if 'hook-gateway' in existing:
    run('docker', 'update', '--restart=no', 'hook-gateway')
    run('docker', 'stop', '-t', '30', 'hook-gateway')
(root/'Caddyfile').write_text('''backend.hook.teamofsilicons.com {
    header Strict-Transport-Security "max-age=31536000"
    reverse_proxy 127.0.0.1:8080
}
''')
if 'hook-https' in existing:
    run('docker', 'exec', 'hook-https', 'caddy', 'reload', '--config', '/etc/caddy/Caddyfile')
else:
    run('docker', 'run', '-d', '--name', 'hook-https', '--restart', 'unless-stopped', '--network', 'host',
        '-v', f'{root}/Caddyfile:/etc/caddy/Caddyfile:ro', '-v', 'hook-caddy:/data',
        '--log-opt', 'max-size=10m', '--log-opt', 'max-file=3', 'caddy:2')
print('Hook runtime installed; verify HTTPS readiness and Silicon Accounts sign-in.')

bucket = os.environ.get('HOOK_BACKUP_BUCKET')
if bucket:
    (Path('/etc/systemd/system')/'hook-backup.service').write_text(f'''[Unit]
Description=Back up Hook databases and encryption configuration
After=docker.service
[Service]
Type=oneshot
ExecStart=/bin/bash /opt/silicon-hook/backup.sh {bucket}
''')
    (Path('/etc/systemd/system')/'hook-backup.timer').write_text('''[Unit]
Description=Daily Hook backup
[Timer]
OnCalendar=*-*-* 03:15:00 UTC
Persistent=true
[Install]
WantedBy=timers.target
''')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'hook-backup.timer')
