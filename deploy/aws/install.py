#!/usr/bin/env python3
"""Install an isolated Hook runtime on the dedicated host; never prints secrets."""
import base64
import json
import os
from pathlib import Path
import secrets
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
    creds['session'] = base64.b64encode(secrets.token_bytes(32)).decode()
    credentials.write_text(json.dumps(creds))
iam = json.loads((root / 'iam.json').read_text())
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

sql = f"""
SELECT 'CREATE DATABASE hook_prod' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='hook_prod')\gexec
SELECT 'CREATE DATABASE hook_test' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='hook_test')\gexec
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
    'HOOK_IAM_BASE_URL': 'https://backend.iam.teamofsilicons.com', 'HOOK_IAM_APP_ID': 'tos>hook',
    **iam,
}
for role in ['api', 'worker']:
    envfile(role + '.env', {**common, 'HOOK_DATABASE_URL': db(role, 'hook_prod'), 'HOOK_TEST_DATABASE_URL': db(role, 'hook_test')})
envfile('migration.env', {**common, 'HOOK_MIGRATOR_DATABASE_URL': db('postgres', 'hook_prod'), 'HOOK_TEST_MIGRATOR_DATABASE_URL': db('postgres', 'hook_test')})
run('docker', 'run', '--rm', '--network', 'host', '--env-file', str(root/'migration.env'),
    '-v', f'{tls}:/run/hook-db:ro', '--entrypoint', '/usr/local/bin/hook-migrate', 'silicon-hook:production')
for database in ['hook_prod', 'hook_test']:
    run('docker', 'exec', '-i', 'hook-postgres', 'psql', '-U', 'postgres', '-d', database,
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
        '--entrypoint', '/usr/local/bin/hook-'+role, 'silicon-hook:production')

sessions = root/'sessions'
sessions.mkdir(exist_ok=True)
os.chown(sessions, 1000, 1000)
sessions.chmod(0o700)
envfile('gateway.env', {
    'NODE_ENV': 'production', 'HOST': '127.0.0.1', 'PORT': '4317',
    'HOOK_WEB_ORIGIN': 'https://backend.hook.teamofsilicons.com',
    'HOOK_FRONTEND_ORIGIN': 'https://hook.teamofsilicons.com',
    'HOOK_API_UPSTREAM': 'http://127.0.0.1:8080',
    'HOOK_SESSION_DIR': '/var/lib/hook-web/sessions', 'HOOK_SESSION_KEY': creds['session']})
if 'hook-gateway' in existing:
    run('docker', 'stop', '-t', '30', 'hook-gateway')
    run('docker', 'rm', 'hook-gateway')
run('docker', 'run', '-d', '--name', 'hook-gateway', '--restart', 'unless-stopped', '--network', 'host',
    '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '--log-opt', 'max-size=10m', '--log-opt', 'max-file=3',
    '--env-file', str(root/'gateway.env'), '-v', f'{sessions}:/var/lib/hook-web/sessions', 'silicon-hook-gateway:production')
(root/'Caddyfile').write_text('''backend.hook.teamofsilicons.com {
    header Strict-Transport-Security "max-age=31536000"
    @console path /console/* /auth/callback
    handle @console {
        reverse_proxy 127.0.0.1:4317
    }
    handle {
        reverse_proxy 127.0.0.1:8080
    }
}
''')
if 'hook-https' in existing:
    run('docker', 'exec', 'hook-https', 'caddy', 'reload', '--config', '/etc/caddy/Caddyfile')
else:
    run('docker', 'run', '-d', '--name', 'hook-https', '--restart', 'unless-stopped', '--network', 'host',
        '-v', f'{root}/Caddyfile:/etc/caddy/Caddyfile:ro', '-v', 'hook-caddy:/data',
        '--log-opt', 'max-size=10m', '--log-opt', 'max-file=3', 'caddy:2')
print('Hook runtime installed; verify HTTPS readiness and IAM sign-in.')

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
