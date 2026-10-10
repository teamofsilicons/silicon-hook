#!/usr/bin/env python3
"""Back up and rehearse restore of only the independent Accounts Hook store."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
from datetime import datetime, timezone

ROOT = Path('/opt/silicon-accounts-apps/hook')
DESTINATION = 's3://silicon-hook-standalone-artifacts-lxpfsbc0jpuk/parallel-accounts-20261010/hook/backups/'


def run(args, **kwargs):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed with exit {result.returncode}')
    return result.stdout


def backup():
    if os.geteuid() != 0:
        raise ValueError('Run as root on the Hook host')
    os.umask(0o077)
    secret = json.loads(json.loads(run(['aws', '--region', 'us-east-1', 'secretsmanager',
        'get-secret-value', '--secret-id', 'silicon-hook/accounts-production/runtime']))['SecretString'])
    if secret['database'] != 'hook_accounts' or set(secret['role_passwords']) != {
            'hook_accounts_migrator', 'hook_accounts_api', 'hook_accounts_worker'}:
        raise ValueError('Refusing a legacy or unrelated database')
    name = 'hook-accounts-restore-' + str(os.getpid())
    with tempfile.TemporaryDirectory(prefix='hook-accounts-backup-') as temporary:
        work = Path(temporary)
        # FORCE RLS deliberately prevents the app's owner role from reading all rows.
        # Use the host's existing local database administrator for this fixed database
        # only, rather than weakening RLS or granting BYPASSRLS to an application role.
        dump = run(['docker', 'exec', '-u', 'postgres', 'hook-postgres', 'pg_dump',
                    '-U', 'postgres', '-d', 'hook_accounts', '-Fc'])
        (work / 'database.dump').write_bytes(dump)
        (work / 'runtime-secret.json').write_text(json.dumps(secret))
        image = run(['docker', 'inspect', '--format', '{{.Image}}', 'hook-postgres']).decode().strip()
        # No published ports or network: the rehearsal cannot reach either production store.
        run(['docker', 'run', '-d', '--name', name, '--network', 'none', '--memory', '256m',
             '--pids-limit', '128', '--tmpfs', '/var/lib/postgresql/data:rw,size=256m',
             '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', image])
        try:
            for _ in range(40):
                check = subprocess.run(['docker', 'exec', name, 'pg_isready', '-U', 'postgres'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if check.returncode == 0:
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError('Isolated restore PostgreSQL did not become ready')
            run(['docker', 'exec', '-i', name, 'pg_restore', '-U', 'postgres', '-d', 'postgres',
                 '--exit-on-error', '--no-owner', '--no-privileges'], input=dump)
            sql = "SELECT schemaname || '.' || tablename FROM pg_tables WHERE schemaname IN ('hook','hook_private','public') ORDER BY 1"
            tables = run(['docker', 'exec', name, 'psql', '-XAt', '-U', 'postgres', '-c', sql]).decode().splitlines()
            counts = {}
            for table in tables:
                schema, relation = table.split('.', 1)
                quoted = '"' + schema.replace('"', '""') + '"."' + relation.replace('"', '""') + '"'
                counts[table] = int(run(['docker', 'exec', name, 'psql', '-XAt', '-U', 'postgres',
                    '-c', 'SELECT count(*) FROM ' + quoted]))
            if not tables or not any(t.startswith('hook.') for t in tables):
                raise RuntimeError('Restored store is missing Hook schema')
        finally:
            run(['docker', 'rm', '-f', name])
        manifest = {'created_at': datetime.now(timezone.utc).isoformat(), 'database': 'hook_accounts',
            'database_dump_sha256': hashlib.sha256(dump).hexdigest(), 'restore_verified': True,
            'restore_network': 'none', 'table_counts': counts,
            'config_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT / 'config').glob('*.env')}}
        (work / 'manifest.json').write_text(json.dumps(manifest, indent=2))
        archive = work / 'backup.tar.gz'
        with tarfile.open(archive, 'w:gz') as bundle:
            for item in ['database.dump', 'runtime-secret.json', 'manifest.json']:
                bundle.add(work / item, arcname=item)
            for item in ['config', 'releases', 'db-ca.crt', 'install-receipt.json']:
                bundle.add(ROOT / item, arcname=item)
            for unit in ['silicon-hook-accounts-api.service', 'silicon-hook-accounts-worker.service']:
                bundle.add(Path('/etc/systemd/system') / unit, arcname='systemd/' + unit)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        uri = DESTINATION + stamp + '.tar.gz'
        run(['aws', '--region', 'us-east-1', 's3', 'cp', str(archive), uri,
             '--sse', 'AES256', '--only-show-errors'])
        receipt = {'destination': uri, 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
                   'bytes': archive.stat().st_size, **manifest}
        (ROOT / 'last-backup.json').write_text(json.dumps(receipt, indent=2))
        print(json.dumps(receipt))


if __name__ == '__main__':
    backup()
