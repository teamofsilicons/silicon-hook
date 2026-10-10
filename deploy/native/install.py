#!/usr/bin/env python3
"""Verify and install Hook native services. --apply requires an off-host backup.

Hook 1.0 signs in with Silicon Accounts. The API settings need HOOK_APP_SECRET
and HOOK_ACCOUNTS_WEBHOOK_SECRET; the first 1.0 install reads them (and any
other Silicon Accounts setting) from a private KEY=value file, --accounts-env
or /opt/silicon-hook/accounts.env, and later installs carry them over. Settings
earlier versions used are dropped from every process, and the retired shared
test database is backed up but no longer migrated. Without --apply the bundle
is verified and, when run as root, the configuration change is previewed by
variable name (never by value).
"""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import subprocess
import time
import urllib.parse
import urllib.request

ROOT = Path('/opt/silicon-hook')
CONFIG = Path('/etc/silicon-hook')
UNITS = Path('/etc/systemd/system')
SERVICES = ('silicon-hook-api', 'silicon-hook-worker')
ROLES = ('api', 'worker', 'migration')
ACCOUNTS_FILE = ROOT / 'accounts.env'
DEFAULT_ACCOUNTS_URL = 'https://accounts.teamofsilicons.com'
# Only these may come from the Silicon Accounts file, and only hook-api gets them.
ACCOUNTS_KEYS = frozenset({
    'ACCOUNTS_URL', 'ACCOUNTS_API_URL', 'HOOK_APP_ID', 'HOOK_APP_SECRET',
    'HOOK_ACCOUNTS_WEBHOOK_SECRET', 'HOOK_ACCOUNTS_WEBHOOK_PREVIOUS_SECRET',
    'HOOK_ACCOUNTS_TIMEOUT_SECONDS', 'HOOK_TING_URL', 'HOOK_TING_APP_ID',
})
API_REQUIRED = ('HOOK_APP_SECRET', 'HOOK_ACCOUNTS_WEBHOOK_SECRET')
# Settings of Hook before 1.0 (previous sign-in, test environments, lifecycle
# callbacks, the v1 WebSocket). HOOK_TING_BASE_URL is not carried over to
# HOOK_TING_URL: delivery through Ting stays off until it is set on purpose.
RETIRED_PREFIXES = ('HOOK_IAM_', 'HOOK_TEST_', 'HOOK_HONEYCOMB_', 'HOOK_REALTIME_')
RETIRED_KEYS = frozenset({'HOOK_ALLOW_LOCAL_AUTH', 'HOOK_TING_BASE_URL', 'HOOK_PROVIDER_CONNECT_TIMEOUT_MS'})
RETIRED_DATABASE_KEYS = ('HOOK_TEST_MIGRATOR_DATABASE_URL',)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, **kwargs).stdout.strip()


def settings(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if line.strip() and not line.lstrip().startswith('#'))


def native_settings(values):
    converted = dict(values)
    for key, value in values.items():
        if key.endswith('DATABASE_URL'):
            converted[key] = value.replace('/run/hook-db/ca.crt', str(ROOT / 'db-tls/ca.crt'))
    if converted.get('HOOK_TELEMETRY_SPOOL_DIR') == '/var/lib/hook-telemetry':
        converted['HOOK_TELEMETRY_SPOOL_DIR'] = str(ROOT / 'telemetry-spool')
    return converted


def retired(key):
    return key.startswith(RETIRED_PREFIXES) or key in RETIRED_KEYS


def accounts_settings(path):
    """The private Silicon Accounts file: owner-only, and only Silicon Accounts keys."""
    if path is None:
        return {}
    if path.stat().st_mode & 0o077:
        raise ValueError(f'{path} must be readable by its owner only (chmod 600)')
    values = settings(path)
    unknown = sorted(set(values) - ACCOUNTS_KEYS)
    if unknown:
        raise ValueError(f'{path} may set only {", ".join(sorted(ACCOUNTS_KEYS))}; it also sets {", ".join(unknown)}')
    empty = sorted(key for key, value in values.items() if not value.strip())
    if empty:
        raise ValueError(f'{path} leaves {", ".join(empty)} empty')
    quoted = sorted(key for key, value in values.items() if value[:1] in ('"', "'") or value != value.strip())
    if quoted:
        raise ValueError(f'{path}: write {", ".join(quoted)} as KEY=value, without quotes or surrounding spaces')
    return values


def plan(values, accounts):
    """Settings per process for this release, and the API settings still missing.

    Retired settings leave every process; Silicon Accounts settings exist only
    for hook-api (the worker and the migrator never read them).
    """
    planned = {}
    for role, environment in values.items():
        kept = {key: value for key, value in environment.items() if not retired(key)}
        if role == 'api':
            kept.setdefault('ACCOUNTS_URL', DEFAULT_ACCOUNTS_URL)
            kept.update(accounts)
        else:
            kept = {key: value for key, value in kept.items() if key not in ACCOUNTS_KEYS}
        planned[role] = kept
    return planned, [key for key in API_REQUIRED if not planned['api'].get(key, '').strip()]


def changes(before, after):
    """What a plan changes, by variable name only."""
    return {role: {'added': sorted(set(after[role]) - set(before[role])),
                   'removed': sorted(set(before[role]) - set(after[role])),
                   'changed': sorted(key for key in set(before[role]) & set(after[role])
                                     if before[role][key] != after[role][key])}
            for role in before}


def current_settings():
    return {role: native_settings(settings((CONFIG if (CONFIG / (role + '.env')).exists() else ROOT) / (role + '.env')))
            for role in ROLES}


def pg_environment(url):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    if parsed.scheme not in ('postgres', 'postgresql') or parsed.hostname != '127.0.0.1':
        raise ValueError('Expected the existing loopback PostgreSQL database')
    return dict(os.environ, PGHOST=parsed.hostname, PGPORT=str(parsed.port or 5432),
                PGUSER=urllib.parse.unquote(parsed.username or ''),
                PGPASSWORD=urllib.parse.unquote(parsed.password or ''),
                PGDATABASE=parsed.path.lstrip('/'), PGSSLMODE='verify-full',
                PGSSLROOTCERT=query['sslrootcert'][0])


def verify(bundle):
    manifest = json.loads((bundle / 'manifest.json').read_text())
    if platform.machine() not in ('aarch64', 'arm64') or platform.system() != 'Linux':
        raise ValueError('This release requires Linux ARM64')
    if manifest['target'] != 'linux-aarch64' or not re.fullmatch(r'[a-f0-9]{12}', manifest['release_id']):
        raise ValueError('Invalid release target or identifier')
    expected = set(manifest['files']) | {'manifest.json'}
    actual = set()
    for path in bundle.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('Release cannot contain symlinks or special files')
        if path.is_file():
            actual.add(str(path.relative_to(bundle)))
    if actual != expected:
        raise ValueError('Release file inventory differs from manifest')
    for name, digest in manifest['files'].items():
        path = Path(name)
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('Unsafe manifest path')
        if hashlib.sha256((bundle / path).read_bytes()).hexdigest() != digest:
            raise ValueError(f'Release checksum mismatch: {name}')
    for name in ('hook-api', 'hook-worker', 'hook-migrate', 'hook-contract'):
        binary = bundle / 'bin' / name
        if not os.access(binary, os.X_OK) or 'not found' in run('ldd', str(binary)):
            raise ValueError(f'Executable dependencies missing: {name}')
    for command in ('systemctl', 'systemd-analyze', 'pg_dump', 'pg_restore', 'psql', 'aws'):
        if not shutil.which(command):
            raise ValueError(f'Missing deployment prerequisite: {command}')
    return manifest


def atomic_link(target):
    temporary = ROOT / '.current-next'
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(target)
    temporary.replace(ROOT / 'current')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--backup-bucket')
    parser.add_argument('--accounts-env', type=Path,
                        help=f'private Silicon Accounts settings (default: {ACCOUNTS_FILE} when it exists)')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    bundle = args.bundle.resolve()
    manifest = verify(bundle)
    accounts_file = args.accounts_env or (ACCOUNTS_FILE if ACCOUNTS_FILE.exists() else None)
    if not args.apply:
        report = {'verified': True, 'release_id': manifest['release_id'], 'services': SERVICES}
        try:
            values = current_settings()
            planned, missing = plan(values, accounts_settings(accounts_file))
            report.update(configuration=changes(values, planned), missing=missing)
        except PermissionError:
            report['configuration'] = 'run as root to preview the configuration change'
        print(json.dumps(report))
        return
    if os.geteuid() != 0 or not args.backup_bucket:
        parser.error('--apply requires root and --backup-bucket')
    release = ROOT / 'releases' / manifest['release_id']
    current = ROOT / 'current'
    previous = current.resolve() if current.is_symlink() else None
    if current.exists() and not current.is_symlink():
        raise ValueError('Refusing to replace a non-symlink current path')
    if previous == release:
        for service in SERVICES:
            run('systemctl', 'is-active', service)
        print(json.dumps({'already_active': True, 'release_id': manifest['release_id']}))
        return
    values = current_settings()
    planned, missing = plan(values, accounts_settings(accounts_file))
    if missing:
        parser.error(f'Hook 1.0 needs {" and ".join(missing)} for hook-api. Put them in {accounts_file or ACCOUNTS_FILE} '
                     '(owner-only KEY=value lines) and run again; see docs/migration/cutover.md.')
    # hook_prod is migrated; the retired shared test database is only backed up.
    databases = [pg_environment(values['migration']['HOOK_MIGRATOR_DATABASE_URL'])]
    retired_databases = [pg_environment(values['migration'][key]) for key in RETIRED_DATABASE_KEYS
                         if values['migration'].get(key)]
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    backup = ROOT / 'backups' / ('before-native-' + stamp)
    backup.mkdir(parents=True)
    for directory, label in ((CONFIG, 'native-config'), (UNITS, 'units')):
        (backup / label).mkdir()
        names = [role + '.env' for role in values] if directory == CONFIG else [s + '.service' for s in SERVICES]
        for name in names:
            if (directory / name).exists():
                shutil.copy2(directory / name, backup / label / name)
    for name in ('credentials.json', 'iam.json', 'accounts.env', 'api.env', 'worker.env', 'migration.env'):
        if (ROOT / name).exists():
            shutil.copy2(ROOT / name, backup / name)
    for database in databases + retired_databases:
        path = backup / (database['PGDATABASE'] + '.dump')
        run('pg_dump', '-Fc', '-f', str(path), env=database)
        run('pg_restore', '--list', str(path))
    legacy = []
    if shutil.which('docker'):
        for name in ('hook-api', 'hook-worker'):
            inspected = subprocess.run(['docker', 'inspect', name], capture_output=True, text=True)
            if inspected.returncode == 0:
                record = json.loads(inspected.stdout)[0]
                if record['State']['Running']:
                    legacy.append({'name': name, 'restart': record['HostConfig']['RestartPolicy']['Name']})
    (backup / 'rollback.json').write_text(json.dumps({'previous_release': str(previous) if previous else None, 'legacy': legacy}))
    run('aws', 's3', 'cp', str(backup) + '/', 's3://' + args.backup_bucket + '/backups/native/' + stamp + '/',
        '--recursive', '--sse', 'AES256', '--only-show-errors')
    # The existing container UID owns the retained telemetry spool.
    try:
        if pwd.getpwuid(10001).pw_name != 'silicon-hook':
            raise ValueError('UID 10001 belongs to another host user')
    except KeyError:
        try:
            if grp.getgrgid(10001).gr_name != 'silicon-hook':
                raise ValueError('GID 10001 belongs to another host group')
        except KeyError:
            run('groupadd', '--system', '--gid', '10001', 'silicon-hook')
        run('useradd', '--system', '--uid', '10001', '--gid', 'silicon-hook', '--no-create-home',
            '--home-dir', '/var/lib/silicon-hook', '--shell', '/usr/sbin/nologin', 'silicon-hook')
    ROOT.chmod(0o711)
    release.parent.mkdir(exist_ok=True)
    release.parent.chmod(0o755)
    if release.exists():
        if verify(release) != manifest:
            raise ValueError('Existing immutable release does not match bundle')
    else:
        shutil.copytree(bundle, release)
    for path in (release, release / 'bin'):
        path.chmod(0o755)
    for path in release.rglob('*'):
        if path.is_file():
            path.chmod(0o755 if path.parent.name == 'bin' else 0o644)
    CONFIG.mkdir(exist_ok=True)
    CONFIG.chmod(0o700)
    started = False
    try:
        for role, environment in planned.items():
            file = CONFIG / (role + '.env')
            file.write_text('\n'.join(key + '=' + value for key, value in environment.items()) + '\n')
            file.chmod(0o600)
        started = True
        for service in SERVICES:
            subprocess.run(['systemctl', 'stop', service], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for record in legacy:
            run('docker', 'update', '--restart=no', record['name'])
            run('docker', 'stop', '-t', '120', record['name'])
        # These dumps are taken after both writers stop and are the recovery
        # point for a schema-changing release. Keep the earlier online backup too.
        for database in databases + retired_databases:
            path = backup / ('quiesced-' + database['PGDATABASE'] + '.dump')
            run('pg_dump', '-Fc', '-f', str(path), env=database)
            run('pg_restore', '--list', str(path))
        run('aws', 's3', 'cp', str(backup) + '/', 's3://' + args.backup_bucket + '/backups/native/' + stamp + '/',
            '--recursive', '--sse', 'AES256', '--only-show-errors')
        output = subprocess.run([str(release / 'bin/hook-migrate')], env=dict(os.environ, **planned['migration']),
                                user=10001, group=10001, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        (backup / 'migration.log').write_text(output.stdout)
        output.check_returncode()
        api_role = urllib.parse.unquote(urllib.parse.urlparse(planned['api']['HOOK_DATABASE_URL']).username)
        worker_role = urllib.parse.unquote(urllib.parse.urlparse(planned['worker']['HOOK_DATABASE_URL']).username)
        for database in databases:
            run('psql', '-v', 'ON_ERROR_STOP=1', '-v', 'api_role=' + api_role, '-v', 'worker_role=' + worker_role,
                '-f', str(release / 'grant-runtime.sql'), env=database)
        atomic_link(release)
        for service in SERVICES:
            shutil.copyfile(release / (service + '.service'), UNITS / (service + '.service'))
            (UNITS / (service + '.service')).chmod(0o644)
        run('systemd-analyze', 'verify', *(str(UNITS / (s + '.service')) for s in SERVICES))
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', *SERVICES)
        run('systemctl', 'start', *SERVICES)
        for attempt in range(45):
            try:
                with urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=2) as response:
                    if response.status == 200:
                        break
            except Exception:
                time.sleep(1)
        else:
            raise RuntimeError('Native Hook readiness did not recover')
        for service in SERVICES:
            run('systemctl', 'is-active', service)
            if run('systemctl', 'show', '--property=NRestarts', '--value', service) != '0':
                raise RuntimeError('Native service restarted during verification')
        print(json.dumps({'deployed': True, 'release_id': manifest['release_id'], 'backup': str(backup),
                          'services': SERVICES, 'readyz': 200, 'configuration': changes(values, planned),
                          'retired_databases_backed_up': [d['PGDATABASE'] for d in retired_databases],
                          'legacy_containers': 'retained stopped with restart disabled'}))
    except BaseException:
        if started:
            subprocess.run(['systemctl', 'stop', *SERVICES], capture_output=True)
            if previous:
                atomic_link(previous)
            else:
                current.unlink(missing_ok=True)
                subprocess.run(['systemctl', 'disable', *SERVICES], capture_output=True)
            for label, directory in (('native-config', CONFIG), ('units', UNITS)):
                for file in (backup / label).iterdir():
                    shutil.copy2(file, directory / file.name)
            run('systemctl', 'daemon-reload')
            if previous:
                run('systemctl', 'start', *SERVICES)
            for record in legacy:
                run('docker', 'update', '--restart=' + record['restart'], record['name'])
                run('docker', 'start', record['name'])
        raise


if __name__ == '__main__':
    main()
