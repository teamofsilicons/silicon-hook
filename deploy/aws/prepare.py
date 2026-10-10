#!/usr/bin/env python3
"""Stage private host-setup files without including development or test credentials.

Reads Hook's Silicon Accounts settings from ~/.silicon-hook/accounts.env (owner-only
KEY=value lines: HOOK_APP_SECRET and HOOK_ACCOUNTS_WEBHOOK_SECRET, optionally
ACCOUNTS_URL, HOOK_APP_ID, HOOK_TING_URL) and the Space Station table key from
~/.config/silicon-hook/telemetry.env, saves the silicon-hook:production image and
prints only the private archive path. Used when (re)building the host with
deploy/aws/install.py; releases use the native bundle.
"""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile

ACCOUNTS_KEYS = {'ACCOUNTS_URL', 'ACCOUNTS_API_URL', 'HOOK_APP_ID', 'HOOK_APP_SECRET', 'HOOK_ACCOUNTS_WEBHOOK_SECRET',
                 'HOOK_ACCOUNTS_WEBHOOK_PREVIOUS_SECRET', 'HOOK_ACCOUNTS_TIMEOUT_SECONDS', 'HOOK_TING_URL',
                 'HOOK_TING_APP_ID'}

os.umask(0o077)
repo = Path(__file__).resolve().parents[2]
source = Path.home()/'.silicon-hook/accounts.env'
if source.stat().st_mode & 0o077:
    raise SystemExit(f'{source} must be readable by its owner only (chmod 600)')
accounts = {}
for line in source.read_text().splitlines():
    if line.strip() and not line.lstrip().startswith('#'):
        key, value = line.split('=', 1)
        accounts[key.strip()] = shlex.split(value)[0]
if set(accounts) - ACCOUNTS_KEYS:
    raise SystemExit(f'{source} may hold only Silicon Accounts settings: ' + ', '.join(sorted(ACCOUNTS_KEYS)))
for key in ('HOOK_APP_SECRET', 'HOOK_ACCOUNTS_WEBHOOK_SECRET'):
    if not accounts.get(key):
        raise SystemExit(f'{source} is missing {key}')
assert accounts.get('HOOK_APP_ID', 'hook') == 'hook'
stage = Path(tempfile.mkdtemp(prefix='hook-production-'))
(stage/'accounts.json').write_text(json.dumps(accounts))
shutil.copy(repo/'deploy/aws/install.py', stage/'install.py')
shutil.copy(repo/'deploy/aws/backup.sh', stage/'backup.sh')
shutil.copy(repo/'deploy/postgres/grant-runtime.sql', stage/'grant-runtime.sql')
shutil.copy(Path.home()/'.config/silicon-hook/telemetry.env', stage/'telemetry.env')
subprocess.run(['docker', 'save', '-o', str(stage/'images.tar'), 'silicon-hook:production'], check=True)
archive = stage/'release.tar.gz'
with tarfile.open(archive, 'w:gz') as out:
    for name in ['accounts.json', 'install.py', 'backup.sh', 'grant-runtime.sql', 'telemetry.env', 'images.tar']:
        out.add(stage/name, arcname=name)
print(archive)
