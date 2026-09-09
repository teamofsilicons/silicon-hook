#!/usr/bin/env python3
"""Stage private release files without including development/test credentials."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile

os.umask(0o077)
repo = Path(__file__).resolve().parents[2]
stage = Path(tempfile.mkdtemp(prefix='hook-production-'))
iam = {}
for line in (Path.home()/'.silicon-hook/iam-webhook.env').read_text().splitlines():
    if line.strip() and not line.lstrip().startswith('#'):
        key, value = line.split('=', 1)
        iam[key] = shlex.split(value)[0]
assert iam['HOOK_IAM_APP_ID'] == 'tos>hook'
(stage/'iam.json').write_text(json.dumps(iam))
shutil.copy(repo/'deploy/aws/install.py', stage/'install.py')
shutil.copy(repo/'deploy/aws/backup.sh', stage/'backup.sh')
shutil.copy(repo/'deploy/postgres/grant-runtime.sql', stage/'grant-runtime.sql')
subprocess.run(['docker', 'save', '-o', str(stage/'images.tar'), 'silicon-hook:production', 'silicon-hook-gateway:production'], check=True)
archive = stage/'release.tar.gz'
with tarfile.open(archive, 'w:gz') as out:
    for name in ['iam.json', 'install.py', 'backup.sh', 'grant-runtime.sql', 'images.tar']:
        out.add(stage/name, arcname=name)
print(archive)
